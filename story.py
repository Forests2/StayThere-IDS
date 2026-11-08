"""v1.3 — 침입 이야기: "어떤 IP 가 들어와서 내 PC 에서 무엇을 했다" 를 시간순 한국어 문장으로

  build(db, ip, hours=72)  → {"ip", "summary", "lines": [{"ts", "text", "kind", "sev"}], "accounts", "processes", "files", "outbound"}

어떻게 엮나
  1. 이 IP 가 들어간 경보·이벤트 (로그인 실패·성공, 들어온 연결, 포트 스캔, 웹 요청 …)
  2. 이 IP 로 로그인 성공한 계정 → 그 뒤 2시간 안에 그 계정이 실행한 명령 (process 이벤트의 username)
     Linux 는 sshd 아래에서 뜬 프로세스도 포함 (ancestors 에 sshd)
  3. 같은 시간대의 중요 파일·자동 실행·웹 폴더 변경 (file 이벤트)
  4. 그 명령들이 밖으로 나간 연결 (outbound, 같은 pid·같은 계정)
  5. 경보(describe)는 그대로 한 줄씩
모두 DB 에 있는 기록만 쓰고, 추측은 하지 않는다. 기록이 없으면 "기록 없음".
"""
import ipaddress
from collections import OrderedDict
from datetime import datetime, timedelta

from attack_taxonomy import INTRUSION_RULES, attack_of

WINDOW_AFTER_LOGON = timedelta(hours=2)
MAX_LINES = 60


def _ts(s):
    try:
        return datetime.fromisoformat(s)
    except (TypeError, ValueError):
        return None


def _short(ts):
    return (ts or "")[5:16].replace("T", " ")


def _acct(u):
    """'DESKTOP\\jun' → 'jun', 'jun' → 'jun'"""
    return (u or "").rsplit("\\", 1)[-1].lower()


def _valid(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def build(db, ip, hours=72, describe=None):
    ip = (ip or "").strip()
    if not _valid(ip):
        return {"ip": ip, "summary": "IP 형식이 아니에요", "lines": [], "accounts": [], "processes": [], "files": [],
                "outbound": [], "attacks": []}
    since = (datetime.now() - timedelta(hours=hours)).isoformat(timespec="seconds")
    alerts, events = db.find_ip(ip, limit=2000)
    alerts = [a for a in alerts if a["ts"] >= since]
    events = [e for e in events if e["ts"] >= since]
    lines = []

    # 1. 로그인 시도 (묶어서)
    fails, successes = [], []
    for e in events:
        d = e["data"] if isinstance(e["data"], dict) else {}
        if e["kind"] == "logon" and d.get("src_ip") == ip:
            (successes if d.get("type") == "logon_success" else fails).append((e["ts"], d))
    if fails:
        users = sorted({_acct(d.get("user")) for _, d in fails if d.get("user")})
        lines.append({"ts": fails[-1][0], "kind": "logon_fail", "sev": "HIGH" if len(fails) >= 5 else "MEDIUM",
                      "text": f"{ip} 가 {_short(fails[-1][0])}" + (f" ~ {_short(fails[0][0])} 사이" if _short(fails[0][0]) != _short(fails[-1][0]) else "")
                              + f"에 로그인에 {len(fails)}번 실패"
                              + (f" (시도한 계정: {', '.join(users[:5])}{' 외' if len(users) > 5 else ''})" if users else "")})
    accounts = OrderedDict()
    for ts, d in sorted(successes, key=lambda x: x[0]):
        u = _acct(d.get("user"))
        accounts.setdefault(u, []).append(ts)
        lt = d.get("logon_type") or d.get("type_name") or ""
        lines.append({"ts": ts, "kind": "logon_success", "sev": "HIGH",
                      "text": f"{ip} 가 {u or '?'} 계정으로 로그인 성공" + (f" ({lt})" if lt else "")})

    # 2. 로그인 뒤 그 계정이 실행한 명령
    procs, pids = [], set()
    if accounts:
        windows = [(_ts(ts), _ts(ts) + WINDOW_AFTER_LOGON) for v in accounts.values() for ts in v if _ts(ts)]
        lo = min(w[0] for w in windows).isoformat(timespec="seconds")
        hi = max(w[1] for w in windows).isoformat(timespec="seconds")
        seen_cmd = set()
        for e in db.events_between(lo, hi, kinds=("process",)):
            d = e["data"] if isinstance(e["data"], dict) else {}
            u = _acct(d.get("username") or d.get("user"))
            anc = " ".join((a.get("name") or "") for a in (d.get("ancestors") or [])).lower()
            if u not in accounts and "sshd" not in anc:
                continue
            t = _ts(e["ts"])
            if not t or not any(a <= t <= b for a, b in windows):
                continue
            cmd = (d.get("cmdline") or d.get("name") or "")[:160]
            key = cmd.lower()
            if not cmd or key in seen_cmd:
                continue
            seen_cmd.add(key)
            pids.add(d.get("pid"))
            procs.append({"ts": e["ts"], "cmd": cmd, "user": u, "parent": d.get("parent") or ""})
        for p in procs[:40]:
            lines.append({"ts": p["ts"], "kind": "process", "sev": "INFO",
                          "text": f"{p['user'] or '?'} 계정이 {p['parent'] + ' → ' if p['parent'] else ''}{p['cmd']} 실행"})

        # 3. 같은 시간대 파일 변경
        for e in db.events_between(lo, hi, kinds=("file",)):
            d = e["data"] if isinstance(e["data"], dict) else {}
            t = _ts(e["ts"])
            if not t or not any(a <= t <= b for a, b in windows):
                continue
            src = d.get("source") or ""
            if src not in ("integrity", "poll", "webroot", "11") and not d.get("path"):
                continue
            pl = (d.get("path") or "").lower()
            if "\\tasks\\microsoft\\windows\\" in pl and d.get("change") != "created":
                continue                      # 윈도우 자체 예약 작업 갱신은 침입 이야기에 안 넣음
            what = {"created": "새로 만듦", "deleted": "지움", "modified": "바꿈"}.get(d.get("change"), "바꿈")
            added = (d.get("value") or "").strip().splitlines()
            lines.append({"ts": e["ts"], "kind": "file", "sev": "HIGH" if src == "integrity" else "MEDIUM",
                          "text": f"{d.get('path')} {what}" + (f" — 추가된 줄: {added[0][:80]}" if added else "")})

        # 4. 밖으로 나간 연결 (그 명령들 · 그 계정)
        outs = OrderedDict()
        for e in db.events_between(lo, hi, kinds=("network",)):
            d = e["data"] if isinstance(e["data"], dict) else {}
            if d.get("kind") != "outbound" or d.get("raddr_ip") in (ip, None, ""):
                continue
            if d.get("pid") not in pids and _acct(d.get("username")) not in accounts:
                continue
            try:
                if ipaddress.ip_address(d["raddr_ip"]).is_private:
                    continue
            except ValueError:
                continue
            k = (d.get("process") or "?", d["raddr_ip"], d.get("raddr_port"))
            outs.setdefault(k, [e["ts"], 0])
            outs[k][1] += 1
        for (pname, rip, rport), (ts, n) in list(outs.items())[:15]:
            lines.append({"ts": ts, "kind": "outbound", "sev": "HIGH",
                          "text": f"{pname} 가 외부 {rip}:{rport} 로 접속 ({n}회)"})
    else:
        outs = {}

    # 5. 이 IP 에 대한 경보
    attacks = OrderedDict()
    for a in sorted(alerts, key=lambda x: x["ts"]):
        if a["rule"] in ("logon_fail",):
            continue
        txt = describe(a) if describe else f"{a['rule']} {a['who']}"
        at = attack_of(a["rule"], a.get("detail"))
        if at:
            attacks.setdefault(at["id"], at)
        n = a.get("count") or 1
        lines.append({"ts": a["ts"], "kind": "alert", "rule": a["rule"], "sev": a["severity"],
                      "text": txt if n <= 1 else f"{txt}", "attack": at and at["id"], "sim": a["sim"]})

    lines.sort(key=lambda x: x["ts"])
    if len(lines) > MAX_LINES:
        lines = lines[:MAX_LINES // 2] + [{"ts": "", "kind": "gap", "sev": "INFO",
                                           "text": f"… 중간 {len(lines) - MAX_LINES}줄 생략 …"}] + lines[-MAX_LINES // 2:]
    for ln in lines:
        ln["t"] = _short(ln["ts"])

    intr = [a for a in alerts if a["rule"] in INTRUSION_RULES and not a["sim"]]
    first = lines[0]["ts"] if lines else ""
    last = lines[-1]["ts"] if lines else ""
    parts = []
    if fails:
        parts.append(f"로그인 실패 {len(fails)}회")
    if accounts:
        parts.append("계정 " + ", ".join(f"{u}({len(v)}회)" for u, v in accounts.items()) + " 로 로그인")
    if procs:
        parts.append(f"명령 {len(procs)}개 실행")
    nfiles = sum(1 for x in lines if x["kind"] == "file")
    if nfiles:
        parts.append(f"파일 {nfiles}개 변경")
    if outs:
        parts.append(f"외부 접속 {len(outs)}곳")
    if intr:
        parts.append(f"침입 경보 {len(intr)}건")
    if not lines:
        summary = f"{ip} 는 최근 {hours}시간 동안 기록이 없어요"
    elif not parts:
        summary = f"{ip} 는 {_short(first)} ~ {_short(last)} 에 {len(lines)}건 기록이 있지만 로그인·명령 실행은 없어요 (들어오려던 흔적만)"
    else:
        summary = f"{ip} 는 {_short(first)} ~ {_short(last)} 사이에 " + ", ".join(parts)
        if accounts and procs:
            summary += " — 들어와서 명령까지 실행했어요"
        elif accounts:
            summary += " — 들어왔지만 기록된 명령은 없어요"
    return {"ip": ip, "hours": hours, "summary": summary, "lines": lines,
            "accounts": list(accounts), "processes": procs[:40],
            "files": [x["text"] for x in lines if x["kind"] == "file"],
            "outbound": [f"{k[0]} → {k[1]}:{k[2]}" for k in outs],
            "attacks": list(attacks.values()), "intrusion": bool(intr) or bool(accounts)}


def as_text(st):
    """LLM 에 넘기거나 콘솔에 찍을 평문"""
    out = [st["summary"], ""]
    for ln in st["lines"]:
        out.append(f"{ln.get('t', '')}  [{ln['sev']}] {ln['text']}" + (f" ({ln['attack']})" if ln.get("attack") else ""))
    return "\n".join(out)


def all_ips(db, days=7, include_sim=True, limit=20, describe=None):
    """최근 days 일 동안 들어온(또는 들어오려 한) 외부 IP 별 침입 이야기 목록 — 침입한 IP 먼저, 그다음 최근 순"""
    from attack_taxonomy import INTRUSION_RULES as _INTR
    since = (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")
    cand = OrderedDict()
    for a in db.alerts_query(since, ["HIGH", "MEDIUM", "LOW"], include_sim, 5000):
        d = a["detail"] if isinstance(a["detail"], dict) else {}
        for ip in (d.get("src_ip"), d.get("raddr_ip")):
            if not ip or not _valid(ip):
                continue
            try:
                ad = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if ad.is_loopback or ad.is_private:
                continue
            c = cand.setdefault(ip, {"intr": 0, "sim": True, "last": ""})
            if a["rule"] in _INTR:
                c["intr"] += 1
            c["sim"] = c["sim"] and bool(a["sim"])
            c["last"] = max(c["last"], a["ts"])
    for e in db.events_between(since, "9999", kinds=("logon",), limit=20000):
        d = e["data"] if isinstance(e["data"], dict) else {}
        ip = d.get("src_ip")
        if ip and _valid(ip) and not ipaddress.ip_address(ip).is_private and not ipaddress.ip_address(ip).is_loopback:
            c = cand.setdefault(ip, {"intr": 0, "sim": True, "last": ""})
            c["sim"] = c["sim"] and bool(e.get("sim"))
            c["last"] = max(c["last"], e["ts"])
    order = sorted(cand.items(), key=lambda kv: kv[1]["last"], reverse=True)     # 최근 순
    order.sort(key=lambda kv: kv[1]["intr"] == 0)                                 # 침입 IP 먼저 (안정 정렬)
    out = []
    for ip, c in order[:limit]:
        st = build(db, ip, hours=days * 24, describe=describe)
        st["sim_only"] = c["sim"]
        st["intr_alerts"] = c["intr"]
        st["last"] = c["last"].replace("T", " ")
        out.append(st)
    return {"days": days, "ips": out, "total": len(cand)}

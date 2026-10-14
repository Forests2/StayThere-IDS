r"""외부 IP 조사: IP 하나를 넣으면 이 PC와 어떤 관계인지 전부 확인

CMD 에서:
    python ip_check.py 101.53.80.20
    check_ip.bat                      (IP 를 물어봄)
대시보드: 위협 IP 목록 → 'IP 조사'

확인 항목
  1. 주소 종류 (외부 / 내부망 / 자기 자신)
  2. ARTEX 공개 공격 IP(IOC) 인지
  3. 지금 이 PC와 연결돼 있는지 (어떤 프로그램이, 어느 포트로)
  4. 지금까지 DDS 가 이 IP로 잡은 탐지 기록
  5. 이 IP에서 온 로그인 시도 (성공/실패)
  6. 방화벽 차단 여부
  7. 역방향 DNS (호스트 이름)
  → 판정(위험/주의/기록 없음) + 이 IP를 넣은 조치 명령어
"""
import ipaddress
import json
import os
import platform
import socket
import subprocess
import sys
import threading

import psutil

BASE = os.path.dirname(os.path.abspath(__file__))
INTRUSION = {"port_scan", "ioc_ip_match", "webserver_spawned_shell", "recon_burst", "brute_force",
             "remote_rdp_logon", "remote_network_logon", "user_created", "added_to_admin_group",
             "threat_feed_match", "lolbin_outbound", "outbound_scan", "risky_port_inbound", "odd_port_outbound"}


def _rdns(ip, timeout=2.0):
    out = {}

    def run():
        try:
            out["name"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            out["name"] = None
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    return out.get("name")


def _fw_blocked(ip):
    if platform.system() != "Windows":
        return None
    try:
        r = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", f"name=DDS_BLOCK_{ip}_in"],
                           capture_output=True, text=True, timeout=5)
        return r.returncode == 0 and "DDS_BLOCK" in r.stdout
    except Exception:
        return None


def investigate(ip, db, cfg, blocked_meta=None):
    ip = ip.strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "msg": f"IP 형식이 아니에요: {ip}"}

    kind = "자기 자신(루프백)" if addr.is_loopback else "내부망" if addr.is_private else \
        "예약/특수 주소" if (addr.is_reserved or addr.is_multicast or addr.is_link_local) else "외부(인터넷)"

    # 지금 연결
    now_conns = []
    try:
        listen = {c.laddr.port for c in psutil.net_connections(kind="inet")
                  if c.status == psutil.CONN_LISTEN and c.laddr}
        for c in psutil.net_connections(kind="inet"):
            if c.raddr and c.raddr.ip == ip:
                try:
                    pname = psutil.Process(c.pid).name() if c.pid else ""
                except Exception:
                    pname = ""
                now_conns.append({"process": pname, "pid": c.pid or 0, "state": c.status,
                                  "direction": "들어옴" if c.laddr and c.laddr.port in listen else "나감",
                                  "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                                  "remote_port": c.raddr.port})
    except Exception as e:
        now_conns = [{"error": str(e)}]

    alerts, events = db.find_ip(ip) if db else ([], [])
    real_alerts = [a for a in alerts if not a["sim"]]
    sim_alerts = [a for a in alerts if a["sim"]]
    rules = {}
    for a in real_alerts:
        rules[a["rule"]] = rules.get(a["rule"], 0) + 1

    logons = {"fail": 0, "success": 0, "users": set(), "types": set()}
    procs = {}
    for e in events:
        if e["sim"]:
            continue
        d = e["data"] if isinstance(e["data"], dict) else {}
        if e["kind"] == "logon" and d.get("src_ip") == ip:
            if d.get("type") == "logon_fail":
                logons["fail"] += 1
            elif d.get("type") == "logon_success":
                logons["success"] += 1
            if d.get("user"):
                logons["users"].add(d["user"])
            if d.get("logon_type"):
                logons["types"].add(d["logon_type"])
        elif e["kind"] == "network" and d.get("raddr_ip") == ip:
            key = d.get("process") or f"pid {d.get('pid')}"
            procs[key] = procs.get(key, 0) + 1

    ioc = ip in set(cfg.get("ioc_ips", []))
    blocked_dds = any(b["ip"] == ip for b in (blocked_meta or []))
    blocked_fw = _fw_blocked(ip)
    rdns = _rdns(ip) if not addr.is_private and not addr.is_loopback else None

    # 판정
    reasons = []
    if ioc:
        reasons.append("ARTEX 공개 공격 IP(CrowdStrike IOC) 목록에 있음")
    hit_intr = [r for r in rules if r in INTRUSION]
    if hit_intr:
        reasons.append("외부 침입 흔적 탐지: " + ", ".join(hit_intr))
    if logons["success"] and not addr.is_private:
        reasons.append(f"외부 IP 로그인 성공 {logons['success']}회")
    if logons["fail"] >= 5:
        reasons.append(f"로그인 실패 {logons['fail']}회 (비밀번호 대입 의심)")
    active = [c for c in now_conns if "error" not in c]
    if active and (ioc or hit_intr):
        reasons.append(f"지금도 연결 중 ({len(active)}개)")

    if ioc or hit_intr or (logons["success"] and logons["fail"] >= 5):
        verdict, level = "위험 — 바로 차단 권장", "high"
    elif reasons or logons["fail"]:
        verdict, level = "주의 — 확인 필요", "med"
    elif events or active or rules:
        verdict, level = "이 PC 프로그램이 접속한 기록만 있음 — 침입 흔적 없음", "low"
    else:
        verdict, level = "이 PC와 주고받은 기록 없음", "none"

    if blocked_dds or blocked_fw:
        verdict += " (이미 차단됨)"

    cmds = [
        ("지금 이 IP와 연결 확인", f"netstat -ano | findstr {ip}"),
        ("이 IP 차단 (들어옴·나감)",
         f'netsh advfirewall firewall add rule name="DDS_BLOCK_{ip}_in" dir=in action=block remoteip={ip}\n'
         f'netsh advfirewall firewall add rule name="DDS_BLOCK_{ip}_out" dir=out action=block remoteip={ip}'),
        ("이 IP에서 온 로그인 기록 (PowerShell)",
         "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625} -MaxEvents 2000 | "
         f"Where-Object {{ $_.Message -match '{ip}' }} | Select TimeCreated, Id"),
        ("경로 추적", f"tracert -d -h 15 {ip}"),
        ("차단 해제", f'netsh advfirewall firewall delete rule name="DDS_BLOCK_{ip}_in"\n'
                     f'netsh advfirewall firewall delete rule name="DDS_BLOCK_{ip}_out"'),
    ]

    return {
        "ok": True, "ip": ip, "kind": kind, "rdns": rdns, "ioc": ioc,
        "blocked": bool(blocked_dds or blocked_fw), "verdict": verdict, "level": level, "reasons": reasons,
        "now": active,
        "alerts": {"real": len(real_alerts), "sim": len(sim_alerts), "rules": rules,
                   "first": real_alerts[-1]["ts"].replace("T", " ") if real_alerts else None,
                   "last": real_alerts[0]["ts"].replace("T", " ") if real_alerts else None,
                   "recent": [{"ts": a["ts"].replace("T", " "), "sev": a["severity"], "rule": a["rule"],
                               "who": a["who"]} for a in real_alerts[:15]]},
        "logons": {"fail": logons["fail"], "success": logons["success"],
                   "users": sorted(logons["users"]), "types": sorted(logons["types"])},
        "processes": [{"process": k, "count": v} for k, v in sorted(procs.items(), key=lambda x: -x[1])],
        "events": len([e for e in events if not e["sim"]]),
        "commands": [{"label": l, "cmd": c} for l, c in cmds],
    }


def print_report(r):
    if not r["ok"]:
        print(r["msg"])
        return
    line = "=" * 60
    print(line)
    print(f" IP 조사: {r['ip']}   ({r['kind']}{' · ' + r['rdns'] if r['rdns'] else ''})")
    print(line)
    print(f" 판정      : {r['verdict']}")
    for x in r["reasons"]:
        print(f"   - {x}")
    print(f" ARTEX IOC : {'예' if r['ioc'] else '아니오'}")
    print(f" 차단 상태 : {'차단됨' if r['blocked'] else '차단 안 됨'}")
    print(f"\n [지금 연결] {len(r['now'])}개")
    for c in r["now"]:
        print(f"   {c['direction']:3} {c['process'] or '?'} (PID {c['pid']}) {c['local']} ↔ :{c['remote_port']} {c['state']}")
    a = r["alerts"]
    print(f"\n [탐지 기록] {a['real']}건" + (f" (시뮬레이션 {a['sim']}건 제외)" if a["sim"] else ""))
    if a["real"]:
        print(f"   처음 {a['first']} / 마지막 {a['last']}")
        for k, v in a["rules"].items():
            print(f"   {k:26} {v}회")
    lg = r["logons"]
    print(f"\n [로그인 시도] 성공 {lg['success']} · 실패 {lg['fail']}" +
          (f" · 계정 {', '.join(lg['users'])}" if lg["users"] else ""))
    if r["processes"]:
        print("\n [이 IP와 통신한 프로그램]")
        for p in r["processes"][:10]:
            print(f"   {p['process']:30} {p['count']}회")
    print("\n [조치 명령어 — 관리자 CMD 에 붙여넣기]")
    for c in r["commands"]:
        print(f"  # {c['label']}")
        for ln in c["cmd"].split("\n"):
            print(f"  {ln}")
    print(line)


def main():
    from storage import Storage
    ip = sys.argv[1] if len(sys.argv) > 1 else input("조사할 IP: ").strip()
    with open(os.path.join(BASE, "config.json"), encoding="utf-8") as f:
        cfg = json.load(f)
    dbp = os.path.join(BASE, cfg["db_path"])
    db = Storage(dbp) if os.path.exists(dbp) else None
    blocked = db.meta_get("blocked_ips", []) if db else []
    r = investigate(ip, db, cfg, blocked)
    if "--json" in sys.argv:
        print(json.dumps(r, ensure_ascii=False, indent=2, default=str))
    else:
        print_report(r)


if __name__ == "__main__":
    main()

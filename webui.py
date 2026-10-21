"""로컬 웹 UI 서버 (127.0.0.1 전용, 표준 라이브러리만 사용)

GET  /               대시보드 화면
GET  /api/state      현재 상태(센서·스트림·침입 사건)
POST /api/simulate   {"type":"ai"|"hacker"|"net"|"agent"|"web"|"llm"} 침입 시뮬레이션
POST /api/ack        침입 확인 → 감시 화면으로
POST /api/action     {"action":"block_ip"|"kill_process"|"evidence"|...}
"""
import ipaddress
import json
import os
import platform
import secrets
import subprocess
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import psutil

from attack_taxonomy import AI_ATTACK_RULES, INTRUSION_RULES, RULE_INFO, chain, classify
from responder import blocked_list, firewall_block, firewall_unblock, kill_tree
from responder import valid_ip as _valid_ip

BASE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(BASE, "static")
TOKEN = secrets.token_hex(16)          # 다른 웹사이트가 조치 API를 몰래 호출하지 못하게
INCIDENT_WINDOW_MIN = 30

AI_RULES = {"port_scan", "ioc_ip_match", "webserver_spawned_shell", "devserver_spawned_shell",
            "recon_burst", "shell_burst", "ai_spawned_shell", "ai_api_connection",
            "ai_program_started", "ai_script_started", "local_llm_server",
            "ai_web_usage", "browser_automation"}
HACKER_RULES = {"brute_force", "remote_rdp_logon", "remote_network_logon", "off_hours_logon",
                "user_created", "added_to_admin_group"}

# INTRUSION_RULES(외부 침입 → 빨간 경보) · AI_ATTACK_RULES 는 attack_taxonomy.py 에서 한 곳으로 관리
# 이상한 IP (위협 IP 목록 화면 표시용)
SUSPICIOUS_RULES = {"threat_feed_match", "lolbin_outbound", "outbound_scan", "risky_port_inbound",
                    "odd_port_outbound", "new_inbound_ip", "port_scan", "ioc_ip_match", "brute_force",
                    "remote_rdp_logon", "remote_network_logon", "distributed_ips", "artex_user_agent",
                    "js_asset_burst", "dev_tool_inbound"}

# 침입 흔적이 아니라 '확인이 필요한 활동' 인 규칙
CHECK_RULES = {"ai_api_connection", "ai_web_usage", "ai_program_started", "ai_script_started",
               "local_llm_server", "browser_automation", "off_hours_logon", "devserver_spawned_shell",
               "dev_tool_exposed", "local_agent_command", "baseline_anomaly"}

SENSORS = [
    ("로그인", "Security 4624·4625", {"brute_force", "off_hours_logon", "user_created", "added_to_admin_group"}),
    ("원격 접속", "RDP · 네트워크 로그인", {"remote_rdp_logon", "remote_network_logon"}),
    ("프로세스", "AI 도구 · 웹쉘", {"webserver_spawned_shell", "devserver_spawned_shell", "ai_spawned_shell",
                               "ai_program_started", "ai_script_started", "browser_automation"}),
    ("네트워크", "공격 IP · 이상한 IP", {"ioc_ip_match", "port_scan", "threat_feed_match", "lolbin_outbound",
                                   "outbound_scan", "risky_port_inbound", "odd_port_outbound"}),
    ("정찰 명령", "whoami · net · systeminfo", {"recon_burst", "shell_burst"}),
    ("AI 에이전트 명령", "기계 형식 · 재시도 · 권한 상승", {"agent_command_style", "retry_loop", "credential_dump",
                                              "privilege_escalation", "payload_staging"}),
    ("ARTEX 흔적", "원본 · 한국어판 · 웹 정찰", {"artex_host_artifact", "artex_user_agent", "js_asset_burst",
                                         "ioc_domain_query", "distributed_ips", "dev_tool_inbound"}),
    ("웹 서버", "웹쉘 · 대량 조회 · 로그 탈취", {"webshell_file_created", "object_enumeration", "log_theft"}),
    ("악성코드 · 랜섬웨어", "LLM 악성코드 · 자동 실행 · 백업 삭제", {"llm_malware_pattern", "llm_then_exec", "autorun_change",
                                                     "ransomware_prep", "mass_file_change", "package_install_exec",
                                                     "git_spawned_unusual", "agent_secret_access"}),
]

LOGON_KO = {"rdp": "RDP", "network": "네트워크", "interactive": "대화형", "unlock": "잠금 해제", "cached": "캐시"}


# ================= 알림 → 사람이 읽는 문장 =================
def describe(a):
    r, d, who = a["rule"], a["detail"] if isinstance(a["detail"], dict) else {}, a.get("who") or ""
    ip = d.get("raddr_ip") or d.get("src_ip") or ""
    if r == "port_scan":
        return f"{who} 이(가) {d.get('window_sec')}초 안에 포트 {len(d.get('ports', []))}개 접속"
    if r == "ioc_ip_match":
        proc = d.get("process") or "프로세스 미상"
        if d.get("kind") == "outbound":
            return f"ARTEX 공격 IP {ip}:{d.get('raddr_port')} 로 나가는 연결 ({proc})"
        if d.get("lport"):
            return f"ARTEX 공격 IP {ip} → 내 포트 :{d.get('lport')} ({proc})"
        return f"ARTEX 공격 IP {ip} 에서 접근 ({who})"
    if r == "threat_feed_match":
        return f"위협 목록 파일에 있는 IP {ip} 와 연결 ({d.get('process') or '프로세스 미상'})"
    if r == "lolbin_outbound":
        return f"시스템 도구 {d.get('process')} 가 외부 {ip}:{d.get('raddr_port')} 로 접속 (원격 조종 의심)"
    if r == "outbound_scan":
        return f"{d.get('process') or who} 가 {d.get('window_sec')}초 안에 IP {d.get('count')}개로 접속 시도 (내부 확산 의심)"
    if r == "risky_port_inbound":
        return f"외부 IP {ip} 가 위험 포트 :{d.get('lport')} 로 접속 ({d.get('process') or '프로세스 미상'})"
    if r == "odd_port_outbound":
        return f"{d.get('process') or '프로세스 미상'} 가 해킹 도구 포트 {ip}:{d.get('raddr_port')} 로 접속"
    if r == "new_inbound_ip":
        return f"처음 보는 외부 IP {ip} 가 내 포트 :{d.get('lport')} 로 들어옴"
    if r == "webserver_spawned_shell":
        return f"{who} 실행 (웹쉘 의심)"
    if r == "devserver_spawned_shell":
        return f"{who} 실행"
    if r == "ai_spawned_shell":
        return f"AI 프로세스가 쉘 실행: {who}"
    if r == "recon_burst":
        cmds = " · ".join(c.replace(".exe", "") for c in d.get("commands", []))
        return f"정찰 명령 {cmds} 를 {d.get('window_sec')}초 안에 연속 실행"
    if r == "shell_burst":
        return f"{who} 이(가) {d.get('window_sec')}초 안에 쉘 {d.get('count')}회 실행"
    if r == "ai_api_connection":
        return f"{d.get('process')} → {d.get('ai_domain')} (LLM API)"
    if r == "ai_web_usage":
        return f"{d.get('process')} 에서 AI 사이트 {d.get('ai_domain')} 이용"
    if r == "browser_automation":
        return f"브라우저 자동조종 실행: {who} ({', '.join(d.get('flags', []))})"
    if r in ("ai_program_started", "ai_script_started"):
        return f"AI 프로그램 실행: {who}"
    if r == "local_llm_server":
        return f"로컬 LLM 서버 열림: {d.get('laddr')}"
    if r == "artex_host_artifact":
        return f"ARTEX(원본·한국어판) 흔적: {who} · {', '.join(map(str, d.get('keywords', [])))[:80]}"
    if r == "artex_user_agent":
        return f"{ip} 가 ARTEX 정찰 User-Agent '{d.get('ua')}' 로 웹 요청 ({d.get('path')})"
    if r == "js_asset_burst":
        return f"{ip} 가 {d.get('window_sec')}초 안에 JS 파일 {d.get('count')}개 요청 (웹 자동 정찰)"
    if r == "ioc_domain_query":
        return f"{d.get('process') or '프로세스 미상'} 가 공격 중계 도메인 {d.get('query')} 조회"
    if r == "agent_command_style":
        gap = f" · 명령 간격 중앙값 {d.get('median_gap')}초" if d.get("median_gap") is not None else ""
        return f"기계 형식 명령 {d.get('count')}건을 {d.get('window_sec')}초 안에 실행 ({', '.join(d.get('markers', [])[:3])}){gap}"
    if r == "local_agent_command":
        return f"내 AI 도구가 기계 형식 명령 실행: {who}"
    if r == "retry_loop":
        return f"거의 같은 명령을 고쳐 가며 {d.get('variants')}번 실행 (실패 → 수정 → 재실행)"
    if r == "credential_dump":
        return f"계정 정보 탈취 명령: {(d.get('cmdline') or who)[:90]}"
    if r == "privilege_escalation":
        what = ", ".join(d.get("tools") or d.get("keywords") or [])
        return f"권한 상승 시도 ({what}): {who}"
    if r == "payload_staging":
        return f"공격 파일 반입: {', '.join(d.get('reasons', []))[:100]}"
    if r == "distributed_ips":
        return f"외부 IP {len(d.get('ips', []))}개가 {d.get('window_sec')}초 안에 같은 포트 :{d.get('lport')} 로 (IP 바꿔 가며 공격)"
    if r == "dev_tool_inbound":
        return f"외부 IP {ip} 가 {d.get('tool')} 포트 :{d.get('lport')} 로 접속"
    if r == "dev_tool_exposed":
        return f"{d.get('tool')} 포트 {d.get('laddr')} 가 외부에서 접속 가능하게 열림 (127.0.0.1 로 바꾸세요)"
    if r == "webshell_file_created":
        by = d.get("process") or "만든 프로그램 미상"
        return f"웹 폴더에 스크립트 파일 생성: {d.get('path')} ({by})"
    if r == "object_enumeration":
        return f"{ip} 가 {d.get('window_sec')}초 안에 값만 바꾼 요청 {d.get('count')}가지 ({(d.get('pattern') or '')[:60]})"
    if r == "log_theft":
        return f"웹 서버({d.get('web_parent')}) 아래에서 로그 압축·복사: {(d.get('cmdline') or '')[:90]}"
    if r == "llm_malware_pattern":
        if d.get("via") == "4104":
            return f"PowerShell 스크립트가 LLM API 호출 ({', '.join(d.get('patterns', [])[:2])})"
        return f"{' ← '.join(d.get('chain', [])[:3]) or d.get('process')} 가 LLM API {d.get('ai_domain') or d.get('query')} 접속 (LLM 을 부르는 악성코드 의심)"
    if r == "llm_then_exec":
        return f"{d.get('llm_process')} 가 LLM 접속 {d.get('after_sec')}초 뒤 명령 실행: {(d.get('cmdline') or d.get('name') or '')[:80]}"
    if r == "autorun_change":
        return f"자동 실행 등록: {(d.get('key') or d.get('path') or '')[:80]} ({', '.join(d.get('reasons', [])[:3])})"
    if r == "ransomware_prep":
        return f"백업·복구 수단 삭제 명령: {(d.get('cmdline') or ', '.join(d.get('patterns', [])))[:90]}"
    if r == "mass_file_change":
        return f"{d.get('process')} 가 {d.get('window_sec')}초 안에 '{d.get('ext')}' 파일 {d.get('count')}개 생성 (암호화 의심)"
    if r == "git_spawned_unusual":
        return f"git 이 {d.get('name')} 실행{' (훅 경유)' if d.get('via_hook') else ''}: {(d.get('cmdline') or '')[:80]}"
    if r == "package_install_exec":
        return f"{d.get('installer')} 중 다운로드·인코딩 명령: {(d.get('cmdline') or '')[:80]}"
    if r == "agent_secret_access":
        return f"AI 도구 토큰·설정 접근: {who} ({', '.join(d.get('targets', [])[:2])})"
    if r == "baseline_anomaly":
        return f"평소에 없던 행동 {d.get('count')}가지가 {int(d.get('window_sec', 600)) // 60}분 안에: {', '.join(d.get('new', [])[:3])}"
    if r == "brute_force":
        return f"{d.get('src_ip')} 에서 5분 안에 로그인 실패 {d.get('fails_5min')}회 ({who})"
    if r == "remote_rdp_logon":
        return f"{ip} 에서 RDP 로그인 성공 ({who})"
    if r == "remote_network_logon":
        return f"{ip} 에서 네트워크 로그인 성공 ({who})"
    if r == "off_hours_logon":
        return f"업무 시간 외 로그인 ({who})"
    if r == "user_created":
        return f"새 계정 생성: {who}"
    if r == "added_to_admin_group":
        return f"관리자 그룹에 추가: {who}"
    return f"{r} {who}"


def event_text(e):
    d, k = e["data"], e["kind"]
    if k == "process":
        par = f" ← {d.get('parent')}" if d.get("parent") else ""
        return f"새 프로세스 {d.get('name')}{par}"
    if k == "network":
        if d.get("kind") == "listen":
            return f"{d.get('process') or 'pid ' + str(d.get('pid'))} 포트 {d.get('lport')} 열림"
        arrow = "→" if d.get("kind") == "outbound" else "←"
        return f"{d.get('process') or '연결'} {arrow} {d.get('raddr_ip')}:{d.get('raddr_port') or d.get('lport')}"
    if k == "logon":
        t = {"logon_success": "로그인 성공", "logon_fail": "로그인 실패", "admin_logon": "관리자 권한 로그인",
             "explicit_cred_logon": "다른 계정으로 실행", "user_created": "새 계정 생성",
             "added_to_admin_group": "관리자 그룹 추가"}.get(d.get("type"), d.get("type"))
        return f"{t} · {d.get('user', '')} {LOGON_KO.get(d.get('logon_type'), '')}".strip()
    if k == "weblog":
        return f"웹 요청 {d.get('src_ip')} {d.get('path')} · {d.get('ua') or ''}"[:120]
    if k == "dns":
        return f"DNS 조회 {d.get('process') or ''} → {d.get('query')}"
    if k == "file":
        return f"파일 생성 {d.get('process') or ''} → {d.get('path')}"[:120]
    if k == "registry":
        return f"레지스트리 {d.get('process') or ''} → {d.get('key')}"[:120]
    if k == "psblock":
        return "PowerShell 스크립트 블록 " + (d.get("text") or "")[:80].replace("\n", " ")
    if k == "object_access":
        return f"파일 접근 {d.get('process')} → {d.get('object')}"[:120]
    return k


# ================= 상태 만들기 =================
def build_state(mon):
    db = mon.db
    ack = db.meta_get("ack_id", 0)
    since = (datetime.now() - timedelta(minutes=INCIDENT_WINDOW_MIN)).isoformat(timespec="seconds")
    all_rows = [a for a in db.alerts_after(ack, since) if a["severity"] in ("HIGH", "MEDIUM", "LOW")]
    # 외부 침입 흔적만 경보 대상. PC 안에서 쓰는 AI 프로그램 활동은 기록만 (AI 도구 탐지 메뉴)
    rows = [a for a in all_rows if a["rule"] in INTRUSION_RULES and a["severity"] in ("HIGH", "MEDIUM")]
    local = [a for a in all_rows if a["rule"] not in INTRUSION_RULES]

    incident = None
    if any(a["severity"] == "HIGH" for a in rows):
        is_ai = any(a["rule"] in AI_ATTACK_RULES for a in rows)
        rel = [a for a in rows if (a["rule"] in AI_ATTACK_RULES) == is_ai]
        incident = build_incident("ai" if is_ai else "hacker", rel, local)

    sensors = []
    for name, hint, rules in SENSORS:
        sev = {a["severity"] for a in rows if a["rule"] in rules}
        st = "bad" if "HIGH" in sev else ("warn" if "MEDIUM" in sev else "ok")
        sensors.append({"name": name, "hint": hint, "state": st})

    stream = [{"ts": e["ts"][11:19], "text": event_text(e), "sim": e["sim"]}
              for e in db.recent_events(8)]
    return {
        "host": mon.host,
        "admin": mon.admin,
        "warnings": mon.warnings,
        "lastScan": mon.last_scan.strftime("%H:%M:%S") if mon.last_scan else None,
        "now": datetime.now().strftime("%H:%M:%S"),
        "highToday": sum(1 for a in db.alerts_query(datetime.now().strftime("%Y-%m-%d"), ["HIGH"], False, 1000)
                         if a["rule"] in INTRUSION_RULES),
        "sensors": sensors,
        "stream": stream,
        "incident": incident,
        "localActivity": len(local),
        "emergency": {k: v for k, v in db.meta_get("emergency", {}).items() if k != "snapshot"},
        "llm": _llm_brief(incident),
        "auto": mon.responder.enabled() if getattr(mon, "responder", None) else False,
        "autoActions": [x for x in (mon.responder.actions() if getattr(mon, "responder", None) else [])
                        if incident and x.get("alertId", 0) > ack],
        "lastIncident": db.meta_get("last_incident"),
        "token": TOKEN,
    }


def _sec(ts):
    return datetime.fromisoformat(ts).timestamp()


def judge_ai(rows, local=()):
    """이 침입이 AI 공격 프로그램인지 판별.
    기계 속도 근거(자동화 여부) 와 AI 근거(AI 도구라는 증거) 를 따로 본다.

    2026-10 기준 재조정 — 공개된 실제 AI 에이전트 침입 사례:
      명령 간격 절반이 5초 이하 · 중앙값 약 6초 · 전체는 수십 분~1시간 (ReliaQuest, Sysdig/CSA)
      → '2분 안에 끝남' 만 보지 않고, 간격 중앙값이 짧은 채로 오래 이어지는 것도 자동화로 본다.
    AI 근거는 두 단계:
      직접 증거  — ARTEX IP·실행 흔적·정찰 User-Agent·LLM 중계 도메인·미등록 프로그램의 LLM 접속
      행동 특징  — 기계 형식 명령, 실패-수정 반복 (LLM 에이전트에서 관측된 특징, 단독으로는 '추정')"""
    d = lambda a: a["detail"] if isinstance(a["detail"], dict) else {}
    speed, ai = [], []          # (맞음 여부, 설명)
    auto_score = 0

    t = sorted(_sec(a["ts"]) for a in rows)
    if len(t) >= 3:
        gaps = sorted(b - a for a, b in zip(t, t[1:]))
        med = gaps[len(gaps) // 2]
        span = t[-1] - t[0]
        fast = med <= 10
        speed.append((fast, f"단계 사이 간격 중앙값 {med:.1f}초 (공개된 AI 에이전트 사례 약 6초 · 사람은 보통 수십 초 이상)"))
        auto_score += 30 if med <= 5 else 20 if fast else 0
        if span <= 120:
            speed.append((True, f"탐지 {len(t)}단계를 {span:.0f}초 만에 진행"))
            auto_score += 15
        elif fast and len(t) >= 6:
            speed.append((True, f"탐지 {len(t)}단계가 {span / 60:.0f}분 동안 짧은 간격으로 이어짐 (쉬지 않는 자동 실행)"))
            auto_score += 10
        else:
            speed.append((False, f"탐지 {len(t)}단계를 {span / 60:.0f}분에 걸쳐 진행"))
    else:
        speed.append((False, "단계가 적어서 속도 판단 불가"))

    seen = set()
    for a in rows:
        r, x = a["rule"], d(a)
        if r in seen:
            continue
        seen.add(r)
        if r == "port_scan":
            speed.append((True, f"{x.get('window_sec')}초 안에 포트 {len(x.get('ports', []))}개 접속 (스캐너 속도)"))
            auto_score += 15
        elif r == "recon_burst":
            speed.append((True, f"정찰 명령 {len(x.get('commands', []))}종을 {x.get('window_sec')}초 안에 연속 실행"))
            auto_score += 15
        elif r == "brute_force":
            speed.append((True, f"5분 안에 로그인 {x.get('fails_5min')}회 실패 (자동 대입)"))
            auto_score += 15
        elif r == "shell_burst":
            speed.append((True, f"{x.get('window_sec')}초 안에 쉘 {x.get('count')}회 실행"))
            auto_score += 10
        elif r == "agent_command_style":
            g = x.get("median_gap")
            speed.append((True, f"기계 형식 명령 {x.get('count')}건을 {x.get('window_sec')}초 안에 실행"
                                + (f" (간격 중앙값 {g}초)" if g is not None else "")))
            auto_score += 15
        elif r == "retry_loop":
            speed.append((True, f"실패한 명령을 바로 고쳐서 {x.get('variants')}번 재실행"))
            auto_score += 10
        elif r == "distributed_ips":
            speed.append((True, f"외부 IP {len(x.get('ips', []))}개를 {x.get('window_sec')}초 안에 바꿔 가며 접속"))
            auto_score += 15
        elif r == "object_enumeration":
            speed.append((True, f"{x.get('window_sec')}초 안에 값만 바꾼 요청 {x.get('count')}가지 (사람 손으로는 어려운 속도)"))
            auto_score += 15
        elif r == "js_asset_burst":
            speed.append((True, f"{x.get('window_sec')}초 안에 JS 파일 {x.get('count')}개 요청 (자동 정찰)"))
            auto_score += 10

    # ---- AI 근거 ① 직접 증거 ----
    first = lambda rule, cond=lambda a: True: next((a for a in rows if a["rule"] == rule and cond(a)), None)
    x = first("ioc_ip_match", lambda a: d(a).get("kind") != "outbound")
    if x:
        ai.append((True, f"ARTEX(AI 해킹 도구) 공개 공격 IP {d(x).get('raddr_ip') or d(x).get('src_ip')} 에서 접근"))
    x = first("ioc_ip_match", lambda a: d(a).get("kind") == "outbound")
    if x:
        ai.append((True, f"ARTEX 서버 {d(x).get('raddr_ip')}:{d(x).get('raddr_port')} 로 통신 (AI 도구 지휘 서버)"))
    x = first("artex_user_agent")
    if x:
        ai.append((True, f"ARTEX 정찰 모듈 User-Agent '{d(x).get('ua')}' (artex-defense-kit 지표 · 높은 신뢰)"))
    x = first("artex_host_artifact")
    if x:
        ai.append((True, f"ARTEX(원본·한국어판) 실행 흔적: {', '.join(map(str, d(x).get('keywords', [])))[:60]}"))
    x = first("llm_malware_pattern")
    if x:
        how = "PowerShell 스크립트" if d(x).get("via") == "4104" else " ← ".join(d(x).get("chain", [])[:2]) or d(x).get("process")
        ai.append((True, f"{how} 가 LLM API 호출 — 실행 중 LLM 에 명령을 받는 악성코드 방식 (PROMPTSTEAL·PROMPTFLUX)"))
    x = first("llm_then_exec")
    if x:
        ai.append((True, f"LLM API 접속 {d(x).get('after_sec')}초 뒤 같은 프로그램이 명령 실행 (LLM 이 명령을 내림)"))
    x = first("ioc_domain_query")
    if x:
        ai.append((True, f"{d(x).get('process')} 가 공격자 LLM 중계 도메인 {d(x).get('query')} 조회"))
    llm = [a for a in local if a["rule"] == "ai_api_connection" and a["severity"] == "HIGH"]
    if llm:
        ai.append((True, f"같은 시간대에 미등록 프로그램 {d(llm[0]).get('process')} 가 LLM 서버 {d(llm[0]).get('ai_domain')} 에 접속"))
    strong = any(ok for ok, _ in ai)

    # ---- AI 근거 ② 행동 특징 ----
    behav = False
    x = first("agent_command_style")
    if x:
        mk = ", ".join(d(x).get("markers", [])[:3])
        ai.append((True, f"AI 에이전트식 명령 형식 ({mk}) — 공개 사례의 LLM 에이전트 특징 (행동 근거)"))
        behav = True
    x = first("retry_loop")
    if x:
        ai.append((True, "실패 → 원인 수정 → 재실행을 기계 속도로 반복 (행동 근거)"))
        behav = True
    if not ai:
        ai.append((False, "ARTEX 흔적 · LLM 통신 · AI 에이전트식 명령 같은 근거는 아직 없음"))

    auto_score = min(100, auto_score)
    automated = auto_score >= 40
    if strong and automated:
        verdict, level = "AI 공격 프로그램 — 근거 확인됨", "ai"
    elif strong:
        verdict, level = "AI 공격 도구와 연관 — 공개 지표 일치", "ai"
    elif behav and automated:
        verdict, level = "AI 에이전트 공격으로 보임 — 행동 근거", "ai"
    elif automated:
        verdict, level = "자동화 공격 도구 — AI 인지는 확실하지 않음", "auto"
    else:
        verdict, level = "사람이 직접 한 공격으로 보임", "human"
    return {"verdict": verdict, "level": level, "autoScore": auto_score,
            "speed": [{"ok": ok, "text": tx} for ok, tx in speed],
            "ai": [{"ok": ok, "text": tx} for ok, tx in ai]}


def _llm_brief(incident):
    try:
        import llm
        m = llm.MANAGER
        if not m:
            return None
        last = m.last if (m.last and incident and
                          m.last.get("incidentFirstId") == incident.get("firstId")) else None
        slots = {k: v.llm is not None for k, v in llm.SLOTS.items()}
        has_model = bool(llm.scan_gguf())
        return {"busy": m.busy, "last": last, "api": m.api_state, "slots": slots, "progress": llm.prog_view(),
                "hasModel": has_model}
    except Exception:
        return None


def build_incident(mode, rows, local=()):
    steps = [{"ts": a["ts"][11:19], "rule": a["rule"], "sev": a["severity"], "text": describe(a),
              "cat": classify(a["rule"])}
             for a in rows][-12:]
    attack_chain = chain([a["rule"] for a in rows])
    sim = any(a["sim"] for a in rows)
    first_ts = rows[0]["ts"][11:19]
    d = lambda a: a["detail"] if isinstance(a["detail"], dict) else {}

    who = what = where = None
    target_ip = target_pid = None
    if mode == "ai":
        ioc_in = next((a for a in rows if a["rule"] == "ioc_ip_match" and d(a).get("kind") != "outbound"), None)
        scan = next((a for a in rows if a["rule"] == "port_scan"), None)
        feed = next((a for a in rows if a["rule"] == "threat_feed_match"), None)
        risky = next((a for a in rows if a["rule"] == "risky_port_inbound"), None)
        ua = next((a for a in rows if a["rule"] == "artex_user_agent"), None)
        dist = next((a for a in rows if a["rule"] == "distributed_ips"), None)
        devin = next((a for a in rows if a["rule"] == "dev_tool_inbound"), None)
        enum_ = next((a for a in rows if a["rule"] == "object_enumeration"), None)
        src = ioc_in or ua or enum_ or feed or dist or devin or scan or risky
        if src:
            target_ip = d(src).get("raddr_ip") or src["who"]
            sub = {"ioc_ip_match": "ARTEX 공격 IP (CrowdStrike 공개 IOC)", "threat_feed_match": "위협 목록 파일에 있는 IP",
                   "artex_user_agent": f"ARTEX 정찰 User-Agent ({d(src).get('ua')})",
                   "distributed_ips": f"IP {len(d(src).get('ips', []))}개를 바꿔 가며 :{d(src).get('lport')} 로 접속",
                   "dev_tool_inbound": f"{d(src).get('tool')} 포트로 외부 접속",
                   "object_enumeration": f"고객번호 등 값을 바꿔 가며 {d(src).get('count')}번 조회",
                   "port_scan": "포트 스캔 출발지", "risky_port_inbound": f"위험 포트 :{d(src).get('lport')} 로 들어옴"}[src["rule"]]
            main = target_ip if src["rule"] != "distributed_ips" else " · ".join(d(src).get("ips", [])[:3])
            who = {"main": main, "sub": sub}
        shell = next((a for a in rows if a["rule"].endswith("_spawned_shell")), None)
        recon = next((a for a in rows if a["rule"] == "recon_burst"), None)
        prio = ("ransomware_prep", "mass_file_change", "credential_dump", "agent_secret_access", "log_theft",
                "webshell_file_created", "llm_then_exec", "llm_malware_pattern", "privilege_escalation",
                "payload_staging", "package_install_exec", "git_spawned_unusual", "autorun_change", "artex_host_artifact")
        heavy = min((a for a in rows if a["rule"] in prio),     # 가장 위험한 단계 · HIGH 우선
                    key=lambda a: (a["severity"] != "HIGH", prio.index(a["rule"]), a["id"]), default=None)
        agent = next((a for a in rows if a["rule"] in ("agent_command_style", "retry_loop")), None)
        if heavy:
            target_pid = d(heavy).get("pid")
            sub = {"credential_dump": "계정 정보(SAM·LSASS) 탈취 시도", "privilege_escalation": "권한 상승 도구 실행",
                   "payload_staging": "공격 파일을 들여와 실행", "artex_host_artifact": "ARTEX 가 이 PC에서 실행됨",
                   "ransomware_prep": "백업·복구 수단 삭제 (랜섬웨어 준비)", "mass_file_change": "파일 대량 암호화 의심",
                   "agent_secret_access": "AI 도구 토큰·설정 탈취 시도", "log_theft": "웹 서버 로그 파일 탈취",
                   "webshell_file_created": "웹 폴더에 웹쉘 파일 생성", "llm_then_exec": "LLM 지시를 받아 명령 실행",
                   "llm_malware_pattern": "LLM 을 부르는 악성코드", "package_install_exec": "설치 스크립트가 외부에서 내려받음",
                   "git_spawned_unusual": "git 설정을 통한 명령 실행", "autorun_change": "자동 실행 등록 (지속성)"}[heavy["rule"]]
            what = {"main": d(heavy).get("name") or d(heavy).get("process") or heavy["who"],
                    "sub": sub + (" · AI 에이전트식 명령" if agent else "")}
        elif agent:
            target_pid = d(agent).get("pid")
            what = {"main": agent["who"], "sub": describe(agent)}
        elif shell:
            target_pid = d(shell).get("pid")
            what = {"main": shell["who"], "sub": "서버 프로세스가 쉘 실행" + (" · 정찰 명령 연속" if recon else "")}
        elif recon:
            what = {"main": "정찰 명령 연속", "sub": describe(recon)}
        lol = next((a for a in rows if a["rule"] == "lolbin_outbound"), None)
        osc = next((a for a in rows if a["rule"] == "outbound_scan"), None)
        if not what and lol:
            target_pid = d(lol).get("pid")
            what = {"main": d(lol).get("process"), "sub": "시스템 도구가 외부로 접속 (원격 조종 의심)"}
        elif not what and osc:
            target_pid = d(osc).get("pid")
            what = {"main": d(osc).get("process") or osc["who"], "sub": f"이 PC가 {d(osc).get('count')}개 IP로 접속 시도 (내부 확산 의심)"}
        out = next((a for a in rows if a["rule"] == "ioc_ip_match" and d(a).get("kind") == "outbound"), None)
        api = next((a for a in rows if a["rule"] == "ai_api_connection"), None)
        odd = next((a for a in rows if a["rule"] in ("lolbin_outbound", "odd_port_outbound")), None)
        if out:
            where = {"main": f"{d(out).get('raddr_ip')}:{d(out).get('raddr_port')}", "sub": "ARTEX 서버로 역접속 시도"}
        elif odd:
            where = {"main": f"{d(odd).get('raddr_ip')}:{d(odd).get('raddr_port')}", "sub": "수상한 외부 서버로 나가는 연결"}
            if not who:
                target_ip = d(odd).get("raddr_ip")
                who = {"main": target_ip, "sub": "이 PC가 접속한 수상한 외부 IP"}
        elif api:
            where = {"main": d(api).get("ai_domain"), "sub": "LLM API 서버 접속"}
        if not who and api:
            who = {"main": d(api).get("process") or api["who"], "sub": "이 PC에서 LLM API에 접속한 프로그램"}
        attack = any(a["rule"] in AI_ATTACK_RULES or a["rule"] == "ai_spawned_shell" for a in rows)
        jd = judge_ai(rows, local)
        if attack and jd["level"] == "ai":
            rs = {a["rule"] for a in rows}
            kind = ("ARTEX 계열" if rs & {"ioc_ip_match", "artex_user_agent", "artex_host_artifact", "ioc_domain_query"}
                    else "LLM 을 부르는 악성코드" if rs & {"llm_malware_pattern", "llm_then_exec"}
                    else "AI 에이전트")
            title, tag, level = "AI 해킹 도구가 침입했어요", f"AI 공격 프로그램 · {kind}", "intrusion"
        elif attack and jd["level"] == "auto":
            title, tag, level = "자동화 공격 도구가 들어왔어요", "자동화 공격 · AI 여부 확인 중", "intrusion"
        elif attack:
            title, tag, level = "외부에서 침입했어요", "외부 침입", "intrusion"
        else:
            title, tag, level = "AI 도구가 움직이고 있어요", "AI 도구 활동 · LLM API 접속", "check"
        actions = [("block_ip", "IP 차단"), ("kill_process", "프로세스 종료"),
                   ("isolate", "네트워크 차단"), ("evidence", "증거 저장")]
    else:
        lg = next((a for a in rows if a["rule"] in ("remote_rdp_logon", "remote_network_logon")), None)
        bf = next((a for a in rows if a["rule"] == "brute_force"), None)
        src = lg or bf
        if src:
            target_ip = d(src).get("src_ip")
            kind = "RDP 로그인" if src["rule"] == "remote_rdp_logon" else ("네트워크 로그인" if lg else "비밀번호 대입")
            who = {"main": src["who"], "sub": f"출발지 {target_ip} · {kind}"}
        adm = next((a for a in rows if a["rule"] == "added_to_admin_group"), None)
        new = next((a for a in rows if a["rule"] == "user_created"), None)
        if adm or new:
            what = {"main": "관리자 그룹 추가" if adm else "새 계정 생성",
                    "sub": f"{(adm or new)['who']}" + (" · 새 계정 생성 후 관리자 편입" if adm and new else "")}
        if lg:
            where = {"main": "RDP :3389" if lg["rule"] == "remote_rdp_logon" else "네트워크 로그인",
                     "sub": "외부 IP 원격 접속"}
        intrusion = any(a["rule"] in ("brute_force", "remote_rdp_logon", "remote_network_logon",
                                      "user_created", "added_to_admin_group") for a in rows)
        if intrusion:
            title, tag, level = "해커가 침입했어요", "해커 · 원격 침입", "intrusion"
        else:
            title, tag, level = "평소와 다른 로그인이 있어요", "로그인 · 확인 필요", "check"
        actions = [("block_ip", "IP 차단"), ("logoff", "세션 끊기"),
                   ("lock_account", "계정 잠금"), ("evidence", "증거 저장")]

    blank = {"main": "-", "sub": "아직 확인 안 됨"}
    return {
        "mode": mode, "sim": sim, "title": title, "tag": tag, "level": level,
        "sub": ("" if level == "intrusion" else "침입 흔적은 없어요 · ") +
               f"탐지 규칙 {len(steps)}건 발동 · 오늘 {first_ts} 시작" + (" · 시뮬레이션" if sim else ""),
        "facts": [{"label": "누가", **(who or blank)}, {"label": "무엇이", **(what or blank)},
                  {"label": "어디로", **(where or blank)}],
        "steps": steps,
        "chain": attack_chain,
        "judge": judge_ai(rows, local),
        "actions": [{"id": i, "label": l} for i, l in actions],
        "targetIp": target_ip, "targetPid": target_pid,
        "pids": sorted({d(a).get("pid") for a in rows
                        if a["rule"] in ("webserver_spawned_shell", "lolbin_outbound", "outbound_scan", "ai_spawned_shell",
                                         "credential_dump", "privilege_escalation", "payload_staging",
                                         "artex_host_artifact", "agent_command_style", "retry_loop",
                                         "log_theft", "llm_malware_pattern", "llm_then_exec", "ransomware_prep",
                                         "mass_file_change", "git_spawned_unusual", "package_install_exec",
                                         "agent_secret_access")
                        and d(a).get("pid")}),
        "lastId": rows[-1]["id"],
        "firstId": rows[0]["id"],
    }


# ================= 조치 =================
def do_action(mon, action):
    st = build_state(mon)
    inc = st["incident"]
    if not inc:
        return False, "진행 중인 침입이 없어요"
    sim = inc["sim"]

    if action == "evidence":
        os.makedirs(os.path.join(BASE, "evidence"), exist_ok=True)
        path = os.path.join(BASE, "evidence", f"incident_{datetime.now():%Y%m%d_%H%M%S}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"incident": inc, "recent_events": mon.db.recent_events(200)},
                      f, ensure_ascii=False, indent=2, default=str)
        return True, f"증거 저장 완료: evidence\\{os.path.basename(path)}"

    if action == "block_ip":
        return firewall_block(mon, inc.get("targetIp"), sim)

    if action == "kill_process":
        return kill_tree(inc.get("targetPid"), sim)

    if action in ("isolate", "logoff", "lock_account"):
        return False, "이 조치는 다음 버전에서 연결할 예정이에요"
    return False, "알 수 없는 조치"


def _blocked(mon):
    return blocked_list(mon.db)


def ack(mon):
    st = build_state(mon)
    inc = st["incident"]
    if inc:
        mon.db.meta_set("last_incident", {"title": inc["title"], "tag": inc["tag"],
                                          "count": len(inc["steps"]), "sim": inc["sim"],
                                          "at": datetime.now().strftime("%m-%d %H:%M")})
        mon.db.add_incident(inc)
    mon.db.meta_set("ack_id", mon.db.max_alert_id())


# ================= 메뉴 화면 데이터 =================
def _since(days):
    return (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")


def api_history(mon, q):
    sim = q.get("sim", "1") == "1"
    days = int(q.get("days", "7"))
    incs = []
    for r in mon.db.incidents(include_sim=sim):
        d = r["data"]
        incs.append({"id": r["id"], "ts": r["ts"], "mode": r["mode"], "title": r["title"], "sim": r["sim"],
                     "tag": d.get("tag"), "level": d.get("level", "intrusion"), "judge": d.get("judge"), "chain": d.get("chain", []), "facts": d.get("facts", []),
                     "steps": d.get("steps", [])})
    alerts = [{"ts": a["ts"].replace("T", " "), "sev": a["severity"], "rule": a["rule"], "who": a["who"],
               "text": describe(a), "cat": classify(a["rule"]), "sim": a["sim"]}
              for a in mon.db.alerts_query(_since(days), ["HIGH", "MEDIUM", "LOW"], sim)
              if a["rule"] in INTRUSION_RULES or a["rule"] == "off_hours_logon"]   # 외부 침입 관련만
    return {"incidents": incs, "alerts": alerts}


_ai_cache = {"t": 0, "v": None}


def api_ai(mon):
    import time as _t
    if _ai_cache["v"] and _t.time() - _ai_cache["t"] < 3:
        return _ai_cache["v"]
    cfg = mon.cfg
    ai_names = {x.lower() for x in cfg["ai_process_names"]}
    kws = [k.lower() for k in cfg["ai_cmdline_keywords"]]
    browsers = {x.lower() for x in cfg.get("browser_processes", [])}
    flags = [f.lower() for f in cfg.get("browser_automation_flags", [])]
    white = {x.lower() for x in cfg.get("process_whitelist", [])}
    ip2dom = mon.net.ip_to_domain if mon.net else {}

    conns = {}
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.pid and c.raddr and c.raddr.ip in ip2dom:
                conns.setdefault(c.pid, set()).add(ip2dom[c.raddr.ip])
    except Exception:
        pass

    procs, seen_browser_auto = [], set()
    for p in psutil.process_iter(["pid", "ppid", "name", "cmdline", "username", "create_time"]):
        try:
            name = (p.info["name"] or "")
            nl = name.lower()
            cmd = " ".join(p.info["cmdline"] or [])
            cl = cmd.lower()
            kind = None
            if nl in ai_names:
                kind = "등록된 AI 앱"
            elif nl.startswith(("python", "node", "uv", "deno", "bun")) and any(k in cl for k in kws):
                kind = "AI 스크립트"
            elif nl in browsers and any(f in cl for f in flags) and "--type=" not in cl:
                kind = "자동조종 브라우저"
            if not kind and p.info["pid"] not in conns:
                continue
            if not kind:
                kind = "브라우저(AI 사이트)" if nl in browsers else "미등록 프로그램"
            if kind == "자동조종 브라우저":
                seen_browser_auto.add(p.info["pid"])
            risk = {"등록된 AI 앱": "low", "브라우저(AI 사이트)": "low", "AI 스크립트": "med",
                    "자동조종 브라우저": "med", "미등록 프로그램": "high"}[kind]
            if nl in white:
                risk = "low"
            procs.append({"pid": p.info["pid"], "name": name, "kind": kind, "risk": risk,
                          "white": nl in white, "user": p.info.get("username") or "",
                          "started": datetime.fromtimestamp(p.info["create_time"]).strftime("%m-%d %H:%M")
                          if p.info.get("create_time") else "",
                          "domains": sorted(conns.get(p.info["pid"], [])), "cmd": cmd[:300]})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    order = {"high": 0, "med": 1, "low": 2}
    procs.sort(key=lambda x: (order[x["risk"]], x["name"].lower()))
    ai_rules = ("ai_api_connection", "ai_web_usage", "browser_automation", "ai_program_started",
                "ai_script_started", "ai_spawned_shell", "local_llm_server")
    recent = [{"ts": a["ts"].replace("T", " "), "sev": a["severity"], "rule": a["rule"], "text": describe(a), "sim": a["sim"]}
              for a in mon.db.alerts_query(_since(1), ["HIGH", "MEDIUM", "LOW"], True, 500)
              if a["rule"] in ai_rules][:40]
    v = {"procs": procs, "recent": recent, "whitelist": sorted(cfg.get("process_whitelist", [])),
         "domains": len(set(ip2dom.values())), "domainList": sorted(set(cfg["ai_api_domains"]))}
    _ai_cache.update(t=_t.time(), v=v)
    return v


def api_ips(mon):
    cfg = mon.cfg
    ioc = set(cfg.get("ioc_ips", []))
    blocked = {b["ip"]: b["at"] for b in _blocked(mon)}
    seen = {}
    for a in mon.db.alerts_query(_since(30), ["HIGH", "MEDIUM", "LOW"], True, 5000):
        d = a["detail"] if isinstance(a["detail"], dict) else {}
        for ip in {d.get("raddr_ip"), d.get("src_ip")} - {None, "", "-"}:
            if not _valid_ip(ip) or ipaddress.ip_address(ip).is_loopback:
                continue
            s = seen.setdefault(ip, {"ip": ip, "count": 0, "real": 0, "sim": 0, "intr": 0, "rules": set(), "last": a["ts"]})
            s["count"] += 1
            if not a["sim"] and a["rule"] in INTRUSION_RULES:
                s["intr"] += 1
            s["sim" if a["sim"] else "real"] += 1
            s["rules"].add(a["rule"])
            if a["rule"] in SUSPICIOUS_RULES and not a["sim"]:
                s.setdefault("susp", set()).add(a["rule"])
            s["last"] = max(s["last"], a["ts"])
    rows = []
    for ip in set(seen) | ioc | set(blocked):
        s = seen.get(ip, {"count": 0, "real": 0, "sim": 0, "intr": 0, "rules": set(), "last": ""})
        ad = ipaddress.ip_address(ip)
        rows.append({"ip": ip, "ioc": ip in ioc, "blocked": ip in blocked, "blockedAt": blocked.get(ip),
                     "count": s["count"], "real": s["real"], "sim": s["sim"], "intr": s["intr"],
                     "susp": sorted(s.get("susp", set())),
                     "rules": sorted(s["rules"]), "last": s["last"].replace("T", " "),
                     "private": ad.is_private})
    rows.sort(key=lambda r: (-r["intr"], not r["ioc"], -r["count"], r["ip"]))
    feeds = mon.det.feed_count if mon.det else 0
    return {"ips": rows, "source": cfg.get("_ioc_source", ""), "ports": cfg.get("ioc_ports", []), "feeds": feeds,
            "domains": cfg.get("ioc_domains", [])}


def api_rules(mon):
    stats = {}
    for r in mon.db.rule_stats(_since(7)):
        s = stats.setdefault(r["rule"], {"real": 0, "sim": 0, "last": ""})
        s["sim" if r["sim"] else "real"] += r["c"]
        s["last"] = max(s["last"], r["last"] or "")
    today = {}
    for r in mon.db.rule_stats(_since(1)):
        today[r["rule"]] = today.get(r["rule"], 0) + (0 if r["sim"] else r["c"])
    out = []
    for rule, (group, sev, desc) in RULE_INFO.items():
        s = stats.get(rule, {"real": 0, "sim": 0, "last": ""})
        out.append({"rule": rule, "group": group, "sev": sev, "desc": desc, "cat": classify(rule),
                    "today": today.get(rule, 0), "real7": s["real"], "sim7": s["sim"],
                    "last": s["last"].replace("T", " ")})
    bl = getattr(mon, "baseline", None)
    return {"rules": out, "logon": mon.logon_enabled, "sources": getattr(mon, "sources", {}),
            "baseline": bl.status() if bl else ""}


# ================= 설정 바꾸기 (config.json 저장 + 감시 중인 탐지기에 바로 반영) =================
def update_cfg(mon, key, value, op):
    with mon.cfg_lock:
        cur = list(mon.cfg.get(key, []))
        if op == "add" and value not in cur:
            cur.append(value)
        elif op == "remove":
            cur = [x for x in cur if x != value]
        mon.cfg[key] = cur
        with open(os.path.join(BASE, "config.json"), "w", encoding="utf-8") as f:
            json.dump(mon.cfg, f, ensure_ascii=False, indent=2)
    if mon.det:
        if key == "process_whitelist":
            mon.det.whitelist = {x.lower() for x in cur}
        if key == "ioc_ips":
            mon.det.ioc_ips = set(cur)
    _ai_cache["v"] = None


# ================= HTTP =================
def make_handler(mon, port):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json; charset=utf-8"):
            if isinstance(body, (dict, list)):
                body = json.dumps(body, ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _host_ok(self):
            return self.headers.get("Host", "") in allowed_hosts

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, {"error": "host"})
            path = self.path.split("?")[0]
            if path == "/":
                with open(os.path.join(STATIC, "index.html"), "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            if path == "/api/state":
                return self._send(200, build_state(mon))
            q = dict(x.split("=", 1) for x in self.path.split("?", 1)[1].split("&") if "=" in x) \
                if "?" in self.path else {}
            try:
                if path == "/api/history":
                    return self._send(200, api_history(mon, q))
                if path == "/api/ai":
                    return self._send(200, api_ai(mon))
                if path == "/api/ips":
                    return self._send(200, api_ips(mon))
                if path == "/api/rules":
                    return self._send(200, api_rules(mon))
                if path == "/api/llm":
                    import llm
                    return self._send(200, llm.status())
                if path == "/api/ipcheck":
                    from urllib.parse import unquote
                    from ip_check import investigate
                    return self._send(200, investigate(unquote(q.get("ip", "")), mon.db, mon.cfg,
                                                       mon.db.meta_get("blocked_ips", [])))
            except Exception as e:
                return self._send(500, {"error": str(e)})
            if path == "/alert.jpg":
                for name in ("A1_D.jpg",):
                    fp = os.path.join(STATIC, name)
                    if os.path.exists(fp):
                        with open(fp, "rb") as f:
                            return self._send(200, f.read(), "image/jpeg")
                fp = os.path.join(BASE, "A1_D.png")
                if os.path.exists(fp):
                    with open(fp, "rb") as f:
                        return self._send(200, f.read(), "image/png")
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            # 커스텀 헤더 토큰 → 다른 사이트에서 몰래 보내는 요청 차단
            if not self._host_ok() or self.headers.get("X-DDS-Token") != TOKEN:
                return self._send(403, {"error": "forbidden"})
            n = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                body = {}
            path = self.path.split("?")[0]
            if path == "/api/simulate":
                kind = body.get("type")
                if kind not in ("ai", "hacker", "net", "agent", "web", "llm"):
                    return self._send(400, {"ok": False, "msg": "type"})
                ack(mon)
                ok = mon.simulate(kind)
                return self._send(200, {"ok": ok, "msg": "시뮬레이션 시작" if ok else "이미 실행 중"})
            if path.startswith("/api/llm/"):
                import llm
                act = path.rsplit("/", 1)[-1]
                try:
                    if act == "config":
                        llm.save_cfg(body)
                        return self._send(200, {"ok": True, "msg": "AI 분석관 설정을 저장했어요", "status": llm.status()})
                    if act == "test":
                        ok, msg = llm.test(body.get("backend"))
                        return self._send(200, {"ok": ok, "msg": msg})
                    if act == "load":
                        k = body.get("slot")
                        cfg = llm.load_cfg()
                        msg = llm.SLOTS[k].load(llm.slot_cfg(cfg, k))
                        llm.MANAGER.warm_failed.discard(llm.slot_cfg(cfg, k)["path"])
                        return self._send(200, {"ok": True, "msg": f"{k} {msg}"})
                    if act == "unload":
                        return self._send(200, {"ok": True, "msg": f"{body.get('slot')} " + llm.SLOTS[body.get("slot")].unload()})
                    if act == "analyze":
                        r = llm.MANAGER.run_analysis(auto=False)
                        msg = r.get("msg") or (f"분석 완료 · {r.get('backend')} · {r.get('seconds')}초" if r.get("ok") else "분석 실패")
                        return self._send(200, {"ok": bool(r.get("ok")), "msg": msg, "result": r})
                    if act == "apply":
                        aid, tgt = body.get("id"), str(body.get("target") or "").split(":")[0].strip()
                        st = build_state(mon)
                        sim = bool(st["incident"] and st["incident"].get("sim"))
                        if aid == "block_ip":
                            ok, msg = firewall_block(mon, tgt, sim, by="AI 추천·사람 승인")
                        elif aid == "kill_process":
                            ok, msg = kill_tree(int(tgt) if tgt.isdigit() else None, sim)
                        elif aid == "evidence":
                            ok, msg = do_action(mon, "evidence")
                        elif aid == "isolate":
                            from responder import emergency_on
                            ok, msg = emergency_on(mon, "AI 분석관 추천")
                        else:
                            ok, msg = False, "이 조치는 조치 가이드의 명령어로 직접 해 주세요"
                        return self._send(200, {"ok": ok, "msg": msg})
                except Exception as e:
                    return self._send(200, {"ok": False, "msg": str(e)[:300]})
                return self._send(404, {"error": "not found"})
            if path == "/api/emergency":
                from responder import emergency_off, emergency_on
                ok, msg = emergency_on(mon) if body.get("on") else emergency_off(mon)
                return self._send(200, {"ok": ok, "msg": msg})
            if path == "/api/auto":
                mon.responder.set_enabled(bool(body.get("enabled")))
                on = mon.responder.enabled()
                return self._send(200, {"ok": True, "msg": "자동 대응을 켰어요 — 확실한 침입은 바로 차단·종료돼요" if on
                                        else "자동 대응을 껐어요 — 알림만 보내요"})
            if path == "/api/ack":
                ack(mon)
                return self._send(200, {"ok": True})
            if path == "/api/action":
                ok, msg = do_action(mon, body.get("action"))
                return self._send(200, {"ok": ok, "msg": msg})
            if path == "/api/block":
                ok, msg = firewall_block(mon, body.get("ip"))
                return self._send(200, {"ok": ok, "msg": msg})
            if path == "/api/unblock":
                ok, msg = firewall_unblock(mon, body.get("ip"))
                return self._send(200, {"ok": ok, "msg": msg})
            if path == "/api/ioc":
                ip, op = body.get("ip", "").strip(), body.get("op")
                if not _valid_ip(ip) or op not in ("add", "remove"):
                    return self._send(200, {"ok": False, "msg": "IP 형식이 아니에요"})
                update_cfg(mon, "ioc_ips", ip, op)
                return self._send(200, {"ok": True, "msg": f"위협 IP {'추가' if op == 'add' else '삭제'}: {ip}"})
            if path == "/api/whitelist":
                name, op = body.get("name", "").strip(), body.get("op")
                if not name or len(name) > 100 or op not in ("add", "remove"):
                    return self._send(200, {"ok": False, "msg": "프로그램 이름을 확인해 주세요"})
                update_cfg(mon, "process_whitelist", name.lower(), op)
                return self._send(200, {"ok": True, "msg": f"허용 목록 {'추가' if op == 'add' else '삭제'}: {name}"})
            return self._send(404, {"error": "not found"})

    return H


def serve(mon, port):
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(mon, port))
    return srv

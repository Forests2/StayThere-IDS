"""ARTEX 공격 흐름 시뮬레이션 테스트 (실제 공격 아님, 가짜 이벤트를 탐지기에 주입)

실행: python test_artex_sim.py
 - 시나리오 A: ARTEX식 공격 → 각 단계가 탐지돼야 함
 - 시나리오 B: 정상 사용 → 알림이 없어야 함
 - 시나리오 C: 실제 사례형 AI 에이전트 (2026-10 공개 사례 패턴, 명령 간격 5~6초) → 새 규칙이 잡아야 함
 - 시나리오 D: ARTEX 한국어판(artex-ko)이 이 PC에서 실행 → 설치 흔적
 - 시나리오 E: 내가 쓰는 AI 도구(Claude Code)가 비슷한 명령을 씀 → 빨간 경보 없이 기록만
 - 수집기 파서: 4688 · Sysmon XML(1·3·22) · IIS/nginx 로그 줄
 - 평소 패턴 학습: 학습한 행동은 조용, 처음 보는 행동이 몰리면 '확인 필요'
"""
import json
import os
from datetime import datetime, timedelta

from collectors import parse_4688, parse_combined_line, parse_sysmon_xml, parse_w3c_line, sysmon_to_event
from detectors import RuleDetector

BASE = os.path.dirname(os.path.abspath(__file__))
CFG = json.load(open(os.path.join(BASE, "config.json"), encoding="utf-8"))


class Clock:
    def __init__(self, start):
        self.t = start

    def __call__(self):
        return self.t

    def tick(self, sec):
        self.t += timedelta(seconds=sec)


def proc(pid, ppid, name, parent, cmd=""):
    return {"pid": pid, "ppid": ppid, "name": name, "parent": parent, "cmdline": cmd}


def net(kind, rip, rport, lport, process="", ai_domain="", state="ESTABLISHED", laddr=""):
    return {"kind": kind, "raddr_ip": rip, "raddr_port": rport, "lport": lport,
            "process": process, "ai_domain": ai_domain, "state": state, "laddr": laddr}


def run(title, steps, det, clock):
    print(f"\n=== {title} ===")
    fired = []
    for label, kind, ev, wait in steps:
        clock.tick(wait)
        fn = {"logon": det.on_logon, "process": det.on_process, "network": det.on_network,
              "weblog": det.on_weblog, "dns": det.on_dns}[kind]
        alerts = fn(ev)
        tag = ", ".join(f"{s}:{r}" for s, r, _, _ in alerts) or "-"
        print(f"[{clock().strftime('%H:%M:%S')}] {label:38} → {tag}")
        fired += [r for _, r, _, _ in alerts]
    return fired


def scenario_attack():
    clock = Clock(datetime(2026, 10, 14, 2, 10, 0))
    det = RuleDetector(CFG, now_fn=clock)
    attacker = "101.53.80.20"     # CrowdStrike 공개 ARTEX 프록시 IP
    unknown = "45.11.22.33"       # IOC 목록에 없는 새 IP (IP 바꾼 경우)
    steps = []
    # 1) 새 IP로 포트 스캔 (IOC 미등록 IP)
    for i, port in enumerate([21, 22, 80, 135, 139, 443, 445, 1433, 3389, 8080, 8443]):
        steps.append((f"스캔 {unknown} → :{port}", "network",
                      net("inbound", unknown, 50000 + i, port), 1))
    # 2) IOC IP에서 웹 서비스 접속
    steps.append(("ARTEX 프록시 IP 접속 :443", "network",
                  net("inbound", attacker, 51111, 443, "w3wp.exe"), 5))
    # 3) 웹쉘: IIS가 cmd 실행
    steps.append(("w3wp.exe → cmd.exe", "process",
                  proc(5001, 4000, "cmd.exe", "w3wp.exe", "cmd /c whoami"), 20))
    # 4) 정찰 명령 연속 실행 (각각 cmd /c 로 띄워져 부모가 매번 다름)
    for i, c in enumerate(["whoami.exe", "ipconfig.exe", "net.exe", "systeminfo.exe"]):
        steps.append((f"정찰 {c}", "process",
                      proc(5100 + i, 5050 + i, c, "cmd.exe"), 2))
    # 5) 공격자 서버 18899 포트로 역접속
    steps.append(("역접속 38.244.50.120:18899", "network",
                  net("outbound", "38.244.50.120", 18899, 52000, "powershell.exe"), 10))
    return run("시나리오 A: ARTEX식 공격", steps, det, clock)


def scenario_normal():
    clock = Clock(datetime(2026, 10, 14, 10, 0, 0))
    det = RuleDetector(CFG, now_fn=clock)
    steps = [
        ("사용자 로컬 로그인", "logon",
         {"type": "logon_success", "user": "PC\\user", "logon_type": "interactive", "src_ip": "127.0.0.1"}, 0),
        ("explorer → chrome", "process", proc(100, 50, "chrome.exe", "explorer.exe"), 5),
        ("explorer → cmd (사람이 직접)", "process", proc(101, 50, "cmd.exe", "explorer.exe"), 30),
        ("ipconfig 한 번", "process", proc(102, 101, "ipconfig.exe", "cmd.exe"), 20),
        ("chrome → 웹사이트 443", "network", net("outbound", "142.250.1.1", 443, 60000, "chrome.exe"), 5),
        ("ping 한 번 (2분 뒤)", "process", proc(103, 101, "ping.exe", "cmd.exe"), 120),
    ]
    return run("시나리오 B: 정상 사용", steps, det, clock)


def scenario_agent():
    """공개 사례 패턴: ARTEX 정찰 UA → IP 바꿔 가며 RDP → 웹쉘에서 기계 형식 명령 · 실패-수정 반복
    → certutil 디코드 · 조각 합치기 · Public 실행 → Potato 권한 상승 → SAM 저장. 명령 간격 5~6초."""
    clock = Clock(datetime(2026, 10, 19, 3, 0, 0))
    det = RuleDetector(CFG, now_fn=clock)
    W, C, P = "w3wp.exe", "cmd.exe", "powershell.exe"
    steps = [("ARTEX enrich UA", "weblog", {"src_ip": "198.51.100.7", "ua": "artex-enrich/1.0", "path": "/"}, 0),
             ("spa-api-recon UA", "weblog", {"src_ip": "198.51.100.7", "ua": "Mozilla/5.0 (spa-api-recon)",
                                             "path": "/static/app.js"}, 2)]
    for i, ip in enumerate(["45.9.1.21", "45.9.2.37", "45.9.3.44"]):
        steps.append((f"RDP 접속 {ip}", "network", net("inbound", ip, 52100 + i, 3389, "svchost.exe"), 20))
    cmds = ['cmd /c "whoami /priv 2>nul & echo --- & hostname"',
            "powershell -c \"Get-ChildItem C:\\inetpub -Recurse 2>$null | Select-Object -First 20; echo '---'\"",
            r'cmd /c "type C:\inetpub\wwwroot\web.config | findstr connectionString 2>nul & echo exit:%errorlevel%"',
            r'cmd /c "type C:\inetpub\wwwroot\App\web.config | findstr connectionString 2>nul & echo exit:%errorlevel%"',
            r'cmd /c "type C:\inetpub\wwwroot\App\Config\web.config | findstr connectionString 2>nul & echo exit:%errorlevel%"']
    for i, c in enumerate(cmds):
        steps.append((f"웹쉘 명령 {i + 1}", "process", proc(7001 + i, 4000, P if c.startswith("powershell") else C, W, c), 6))
    steps += [("certutil 디코드", "process", proc(7020, 4000, C, W, r"cmd /c certutil -decode C:\Users\Public\w0.b64 C:\Users\Public\w0"), 5),
              ("조각 합치기", "process", proc(7021, 4000, C, W, r"cmd /c copy /b w0+w1 C:\Users\Public\g.exe"), 5),
              ("Public 폴더 실행", "process", {**proc(7022, 7021, "g.exe", C, "g.exe -cmd whoami"),
                                            "exe": r"C:\Users\Public\g.exe"}, 5),
              ("GodPotato", "process", proc(7023, 4000, "GodPotato-NET4.exe", C, "GodPotato-NET4.exe -cmd whoami"), 6),
              ("SAM 저장", "process", proc(7024, 7023, "reg.exe", C, r"reg save HKLM\SAM C:\Windows\Temp\s.hiv"), 6),
              ("xcai.pro 조회 (Sysmon 22)", "dns", {"query": "api.xcai.pro", "process": "g.exe", "pid": 7022}, 3)]
    return run("시나리오 C: 실제 사례형 AI 에이전트", steps, det, clock)


def scenario_artex_ko():
    clock = Clock(datetime(2026, 10, 19, 11, 0, 0))
    det = RuleDetector(CFG, now_fn=clock)
    steps = [("artex-ko 실행", "process", {**proc(8001, 1200, "artex-ko.exe", "explorer.exe", "artex-ko.exe serve"),
                                          "exe": r"D:\tools\artex-ko\artex-ko.exe"}, 0),
             ("콘솔 :8787 열림", "network", {**net("listen", "", 0, 8787, "artex-ko.exe"), "laddr": "0.0.0.0:8787"}, 2)]
    return run("시나리오 D: ARTEX 한국어판이 이 PC에서 실행", steps, det, clock)


def scenario_local_ai():
    """내가 Claude Code 로 개발 — 기계 형식 명령 · 재시도가 있어도 외부 침입 아님"""
    clock = Clock(datetime(2026, 10, 19, 14, 0, 0))
    det = RuleDetector(CFG, now_fn=clock)
    anc = [{"pid": 900, "name": "node.exe", "cmdline": "node C:\\npm\\node_modules\\@anthropic-ai\\claude-code\\cli.js"},
           {"pid": 800, "name": "WindowsTerminal.exe", "cmdline": ""}]
    steps = []
    for i, c in enumerate(['cmd /c "git status 2>nul & echo --- & git log -3"',
                           'cmd /c "python -m pytest -q 2>nul | head -20 & echo exit:%errorlevel%"',
                           'cmd /c "python -m pytest -q tests 2>nul | head -20 & echo exit:%errorlevel%"',
                           'cmd /c "python -m pytest -q tests/unit 2>nul | head -20 & echo exit:%errorlevel%"']):
        steps.append((f"Claude Code 명령 {i + 1}", "process",
                      {**proc(9001 + i, 900, "cmd.exe", "node.exe", c), "ancestors": anc}, 5))
    steps += [("Jupyter 127.0.0.1:8888", "network", {**net("listen", "", 0, 8888, "python.exe"), "laddr": "127.0.0.1:8888"}, 3),
              ("정상 브라우저 웹 요청", "weblog", {"src_ip": "203.0.113.9", "ua": "Mozilla/5.0 (Windows NT 10.0) Chrome/141",
                                           "path": "/main.js"}, 1)]
    return run("시나리오 E: 내가 쓰는 AI 도구 (외부 침입 아님)", steps, det, clock)


def test_parsers():
    print("\n=== 수집기 파서 ===")
    ok = True
    s = ["S-1-5-18", "WEB01$", "CORP", "0x3e7", "0x1c2c", r"C:\Windows\System32\cmd.exe", "%%1936", "0x1a2b",
         'cmd /c "whoami /priv 2>nul & echo ---"', "S-1-0-0", "-", "-", "0x0", r"C:\Windows\System32\inetsrv\w3wp.exe",
         "S-1-16-12288"]
    e = parse_4688(s)
    ok &= e["pid"] == 0x1c2c and e["ppid"] == 0x1a2b and e["name"] == "cmd.exe" and e["parent"] == "w3wp.exe"
    print(f"  4688        → {e['name']} ← {e['parent']} pid={e['pid']} {'OK' if ok else 'FAIL'}")
    xml = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>22</EventID>"
           "<EventRecordID>4242</EventRecordID></System><EventData><Data Name='ProcessId'>7022</Data>"
           "<Data Name='QueryName'>api.xcai.pro</Data><Data Name='Image'>C:\\Users\\Public\\g.exe</Data></EventData></Event>")
    eid, rec, data = parse_sysmon_xml(xml)
    kind, ev = sysmon_to_event(eid, data)
    o2 = eid == 22 and rec == 4242 and kind == "dns" and ev["process"] == "g.exe" and ev["query"] == "api.xcai.pro"
    print(f"  Sysmon 22   → {ev['process']} → {ev['query']} {'OK' if o2 else 'FAIL'}")
    x3 = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>3</EventID>"
          "<EventRecordID>4243</EventRecordID></System><EventData><Data Name='Image'>C:\\Windows\\System32\\certutil.exe</Data>"
          "<Data Name='ProcessId'>7030</Data><Data Name='Initiated'>true</Data><Data Name='SourceIp'>10.0.0.5</Data>"
          "<Data Name='SourcePort'>52011</Data><Data Name='DestinationIp'>38.244.50.120</Data>"
          "<Data Name='DestinationPort'>18899</Data></EventData></Event>")
    k3, e3 = sysmon_to_event(*[v for i, v in enumerate(parse_sysmon_xml(x3)) if i != 1])
    o2 = o2 and k3 == "network" and e3["kind"] == "outbound" and e3["raddr_ip"] == "38.244.50.120" and e3["raddr_port"] == 18899
    print(f"  Sysmon 3    → {e3['process']} → {e3['raddr_ip']}:{e3['raddr_port']} {'OK' if o2 else 'FAIL'}")
    fields = "date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken".split()
    w = parse_w3c_line("2026-10-19 03:00:01 10.0.0.5 GET /main.js - 443 - 198.51.100.7 Mozilla/5.0+(spa-api-recon) - 200 0 0 12", fields)
    o3 = w and w["ua"] == "Mozilla/5.0 (spa-api-recon)" and w["src_ip"] == "198.51.100.7"
    print(f"  IIS W3C     → {w['src_ip']} '{w['ua']}' {'OK' if o3 else 'FAIL'}")
    c = parse_combined_line('198.51.100.7 - - [19/Oct/2026:03:00:01 +0900] "GET / HTTP/1.1" 200 512 "-" "artex-enrich/1.0"')
    o4 = c and c["ua"] == "artex-enrich/1.0"
    print(f"  nginx 로그  → {c['src_ip']} '{c['ua']}' {'OK' if o4 else 'FAIL'}")
    return ok and o2 and o3 and o4


def test_baseline():
    """평소 패턴 학습: 8일 동안 평소 행동을 배운 뒤 → 평소 행동은 조용, 처음 보는 행동 3가지가 몰리면 알림"""
    from baseline import Baseline
    print("\n=== 평소 패턴 학습 ===")
    clock = Clock(datetime(2026, 10, 1, 9, 0, 0))
    cfg = {**CFG, "baseline": {"enabled": True, "learn_days": 7, "min_events": 200, "burst": 3, "window_sec": 600}}
    bl = Baseline(cfg, now_fn=clock)
    normal = [("process", {"name": "chrome.exe", "parent": "explorer.exe", "exe": r"C:\Program Files\Google\Chrome\chrome.exe"}),
              ("process", {"name": "git.exe", "parent": "cmd.exe", "exe": r"C:\Program Files\Git\cmd\git.exe"}),
              ("network", {"kind": "outbound", "process": "chrome.exe", "raddr_port": 443}),
              ("process", {"name": "python.exe", "parent": "cmd.exe", "exe": r"C:\Users\jun\AppData\Local\Programs\Python\python.exe"})]
    for day in range(8):
        for k, ev in normal * 10:
            bl.check(k, ev)
        clock.tick(86400)
    print(f"  상태: {bl.status()}")
    quiet = sum(len(bl.check(k, ev)) for k, ev in normal)
    odd = [("process", {"name": "rundll32.exe", "parent": "excel.exe", "exe": r"C:\Windows\System32\rundll32.exe"}),
           ("process", {"name": "x.exe", "parent": "rundll32.exe", "exe": r"C:\ProgramData\x\x.exe"}),
           ("network", {"kind": "outbound", "process": "x.exe", "raddr_port": 8443})]
    hits = []
    for k, ev in odd:
        clock.tick(30)
        hits += bl.check(k, ev)
    again = sum(len(bl.check(k, ev)) for k, ev in odd)   # 한 번 본 조합은 다시 알리지 않음
    for h in hits:
        print(f"  {h[0]}:{h[1]} — {', '.join(h[3]['new'])}")
    ok = bl.ready() and quiet == 0 and len(hits) == 1 and again == 0
    print(f"  평소 행동 알림 {quiet}건 · 처음 보는 행동 알림 {len(hits)}건 · 반복 알림 {again}건 → {'OK' if ok else 'FAIL'}")
    return ok


def judge_check(det_rules):
    """시나리오 C 알림으로 'AI 공격 프로그램' 판정이 나오는지 (webui.judge_ai)"""
    import webui
    rows = [{"rule": r, "severity": "HIGH", "detail": {}, "ts": f"2026-10-19T03:{i // 10:02d}:{(i * 6) % 60:02d}"}
            for i, r in enumerate(det_rules)]
    jd = webui.judge_ai(rows)
    print(f"\n=== AI 판정 (시나리오 C) ===\n  {jd['verdict']} · 자동화 점수 {jd['autoScore']}")
    return jd["level"] == "ai"


if __name__ == "__main__":
    from attack_taxonomy import INTRUSION_RULES
    a = scenario_attack()
    b = scenario_normal()
    c = scenario_agent()
    d = scenario_artex_ko()
    e = scenario_local_ai()
    parsers = test_parsers()
    base_ok = test_baseline()
    judged = judge_check(c)
    expect = {"port_scan", "ioc_ip_match", "webserver_spawned_shell", "recon_burst"}
    expect_c = {"artex_user_agent", "distributed_ips", "agent_command_style", "retry_loop", "payload_staging",
                "privilege_escalation", "credential_dump", "ioc_domain_query"}
    print("\n=== 결과 ===")
    miss = 0
    for r in sorted(expect):
        print(f"  {'OK ' if r in a else 'MISS'} A {r}")
        miss += r not in a
    for r in sorted(expect_c):
        print(f"  {'OK ' if r in c else 'MISS'} C {r}")
        miss += r not in c
    print(f"  {'OK ' if 'artex_host_artifact' in d else 'MISS'} D artex_host_artifact")
    miss += "artex_host_artifact" not in d
    e_intr = [r for r in e if r in INTRUSION_RULES]
    print(f"  정상 사용 알림 수: {len(b)} ({'OK' if not b else '오탐 있음: ' + ', '.join(b)})")
    print(f"  내 AI 도구 사용 → 빨간 경보 {len(e_intr)}건 ({'OK' if not e_intr else '오탐: ' + ', '.join(e_intr)})"
          f" · 기록만: {', '.join(e) or '없음'}")
    print(f"  수집기 파서: {'OK' if parsers else 'FAIL'} · AI 판정: {'OK' if judged else 'FAIL'}"
          f" · 평소 패턴 학습: {'OK' if base_ok else 'FAIL'}")
    bad = miss + len(b) + len(e_intr) + (not parsers) + (not judged) + (not base_ok)
    print(f"\n{'모두 통과' if not bad else f'실패 {bad}건'}")
    raise SystemExit(1 if bad else 0)

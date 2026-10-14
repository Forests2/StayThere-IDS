"""수집기: 로그인 이벤트(누가), 프로세스·네트워크(어떤 프로그램)"""
import socket
import psutil

try:
    import win32evtlog  # pywin32
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

# 보안 이벤트 ID
LOGON_EVENTS = {
    4624: "logon_success",
    4625: "logon_fail",
    4648: "explicit_cred_logon",
    4672: "admin_logon",
    4720: "user_created",
    4732: "added_to_admin_group",
}
# 4624/4625 LogonType
LOGON_TYPES = {2: "interactive", 3: "network", 7: "unlock", 10: "rdp", 11: "cached"}


class LogonCollector:
    """Windows Security 로그에서 로그인 관련 이벤트 수집 (관리자 권한 필요)"""

    def __init__(self):
        self.last_record = 0
        if HAS_WIN32:
            self._init_last_record()

    def _init_last_record(self):
        # 최초 실행 시 과거 로그는 건너뛰고 현재 시점부터 수집
        h = win32evtlog.OpenEventLog(None, "Security")
        try:
            self.last_record = win32evtlog.GetOldestEventLogRecord(h) + \
                win32evtlog.GetNumberOfEventLogRecords(h) - 1
        finally:
            win32evtlog.CloseEventLog(h)

    def collect(self):
        if not HAS_WIN32:
            return []
        out = []
        h = win32evtlog.OpenEventLog(None, "Security")
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        newest = self.last_record
        try:
            done = False
            while not done:
                recs = win32evtlog.ReadEventLog(h, flags, 0)
                if not recs:
                    break
                for r in recs:
                    if r.RecordNumber <= self.last_record:
                        done = True
                        break
                    newest = max(newest, r.RecordNumber)
                    eid = r.EventID & 0xFFFF
                    if eid not in LOGON_EVENTS:
                        continue
                    out.append(self._parse(r, eid))
        finally:
            win32evtlog.CloseEventLog(h)
        self.last_record = newest
        return out

    @staticmethod
    def _parse(r, eid):
        s = list(r.StringInserts or [])
        ev = {"event_id": eid, "type": LOGON_EVENTS[eid],
              "time": str(r.TimeGenerated), "record": r.RecordNumber}
        if eid in (4624, 4625) and len(s) >= 19:
            ev.update({
                "user": f"{s[6]}\\{s[5]}",
                "logon_type": LOGON_TYPES.get(int(s[8]) if s[8].isdigit() else -1, s[8]),
                "src_ip": s[18] if len(s) > 18 else "",
                "workstation": s[11] if len(s) > 11 else "",
                "process": s[17] if len(s) > 17 else "",
            })
        elif len(s) >= 2:
            ev["user"] = f"{s[2] if len(s) > 2 else ''}\\{s[1]}"
        return ev


class ProcessCollector:
    """새로 생긴 프로세스만 반환"""

    def __init__(self):
        self.seen = set()
        for p in psutil.process_iter(["pid", "create_time"]):
            self.seen.add((p.info["pid"], p.info["create_time"]))

    def collect(self):
        out = []
        current = set()
        for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline",
                                      "username", "create_time"]):
            key = (p.info["pid"], p.info["create_time"])
            current.add(key)
            if key in self.seen:
                continue
            info = dict(p.info)
            info["cmdline"] = " ".join(info.get("cmdline") or [])
            try:
                info["parent"] = psutil.Process(info["ppid"]).name()
            except Exception:
                info["parent"] = ""
            out.append(info)
        self.seen = current
        return out


class NetworkCollector:
    """외부 연결(ESTABLISHED) + 로컬 LISTEN 포트 수집"""

    def __init__(self, ai_domains):
        self.ai_domains = ai_domains
        self.ip_to_domain = {}
        self.seen = set()
        self.refresh_dns()

    def refresh_dns(self):
        # AI API 도메인 → IP 매핑 (CDN이라 IP가 바뀌므로 주기적으로 갱신)
        m = {}
        for d in self.ai_domains:
            try:
                for ip in socket.gethostbyname_ex(d)[2]:
                    m[ip] = d
            except OSError:
                pass
        self.ip_to_domain = m

    # 스캔은 SYN_RECV/TIME_WAIT 같은 짧은 상태로만 남기도 해서 같이 수집
    REMOTE_STATES = {"ESTABLISHED", "SYN_SENT", "SYN_RECV", "TIME_WAIT", "CLOSE_WAIT", "FIN_WAIT1", "FIN_WAIT2"}

    def collect(self):
        out = []
        current = set()
        conns = psutil.net_connections(kind="inet")
        listen_ports = {c.laddr.port for c in conns
                        if c.status == psutil.CONN_LISTEN and c.laddr}
        for c in conns:
            if c.status == psutil.CONN_LISTEN and c.laddr:
                key = (c.pid, "LISTEN", c.laddr.port)
                kind = "listen"
            elif c.status in self.REMOTE_STATES and c.raddr and c.laddr:
                if c.raddr.ip.startswith("127.") or c.raddr.ip in ("::1", "0.0.0.0"):
                    continue   # PC 내부 연결(대시보드 자체 통신 등)은 제외
                # 내 LISTEN 포트로 들어온 연결 = inbound, 그 외 = outbound
                kind = "inbound" if c.laddr.port in listen_ports else "outbound"
                key = (kind, c.raddr.ip, c.raddr.port, c.laddr.port)
            else:
                continue
            current.add(key)
            if key in self.seen:
                continue
            pname = ""
            if c.pid:
                try:
                    pname = psutil.Process(c.pid).name()
                except Exception:
                    pass
            out.append({
                "kind": kind, "state": c.status, "pid": c.pid or 0, "process": pname,
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "lport": c.laddr.port if c.laddr else 0,
                "raddr_ip": c.raddr.ip if c.raddr else "",
                "raddr_port": c.raddr.port if c.raddr else 0,
                "ai_domain": self.ip_to_domain.get(c.raddr.ip, "") if c.raddr else "",
            })
        self.seen = current
        return out

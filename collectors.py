"""수집기: 로그인 이벤트(누가), 프로세스·네트워크(어떤 프로그램)

2026-10 개선
 - 보안 이벤트 4688(프로세스 생성 + 명령줄): 2초 사이에 생겼다 사라진 명령도 잡음
   (enable_cmdline_audit.bat 로 '명령줄 기록' 을 켜야 명령줄이 들어옴)
 - Sysmon(있으면): 이벤트 1 프로세스 생성, 3 네트워크 연결, 22 DNS 조회
 - 웹 서버 로그(IIS·nginx·Apache, 있으면): ARTEX 정찰 User-Agent 확인용
 - 새 프로세스의 조상(부모의 부모…) 이름·명령줄: 내가 쓰는 AI 도구 아래에서 실행됐는지 판단
"""
import glob
import ntpath
import os
import re
import socket
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import unquote_plus

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
    4688: "process_create",
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
        if eid == 4688:
            return parse_4688(s, ev)
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


def _hexint(x):
    try:
        return int(str(x), 16) if str(x).lower().startswith("0x") else int(x)
    except (TypeError, ValueError):
        return 0


def parse_4688(s, ev=None):
    """4688 StringInserts → 프로세스 이벤트
    0 SubjectUserSid 1 SubjectUserName 2 SubjectDomainName 3 SubjectLogonId 4 NewProcessId 5 NewProcessName
    6 TokenElevationType 7 ProcessId(부모) 8 CommandLine 9 TargetUserSid 10 TargetUserName
    11 TargetDomainName 12 TargetLogonId 13 ParentProcessName 14 MandatoryLabel"""
    ev = dict(ev or {})
    g = lambda i: s[i] if len(s) > i and s[i] is not None else ""
    exe = g(5)
    ev.update({"type": "process_create", "pid": _hexint(g(4)), "ppid": _hexint(g(7)),
               "name": ntpath.basename(exe), "exe": exe, "cmdline": g(8),
               "parent": ntpath.basename(g(13)), "username": f"{g(2)}\\{g(1)}", "source": "4688"})
    return ev


def ancestors(ppid, depth=5):
    """부모 → 조부모 … 이름·명령줄 (내가 쓰는 AI 도구 아래에서 실행됐는지 판단용)"""
    out = []
    try:
        p = psutil.Process(ppid)
        for _ in range(depth):
            try:
                out.append({"pid": p.pid, "name": p.name(), "cmdline": " ".join(p.cmdline())[:300]})
            except Exception:
                out.append({"pid": p.pid, "name": "", "cmdline": ""})
            p = p.parent()
            if p is None or p.pid in (0, 4):
                break
    except Exception:
        pass
    return out


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
            info["ancestors"] = ancestors(info["ppid"])
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


# ================= Sysmon (있을 때만) =================
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def parse_sysmon_xml(xml):
    """Sysmon 이벤트 XML → (이벤트ID, 레코드번호, {필드: 값})"""
    root = ET.fromstring(xml)
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    eid = int(root.findtext("e:System/e:EventID", "0", ns))
    rec = int(root.findtext("e:System/e:EventRecordID", "0", ns))
    data = {d.get("Name"): (d.text or "") for d in root.findall("e:EventData/e:Data", ns)}
    return eid, rec, data


def sysmon_to_event(eid, data):
    """Sysmon 1 → 프로세스 이벤트, 3 → 네트워크 이벤트, 22 → DNS 이벤트 (나머지는 None)"""
    if eid == 1:
        return "process", {"pid": _hexint(data.get("ProcessId")), "ppid": _hexint(data.get("ParentProcessId")),
                           "name": ntpath.basename(data.get("Image", "")), "exe": data.get("Image", ""),
                           "cmdline": data.get("CommandLine", ""), "parent": ntpath.basename(data.get("ParentImage", "")),
                           "parent_cmdline": data.get("ParentCommandLine", ""), "username": data.get("User", ""),
                           "source": "sysmon"}
    if eid == 3:
        out = data.get("Initiated", "").lower() == "true"     # 이 PC 가 연결을 시작했으면 나감
        rip = data.get("DestinationIp", "") if out else data.get("SourceIp", "")
        if rip.startswith("127.") or rip in ("::1", "0:0:0:0:0:0:0:1", ""):
            return None
        return "network", {"kind": "outbound" if out else "inbound", "state": "ESTABLISHED",
                           "pid": _hexint(data.get("ProcessId")), "process": ntpath.basename(data.get("Image", "")),
                           "raddr_ip": rip,
                           "raddr_port": _hexint(data.get("DestinationPort") if out else data.get("SourcePort")),
                           "lport": _hexint(data.get("SourcePort") if out else data.get("DestinationPort")),
                           "laddr": f"{data.get('SourceIp' if out else 'DestinationIp', '')}:"
                                    f"{data.get('SourcePort' if out else 'DestinationPort', '')}",
                           "rhost": data.get("DestinationHostname", "") if out else data.get("SourceHostname", ""),
                           "ai_domain": "", "source": "sysmon"}
    if eid == 22:
        return "dns", {"query": data.get("QueryName", ""), "pid": _hexint(data.get("ProcessId")),
                       "process": ntpath.basename(data.get("Image", "")), "exe": data.get("Image", ""),
                       "result": data.get("QueryResults", "")[:300], "source": "sysmon"}
    return None


class SysmonCollector:
    """Sysmon 이 설치돼 있으면 이벤트 1·3·22 를 읽음. 없거나 권한이 없으면 조용히 꺼짐."""

    def __init__(self):
        self.ok, self.last, self.error = False, 0, ""
        if not HAS_WIN32:
            self.error = "pywin32 없음"
            return
        try:
            h = win32evtlog.EvtQuery(SYSMON_CHANNEL,
                                     win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection, "*")
            evs = win32evtlog.EvtNext(h, 1)
            if evs:
                _, self.last, _ = parse_sysmon_xml(win32evtlog.EvtRender(evs[0], win32evtlog.EvtRenderEventXml))
            self.ok = True
        except Exception as e:
            self.error = str(e)[:120]

    def collect(self, limit=500):
        if not self.ok:
            return []
        out = []
        try:
            h = win32evtlog.EvtQuery(SYSMON_CHANNEL, win32evtlog.EvtQueryChannelPath,
                                     f"*[System[(EventID=1 or EventID=3 or EventID=22) and EventRecordID>{self.last}]]")
            while len(out) < limit:
                evs = win32evtlog.EvtNext(h, 64)
                if not evs:
                    break
                for e in evs:
                    eid, rec, data = parse_sysmon_xml(win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml))
                    self.last = max(self.last, rec)
                    r = sysmon_to_event(eid, data)
                    if r:
                        out.append(r)
        except Exception as e:
            if "No more" not in str(e) and "259" not in str(e):
                self.error = str(e)[:120]
        return out


# ================= 웹 서버 로그 (IIS W3C · nginx/Apache combined) =================
_COMBINED = re.compile(r'^(\S+) \S+ \S+ \[[^\]]*\] "(?:\S+) (\S+)[^"]*" (\d{3}) \S+ "[^"]*" "([^"]*)"')


def parse_w3c_line(line, fields):
    if not fields or line.startswith("#"):
        return None
    parts = line.split(" ")
    if len(parts) != len(fields):
        return None
    row = dict(zip(fields, parts))
    path = row.get("cs-uri-stem", "")
    return {"src_ip": row.get("c-ip", ""), "path": path, "status": row.get("sc-status", ""),
            "ua": unquote_plus(row.get("cs(User-Agent)", "").replace("+", " ")) if row.get("cs(User-Agent)") not in (None, "-") else ""}


def parse_combined_line(line):
    m = _COMBINED.match(line)
    if not m:
        return None
    return {"src_ip": m.group(1), "path": m.group(2), "status": m.group(3), "ua": m.group(4)}


class WebLogCollector:
    """웹 서버 로그 폴더가 있으면 새로 추가된 줄만 읽음 (처음엔 끝에서 시작)"""

    def __init__(self, dirs):
        self.dirs = [d for d in dirs if os.path.isdir(d)]
        self.pos, self.fields = {}, {}
        for f in self._files():
            try:
                self.pos[f] = os.path.getsize(f)
                with open(f, "r", encoding="utf-8", errors="ignore") as fh:   # IIS 는 맨 위에 #Fields 머리줄
                    for line in fh.read(8192).splitlines():
                        if line.startswith("#Fields:"):
                            self.fields[f] = line[8:].split()
            except OSError:
                pass

    def _files(self):
        out = []
        for d in self.dirs:
            out += glob.glob(os.path.join(d, "**", "*.log"), recursive=True)
        return out[:200]

    def collect(self, limit=5000):
        out = []
        for f in self._files():
            try:
                size = os.path.getsize(f)
                start = self.pos.get(f, 0)
                if size < start:
                    start = 0
                if size == start:
                    continue
                with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                    fh.seek(start)
                    for line in fh:
                        line = line.rstrip("\r\n")
                        if line.startswith("#Fields:"):
                            self.fields[f] = line[8:].split()
                            continue
                        w = parse_w3c_line(line, self.fields.get(f)) if self.fields.get(f) else parse_combined_line(line)
                        if w:
                            w["file"] = os.path.basename(f)
                            out.append(w)
                        if len(out) >= limit:
                            break
                    self.pos[f] = fh.tell()
            except OSError:
                continue
        return out

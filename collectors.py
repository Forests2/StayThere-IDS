"""수집기: 로그인 이벤트(누가), 프로세스·네트워크(어떤 프로그램)

2026-10 개선
 - 보안 이벤트 4688(프로세스 생성 + 명령줄): 2초 사이에 생겼다 사라진 명령도 잡음
   (enable_cmdline_audit.bat 로 '명령줄 기록' 을 켜야 명령줄이 들어옴)
 - Sysmon(있으면): 이벤트 1 프로세스 생성, 3 네트워크 연결, 11 파일 생성, 12·13 레지스트리, 22 DNS 조회
 - PowerShell 스크립트 블록(4104, 있으면) · 보안 이벤트 4663(파일 접근 감사를 켰을 때)
 - 폴링(Sysmon 없을 때 보완): 자동 실행(Run 키 · 시작프로그램 폴더), 웹 폴더의 새 스크립트 파일
 - 웹 서버 로그(IIS·nginx·Apache, 있으면): ARTEX 정찰 User-Agent 확인용
 - 새 프로세스의 조상(부모의 부모…) 이름·명령줄: 내가 쓰는 AI 도구 아래에서 실행됐는지 판단
Linux
 - 로그인: /var/log/auth.log · /var/log/secure (없으면 journalctl) — SSH 성공·실패, 계정 생성, sudo/wheel 그룹 추가
 - 자동 실행: cron · systemd 서비스 · authorized_keys · .bashrc · ld.so.preload 변경 (30초 비교)
"""
import glob
import hashlib
import ntpath
import os
import re
import shutil
import socket
import subprocess
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
    4663: "object_access",
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
        if eid == 4663:
            return parse_4663(s, ev)
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


def parse_4663(s, ev=None):
    """4663 (개체 접근) StringInserts → 파일 접근 이벤트
    0 SubjectUserSid 1 SubjectUserName 2 SubjectDomainName 3 SubjectLogonId 4 ObjectServer 5 ObjectType
    6 ObjectName 7 HandleId 8 AccessList 9 AccessMask 10 ProcessId 11 ProcessName"""
    ev = dict(ev or {})
    g = lambda i: s[i] if len(s) > i and s[i] is not None else ""
    ev.update({"type": "object_access", "object": g(6), "object_type": g(5), "pid": _hexint(g(10)),
               "process": ntpath.basename(g(11)), "exe": g(11), "user": f"{g(2)}\\{g(1)}", "source": "4663"})
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


# ================= Linux 로그인 기록 =================
_RE_FAIL = re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(\S+) from (\S+)")
_RE_OK = re.compile(r"Accepted (\S+) for (\S+) from (\S+)")
_RE_USERADD = re.compile(r"useradd\[\d+\]: new user: name=([^,\s]+)")
_RE_GROUP = re.compile(r"(?:usermod\[\d+\]: add '([^']+)' to (?:shadow )?group '(sudo|wheel|admin|root)'"
                       r"|gpasswd\[\d+\]: user (\S+) added by \S+ to group (sudo|wheel|admin|root))")


def parse_auth_line(line):
    """auth.log / secure 한 줄 → 로그인 이벤트 (관련 없으면 None)"""
    m = _RE_OK.search(line)
    if m:
        return {"type": "logon_success", "event_id": "sshd", "user": m.group(2), "src_ip": m.group(3),
                "logon_type": "ssh", "method": m.group(1), "raw": line[:300]}
    m = _RE_FAIL.search(line)          # "Invalid user" 줄은 같은 시도의 "Failed password" 와 겹쳐서 안 셈
    if m:
        return {"type": "logon_fail", "event_id": "sshd", "user": m.group(1), "src_ip": m.group(2),
                "logon_type": "ssh", "raw": line[:300]}
    m = _RE_USERADD.search(line)
    if m:
        return {"type": "user_created", "event_id": "useradd", "user": m.group(1), "raw": line[:300]}
    m = _RE_GROUP.search(line)
    if m:
        return {"type": "added_to_admin_group", "event_id": "usermod", "user": m.group(1) or m.group(3),
                "group": m.group(2) or m.group(4), "raw": line[:300]}
    return None


class LinuxAuthCollector:
    """Linux 인증 로그에서 새 줄만 읽음 (root 권한 필요). 파일이 없으면 journalctl 사용"""
    FILES = ("/var/log/auth.log", "/var/log/secure")

    def __init__(self):
        self.path = next((f for f in self.FILES if os.path.isfile(f) and os.access(f, os.R_OK)), None)
        self.pos = os.path.getsize(self.path) if self.path else 0
        self.journal = None
        if not self.path and shutil.which("journalctl"):
            try:
                r = subprocess.run(["journalctl", "-n", "0", "--show-cursor", "-q"], capture_output=True,
                                   text=True, timeout=20)
                m = re.search(r"cursor: (\S+)", r.stdout + r.stderr)
                self.journal = m.group(1) if m else ""
            except Exception:
                self.journal = None
        self.ok = bool(self.path) or self.journal is not None
        self.source = self.path or ("journalctl" if self.journal is not None else "")

    def _lines(self):
        if self.path:
            size = os.path.getsize(self.path)
            if size < self.pos:          # 로그 교체(logrotate)
                self.pos = 0
            with open(self.path, encoding="utf-8", errors="ignore") as f:
                f.seek(self.pos)
                data = f.read(2_000_000)
                self.pos = f.tell()
            return data.splitlines()
        args = ["journalctl", "-q", "--no-pager", "-o", "short-iso", "--show-cursor",
                "_COMM=sshd", "+", "_COMM=sshd-session", "+", "_COMM=useradd", "+", "_COMM=usermod", "+", "_COMM=gpasswd"]
        args += ["--after-cursor", self.journal] if self.journal else ["--since", "-10s"]
        r = subprocess.run(args, capture_output=True, text=True, timeout=20)
        out = []
        for line in r.stdout.splitlines():
            if line.startswith("-- cursor:"):
                self.journal = line.split(":", 1)[1].strip()
            else:
                out.append(line)
        return out

    def collect(self):
        if not self.ok:
            return []
        out = []
        try:
            for line in self._lines():
                ev = parse_auth_line(line)
                if ev:
                    out.append(ev)
        except Exception:
            pass
        return out


LINUX_AUTORUN = ["/etc/crontab", "/etc/cron.d", "/var/spool/cron", "/etc/systemd/system", "/etc/rc.local",
                 "/etc/profile.d", "/root/.bashrc"]


def _homes():
    out = ["/root"] if os.path.isdir("/root") else []
    if os.path.isdir("/home"):
        out += [os.path.join("/home", h) for h in os.listdir("/home")]
    return out


class CriticalFileCollector:
    """v1.2 — 중요 파일 변조 감시: /etc/passwd · sudoers · ld.so.preload · authorized_keys · hosts 등을
    30초마다 비교 → 바뀐 줄·추가된 파일·지워진 파일·권한 변경 (config critical_files_linux / critical_files_windows)
    "~/" 로 시작하는 항목은 /root 와 /home/* 모든 계정에 적용"""

    def __init__(self, paths):
        self.paths = [p for p in (paths or []) if p]
        self.ok = bool(self.paths)
        self.seen = self._snapshot() if self.ok else {}

    def _expand(self):
        out = []
        for p in self.paths:
            if p.startswith("~/"):
                out += [os.path.join(h, p[2:]) for h in _homes()]
            else:
                out.append(os.path.expandvars(p))
        files = []
        for p in out:
            if os.path.isdir(p):
                for root, _, names in os.walk(p):
                    files += [os.path.join(root, f) for f in names]
                    if len(files) > 2000:
                        break
            else:
                files.append(p)          # 없는 파일도 넣어 둠 → 새로 생기면 잡힘 (ld.so.preload 처럼)
        return files[:2000]

    def _snapshot(self):
        snap = {}
        for p in self._expand():
            try:
                st = os.stat(p)
            except OSError:
                snap[p] = None
                continue
            try:
                with open(p, "rb") as f:
                    body = f.read(262144)
                text = body.decode("utf-8", "ignore") if st.st_size <= 262144 else hashlib.sha256(body).hexdigest()
            except OSError:
                text = ""
            snap[p] = (text, st.st_mode & 0o7777, st.st_uid if hasattr(st, "st_uid") else 0)
        return snap

    def collect(self):
        if not self.ok:
            return []
        now = self._snapshot()
        out = []
        for p, cur in now.items():
            old = self.seen.get(p, None)
            if old == cur or (old is None and cur is None):
                continue
            ev = {"path": p, "process": "", "exe": "", "source": "integrity"}
            if cur is None:
                ev["change"] = "deleted"
            elif old is None:
                ev["change"] = "created"
                ev["value"] = cur[0][:2000]
            else:
                ev["change"] = "modified"
                prev, text = set(old[0].splitlines()), cur[0].splitlines()
                ev["value"] = "\n".join(ln for ln in text if ln.strip() and ln not in prev)[:2000]
                ev["removed"] = "\n".join(ln for ln in old[0].splitlines() if ln.strip() and ln not in set(text))[:1000]
                if old[1] != cur[1]:
                    ev["mode"] = f"{old[1]:o} → {cur[1]:o}"
                if old[2] != cur[2]:
                    ev["owner_changed"] = True
            out.append(("file", ev))
        self.seen = now
        return out


class LinuxAutorunCollector:
    """cron · systemd · authorized_keys · .bashrc · ld.so.preload 를 30초마다 비교 → 바뀐 파일과 추가된 줄"""

    def __init__(self):
        self.ok = True
        self.seen = self._snapshot()

    def _paths(self):
        out = []
        homes = [os.path.join("/home", h) for h in (os.listdir("/home") if os.path.isdir("/home") else [])]
        for p in LINUX_AUTORUN + [os.path.join(h, x) for h in homes
                                  for x in (".ssh/authorized_keys", ".bashrc", ".profile", ".config/systemd/user")]:
            if os.path.isdir(p):
                for root, _, files in os.walk(p):
                    out += [os.path.join(root, f) for f in files]
                    if len(out) > 3000:
                        break
            elif os.path.isfile(p):
                out.append(p)
        return out[:3000]

    def _snapshot(self):
        snap = {}
        for p in self._paths():
            try:
                with open(p, encoding="utf-8", errors="ignore") as f:
                    snap[p] = f.read(65536)
            except OSError:
                continue
        return snap

    def collect(self):
        now = self._snapshot()
        out = []
        for p, text in now.items():
            old = self.seen.get(p)
            if old == text:
                continue
            prev = set((old or "").splitlines())
            added = [ln for ln in text.splitlines() if ln.strip() and ln not in prev]
            out.append(("file", {"path": p, "value": "\n".join(added)[:2000], "process": "", "exe": "",
                                 "source": "poll", "new_file": old is None}))
        self.seen = now
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
    if eid == 11:
        return "file", {"pid": _hexint(data.get("ProcessId")), "process": ntpath.basename(data.get("Image", "")),
                        "exe": data.get("Image", ""), "path": data.get("TargetFilename", ""), "source": "sysmon"}
    if eid in (12, 13):
        return "registry", {"pid": _hexint(data.get("ProcessId")), "process": ntpath.basename(data.get("Image", "")),
                            "exe": data.get("Image", ""), "key": data.get("TargetObject", ""),
                            "value": data.get("Details", ""), "op": data.get("EventType", ""), "source": "sysmon"}
    if eid == 22:
        return "dns", {"query": data.get("QueryName", ""), "pid": _hexint(data.get("ProcessId")),
                       "process": ntpath.basename(data.get("Image", "")), "exe": data.get("Image", ""),
                       "result": data.get("QueryResults", "")[:300], "source": "sysmon"}
    return None


class EvtChannelCollector:
    """Windows 이벤트 채널(Sysmon · PowerShell 등)에서 새 이벤트만 읽음. 없거나 권한이 없으면 조용히 꺼짐."""
    channel, ids = "", ()

    def __init__(self):
        self.ok, self.last, self.error = False, 0, ""
        if not HAS_WIN32:
            self.error = "pywin32 없음"
            return
        try:
            h = win32evtlog.EvtQuery(self.channel,
                                     win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection, "*")
            evs = win32evtlog.EvtNext(h, 1)
            if evs:
                _, self.last, _ = parse_sysmon_xml(win32evtlog.EvtRender(evs[0], win32evtlog.EvtRenderEventXml))
            self.ok = True
        except Exception as e:
            self.error = str(e)[:120]

    def convert(self, eid, data):
        raise NotImplementedError

    def collect(self, limit=1000):
        if not self.ok:
            return []
        out = []
        cond = " or ".join(f"EventID={i}" for i in self.ids)
        try:
            h = win32evtlog.EvtQuery(self.channel, win32evtlog.EvtQueryChannelPath,
                                     f"*[System[({cond}) and EventRecordID>{self.last}]]")
            while len(out) < limit:
                evs = win32evtlog.EvtNext(h, 64)
                if not evs:
                    break
                for e in evs:
                    eid, rec, data = parse_sysmon_xml(win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml))
                    self.last = max(self.last, rec)
                    r = self.convert(eid, data)
                    if r:
                        out.append(r)
        except Exception as e:
            if "No more" not in str(e) and "259" not in str(e):
                self.error = str(e)[:120]
        return out


class SysmonCollector(EvtChannelCollector):
    """Sysmon 이벤트 1·3·11·12·13·22"""
    channel, ids = SYSMON_CHANNEL, (1, 3, 11, 12, 13, 22)

    def convert(self, eid, data):
        return sysmon_to_event(eid, data)


POWERSHELL_CHANNEL = "Microsoft-Windows-PowerShell/Operational"


def ps4104_to_event(eid, data):
    """PowerShell 4104 (스크립트 블록 기록) → 스크립트 내용 이벤트"""
    if eid != 4104 or not data.get("ScriptBlockText"):
        return None
    return "psblock", {"text": data.get("ScriptBlockText", "")[:20000], "path": data.get("Path", ""),
                       "block_id": data.get("ScriptBlockId", ""), "part": data.get("MessageNumber", ""),
                       "source": "4104"}


class PowerShellCollector(EvtChannelCollector):
    """PowerShell 스크립트 블록 기록 (enable_cmdline_audit.bat 가 켬)"""
    channel, ids = POWERSHELL_CHANNEL, (4104,)

    def convert(self, eid, data):
        return ps4104_to_event(eid, data)


# ================= 폴링 보완 (Sysmon 이 없을 때) =================
AUTORUN_KEYS = [r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce"]


class AutorunCollector:
    """Run · RunOnce 키(HKCU · HKLM)와 시작프로그램 폴더를 주기적으로 비교 → 새로 생긴 항목"""

    def __init__(self):
        self.ok = os.name == "nt"
        self.dirs = [d for d in (os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
                                 os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp"))
                     if os.path.isdir(d)] if self.ok else []
        self.seen = self._snapshot() if self.ok else {}

    def _snapshot(self):
        snap = {}
        try:
            import winreg
            for hive, hname in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
                for sub in AUTORUN_KEYS:
                    try:
                        k = winreg.OpenKey(hive, sub)
                    except OSError:
                        continue
                    i = 0
                    while True:
                        try:
                            n, v, _ = winreg.EnumValue(k, i)
                        except OSError:
                            break
                        snap[f"{hname}\\{sub}\\{n}"] = ("registry", str(v))
                        i += 1
        except Exception:
            pass
        for d in self.dirs:
            try:
                for n in os.listdir(d):
                    snap[os.path.join(d, n)] = ("file", "")
            except OSError:
                pass
        return snap

    def collect(self):
        if not self.ok:
            return []
        now = self._snapshot()
        out = []
        for k, (kind, v) in now.items():
            if self.seen.get(k) != (kind, v):
                if kind == "registry":
                    out.append(("registry", {"key": k, "value": v, "process": "", "exe": "", "source": "poll"}))
                else:
                    out.append(("file", {"path": k, "process": "", "exe": "", "source": "poll"}))
        self.seen = now
        return out


def _owner(path):
    """파일 소유자 (Linux: www-data 같은 웹 서버 계정이 만들었는지 보려고)"""
    try:
        import pwd
        return pwd.getpwuid(os.stat(path).st_uid).pw_name
    except Exception:
        return ""


class WebRootCollector:
    """웹 폴더(예: C:\\inetpub\\wwwroot)에 새로 생긴 스크립트 파일 — 만든 프로그램은 모름"""

    def __init__(self, dirs, exts):
        self.dirs = [d for d in dirs if os.path.isdir(d)]
        self.exts = tuple(e.lower() for e in exts)
        self.seen = self._snapshot()

    def _snapshot(self):
        out = set()
        for d in self.dirs:
            for root, _, files in os.walk(d):
                for f in files:
                    if f.lower().endswith(self.exts):
                        out.add(os.path.join(root, f))
                if len(out) > 50000:
                    return out
        return out

    def collect(self):
        if not self.dirs:
            return []
        now = self._snapshot()
        new = now - self.seen
        self.seen = now
        return [("file", {"path": p, "process": "", "exe": "", "source": "poll", "owner": _owner(p)})
                for p in sorted(new)[:200]]


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
    q = row.get("cs-uri-query", "-")
    if q and q != "-":
        path = f"{path}?{q}"
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
            for f in glob.glob(os.path.join(d, "**", "*"), recursive=True):
                n = os.path.basename(f).lower()
                if os.path.isfile(f) and (n.endswith(".log") or "access" in n) \
                        and not n.endswith((".gz", ".zip", ".bz2", ".xz")) and "error" not in n:
                    out.append(f)
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

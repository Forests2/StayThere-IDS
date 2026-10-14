"""룰 기반 탐지기. 반환: [(severity, rule, who, detail), ...]

규칙 목록
 [누가 침입했나]
  brute_force              5분 내 같은 계정/IP 로그인 실패 5회      HIGH
  remote_rdp_logon         외부 IP에서 RDP 로그인 성공              HIGH
  remote_network_logon     외부 IP에서 네트워크 로그인 성공          MEDIUM
  off_hours_logon          업무 시간 외 로그인                     MEDIUM
  user_created / added_to_admin_group                             HIGH
 [ARTEX 같은 AI 자동 해킹 도구]
  ioc_ip_match             공개된 ARTEX 공격 IP/포트와 연결          HIGH
  port_scan                한 IP가 짧은 시간에 여러 포트 접속        HIGH
  webserver_spawned_shell  웹/DB 서버 프로세스가 쉘 실행(웹쉘)       HIGH
  devserver_spawned_shell  python/node 가 쉘 실행                  MEDIUM
  recon_burst              정찰 명령이 짧은 시간에 몰아서 실행        HIGH
  shell_burst              같은 부모가 1분에 쉘을 다수 실행(기계 속도) MEDIUM
 [PC 안에서 도는 AI 프로그램]
  ai_program_started / ai_script_started                          MEDIUM
  ai_spawned_shell         AI 프로세스가 쉘 실행                    HIGH
  ai_api_connection        LLM API 서버 접속                       HIGH/LOW
  local_llm_server         로컬 LLM 포트 LISTEN                    LOW
"""
import ipaddress
import os
from collections import defaultdict, deque
from datetime import datetime, timedelta

BASE = os.path.dirname(os.path.abspath(__file__))


def _lower_set(xs):
    return {x.lower() for x in xs}


class RuleDetector:
    def __init__(self, cfg, now_fn=datetime.now):
        self.cfg = cfg
        self.now = now_fn
        self.ai_names = _lower_set(cfg["ai_process_names"])
        self.ai_kw = [k.lower() for k in cfg["ai_cmdline_keywords"]]
        self.ai_ports = set(cfg["ai_local_ports"])
        self.whitelist = _lower_set(cfg["process_whitelist"])
        self.trusted_ips = set(cfg["trusted_ips"])
        self.ioc_ips = set(cfg.get("ioc_ips", []))
        self.ioc_ports = set(cfg.get("ioc_ports", []))
        self.web_procs = _lower_set(cfg.get("web_server_processes", []))
        self.dev_procs = _lower_set(cfg.get("dev_server_processes", []))
        self.shells = _lower_set(cfg.get("shell_processes", []))
        self.recon = _lower_set(cfg.get("recon_commands", []))
        self.recon_cfg = cfg.get("recon_burst", {"count": 4, "window_sec": 60})
        self.scan_cfg = cfg.get("scan_burst", {"ports": 10, "window_sec": 30})
        self.shell_cfg = cfg.get("shell_burst", {"count": 10, "window_sec": 60})

        self.fail_window = defaultdict(deque)   # (계정, IP) → 실패 시각
        self.scan_window = defaultdict(deque)   # 원격 IP → (시각, 로컬포트)
        self.recon_window = deque()             # (시각, 명령, 부모)
        self.shell_window = defaultdict(deque)  # 부모 pid → 시각
        self.ai_pids = {}                       # AI로 판정된 pid → 이름
        self.api_seen = {}                      # (프로세스, 도메인) → 마지막 알림 시각
        self.browsers = _lower_set(cfg.get("browser_processes", []))
        # --- 이상한 IP 감시 ---
        self.risky_ports = set(cfg.get("risky_inbound_ports", []))
        self.bad_ports = set(cfg.get("bad_outbound_ports", [])) - self.ioc_ports
        self.lolbins = _lower_set(cfg.get("lolbin_processes", []))
        self.oscan_cfg = cfg.get("outbound_scan", {"ips": 15, "window_sec": 60})
        self.oscan = defaultdict(deque)        # pid → (시각, 원격 IP)  SYN_SENT
        self.seen_inbound = set()              # 들어온 적 있는 외부 IP
        self.susp_seen = {}                    # (규칙, 키) → 마지막 알림 (10분 중복 방지)
        self.feed_ips, self.feed_nets, self.feed_count = set(), [], 0
        self.load_feeds()
        self.auto_flags = [f.lower() for f in cfg.get("browser_automation_flags", [])]

    # ---------- 위협 목록 파일 (threat_feeds/*.txt : 한 줄에 IP 또는 CIDR, # 주석) ----------
    def load_feeds(self):
        d = self.cfg.get("threat_feed_dir", "threat_feeds")
        d = d if os.path.isabs(d) else os.path.join(BASE, d)
        ips, nets = set(), []
        try:
            os.makedirs(d, exist_ok=True)
            for n in os.listdir(d):
                if not n.lower().endswith((".txt", ".csv", ".list")):
                    continue
                with open(os.path.join(d, n), encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        t = line.split("#")[0].strip().split(",")[0].strip()
                        if not t:
                            continue
                        try:
                            if "/" in t:
                                nets.append(ipaddress.ip_network(t, strict=False))
                            else:
                                ips.add(str(ipaddress.ip_address(t)))
                        except ValueError:
                            pass
        except Exception:
            pass
        self.feed_ips, self.feed_nets, self.feed_count = ips, nets[:20000], len(ips) + len(nets)
        return self.feed_count

    def in_feed(self, ip):
        if ip in self.feed_ips:
            return True
        if self.feed_nets:
            try:
                a = ipaddress.ip_address(ip)
                return any(a in n for n in self.feed_nets)
            except ValueError:
                return False
        return False

    def _external(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
                    or a.is_reserved or a.is_unspecified) and ip not in self.trusted_ips

    def _once(self, rule, key, now, sec=600):
        last = self.susp_seen.get((rule, key))
        if last and (now - last).total_seconds() < sec:
            return False
        self.susp_seen[(rule, key)] = now
        if len(self.susp_seen) > 20000:
            self.susp_seen.clear()
        return True

    @staticmethod
    def _trim(q, now, sec, key=lambda x: x):
        while q and (now - key(q[0])).total_seconds() > sec:
            q.popleft()

    # ================= 누가 침입했나 =================
    def on_logon(self, ev):
        alerts = []
        user = ev.get("user", "?")
        ip = ev.get("src_ip", "")
        t = ev["type"]
        now = self.now()

        if ip in self.ioc_ips:
            alerts.append(("HIGH", "ioc_ip_match", user, {**ev, "ioc": "ARTEX 공격 IP"}))

        if t == "logon_fail":
            q = self.fail_window[(user, ip)]
            q.append(now)
            self._trim(q, now, 300)
            if len(q) >= 5:
                alerts.append(("HIGH", "brute_force", user,
                               {"src_ip": ip, "fails_5min": len(q)}))
                q.clear()

        if t == "logon_success":
            lt = ev.get("logon_type")
            if lt == "rdp" and ip not in self.trusted_ips:
                alerts.append(("HIGH", "remote_rdp_logon", user, ev))
            elif lt == "network" and ip and ip not in self.trusted_ips and ip != "-":
                alerts.append(("MEDIUM", "remote_network_logon", user, ev))
            wh = self.cfg["work_hours"]
            if not (wh["start"] <= now.hour < wh["end"]) and lt in ("interactive", "rdp", "unlock"):
                alerts.append(("MEDIUM", "off_hours_logon", user, ev))

        if t in ("user_created", "added_to_admin_group"):
            alerts.append(("HIGH", t, user, ev))
        return alerts

    # ================= 무엇이 실행됐나 =================
    def on_process(self, p):
        alerts = []
        now = self.now()
        name = (p.get("name") or "").lower()
        parent = (p.get("parent") or "").lower()
        cmd = (p.get("cmdline") or "").lower()
        if name in self.whitelist:
            return alerts

        # --- AI 프로그램 실행 ---
        hit_kw = [k for k in self.ai_kw if k in cmd]
        if name in self.ai_names:
            self.ai_pids[p["pid"]] = name
            alerts.append(("MEDIUM", "ai_program_started", name, p))
        elif hit_kw and name.startswith(("python", "node", "uv", "deno", "bun")):
            self.ai_pids[p["pid"]] = name
            alerts.append(("MEDIUM", "ai_script_started", name, {**p, "keywords": hit_kw}))

        # --- 브라우저 자동조종 (AI 에이전트가 브라우저를 원격 조작할 때 쓰는 옵션) ---
        if name in self.browsers:
            flags = [f for f in self.auto_flags if f in cmd]
            if flags and parent not in self.browsers:   # 브라우저 자식 프로세스(렌더러 등) 중복 제외
                self.ai_pids[p["pid"]] = name
                alerts.append(("MEDIUM", "browser_automation", f"{parent} → {name}",
                               {**p, "flags": flags}))

        is_shell = name in self.shells
        is_recon = name in self.recon
        parent_is_ai = p.get("ppid") in self.ai_pids

        # --- 부모가 쉘을 띄움 ---
        if is_shell or is_recon:
            if parent_is_ai:
                alerts.append(("HIGH", "ai_spawned_shell", f"{parent} → {name}", p))
            elif parent in self.web_procs:
                alerts.append(("HIGH", "webserver_spawned_shell", f"{parent} → {name}", p))
            elif parent in self.dev_procs:
                alerts.append(("MEDIUM", "devserver_spawned_shell", f"{parent} → {name}", p))

        # --- 같은 부모가 기계 속도로 쉘 실행 ---
        if is_shell:
            q = self.shell_window[p.get("ppid")]
            q.append(now)
            self._trim(q, now, self.shell_cfg["window_sec"])
            if len(q) >= self.shell_cfg["count"]:
                alerts.append(("MEDIUM", "shell_burst", parent,
                               {"ppid": p.get("ppid"), "count": len(q),
                                "window_sec": self.shell_cfg["window_sec"]}))
                q.clear()

        # --- 정찰 명령 몰아서 실행 (cmd /c whoami 처럼 부모가 매번 달라도 잡도록 PC 전체 기준) ---
        if is_recon:
            self.recon_window.append((now, name, parent))
            self._trim(self.recon_window, now, self.recon_cfg["window_sec"], key=lambda x: x[0])
            distinct = sorted({x[1] for x in self.recon_window})
            if len(distinct) >= self.recon_cfg["count"]:
                alerts.append(("HIGH", "recon_burst", ", ".join(sorted({x[2] for x in self.recon_window})),
                               {"commands": distinct, "window_sec": self.recon_cfg["window_sec"]}))
                self.recon_window.clear()

        # AI 로 판정된 프로세스의 자식도 AI 로 추적 (크롬 네트워크 서비스 등은 자식 프로세스가 통신함)
        if parent_is_ai and p["pid"] not in self.ai_pids:
            self.ai_pids[p["pid"]] = name
        if len(self.ai_pids) > 5000:   # 오래 켜 둬도 메모리 안 늘도록
            self.ai_pids = dict(list(self.ai_pids.items())[-2000:])
        return alerts

    # ================= 어디와 통신했나 =================
    def on_network(self, n):
        alerts = []
        now = self.now()
        proc = n.get("process", "")
        rip = n.get("raddr_ip", "")

        # --- ARTEX 공개 IOC ---
        if rip and rip in self.ioc_ips:
            alerts.append(("HIGH", "ioc_ip_match", proc or rip,
                           {**n, "ioc": "ARTEX 공격 IP"}))
        elif n["kind"] == "outbound" and n.get("raddr_port") in self.ioc_ports:
            alerts.append(("HIGH", "ioc_ip_match", proc or rip,
                           {**n, "ioc": "ARTEX 포트"}))

        # --- 포트 스캔: 같은 IP가 여러 포트로 들어옴 ---
        if n["kind"] == "inbound" and rip and rip not in self.trusted_ips:
            q = self.scan_window[rip]
            q.append((now, n.get("lport")))
            self._trim(q, now, self.scan_cfg["window_sec"], key=lambda x: x[0])
            ports = {x[1] for x in q}
            if len(ports) >= self.scan_cfg["ports"]:
                alerts.append(("HIGH", "port_scan", rip,
                               {"ports": sorted(ports), "window_sec": self.scan_cfg["window_sec"]}))
                q.clear()

        # --- LLM API 접속 (같은 프로세스·도메인은 1시간에 한 번만) ---
        if n["kind"] == "outbound" and n.get("ai_domain"):
            key = (proc.lower(), n["ai_domain"])
            last = self.api_seen.get(key)
            if last is None or (now - last).total_seconds() > 3600:
                self.api_seen[key] = now
                pl = proc.lower()
                if n.get("pid") in self.ai_pids:            # 자동조종 브라우저 / AI 스크립트
                    alerts.append(("HIGH", "ai_api_connection", proc, n))
                elif pl in self.browsers:                   # 사람이 브라우저로 AI 사이트 사용
                    alerts.append(("LOW", "ai_web_usage", proc, n))
                elif pl in self.ai_names or pl in self.whitelist:   # 등록된 AI 앱 / 허용 목록
                    alerts.append(("LOW", "ai_api_connection", proc, n))
                else:                                       # 목록에 없는 프로그램
                    alerts.append(("HIGH", "ai_api_connection", proc, n))

        # ================= 이상한 IP 감시 =================
        ext = bool(rip) and self._external(rip)
        pl = proc.lower()
        if rip and self.in_feed(rip) and self._once("threat_feed_match", rip, now):
            alerts.append(("HIGH", "threat_feed_match", proc or rip, {**n, "feed": "위협 목록 파일"}))
        if n["kind"] == "inbound" and ext:
            if n.get("lport") in self.risky_ports and n.get("state") == "ESTABLISHED" \
                    and self._once("risky_port_inbound", rip, now):
                alerts.append(("MEDIUM", "risky_port_inbound", rip, n))
            if rip not in self.seen_inbound:
                self.seen_inbound.add(rip)
                alerts.append(("LOW", "new_inbound_ip", rip, n))
        if n["kind"] == "outbound" and ext:
            if pl in self.lolbins and self._once("lolbin_outbound", (pl, rip), now):
                alerts.append(("HIGH", "lolbin_outbound", f"{proc} → {rip}", n))
            if n.get("raddr_port") in self.bad_ports and self._once("odd_port_outbound", (rip, n.get("raddr_port")), now):
                alerts.append(("MEDIUM", "odd_port_outbound", f"{proc or '?'} → {rip}:{n.get('raddr_port')}", n))
        if n["kind"] == "outbound" and n.get("state") == "SYN_SENT" and rip:
            q = self.oscan[n.get("pid")]
            q.append((now, rip))
            self._trim(q, now, self.oscan_cfg["window_sec"], key=lambda x: x[0])
            ips = {x[1] for x in q}
            if len(ips) >= self.oscan_cfg["ips"]:
                alerts.append(("HIGH", "outbound_scan", proc or f"pid {n.get('pid')}",
                               {"pid": n.get("pid"), "process": proc, "targets": sorted(ips)[:30],
                                "count": len(ips), "window_sec": self.oscan_cfg["window_sec"]}))
                q.clear()

        # --- 로컬 LLM 서버 ---
        if n["kind"] == "listen" and n.get("lport") in self.ai_ports:
            alerts.append(("LOW", "local_llm_server", proc, n))
        return alerts

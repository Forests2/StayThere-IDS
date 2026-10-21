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
 [2026-10 개선 — ARTEX 원본·한국어판(artex-ko) · 실제 AI 에이전트 침입 사례]
  artex_host_artifact      ARTEX 실행 파일·콘솔·설정 흔적           HIGH
  artex_user_agent         웹 로그에 ARTEX 정찰 User-Agent           HIGH   (on_weblog)
  js_asset_burst           한 IP가 JS 파일 대량 요청                MEDIUM (on_weblog)
  ioc_domain_query         공격 중계 도메인 DNS 조회                HIGH   (on_dns, Sysmon 22)
  agent_command_style      기계 형식 명령이 몰려서 실행              HIGH
  local_agent_command      내 AI 도구가 기계 형식 명령 실행          LOW (기록만)
  retry_loop               실패-수정-재실행 반복                    MEDIUM
  credential_dump          SAM/SYSTEM 저장 · LSASS 덤프             HIGH
  privilege_escalation     Potato 계열 · SeImpersonate 확인         HIGH
  payload_staging          certutil 디코드 · 조각 합치기 · Public 실행 HIGH
  distributed_ips          여러 외부 IP가 같은 위험 포트로           HIGH
  dev_tool_inbound         외부 IP → Jupyter/Ollama 등 포트          HIGH
  dev_tool_exposed         AI 개발 도구 포트가 외부에 열림            MEDIUM (기록)
 [v1.1 · 2026-10-21 — 금융권 공격 유형 · LLM 을 부르는 악성코드 · AI 코딩 에이전트 공격 · 랜섬웨어 · 공급망]
  webshell_file_created    웹 서버가 웹 폴더에 스크립트 파일 생성     HIGH (만든 프로그램 모르면 MEDIUM)
  object_enumeration       웹 로그: 값만 바꾼 요청이 몰림(고객번호 열거) HIGH   (on_weblog)
  log_theft                웹 서버 아래에서 로그 폴더 압축·복사        HIGH
  llm_malware_pattern      스크립트 호스트·Office 가 LLM API 접속      HIGH
  llm_then_exec            LLM API 접속 직후 같은 프로그램이 셸 실행    HIGH
  autorun_change           Run 키 · 시작프로그램에 수상한 항목 추가     MEDIUM/HIGH
  ransomware_prep          백업·복구 수단 삭제 (vssadmin · wbadmin · bcdedit) HIGH
  mass_file_change         한 프로그램이 1분 안에 문서 뒤에 낯선 확장자를 붙인 파일 대량 생성 HIGH
  git_spawned_unusual      git 이 셸·스크립트 호스트를 실행 (GitSpawn)  HIGH (훅 경유 MEDIUM)
  package_install_exec     npm·pip 설치 중 다운로드·인코딩 명령         HIGH
  agent_secret_access      AI 도구가 아닌 프로그램이 AI 토큰·MCP 설정 접근 HIGH
"""
import difflib
import ipaddress
import os
import re
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
        # --- 2026-10 개선: ARTEX 원본·한국어판 + AI 에이전트 행동 ---
        self.artex_names = _lower_set(cfg.get("artex_process_names", []))
        self.artex_kw = [k.lower() for k in cfg.get("artex_host_keywords", [])]
        self.artex_ua = {u.lower() for u in cfg.get("artex_user_agents", [])}
        self.ioc_domains = [d.lower() for d in cfg.get("ioc_domains", [])]
        self.markers = [m.lower() for m in cfg.get("agent_command_markers", [])]
        self.agent_cfg = cfg.get("agent_burst", {"count": 3, "window_sec": 120, "min_markers": 2})
        self.retry_cfg = cfg.get("retry_burst", {"count": 3, "window_sec": 120, "similarity": 0.8})
        self.cred_pat = [x.lower() for x in cfg.get("credential_dump_patterns", [])]
        self.privesc_tools = [x.lower() for x in cfg.get("privesc_tools", [])]
        self.privesc_kw = [x.lower() for x in cfg.get("privesc_keywords", [])]
        self.staging_pat = [x.lower() for x in cfg.get("staging_patterns", [])]
        self.staging_dirs = [x.lower() for x in cfg.get("staging_dirs", [])]
        self.dist_cfg = cfg.get("distributed_ips", {"ips": 3, "window_sec": 120})
        self.dev_ports = {int(k): v for k, v in cfg.get("dev_tool_ports", {}).items()}
        self.js_cfg = cfg.get("js_burst", {"distinct_js": 30, "window_sec": 60})
        self.agent_window = deque()            # (시각, 명령줄, pid) 기계 형식 명령
        self.cmd_window = deque()              # (시각, 정규화 명령줄) 재시도 판단용
        self.dist_window = defaultdict(deque)  # 로컬 포트 → (시각, 외부 IP)
        self.js_window = defaultdict(deque)    # 웹 로그 출발지 IP → (시각, 경로)
        # --- v1.1 ---
        L = lambda k: [x.lower() for x in cfg.get(k, [])]
        self.web_markers, self.web_ext = L("web_root_markers"), tuple(L("web_script_ext"))
        self.enum_cfg = cfg.get("enum_burst", {"distinct": 30, "window_sec": 60})
        self.static_ext = tuple(L("static_ext"))
        self.log_markers, self.archive_markers = L("log_markers"), L("archive_markers")
        self.script_hosts, self.office = set(L("script_hosts")), set(L("office_processes"))
        self.llm_window = cfg.get("llm_exec_window_sec", 15)
        self.autorun_markers, self.sus_autorun = L("autorun_markers"), L("suspicious_autorun_values")
        self.ransom_pat = L("ransomware_patterns")
        self.mass_cfg = cfg.get("mass_file", {"files": 100, "window_sec": 60, "share": 0.6})
        self.common_ext = set(L("common_ext"))
        self.doc_ext = set(L("doc_ext"))
        self.pkg_markers, self.dl_markers = L("package_install_markers"), L("download_markers")
        self.git_sus = set(L("git_suspicious_children"))
        self.secret_markers, self.secret_allow = L("secret_markers"), set(L("secret_readers_allow"))
        self.exfil_verbs = L("exfil_verbs")
        self.ai_domains_l = [d.lower() for d in cfg.get("ai_api_domains", [])]
        self.web_shell_allow = L("webserver_shell_allow")
        self.git_child_allow = L("git_child_allow")
        self.automation_allow = L("automation_allow")
        self.web_users = set(L("web_server_users"))
        self.proc_cache = {}                   # pid → {name, parent, chain(조상 이름), exe}
        self.llm_seen = {}                     # pid → LLM API 에 접속한 시각
        self.enum_window = defaultdict(deque)  # (IP, 정규화 경로) → (시각, 원래 경로)
        self.file_window = defaultdict(deque)  # pid → (시각, 확장자)

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

    def _external_or_any(self, ip):
        """원격 로그인 경보 대상인가 — 기본은 외부 IP 만. config remote_logon_alert_internal=true 면 내부망 IP 도"""
        return self.cfg.get("remote_logon_alert_internal", False) or self._external(ip)

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

    # ---------- 명령줄 분석 도우미 ----------
    def agent_markers(self, cmd):
        """기계가 읽기 쉬운 출력 형식 표시 (AI 에이전트가 결과를 파싱하려고 붙이는 것들)"""
        found = [m for m in self.markers if m in cmd]
        chained = len(re.findall(r"&&|\|\||(?<![&|>])&(?![&>])|;", cmd))
        if chained >= 3:
            found.append(f"명령 {chained + 1}개 연결")
        return found

    def local_ai_tree(self, p):
        """이 프로세스가 내가 쓰는 AI 도구(Claude Code·Cursor 등) 아래에서 실행됐나"""
        if p.get("ppid") in self.ai_pids or p.get("pid") in self.ai_pids:
            return True
        for anc in p.get("ancestors") or []:
            n = (anc.get("name") or "").lower()
            c = (anc.get("cmdline") or "").lower()
            if n in self.ai_names or n in self.whitelist:
                return True
            if n.startswith(("python", "node", "uv", "deno", "bun")) and any(k in c for k in self.ai_kw):
                return True
        return False

    def trusted_automation(self, p):
        """회사에서 쓰는 관리 자동화(ansible · 모니터링 에이전트 등) 아래에서 실행됐나 — config automation_allow"""
        if not self.automation_allow:
            return False
        text = " ".join([(p.get("parent") or "").lower()] +
                        [((a.get("name") or "") + " " + (a.get("cmdline") or "")).lower() for a in p.get("ancestors") or []])
        return any(a in text for a in self.automation_allow)

    @staticmethod
    def _norm_cmd(cmd):
        return re.sub(r"\s+", " ", re.sub(r"\d{3,}", "#", cmd)).strip()[:400]

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
            if (lt == "rdp" and ip not in self.trusted_ips) or \
                    (lt == "ssh" and ip and ip not in self.trusted_ips and self._external_or_any(ip)):
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
            elif parent in self.web_procs and not any(a in cmd for a in self.web_shell_allow):
                alerts.append(("HIGH", "webserver_spawned_shell", f"{parent} → {name}", p))
            elif parent in self.dev_procs and not self.trusted_automation(p):
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
        if is_recon and not self.trusted_automation(p):
            self.recon_window.append((now, name, parent))
            self._trim(self.recon_window, now, self.recon_cfg["window_sec"], key=lambda x: x[0])
            distinct = sorted({x[1] for x in self.recon_window})
            if len(distinct) >= self.recon_cfg["count"]:
                alerts.append(("HIGH", "recon_burst", ", ".join(sorted({x[2] for x in self.recon_window})),
                               {"commands": distinct, "window_sec": self.recon_cfg["window_sec"]}))
                self.recon_window.clear()

        alerts += self._process_2026(p, name, parent, cmd, now, is_shell or is_recon)
        alerts += self._process_v11(p, name, parent, cmd, now, is_shell or is_recon)

        # AI 로 판정된 프로세스의 자식도 AI 로 추적 (크롬 네트워크 서비스 등은 자식 프로세스가 통신함)
        if parent_is_ai and p["pid"] not in self.ai_pids:
            self.ai_pids[p["pid"]] = name
        if len(self.ai_pids) > 5000:   # 오래 켜 둬도 메모리 안 늘도록
            self.ai_pids = dict(list(self.ai_pids.items())[-2000:])
        return alerts

    def _process_2026(self, p, name, parent, cmd, now, shellish):
        """ARTEX 호스트 흔적 · AI 에이전트 행동 · 권한 상승 · 파일 반입"""
        alerts = []
        exe = (p.get("exe") or "").lower()
        base = name[:-4] if name.endswith(".exe") else name
        local_ai = self.local_ai_tree(p) or self.trusted_automation(p)

        # --- ARTEX(원본·한국어판) 설치·실행 흔적 ---
        kw = [k for k in self.artex_kw if k in cmd or k in exe]
        if (name in self.artex_names or base in self.artex_names or kw) and self._once("artex_host_artifact", p.get("pid"), now):
            alerts.append(("HIGH", "artex_host_artifact", name or "?",
                           {**p, "keywords": kw or [name]}))

        # --- 계정 정보 탈취 ---
        hit = [x for x in self.cred_pat if x in cmd]
        if hit or ("lsass" in cmd and ("minidump" in cmd or "-ma " in cmd)):
            alerts.append(("HIGH", "credential_dump", f"{parent} → {name}", {**p, "patterns": hit or ["lsass dump"]}))

        # --- 권한 상승 ---
        tools = [t for t in self.privesc_tools if t in name or t in cmd or t in exe]
        kws = [k for k in self.privesc_kw if k in cmd]
        if tools:
            alerts.append(("HIGH", "privilege_escalation", f"{parent} → {name}", {**p, "tools": tools}))
        elif kws and not local_ai and self._once("privilege_escalation", (p.get("ppid"), kws[0]), now, 120):
            alerts.append(("HIGH" if "seimpersonateprivilege" in kws else "MEDIUM", "privilege_escalation",
                           f"{parent} → {name}", {**p, "keywords": kws}))

        # --- 공격 파일 반입 (certutil 디코드, .b64, 조각 합치기, Public·Temp 폴더 실행) ---
        why = [x for x in self.staging_pat if x in cmd]
        if re.search(r"copy\s+/b\s+\S+\+\S+", cmd):
            why.append("조각 파일 합치기 (copy /b a+b)")
        par_risky = parent in self.shells or parent in self.web_procs or parent in self.dev_procs or parent in self.recon
        if exe and any(d in exe for d in self.staging_dirs) and par_risky:
            why.append(f"{p.get('exe')} 실행")
        if why:   # 내 AI 도구 아래에서도 공격 파일 반입은 경보
            alerts.append(("HIGH", "payload_staging", f"{parent} → {name}", {**p, "reasons": why}))

        # --- 기계 형식 명령 (AI 에이전트) ---
        if shellish or name in self.lolbins or name in self.shells:
            mk = self.agent_markers(cmd)
            if len(mk) >= self.agent_cfg["min_markers"]:
                if local_ai:
                    if self._once("local_agent_command", p.get("ppid"), now, 600):
                        alerts.append(("LOW", "local_agent_command", f"{parent} → {name}", {**p, "markers": mk}))
                else:
                    self.agent_window.append((now, cmd[:300], p.get("pid")))
                    self._trim(self.agent_window, now, self.agent_cfg["window_sec"], key=lambda x: x[0])
                    if len(self.agent_window) >= self.agent_cfg["count"]:
                        ts = [x[0] for x in self.agent_window]
                        gaps = sorted((b - a).total_seconds() for a, b in zip(ts, ts[1:]))
                        alerts.append(("HIGH", "agent_command_style", f"{parent} → {name}",
                                       {**p, "markers": mk, "count": len(self.agent_window),
                                        "window_sec": self.agent_cfg["window_sec"],
                                        "median_gap": round(gaps[len(gaps) // 2], 1) if gaps else None,
                                        "samples": [x[1] for x in self.agent_window][-3:]}))
                        self.agent_window.clear()

            # --- 실패 → 조금 고쳐서 재실행 반복 ---
            if not local_ai and len(cmd) >= 12:
                nc = self._norm_cmd(cmd)
                self._trim(self.cmd_window, now, self.retry_cfg["window_sec"], key=lambda x: x[0])
                near = [c for _, c in self.cmd_window
                        if c != nc and difflib.SequenceMatcher(None, c, nc).ratio() >= self.retry_cfg["similarity"]]
                self.cmd_window.append((now, nc))
                if len(near) + 1 >= self.retry_cfg["count"] and self._once("retry_loop", nc[:60], now, 300):
                    alerts.append(("MEDIUM", "retry_loop", f"{parent} → {name}",
                                   {**p, "variants": len(near) + 1, "window_sec": self.retry_cfg["window_sec"],
                                    "samples": near[-2:] + [nc]}))
        return alerts

    # ================= v1.1 — 프로세스 =================
    def _chain(self, p):
        """[이름, 부모, 조부모…] (소문자)"""
        out = [(p.get("name") or "").lower(), (p.get("parent") or "").lower()]
        out += [(a.get("name") or "").lower() for a in p.get("ancestors") or []]
        return [x for x in out if x]

    def _process_v11(self, p, name, parent, cmd, now, shellish):
        alerts = []
        chain = self._chain(p)
        anc_cmds = " ".join((a.get("cmdline") or "").lower() for a in p.get("ancestors") or [])
        exe = (p.get("exe") or "").lower()
        local_ai = self.local_ai_tree(p)
        self.proc_cache[p.get("pid")] = {"name": name, "parent": parent, "chain": chain, "exe": exe}
        if len(self.proc_cache) > 20000:
            self.proc_cache = dict(list(self.proc_cache.items())[-10000:])
        shell_like = shellish or name in self.shells or name in self.lolbins or name in self.script_hosts

        # --- 랜섬웨어 준비: 백업·복구 수단 삭제 ---
        hit = [x for x in self.ransom_pat if x in cmd]
        if hit:
            alerts.append(("HIGH", "ransomware_prep", f"{parent} → {name}", {**p, "patterns": hit}))

        # --- 웹 서버 아래에서 로그 폴더 압축·복사 (금융권 공격 유형 ③) ---
        under_web = any(x in self.web_procs for x in chain[1:])
        if under_web and any(m in cmd for m in self.log_markers) and any(a in cmd for a in self.archive_markers):
            alerts.append(("HIGH", "log_theft", f"{parent} → {name}", {**p, "web_parent": next(x for x in chain[1:] if x in self.web_procs)}))

        # --- LLM 접속 직후 같은 프로그램(또는 그 조상)이 셸 실행 (PROMPTSTEAL 방식) ---
        if shell_like and not local_ai and self.llm_seen:
            pids = [p.get("ppid")] + [a.get("pid") for a in p.get("ancestors") or []]
            src = next((x for x in pids if x in self.llm_seen and (now - self.llm_seen[x]).total_seconds() <= self.llm_window), None)
            if src is not None:
                info = self.proc_cache.get(src, {})
                alerts.append(("HIGH", "llm_then_exec", f"{info.get('name') or src} → {name}",
                               {**p, "llm_pid": src, "llm_process": info.get("name"),
                                "after_sec": round((now - self.llm_seen[src]).total_seconds(), 1)}))

        # --- git 이 셸·스크립트 호스트 실행 (GitSpawn: .git/config 로 실행) — 내 AI 도구 아래여도 경보 ---
        if parent in ("git.exe", "git") and (name in self.git_sus or any(d in exe for d in self.staging_dirs)) \
                and not any(a in cmd for a in self.git_child_allow):
            alerts.append(("HIGH", "git_spawned_unusual", f"git.exe → {name}", p))
        elif parent in ("sh.exe", "bash.exe") and "git.exe" in chain[2:4] and name in self.git_sus \
                and not any(a in cmd for a in self.git_child_allow):
            alerts.append(("MEDIUM", "git_spawned_unusual", f"git → {parent} → {name}", {**p, "via_hook": True}))

        # --- 패키지 설치 중 다운로드·인코딩 명령 (공급망) ---
        if any(m in anc_cmds for m in self.pkg_markers) and any(m in cmd for m in self.dl_markers):
            alerts.append(("HIGH", "package_install_exec", f"{parent} → {name}",
                           {**p, "installer": next(m for m in self.pkg_markers if m in anc_cmds).strip(),
                            "markers": [m.strip() for m in self.dl_markers if m in cmd][:3]}))

        # --- AI 도구 토큰 · MCP 설정을 읽어 가는 명령 (인포스틸러) ---
        sec = [m for m in self.secret_markers if m in cmd]
        if sec and not local_ai and name not in self.secret_allow and name not in self.ai_names \
                and any(v in cmd for v in self.exfil_verbs):
            alerts.append(("HIGH", "agent_secret_access", f"{parent} → {name}", {**p, "targets": sec}))
        return alerts

    # ================= v1.1 — 파일 (Sysmon 11 · 폴링) =================
    def on_file(self, f):
        alerts = []
        now = self.now()
        path = (f.get("path") or "").lower()
        proc = (f.get("process") or "").lower()
        exe = (f.get("exe") or "").lower()
        # 웹쉘: 웹 폴더에 스크립트 파일
        if path.endswith(self.web_ext) and any(m in path for m in self.web_markers):
            creator_web = proc in self.web_procs or proc in self.shells or proc in self.script_hosts \
                or any(d in exe for d in self.staging_dirs)
            if creator_web:
                alerts.append(("HIGH", "webshell_file_created", f"{f.get('process')} → {f.get('path')}", f))
            elif not proc and (f.get("owner") or "").lower() in self.web_users:   # Linux: 웹 서버 계정이 만든 파일
                alerts.append(("HIGH", "webshell_file_created", f"{f.get('owner')} → {f.get('path')}",
                               {**f, "creator": f"웹 서버 계정 {f.get('owner')}"}))
            elif not proc and not f.get("owner"):   # 폴링으로 발견 · 만든 프로그램 · 소유자 모름 (Windows)
                alerts.append(("MEDIUM", "webshell_file_created", f.get("path"), {**f, "creator": "미상"}))
        # 시작프로그램 폴더
        if any(m in path for m in self.autorun_markers):
            alerts += self._autorun(f, path + " " + (f.get("value") or "").lower(), proc, exe, f.get("path"))
        # 대량 파일 생성 (랜섬웨어 암호화 흔적) — 문서 확장자 뒤에 낯선 확장자가 붙은 파일 (report.docx.lock 같은)
        if proc and ("\\users\\" in path or path.startswith("/home/")) and f.get("pid"):
            base, ext = os.path.splitext(path)
            inner = os.path.splitext(base)[1]
            if inner in self.doc_ext and ext and ext not in self.common_ext and ext not in self.doc_ext:
                q = self.file_window[f.get("pid")]
                q.append((now, ext))
                self._trim(q, now, self.mass_cfg["window_sec"], key=lambda x: x[0])
                if len(q) >= self.mass_cfg["files"]:
                    cnt = defaultdict(int)
                    for _, e in q:
                        cnt[e] += 1
                    top, n = max(cnt.items(), key=lambda x: x[1])
                    if n / len(q) >= self.mass_cfg["share"] and self._once("mass_file_change", f.get("pid"), now):
                        alerts.append(("HIGH", "mass_file_change", f.get("process"),
                                       {"pid": f.get("pid"), "process": f.get("process"), "exe": f.get("exe"), "ext": top,
                                        "count": len(q), "window_sec": self.mass_cfg["window_sec"],
                                        "sample": f.get("path")}))
                        q.clear()
        return alerts

    # ================= v1.1 — 레지스트리 (Sysmon 12·13 · 폴링) =================
    def on_registry(self, r):
        key = (r.get("key") or "").lower()
        if not any(m in key for m in self.autorun_markers):
            return []
        return self._autorun(r, key + " " + (r.get("value") or "").lower(), (r.get("process") or "").lower(),
                             (r.get("exe") or "").lower(), r.get("key"))

    def _autorun(self, ev, text, proc, exe, where):
        """자동 실행 등록 — 값이 스크립트·Temp·Public 을 가리키거나, 셸·스크립트 호스트가 등록하면 경보"""
        sus = [m for m in self.sus_autorun if m in text]
        writer_bad = proc in self.shells or proc in self.script_hosts or proc in self.lolbins \
            or any(d in exe for d in self.staging_dirs)
        if not (sus or writer_bad):
            return []
        sev = "HIGH" if (sus and writer_bad) else "MEDIUM"
        if not self._once("autorun_change", where, self.now(), 3600):
            return []
        return [(sev, "autorun_change", f"{ev.get('process') or '프로그램 미상'} → {where}",
                 {**ev, "reasons": sus[:4] + (["셸·스크립트가 등록"] if writer_bad else [])})]

    # ================= v1.1 — PowerShell 스크립트 블록 (4104) =================
    def on_script(self, b):
        """스크립트 내용에 계정 탈취 · 파일 반입 · 랜섬웨어 준비 · LLM API 호출이 있는지"""
        text = (b.get("text") or "").lower()
        alerts, now = [], self.now()
        key = b.get("block_id") or text[:80]
        checks = [("credential_dump", [x for x in self.cred_pat if x in text]),
                  ("ransomware_prep", [x for x in self.ransom_pat if x in text]),
                  ("payload_staging", [x for x in self.staging_pat if x in text and x != ".b64"]),
                  ("llm_malware_pattern", [d for d in self.ai_domains_l if d in text]
                   if any(w in text for w in ("invoke-webrequest", "invoke-restmethod", "iwr ", "irm ", "webclient", "httpclient"))
                   else [])]
        for rule, hit in checks:
            if hit and self._once(rule, (key, rule), now):
                alerts.append(("HIGH", rule, "PowerShell 스크립트", {**b, "text": b.get("text", "")[:500],
                                                                    "patterns": hit[:4], "via": "4104"}))
        return alerts

    # ================= v1.1 — 파일 접근 감사 (4663) =================
    def on_object_access(self, o):
        obj = (o.get("object") or "").lower()
        proc = (o.get("process") or "").lower()
        sec = [m for m in self.secret_markers if m in obj]
        if not sec or proc in self.secret_allow or proc in self.ai_names or proc in self.whitelist:
            return []
        if not self._once("agent_secret_access", (proc, obj), self.now(), 3600):
            return []
        return [("HIGH", "agent_secret_access", f"{o.get('process')} → {o.get('object')}", {**o, "targets": sec})]

    def _llm_owner(self, pid, proc, now, ev):
        """LLM API 에 접속한 프로그램 기록 + 스크립트 호스트 · Office 계열이면 경보 (PROMPTSTEAL · PROMPTFLUX 방식)"""
        pl = (proc or "").lower()
        if pl in self.browsers:
            return []
        if pid:
            self.llm_seen[pid] = now
            if len(self.llm_seen) > 5000:
                self.llm_seen = dict(list(self.llm_seen.items())[-2000:])
        info = self.proc_cache.get(pid, {})
        chain = [pl] + info.get("chain", [])[1:]
        bad = [x for x in chain if x in self.script_hosts or x in self.office]
        if bad and self._once("llm_malware_pattern", pid or pl, now):
            return [("HIGH", "llm_malware_pattern", f"{proc} ({' ← '.join(chain[:3])})",
                     {**ev, "chain": chain[:5], "why": bad[0]})]
        return []

    # ================= 웹 서버 로그 (웹 서버가 있는 PC) =================
    def on_weblog(self, w):
        """w = {src_ip, ua, path, status, time}"""
        alerts = []
        now = self.now()
        ip, ua = w.get("src_ip", ""), (w.get("ua") or "").lower()
        if ip in self.trusted_ips:
            return alerts
        if ua in self.artex_ua and self._once("artex_user_agent", (ip, ua), now):
            alerts.append(("HIGH", "artex_user_agent", ip, {**w, "raddr_ip": ip}))
        full = (w.get("path") or "")
        path = full.lower().split("?")[0]
        # --- 값만 바꾼 요청이 몰림 (고객번호 열거 · 금융권 공격 유형 ①) ---
        if not path.endswith(self.static_ext):
            norm = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\d{3,}", "#", full.lower())
            norm = re.sub(r"=([^&]*)", lambda m: "=#" if re.search(r"\d", m.group(1)) else m.group(0), norm)
            if "#" in norm:
                q = self.enum_window[(ip, norm)]
                q.append((now, full))
                self._trim(q, now, self.enum_cfg["window_sec"], key=lambda x: x[0])
                n = len({x[1] for x in q})
                if n >= self.enum_cfg["distinct"] and self._once("object_enumeration", (ip, norm), now):
                    alerts.append(("HIGH", "object_enumeration", ip,
                                   {"raddr_ip": ip, "pattern": norm[:120], "count": n, "window_sec": self.enum_cfg["window_sec"],
                                    "samples": [x[1] for x in list(q)[-3:]], "ua": w.get("ua")}))
                    q.clear()
        if path.endswith(".js"):
            q = self.js_window[ip]
            q.append((now, path))
            self._trim(q, now, self.js_cfg["window_sec"], key=lambda x: x[0])
            n = len({x[1] for x in q})
            if n >= self.js_cfg["distinct_js"] and self._once("js_asset_burst", ip, now):
                alerts.append(("MEDIUM", "js_asset_burst", ip,
                               {"raddr_ip": ip, "count": n, "window_sec": self.js_cfg["window_sec"], "ua": w.get("ua")}))
                q.clear()
        return alerts

    # ================= DNS 조회 (Sysmon 이벤트 22) =================
    def on_dns(self, q):
        alerts = []
        name = (q.get("query") or "").lower().rstrip(".")
        hit = next((d for d in self.ioc_domains if name == d or name.endswith("." + d)), None)
        if hit and self._once("ioc_domain_query", (q.get("process"), hit), self.now()):
            alerts.append(("HIGH", "ioc_domain_query", q.get("process") or "?", {**q, "ioc": hit}))
        ai = next((d for d in self.ai_domains_l if name == d or name.endswith("." + d)), None)
        if ai:
            alerts += self._llm_owner(q.get("pid"), q.get("process"), self.now(), {**q, "ai_domain": ai})
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
            alerts += self._llm_owner(n.get("pid"), proc, now, n)
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

        # --- IP 를 바꿔 가며 같은 위험 포트로 (분산 IP 공격) ---
        if n["kind"] == "inbound" and ext and n.get("lport") in self.risky_ports | set(self.dev_ports):
            q = self.dist_window[n.get("lport")]
            q.append((now, rip))
            self._trim(q, now, self.dist_cfg["window_sec"], key=lambda x: x[0])
            ips = sorted({x[1] for x in q})
            if len(ips) >= self.dist_cfg["ips"]:
                alerts.append(("HIGH", "distributed_ips", f"IP {len(ips)}개 → :{n.get('lport')}",
                               {"ips": ips, "lport": n.get("lport"), "window_sec": self.dist_cfg["window_sec"],
                                "process": proc, "raddr_ip": ips[-1]}))
                q.clear()

        # --- AI 개발 도구(Jupyter·Ollama 등) ---
        if n["kind"] == "inbound" and ext and n.get("lport") in self.dev_ports \
                and self._once("dev_tool_inbound", rip, now):
            alerts.append(("HIGH", "dev_tool_inbound", rip, {**n, "tool": self.dev_ports[n.get("lport")]}))
        if n["kind"] == "listen" and n.get("lport") in self.dev_ports:
            lip = (n.get("laddr") or "").rsplit(":", 1)[0].strip("[]")
            if lip and not (lip.startswith("127.") or lip == "::1") and self._once("dev_tool_exposed", n.get("lport"), now, 86400):
                alerts.append(("MEDIUM", "dev_tool_exposed", proc or f":{n.get('lport')}",
                               {**n, "tool": self.dev_ports[n.get("lport")]}))
        # --- ARTEX 콘솔이 이 PC에서 열림 (8787 은 단독 근거로 안 씀: 이름이 artex 일 때만) ---
        if n["kind"] == "listen" and pl and (pl in self.artex_names or pl.replace(".exe", "") in self.artex_names) \
                and self._once("artex_host_artifact", ("listen", n.get("lport")), now):
            alerts.append(("HIGH", "artex_host_artifact", proc, {**n, "keywords": [f"{proc} 가 :{n.get('lport')} 열고 대기"]}))

        # --- 로컬 LLM 서버 ---
        if n["kind"] == "listen" and n.get("lport") in self.ai_ports:
            alerts.append(("LOW", "local_llm_server", proc, n))
        return alerts

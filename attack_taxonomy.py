"""DDS 탐지 규칙 ↔ AIPFL-IDS 공격 분류 연결표

참고: https://github.com/PrathamWankhade/AIPFL-IDS (MIT)
 - NF-ToN-IoT-V2 라벨(Attack 컬럼, 10종):
     Benign, DDoS, DoS, Injection, Ransomware, Scanning, XSS, Backdoor, Password, MITM
 - CICIoT2023 라벨(34종 → 10종, train.py CICIOT_CLASS_MAP):
     DDOS, DOS, MIRAI, RECON, BENIGN, DICTIONARYBRUTEFORCE, DNS_SPOOFING,
     MITM-ARPSPOOFING, VULNERABILITYSCAN, OTHER
     (OTHER = BACKDOOR_MALWARE, COMMANDINJECTION, SQLINJECTION, UPLOADING_ATTACK, XSS, BROWSERHIJACKING)

AIPFL 데이터셋은 '네트워크 흐름' 기준이라, PC 안에서 보는 DDS 규칙과 1:1로 맞지 않는 것은
nf/cic 를 None 으로 두고 DDS 고유 분류(dds)만 표시한다.
"""

# rule: (한글 분류, NF-ToN-IoT-V2, CICIoT2023 원래 라벨 → 병합 라벨)
RULE_TAXONOMY = {
    # 정찰
    "port_scan":               ("정찰 · 포트 스캔",     "Scanning",  "RECON-PORTSCAN → RECON"),
    "recon_burst":             ("정찰 · 내부 정보 수집", "Scanning",  "RECON-HOSTDISCOVERY → RECON"),
    # 계정 공격
    "brute_force":             ("비밀번호 대입",        "Password",  "DICTIONARYBRUTEFORCE"),
    "remote_rdp_logon":        ("원격 로그인",          "Password",  None),
    "remote_network_logon":    ("원격 로그인",          "Password",  None),
    "off_hours_logon":         ("이상 시간 접속",        None,        None),
    # 침투 · 명령 실행
    "webserver_spawned_shell": ("명령 주입 · 웹쉘",      "Injection", "COMMANDINJECTION → OTHER"),
    "devserver_spawned_shell": ("명령 실행",            "Injection", "COMMANDINJECTION → OTHER"),
    "ai_spawned_shell":        ("AI 명령 실행",         "Backdoor",  "BACKDOOR_MALWARE → OTHER"),
    "shell_burst":             ("자동화 명령 실행",       "Backdoor",  "BACKDOOR_MALWARE → OTHER"),
    # 지속 · 권한 상승
    "user_created":            ("백도어 계정",          "Backdoor",  "BACKDOOR_MALWARE → OTHER"),
    "added_to_admin_group":    ("권한 상승",            "Backdoor",  "BACKDOOR_MALWARE → OTHER"),
    # 외부 통신
    "ioc_ip_match":            ("공격 서버 통신",        "Backdoor",  "BACKDOOR_MALWARE → OTHER"),
    # 이상한 IP
    "threat_feed_match":       ("위협 목록 IP",          "Backdoor",  None),
    "lolbin_outbound":         ("원격 조종 의심",         "Backdoor",  "BACKDOOR_MALWARE → OTHER"),
    "outbound_scan":           ("내부 확산 · 스캔",       "Scanning",  "RECON-HOSTDISCOVERY → RECON"),
    "risky_port_inbound":      ("위험 포트 접근",         "Scanning",  None),
    "odd_port_outbound":       ("해킹 도구 포트 통신",     "Backdoor",  None),
    "new_inbound_ip":          ("처음 보는 외부 IP",       None,        None),
    # AI 도구 (DDS 고유, AIPFL 데이터셋에는 없음)
    "ai_api_connection":       ("AI 도구 · LLM 통신",    None,        None),
    "ai_web_usage":            ("AI 사이트 이용",         None,        None),
    "browser_automation":      ("브라우저 자동조종",       None,        "BROWSERHIJACKING → OTHER"),
    "ai_program_started":      ("AI 도구 실행",          None,        None),
    "ai_script_started":       ("AI 도구 실행",          None,        None),
    "local_llm_server":        ("로컬 LLM",             None,        None),
    # 2026-10 개선: ARTEX(원본·한국어판 artex-ko) · AI 에이전트 행동
    "artex_host_artifact":     ("AI 해킹 도구 설치 흔적",  "Backdoor",  "BACKDOOR_MALWARE → OTHER"),
    "artex_user_agent":        ("AI 해킹 도구 웹 정찰",    "Scanning",  "VULNERABILITYSCAN"),
    "js_asset_burst":          ("웹 자동 정찰",           "Scanning",  "VULNERABILITYSCAN"),
    "ioc_domain_query":        ("공격 서버 통신",          "Backdoor",  "BACKDOOR_MALWARE → OTHER"),
    "agent_command_style":     ("AI 에이전트 명령 실행",    "Injection", "COMMANDINJECTION → OTHER"),
    "retry_loop":              ("실패-수정 반복 실행",      "Injection", "COMMANDINJECTION → OTHER"),
    "credential_dump":         ("계정 정보 탈취",          "Password",  None),
    "privilege_escalation":    ("권한 상승",              "Backdoor",  "BACKDOOR_MALWARE → OTHER"),
    "payload_staging":         ("공격 파일 반입",          "Backdoor",  "UPLOADING_ATTACK → OTHER"),
    "distributed_ips":         ("분산 IP 공격",            "Scanning",  None),
    "dev_tool_inbound":        ("AI 개발 도구로 침입",      "Injection", None),
    "dev_tool_exposed":        ("AI 개발 도구 외부 노출",    None,        None),
    "local_agent_command":     ("AI 도구 명령 실행",        None,        None),
    "baseline_anomaly":        ("평소와 다른 행동",          None,        None),
    # v1.1 (2026-10-21)
    "webshell_file_created":   ("웹쉘 설치",              "Backdoor",  "UPLOADING_ATTACK → OTHER"),
    "object_enumeration":      ("고객번호 열거 · 대량 조회", "Injection", "VULNERABILITYSCAN"),
    "log_theft":               ("로그 파일 탈취",          "Backdoor",  None),
    "llm_malware_pattern":     ("LLM 을 부르는 악성코드",   "Backdoor",  "BACKDOOR_MALWARE → OTHER"),
    "llm_then_exec":           ("LLM 지시로 명령 실행",     "Backdoor",  "BACKDOOR_MALWARE → OTHER"),
    "autorun_change":          ("자동 실행 등록",          "Backdoor",  "BACKDOOR_MALWARE → OTHER"),
    "ransomware_prep":         ("랜섬웨어 준비",           "Ransomware", None),
    "mass_file_change":        ("대량 파일 암호화 의심",    "Ransomware", None),
    "git_spawned_unusual":     ("git 설정으로 실행",        "Injection", "COMMANDINJECTION → OTHER"),
    "package_install_exec":    ("공급망 · 설치 스크립트",   "Backdoor",  "BACKDOOR_MALWARE → OTHER"),
    "agent_secret_access":     ("AI 도구 토큰 탈취",        "Password",  None),
    # v1.2 (2026-10-22)
    "critical_file_change":    ("중요 파일 변조 · 지속",     "Backdoor",  "BACKDOOR_MALWARE → OTHER"),
    "browser_hijack":          ("브라우저 탈취",            "Backdoor",  "BROWSERHIJACKING → OTHER"),
    "c2_beacon":               ("공격 서버 주기 보고",       "Backdoor",  "BACKDOOR_MALWARE → OTHER"),
}


# rule: (그룹, 심각도, 언제 발동하나)
RULE_INFO = {
    "brute_force":             ("누가 침입했나", "HIGH", "같은 계정·IP에서 5분 안에 로그인 실패 5회"),
    "remote_rdp_logon":        ("누가 침입했나", "HIGH", "신뢰 목록에 없는 IP에서 RDP 로그인 성공 (Linux: 외부 IP 의 SSH 로그인 성공)"),
    "remote_network_logon":    ("누가 침입했나", "MEDIUM", "신뢰 목록에 없는 IP에서 네트워크 로그인 성공"),
    "off_hours_logon":         ("누가 침입했나", "MEDIUM", "업무 시간(config work_hours) 밖의 로그인"),
    "user_created":            ("누가 침입했나", "HIGH", "새 계정 생성 (Windows 4720 · Linux useradd)"),
    "added_to_admin_group":    ("누가 침입했나", "HIGH", "관리자 그룹에 계정 추가 (Windows 4732 · Linux sudo/wheel 그룹)"),
    "ioc_ip_match":            ("AI 해킹 도구", "HIGH", "공개된 ARTEX 공격 IP·포트와 연결"),
    "port_scan":               ("AI 해킹 도구", "HIGH", "한 IP가 30초 안에 내 포트 10개 이상 접속"),
    "webserver_spawned_shell": ("AI 해킹 도구", "HIGH", "웹·DB 서버 프로세스가 cmd/powershell/sh/bash 실행 (웹쉘)"),
    "devserver_spawned_shell": ("AI 해킹 도구", "MEDIUM", "python/node 가 쉘 실행"),
    "recon_burst":             ("AI 해킹 도구", "HIGH", "정찰 명령 4종 이상이 60초 안에 실행"),
    "shell_burst":             ("AI 해킹 도구", "MEDIUM", "같은 부모가 60초 안에 쉘 10회 이상 실행"),
    "threat_feed_match":       ("이상한 IP", "HIGH", "threat_feeds 폴더의 위협 목록(IP·CIDR)에 있는 주소와 연결"),
    "lolbin_outbound":         ("이상한 IP", "HIGH", "powershell·cmd·certutil·mshta (Linux: bash·nc·socat) 같은 도구가 외부 IP 로 직접 접속 — 원격 조종·역접속"),
    "outbound_scan":           ("이상한 IP", "HIGH", "한 프로그램이 60초 안에 IP 15개 이상에 접속 시도 (이 PC가 감염돼 퍼지는 신호)"),
    "risky_port_inbound":      ("이상한 IP", "MEDIUM", "외부 IP 가 RDP·SMB·WinRM·SSH·DB 같은 위험 포트로 연결"),
    "odd_port_outbound":       ("이상한 IP", "MEDIUM", "4444·1337·6667·9050 같은 해킹 도구 포트로 나가는 연결"),
    "new_inbound_ip":          ("이상한 IP", "LOW", "처음 보는 외부 IP 가 열린 포트로 들어옴 (기록만)"),
    "ai_spawned_shell":        ("PC 안의 AI 도구 (외부 침입 아님 · 기록용)", "HIGH", "AI 프로세스(또는 그 자식)가 쉘 실행"),
    "ai_api_connection":       ("PC 안의 AI 도구 (외부 침입 아님 · 기록용)", "HIGH/LOW", "LLM API 접속 — 목록에 없는 프로그램이면 HIGH, 등록된 AI 앱이면 LOW"),
    "ai_web_usage":            ("PC 안의 AI 도구 (외부 침입 아님 · 기록용)", "LOW", "사람이 브라우저로 AI 사이트 이용 (기록만)"),
    "browser_automation":      ("PC 안의 AI 도구 (외부 침입 아님 · 기록용)", "MEDIUM", "브라우저가 원격 조종 옵션으로 실행"),
    "ai_program_started":      ("PC 안의 AI 도구 (외부 침입 아님 · 기록용)", "MEDIUM", "등록된 AI 프로그램 실행"),
    "ai_script_started":       ("PC 안의 AI 도구 (외부 침입 아님 · 기록용)", "MEDIUM", "python/node 명령줄에 AI 라이브러리 이름"),
    "local_llm_server":        ("PC 안의 AI 도구 (외부 침입 아님 · 기록용)", "LOW", "로컬 LLM 포트(11434 등) 열림"),
    # ---- 2026-10 개선 ----
    "artex_host_artifact":     ("AI 해킹 도구", "HIGH", "ARTEX(원본·한국어판 artex-ko) 실행 파일·콘솔·설정 흔적 (artex, artex_token, autumn27/artex 등)"),
    "artex_user_agent":        ("AI 해킹 도구", "HIGH", "웹 서버 로그에 ARTEX 정찰 User-Agent (artex-enrich/1.0, spa-api-recon) — 웹 서버가 있는 PC만"),
    "js_asset_burst":          ("AI 해킹 도구", "MEDIUM", "한 IP가 짧은 시간에 JS 파일을 많이 요청 (웹 자동 정찰) — 웹 서버가 있는 PC만"),
    "ioc_domain_query":        ("AI 해킹 도구", "HIGH", "공격자가 쓴 LLM 중계 도메인(xcai.pro 등) 조회 — Sysmon DNS 기록"),
    "agent_command_style":     ("AI 해킹 도구", "HIGH", "기계가 읽기 쉬운 형식의 명령(구분자 echo · head · 2>nul 등)이 2분 안에 3번 이상 — AI 에이전트 특징"),
    "retry_loop":              ("AI 해킹 도구", "MEDIUM", "실패한 명령을 조금 고쳐서 바로 다시 실행하는 반복 (2분 안에 3번)"),
    "credential_dump":         ("AI 해킹 도구", "HIGH", "SAM·SYSTEM·SECURITY 저장, LSASS 메모리 덤프 같은 계정 정보 탈취 명령"),
    "privilege_escalation":    ("AI 해킹 도구", "HIGH", "PrintSpoofer·GodPotato 같은 권한 상승 도구, SeImpersonate 권한 확인"),
    "payload_staging":         ("AI 해킹 도구", "HIGH", "certutil 디코드, .b64 파일, 조각 파일 합치기(copy /b), Public·Temp 폴더 실행 파일"),
    "distributed_ips":         ("이상한 IP", "HIGH", "외부 IP 3개 이상이 2분 안에 같은 위험 포트로 들어옴 (IP 바꿔 가며 공격)"),
    "dev_tool_inbound":        ("이상한 IP", "HIGH", "외부 IP 가 Jupyter·Ollama 같은 AI 개발 도구 포트로 접속"),
    "dev_tool_exposed":        ("PC 안의 AI 도구 (외부 침입 아님 · 기록용)", "MEDIUM", "AI 개발 도구 포트가 외부에서 접속 가능하게 열림 (127.0.0.1 아님)"),
    "local_agent_command":     ("PC 안의 AI 도구 (외부 침입 아님 · 기록용)", "LOW", "내가 쓰는 AI 도구(Claude Code 등)가 기계 형식 명령 실행 (기록만)"),
    "baseline_anomaly":        ("평소 패턴 (확인 필요 · 기록용)", "MEDIUM", "평소 패턴 학습(7일) 뒤, 처음 보는 프로그램 조합·실행 폴더·통신 포트가 10분 안에 3개 이상"),
    # ---- v1.1 (2026-10-21) ----
    "webshell_file_created":   ("웹 서버 공격 (금융권 유형)", "HIGH/MEDIUM", "웹 서버·셸이 웹 폴더에 .aspx·.jsp·.php 등을 새로 만듦 (Sysmon 11). 만든 프로그램을 모르면(폴링) MEDIUM"),
    "object_enumeration":      ("웹 서버 공격 (금융권 유형)", "HIGH", "웹 로그: 한 IP 가 같은 주소에 값(고객번호 등)만 바꾼 요청을 60초 안에 30가지 이상"),
    "log_theft":               ("웹 서버 공격 (금융권 유형)", "HIGH", "웹 서버 프로세스 아래에서 로그 폴더를 압축·복사"),
    "llm_malware_pattern":     ("LLM 을 부르는 악성코드", "HIGH", "wscript·cscript·mshta·Office(또는 그 자식)가 LLM API 접속, PowerShell 스크립트에서 LLM API 호출"),
    "llm_then_exec":           ("LLM 을 부르는 악성코드", "HIGH", "LLM API 에 접속한 프로그램이 15초 안에 셸·정찰 명령 실행 (내 AI 도구는 제외)"),
    "autorun_change":          ("지속 · 랜섬웨어 · 공급망", "HIGH/MEDIUM", "Run 키·시작프로그램에 스크립트·Temp·Public 을 가리키는 항목, 또는 셸·스크립트가 등록"),
    "ransomware_prep":         ("지속 · 랜섬웨어 · 공급망", "HIGH", "백업·복구 수단 삭제 (vssadmin delete shadows · wbadmin delete · bcdedit recoveryenabled no)"),
    "mass_file_change":        ("지속 · 랜섬웨어 · 공급망", "HIGH", "한 프로그램이 1분 안에 사용자 폴더에 문서 뒤에 낯선 확장자를 붙인 파일(report.docx.lock 등)을 50개 이상 생성 (Sysmon 11)"),
    "git_spawned_unusual":     ("AI 코딩 도구 공격", "HIGH/MEDIUM", "git 이 cmd·powershell·스크립트 호스트를 실행 (GitSpawn: .git/config 로 실행). 훅(sh) 경유면 MEDIUM"),
    "package_install_exec":    ("지속 · 랜섬웨어 · 공급망", "HIGH", "npm·pip 설치 중 실행된 명령에 다운로드·인코딩(curl·iwr·-enc·certutil -urlcache)"),
    "agent_secret_access":     ("AI 코딩 도구 공격", "HIGH", "AI 도구가 아닌 프로그램이 Claude·Cursor·Codex 토큰·MCP 설정을 읽거나 복사 (명령줄 · 4663)"),
    # ---- v1.2 (2026-10-22) ----
    "critical_file_change":    ("중요 파일 · 브라우저 · 비콘", "HIGH/MEDIUM", "passwd·shadow·sudoers·ld.so.preload·authorized_keys·sshd_config·pam.d (Windows: hosts·예약 작업 폴더)가 바뀜 — 30초 비교, 추가·삭제된 줄 표시. 줄 변화가 없으면 MEDIUM"),
    "browser_hijack":          ("중요 파일 · 브라우저 · 비콘", "HIGH", "cmd·powershell·wscript·Temp 의 프로그램이 브라우저를 원격 조종 옵션(--remote-debugging-port 등)으로 띄움, 디버깅 포트를 외부에 개방(--remote-debugging-address), Temp·Public 의 확장 프로그램 강제 로드. 내 AI 도구 아래는 제외"),
    "c2_beacon":               ("중요 파일 · 브라우저 · 비콘", "HIGH/MEDIUM", "같은 프로그램이 같은 외부 IP:포트로 새 연결을 6번 이상 거의 같은 간격(30초 이상, 편차 20% 이내)으로 반복 — 원격 조종 서버 주기 보고. 셸·스크립트·Temp 프로그램이면 HIGH, 브라우저·메신저·동기화(beacon_allow)는 제외"),
}

# ================= 규칙 묶음 (webui · responder · ip_check · llm 가 같이 씀) =================
# 외부에서 들어온 흔적 → 이것만 빨간 경보
INTRUSION_RULES = {"port_scan", "ioc_ip_match", "webserver_spawned_shell", "recon_burst",
                   "brute_force", "remote_rdp_logon", "remote_network_logon",
                   "user_created", "added_to_admin_group",
                   "threat_feed_match", "lolbin_outbound", "outbound_scan", "risky_port_inbound", "odd_port_outbound",
                   "artex_host_artifact", "artex_user_agent", "js_asset_burst", "ioc_domain_query",
                   "agent_command_style", "retry_loop", "credential_dump", "privilege_escalation",
                   "payload_staging", "distributed_ips", "dev_tool_inbound",
                   "webshell_file_created", "object_enumeration", "log_theft", "llm_malware_pattern",
                   "llm_then_exec", "autorun_change", "ransomware_prep", "mass_file_change", "git_spawned_unusual",
                   "package_install_exec", "agent_secret_access",
                   "critical_file_change", "browser_hijack", "c2_beacon"}
# AI 해킹 도구 쪽 사건으로 보는 규칙
AI_ATTACK_RULES = {"port_scan", "ioc_ip_match", "webserver_spawned_shell", "recon_burst",
                   "threat_feed_match", "lolbin_outbound", "outbound_scan", "risky_port_inbound", "odd_port_outbound",
                   "artex_host_artifact", "artex_user_agent", "js_asset_burst", "ioc_domain_query",
                   "agent_command_style", "retry_loop", "credential_dump", "privilege_escalation",
                   "payload_staging", "distributed_ips", "dev_tool_inbound",
                   "webshell_file_created", "object_enumeration", "log_theft", "llm_malware_pattern",
                   "llm_then_exec", "autorun_change", "ransomware_prep", "mass_file_change", "git_spawned_unusual",
                   "package_install_exec", "agent_secret_access",
                   "critical_file_change", "browser_hijack", "c2_beacon"}
# 자동 대응: IP 차단 / 프로세스 종료
BLOCK_RULES = {"ioc_ip_match", "port_scan", "brute_force", "remote_rdp_logon", "threat_feed_match",
               "lolbin_outbound", "artex_user_agent", "distributed_ips", "dev_tool_inbound", "object_enumeration",
               "c2_beacon"}
KILL_RULES = {"webserver_spawned_shell", "credential_dump", "privilege_escalation", "payload_staging",
              "artex_host_artifact", "log_theft", "llm_malware_pattern", "llm_then_exec", "ransomware_prep",
              "mass_file_change", "git_spawned_unusual", "package_install_exec", "agent_secret_access", "browser_hijack"}


def classify(rule):
    ko, nf, cic = RULE_TAXONOMY.get(rule, ("기타", None, None))
    return {"ko": ko, "nf": nf, "cic": cic}


# 공격이 보통 진행되는 순서 (정찰 → 계정 탈취 → 침투 → 장악)
STAGE_ORDER = ["Scanning", "Password", "MITM", "Injection", "XSS", "Backdoor", "Ransomware", "DoS", "DDoS"]


def chain(rules):
    """발동 규칙 → 중복 없는 공격 단계, 진행 순서대로 (예: Scanning → Injection → Backdoor)"""
    found = {RULE_TAXONOMY.get(r, (None, None, None))[1] for r in rules} - {None}
    return [s for s in STAGE_ORDER if s in found]

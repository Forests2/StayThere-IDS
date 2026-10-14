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
}


# rule: (그룹, 심각도, 언제 발동하나)
RULE_INFO = {
    "brute_force":             ("누가 침입했나", "HIGH", "같은 계정·IP에서 5분 안에 로그인 실패 5회"),
    "remote_rdp_logon":        ("누가 침입했나", "HIGH", "신뢰 목록에 없는 IP에서 RDP 로그인 성공"),
    "remote_network_logon":    ("누가 침입했나", "MEDIUM", "신뢰 목록에 없는 IP에서 네트워크 로그인 성공"),
    "off_hours_logon":         ("누가 침입했나", "MEDIUM", "업무 시간(config work_hours) 밖의 로그인"),
    "user_created":            ("누가 침입했나", "HIGH", "새 Windows 계정 생성 (이벤트 4720)"),
    "added_to_admin_group":    ("누가 침입했나", "HIGH", "관리자 그룹에 계정 추가 (이벤트 4732)"),
    "ioc_ip_match":            ("AI 해킹 도구", "HIGH", "공개된 ARTEX 공격 IP·포트와 연결"),
    "port_scan":               ("AI 해킹 도구", "HIGH", "한 IP가 30초 안에 내 포트 10개 이상 접속"),
    "webserver_spawned_shell": ("AI 해킹 도구", "HIGH", "웹·DB 서버 프로세스가 cmd/powershell 실행 (웹쉘)"),
    "devserver_spawned_shell": ("AI 해킹 도구", "MEDIUM", "python/node 가 쉘 실행"),
    "recon_burst":             ("AI 해킹 도구", "HIGH", "정찰 명령 4종 이상이 60초 안에 실행"),
    "shell_burst":             ("AI 해킹 도구", "MEDIUM", "같은 부모가 60초 안에 쉘 10회 이상 실행"),
    "threat_feed_match":       ("이상한 IP", "HIGH", "threat_feeds 폴더의 위협 목록(IP·CIDR)에 있는 주소와 연결"),
    "lolbin_outbound":         ("이상한 IP", "HIGH", "powershell·cmd·certutil·mshta 같은 시스템 도구가 외부 IP 로 접속"),
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
}


def classify(rule):
    ko, nf, cic = RULE_TAXONOMY.get(rule, ("기타", None, None))
    return {"ko": ko, "nf": nf, "cic": cic}


# 공격이 보통 진행되는 순서 (정찰 → 계정 탈취 → 침투 → 장악)
STAGE_ORDER = ["Scanning", "Password", "MITM", "Injection", "XSS", "Backdoor", "Ransomware", "DoS", "DDoS"]


def chain(rules):
    """발동 규칙 → 중복 없는 공격 단계, 진행 순서대로 (예: Scanning → Injection → Backdoor)"""
    found = {RULE_TAXONOMY.get(r, (None, None, None))[1] for r in rules} - {None}
    return [s for s in STAGE_ORDER if s in found]

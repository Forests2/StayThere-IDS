# 탐지 규칙 목록

DDS 에 들어 있는 탐지 규칙 53개입니다. (`attack_taxonomy.py` 의 `RULE_INFO`·`RULE_TAXONOMY` 에서 자동 생성 — `python tools/gen_rules_doc.py`)

- **경보 화면**은 '외부 침입 흔적' 규칙(아래 ★)이 HIGH 로 걸릴 때만 뜹니다. PC 안에서 사용자가 쓰는 AI 프로그램 활동은 기록만 남깁니다.
- **자동 대응**(켜져 있을 때): 🛡 = 출발지 IP 자동 차단, ⛔ = 해당 프로세스 자동 종료.
- 🆕 = 2026-10-19 추가 (ARTEX 원본·한국어판 · AI 에이전트 행동 · 평소 패턴), 🆕¹·¹ = v1.1 (2026-10-21, 금융권 공격 유형 · LLM 을 부르는 악성코드 · AI 코딩 도구 공격 · 랜섬웨어 · 공급망), 🆕¹·² = v1.2 (2026-10-22, 중요 파일 변조 · 브라우저 탈취 · C2 비콘 · 경보 묶기 · 기록 보관). 근거: [CHANGELOG](../CHANGELOG.md) · [최신 위협 정보 정리](THREAT_NOTES_2026-10-19.md)
- **공격 분류**는 [AIPFL-IDS](https://github.com/PrathamWankhade/AIPFL-IDS) 가 쓰는 데이터셋 라벨(NF-ToN-IoT-V2 / CICIoT2023)에 맞춰 붙였습니다. 데이터셋에 해당 개념이 없는 규칙은 `-` 로 표시합니다.

## 누가 침입했나

| 규칙 | 심각도 | 언제 걸리나 | 공격 분류 (NF-ToN-IoT-V2) | CICIoT2023 라벨 |
|---|---|---|---|---|
| `brute_force` ★ 🛡 | HIGH | 같은 계정·IP에서 5분 안에 로그인 실패 5회 | 비밀번호 대입 · **Password** | DICTIONARYBRUTEFORCE |
| `remote_rdp_logon` ★ 🛡 | HIGH | 신뢰 목록에 없는 IP에서 RDP 로그인 성공 (Linux: 외부 IP 의 SSH 로그인 성공) | 원격 로그인 · **Password** | - |
| `remote_network_logon` ★ | MEDIUM | 신뢰 목록에 없는 IP에서 네트워크 로그인 성공 | 원격 로그인 · **Password** | - |
| `off_hours_logon` | MEDIUM | 업무 시간(config work_hours) 밖의 로그인 | 이상 시간 접속 | - |
| `user_created` ★ | HIGH | 새 계정 생성 (Windows 4720 · Linux useradd) | 백도어 계정 · **Backdoor** | BACKDOOR_MALWARE → OTHER |
| `added_to_admin_group` ★ | HIGH | 관리자 그룹에 계정 추가 (Windows 4732 · Linux sudo/wheel 그룹) | 권한 상승 · **Backdoor** | BACKDOOR_MALWARE → OTHER |

## AI 해킹 도구

| 규칙 | 심각도 | 언제 걸리나 | 공격 분류 (NF-ToN-IoT-V2) | CICIoT2023 라벨 |
|---|---|---|---|---|
| `ioc_ip_match` ★ 🛡 | HIGH | 공개된 ARTEX 공격 IP·포트와 연결 | 공격 서버 통신 · **Backdoor** | BACKDOOR_MALWARE → OTHER |
| `port_scan` ★ 🛡 | HIGH | 한 IP가 30초 안에 내 포트 10개 이상 접속 | 정찰 · 포트 스캔 · **Scanning** | RECON-PORTSCAN → RECON |
| `webserver_spawned_shell` ★ ⛔ | HIGH | 웹·DB 서버 프로세스가 cmd/powershell/sh/bash 실행 (웹쉘) | 명령 주입 · 웹쉘 · **Injection** | COMMANDINJECTION → OTHER |
| `devserver_spawned_shell` | MEDIUM | python/node 가 쉘 실행 | 명령 실행 · **Injection** | COMMANDINJECTION → OTHER |
| `recon_burst` ★ | HIGH | 정찰 명령 4종 이상이 60초 안에 실행 | 정찰 · 내부 정보 수집 · **Scanning** | RECON-HOSTDISCOVERY → RECON |
| `shell_burst` | MEDIUM | 같은 부모가 60초 안에 쉘 10회 이상 실행 | 자동화 명령 실행 · **Backdoor** | BACKDOOR_MALWARE → OTHER |
| `artex_host_artifact` ★ ⛔ 🆕 | HIGH | ARTEX(원본·한국어판 artex-ko) 실행 파일·콘솔·설정 흔적 (artex, artex_token, autumn27/artex 등) | AI 해킹 도구 설치 흔적 · **Backdoor** | BACKDOOR_MALWARE → OTHER |
| `artex_user_agent` ★ 🛡 🆕 | HIGH | 웹 서버 로그에 ARTEX 정찰 User-Agent (artex-enrich/1.0, spa-api-recon) — 웹 서버가 있는 PC만 | AI 해킹 도구 웹 정찰 · **Scanning** | VULNERABILITYSCAN |
| `js_asset_burst` ★ 🆕 | MEDIUM | 한 IP가 짧은 시간에 JS 파일을 많이 요청 (웹 자동 정찰) — 웹 서버가 있는 PC만 | 웹 자동 정찰 · **Scanning** | VULNERABILITYSCAN |
| `ioc_domain_query` ★ 🆕 | HIGH | 공격자가 쓴 LLM 중계 도메인(xcai.pro 등) 조회 — Sysmon DNS 기록 | 공격 서버 통신 · **Backdoor** | BACKDOOR_MALWARE → OTHER |
| `agent_command_style` ★ 🆕 | HIGH | 기계가 읽기 쉬운 형식의 명령(구분자 echo · head · 2>nul 등)이 2분 안에 3번 이상 — AI 에이전트 특징 | AI 에이전트 명령 실행 · **Injection** | COMMANDINJECTION → OTHER |
| `retry_loop` ★ 🆕 | MEDIUM | 실패한 명령을 조금 고쳐서 바로 다시 실행하는 반복 (2분 안에 3번) | 실패-수정 반복 실행 · **Injection** | COMMANDINJECTION → OTHER |
| `credential_dump` ★ ⛔ 🆕 | HIGH | SAM·SYSTEM·SECURITY 저장, LSASS 메모리 덤프 같은 계정 정보 탈취 명령 | 계정 정보 탈취 · **Password** | - |
| `privilege_escalation` ★ ⛔ 🆕 | HIGH | PrintSpoofer·GodPotato 같은 권한 상승 도구, SeImpersonate 권한 확인 | 권한 상승 · **Backdoor** | BACKDOOR_MALWARE → OTHER |
| `payload_staging` ★ ⛔ 🆕 | HIGH | certutil 디코드, .b64 파일, 조각 파일 합치기(copy /b), Public·Temp 폴더 실행 파일 | 공격 파일 반입 · **Backdoor** | UPLOADING_ATTACK → OTHER |

## 이상한 IP

| 규칙 | 심각도 | 언제 걸리나 | 공격 분류 (NF-ToN-IoT-V2) | CICIoT2023 라벨 |
|---|---|---|---|---|
| `threat_feed_match` ★ 🛡 | HIGH | threat_feeds 폴더의 위협 목록(IP·CIDR)에 있는 주소와 연결 | 위협 목록 IP · **Backdoor** | - |
| `lolbin_outbound` ★ 🛡 | HIGH | powershell·cmd·certutil·mshta (Linux: bash·nc·socat) 같은 도구가 외부 IP 로 직접 접속 — 원격 조종·역접속 | 원격 조종 의심 · **Backdoor** | BACKDOOR_MALWARE → OTHER |
| `outbound_scan` ★ | HIGH | 한 프로그램이 60초 안에 IP 15개 이상에 접속 시도 (이 PC가 감염돼 퍼지는 신호) | 내부 확산 · 스캔 · **Scanning** | RECON-HOSTDISCOVERY → RECON |
| `risky_port_inbound` ★ | MEDIUM | 외부 IP 가 RDP·SMB·WinRM·SSH·DB 같은 위험 포트로 연결 | 위험 포트 접근 · **Scanning** | - |
| `odd_port_outbound` ★ | MEDIUM | 4444·1337·6667·9050 같은 해킹 도구 포트로 나가는 연결 | 해킹 도구 포트 통신 · **Backdoor** | - |
| `new_inbound_ip` | LOW | 처음 보는 외부 IP 가 열린 포트로 들어옴 (기록만) | 처음 보는 외부 IP | - |
| `distributed_ips` ★ 🛡 🆕 | HIGH | 외부 IP 3개 이상이 2분 안에 같은 위험 포트로 들어옴 (IP 바꿔 가며 공격) | 분산 IP 공격 · **Scanning** | - |
| `dev_tool_inbound` ★ 🛡 🆕 | HIGH | 외부 IP 가 Jupyter·Ollama 같은 AI 개발 도구 포트로 접속 | AI 개발 도구로 침입 · **Injection** | - |

## PC 안의 AI 도구 (외부 침입 아님 · 기록용)

| 규칙 | 심각도 | 언제 걸리나 | 공격 분류 (NF-ToN-IoT-V2) | CICIoT2023 라벨 |
|---|---|---|---|---|
| `ai_spawned_shell` | HIGH | AI 프로세스(또는 그 자식)가 쉘 실행 | AI 명령 실행 · **Backdoor** | BACKDOOR_MALWARE → OTHER |
| `ai_api_connection` | HIGH/LOW | LLM API 접속 — 목록에 없는 프로그램이면 HIGH, 등록된 AI 앱이면 LOW | AI 도구 · LLM 통신 | - |
| `ai_web_usage` | LOW | 사람이 브라우저로 AI 사이트 이용 (기록만) | AI 사이트 이용 | - |
| `browser_automation` | MEDIUM | 브라우저가 원격 조종 옵션으로 실행 | 브라우저 자동조종 | BROWSERHIJACKING → OTHER |
| `ai_program_started` | MEDIUM | 등록된 AI 프로그램 실행 | AI 도구 실행 | - |
| `ai_script_started` | MEDIUM | python/node 명령줄에 AI 라이브러리 이름 | AI 도구 실행 | - |
| `local_llm_server` | LOW | 로컬 LLM 포트(11434 등) 열림 | 로컬 LLM | - |
| `dev_tool_exposed` 🆕 | MEDIUM | AI 개발 도구 포트가 외부에서 접속 가능하게 열림 (127.0.0.1 아님) | AI 개발 도구 외부 노출 | - |
| `local_agent_command` 🆕 | LOW | 내가 쓰는 AI 도구(Claude Code 등)가 기계 형식 명령 실행 (기록만) | AI 도구 명령 실행 | - |

## 평소 패턴 (확인 필요 · 기록용)

| 규칙 | 심각도 | 언제 걸리나 | 공격 분류 (NF-ToN-IoT-V2) | CICIoT2023 라벨 |
|---|---|---|---|---|
| `baseline_anomaly` 🆕 | MEDIUM | 평소 패턴 학습(7일) 뒤, 처음 보는 프로그램 조합·실행 폴더·통신 포트가 10분 안에 3개 이상 | 평소와 다른 행동 | - |

## 웹 서버 공격 (금융권 유형)

| 규칙 | 심각도 | 언제 걸리나 | 공격 분류 (NF-ToN-IoT-V2) | CICIoT2023 라벨 |
|---|---|---|---|---|
| `webshell_file_created` ★ 🆕¹·¹ | HIGH/MEDIUM | 웹 서버·셸이 웹 폴더에 .aspx·.jsp·.php 등을 새로 만듦 (Sysmon 11). 만든 프로그램을 모르면(폴링) MEDIUM | 웹쉘 설치 · **Backdoor** | UPLOADING_ATTACK → OTHER |
| `object_enumeration` ★ 🛡 🆕¹·¹ | HIGH | 웹 로그: 한 IP 가 같은 주소에 값(고객번호 등)만 바꾼 요청을 60초 안에 30가지 이상 | 고객번호 열거 · 대량 조회 · **Injection** | VULNERABILITYSCAN |
| `log_theft` ★ ⛔ 🆕¹·¹ | HIGH | 웹 서버 프로세스 아래에서 로그 폴더를 압축·복사 | 로그 파일 탈취 · **Backdoor** | - |

## LLM 을 부르는 악성코드

| 규칙 | 심각도 | 언제 걸리나 | 공격 분류 (NF-ToN-IoT-V2) | CICIoT2023 라벨 |
|---|---|---|---|---|
| `llm_malware_pattern` ★ ⛔ 🆕¹·¹ | HIGH | wscript·cscript·mshta·Office(또는 그 자식)가 LLM API 접속, PowerShell 스크립트에서 LLM API 호출 | LLM 을 부르는 악성코드 · **Backdoor** | BACKDOOR_MALWARE → OTHER |
| `llm_then_exec` ★ ⛔ 🆕¹·¹ | HIGH | LLM API 에 접속한 프로그램이 15초 안에 셸·정찰 명령 실행 (내 AI 도구는 제외) | LLM 지시로 명령 실행 · **Backdoor** | BACKDOOR_MALWARE → OTHER |

## 지속 · 랜섬웨어 · 공급망

| 규칙 | 심각도 | 언제 걸리나 | 공격 분류 (NF-ToN-IoT-V2) | CICIoT2023 라벨 |
|---|---|---|---|---|
| `autorun_change` ★ 🆕¹·¹ | HIGH/MEDIUM | Run 키·시작프로그램에 스크립트·Temp·Public 을 가리키는 항목, 또는 셸·스크립트가 등록 | 자동 실행 등록 · **Backdoor** | BACKDOOR_MALWARE → OTHER |
| `ransomware_prep` ★ ⛔ 🆕¹·¹ | HIGH | 백업·복구 수단 삭제 (vssadmin delete shadows · wbadmin delete · bcdedit recoveryenabled no) | 랜섬웨어 준비 · **Ransomware** | - |
| `mass_file_change` ★ ⛔ 🆕¹·¹ | HIGH | 한 프로그램이 1분 안에 사용자 폴더에 문서 뒤에 낯선 확장자를 붙인 파일(report.docx.lock 등)을 50개 이상 생성 (Sysmon 11) | 대량 파일 암호화 의심 · **Ransomware** | - |
| `package_install_exec` ★ ⛔ 🆕¹·¹ | HIGH | npm·pip 설치 중 실행된 명령에 다운로드·인코딩(curl·iwr·-enc·certutil -urlcache) | 공급망 · 설치 스크립트 · **Backdoor** | BACKDOOR_MALWARE → OTHER |

## AI 코딩 도구 공격

| 규칙 | 심각도 | 언제 걸리나 | 공격 분류 (NF-ToN-IoT-V2) | CICIoT2023 라벨 |
|---|---|---|---|---|
| `git_spawned_unusual` ★ ⛔ 🆕¹·¹ | HIGH/MEDIUM | git 이 cmd·powershell·스크립트 호스트를 실행 (GitSpawn: .git/config 로 실행). 훅(sh) 경유면 MEDIUM | git 설정으로 실행 · **Injection** | COMMANDINJECTION → OTHER |
| `agent_secret_access` ★ ⛔ 🆕¹·¹ | HIGH | AI 도구가 아닌 프로그램이 Claude·Cursor·Codex 토큰·MCP 설정을 읽거나 복사 (명령줄 · 4663) | AI 도구 토큰 탈취 · **Password** | - |

## 중요 파일 · 브라우저 · 비콘

| 규칙 | 심각도 | 언제 걸리나 | 공격 분류 (NF-ToN-IoT-V2) | CICIoT2023 라벨 |
|---|---|---|---|---|
| `critical_file_change` ★ 🆕¹·² | HIGH/MEDIUM | passwd·shadow·sudoers·ld.so.preload·authorized_keys·sshd_config·pam.d (Windows: hosts·예약 작업 폴더)가 바뀜 — 30초 비교, 추가·삭제된 줄 표시. 줄 변화가 없으면 MEDIUM | 중요 파일 변조 · 지속 · **Backdoor** | BACKDOOR_MALWARE → OTHER |
| `browser_hijack` ★ ⛔ 🆕¹·² | HIGH | cmd·powershell·wscript·Temp 의 프로그램이 브라우저를 원격 조종 옵션(--remote-debugging-port 등)으로 띄움, 디버깅 포트를 외부에 개방(--remote-debugging-address), Temp·Public 의 확장 프로그램 강제 로드. 내 AI 도구 아래는 제외 | 브라우저 탈취 · **Backdoor** | BROWSERHIJACKING → OTHER |
| `c2_beacon` ★ 🛡 🆕¹·² | HIGH/MEDIUM | 같은 프로그램이 같은 외부 IP:포트로 새 연결을 6번 이상 거의 같은 간격(30초 이상, 편차 20% 이내)으로 반복 — 원격 조종 서버 주기 보고. 셸·스크립트·Temp 프로그램이면 HIGH, 브라우저·메신저·동기화(beacon_allow)는 제외 | 공격 서버 주기 보고 · **Backdoor** | BACKDOOR_MALWARE → OTHER |

## 기본 설정값 (config.json)

| 항목 | 값 | 뜻 |
|---|---|---|
| `interval_sec` | 2 | 수집 주기(초) |
| `work_hours` | 8–20시 | 이 시간 밖 로그인은 `off_hours_logon` |
| `scan_burst` | 30초 · 포트 10개 | `port_scan` 기준 |
| `recon_burst` | 60초 · 명령 4종 | `recon_burst` 기준 |
| `shell_burst` | 60초 · 10회 | `shell_burst` 기준 |
| `outbound_scan` | 60초 · IP 15개 | `outbound_scan` 기준 |
| `risky_inbound_ports` | 21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 5985, 5986 | 외부에서 들어오면 `risky_port_inbound` |
| `bad_outbound_ports` | 1337, 31337, 4444, 4445, 5555, 6666, 6667, 6668, 6669, 9001, 9050, 9051, 12345, 18899, 50050 | 이 포트로 나가면 `odd_port_outbound` |
| `ioc_ips` | 10개 | CrowdStrike ARTEX 보고서 공개 IP |
| `ioc_ports / ioc_domains` | [18899] / ['xcai.pro'] | 같은 보고서 |
| `artex_process_names` | artex, artex.exe, artex-ko, artex-ko.exe | 🆕 ARTEX 원본·한국어판 실행 파일 이름 → `artex_host_artifact` |
| `artex_host_keywords` | 11개 (artex_token, autumn27/artex, 콘솔 제목, cyberstrikeai 등) | 🆕 명령줄·경로에 있으면 `artex_host_artifact` |
| `artex_user_agents` | artex-enrich/1.0 · Mozilla/5.0 (spa-api-recon) · Mozilla/5.0 (spa-api-recon spider) | 🆕 웹 로그에 있으면 `artex_user_agent` |
| `web_log_dirs` | C:\inetpub\logs\LogFiles · C:\nginx\logs · C:\Apache24\logs · /var/log/nginx · /var/log/apache2 · /var/log/httpd | 🆕 있으면 읽는 웹 서버 로그 폴더 (IIS W3C · nginx/Apache combined) |
| `js_burst` | 60초 · JS 30개 | 🆕 `js_asset_burst` 기준 |
| `agent_burst` | 120초 · 3건 · 표시 2개 이상 | 🆕 `agent_command_style` 기준 (`agent_command_markers` 목록) |
| `retry_burst` | 120초 · 3번 · 유사도 0.8 | 🆕 `retry_loop` 기준 |
| `distributed_ips` | 120초 · IP 3개 | 🆕 `distributed_ips` 기준 |
| `dev_tool_ports` | 8888(Jupyter), 11434(Ollama), 1234(LM Studio), 7860(Gradio / text-generation-webui), 8188(ComfyUI), 9222(Chrome 원격 디버깅(CDP)), 9229(Node inspector), 9515(ChromeDriver) | 🆕 `dev_tool_exposed` · `dev_tool_inbound` |
| `sysmon` | true | Sysmon 이 있으면 이벤트 1·3·11·12·13·22 사용 |
| `baseline` | 7일 · 이벤트 3,000건 학습 뒤 · 10분 안에 3가지 | 🆕 `baseline_anomaly` 기준 |
| `powershell_4104` | true | 🆕¹·¹ PowerShell 스크립트 블록 기록 읽기 (enable_cmdline_audit.bat 가 켬) |
| `web_root_dirs · web_root_markers · web_script_ext` | C:\inetpub\wwwroot, /var/www, /usr/share/nginx/html · 확장자 14종 | 🆕¹·¹ `webshell_file_created` (Sysmon 없으면 웹 폴더를 30초마다 비교) |
| `enum_burst` | 60초 · 값 30가지 | 🆕¹·¹ `object_enumeration` 기준 (정적 파일 제외) |
| `log_markers · archive_markers` | 5 · 18개 | 🆕¹·¹ `log_theft` (웹 서버 아래에서만) |
| `script_hosts · office_processes` | wscript.exe, cscript.exe, mshta.exe · Office 9종 | 🆕¹·¹ `llm_malware_pattern` |
| `llm_exec_window_sec` | 15 | 🆕¹·¹ `llm_then_exec` — LLM 접속 뒤 이 시간 안의 셸 실행 |
| `autorun_markers · suspicious_autorun_values` | 17 · 28개 | 🆕¹·¹ `autorun_change` (Sysmon 없으면 Run 키 · 시작프로그램 폴더를 30초마다 비교) |
| `ransomware_patterns` | 11개 (vssadmin · wmic · wbadmin · bcdedit) | 🆕¹·¹ `ransomware_prep` |
| `mass_file · doc_ext` | 60초 · 50개 · 비율 0.6 | 🆕¹·¹ `mass_file_change` — 문서 확장자 뒤에 낯선 확장자가 붙은 파일만 셈 |
| `package_install_markers · download_markers` | 12 · 15개 | 🆕¹·¹ `package_install_exec` |
| `git_suspicious_children` | cmd.exe, powershell.exe, pwsh.exe, wscript.exe, cscript.exe, mshta.exe, rundll32.exe, regsvr32.exe, certutil.exe, bitsadmin.exe, bash, sh, dash, zsh, python3, perl, curl, wget, nc | 🆕¹·¹ `git_spawned_unusual` |
| `secret_markers · secret_readers_allow` | 21 · 29개 | 🆕¹·¹ `agent_secret_access` (4663 은 enable_secret_audit.ps1 로 켬) |
| `notify` | syslog · 웹훅 (기본 꺼짐) | 🆕¹·¹ 침입 알림을 PC 밖으로 전송 (Logpresso 등) |
| `retention` | 로그 파일 30일 · DB 30일 | 🆕¹·² logs/dds_날짜.log 날짜별 기록 · 오래된 로그 파일과 dds.db 기록 자동 삭제 (0 = 안 지움) |
| `alert_group_sec` | 600초 | 🆕¹·² 같은 규칙·대상·IP 경보가 이 시간 안에 반복되면 새 줄 대신 횟수(×N)만 올림 |
| `critical_files_linux · critical_files_windows` | 11 · 2개 | 🆕¹·² `critical_file_change` — 30초마다 내용·권한 비교 (`~/` 는 모든 계정 홈) |
| `browser_hijack_flags` | 7개 | 🆕¹·² `browser_hijack` — 디버깅 포트 외부 개방 · 보안 끄기 · Temp 프로필 |
| `beacon · beacon_allow` | 6회 · 간격 30초 이상 · 편차 0.2 · 제외 38개 | 🆕¹·² `c2_beacon` — 브라우저·메신저·동기화·모니터링 에이전트는 제외 |

> 기준값은 개발자가 정한 초기값입니다. 실제 PC 에서 며칠 돌려 보고 오탐에 맞춰 조정하세요.

# 탐지 규칙 목록

DDS 에 들어 있는 탐지 규칙 25개입니다. (`attack_taxonomy.py` 의 `RULE_INFO`·`RULE_TAXONOMY` 에서 자동 생성)

- **경보 화면**은 '외부 침입 흔적' 규칙(아래 ★)이 HIGH 로 걸릴 때만 뜹니다. PC 안에서 사용자가 쓰는 AI 프로그램 활동은 기록만 남깁니다.
- **공격 분류**는 [AIPFL-IDS](https://github.com/PrathamWankhade/AIPFL-IDS) 가 쓰는 데이터셋 라벨(NF-ToN-IoT-V2 / CICIoT2023)에 맞춰 붙였습니다. 데이터셋에 해당 개념이 없는 규칙은 `-` 로 표시합니다.

## 누가 침입했나

| 규칙 | 심각도 | 언제 걸리나 | 공격 분류 (NF-ToN-IoT-V2) | CICIoT2023 라벨 |
|---|---|---|---|---|
| `brute_force` ★ | HIGH | 같은 계정·IP에서 5분 안에 로그인 실패 5회 | 비밀번호 대입 · **Password** | DICTIONARYBRUTEFORCE |
| `remote_rdp_logon` ★ | HIGH | 신뢰 목록에 없는 IP에서 RDP 로그인 성공 | 원격 로그인 · **Password** | - |
| `remote_network_logon` ★ | MEDIUM | 신뢰 목록에 없는 IP에서 네트워크 로그인 성공 | 원격 로그인 · **Password** | - |
| `off_hours_logon` | MEDIUM | 업무 시간(config work_hours) 밖의 로그인 | 이상 시간 접속 | - |
| `user_created` ★ | HIGH | 새 Windows 계정 생성 (이벤트 4720) | 백도어 계정 · **Backdoor** | BACKDOOR_MALWARE → OTHER |
| `added_to_admin_group` ★ | HIGH | 관리자 그룹에 계정 추가 (이벤트 4732) | 권한 상승 · **Backdoor** | BACKDOOR_MALWARE → OTHER |

## AI 해킹 도구

| 규칙 | 심각도 | 언제 걸리나 | 공격 분류 (NF-ToN-IoT-V2) | CICIoT2023 라벨 |
|---|---|---|---|---|
| `ioc_ip_match` ★ | HIGH | 공개된 ARTEX 공격 IP·포트와 연결 | 공격 서버 통신 · **Backdoor** | BACKDOOR_MALWARE → OTHER |
| `port_scan` ★ | HIGH | 한 IP가 30초 안에 내 포트 10개 이상 접속 | 정찰 · 포트 스캔 · **Scanning** | RECON-PORTSCAN → RECON |
| `webserver_spawned_shell` ★ | HIGH | 웹·DB 서버 프로세스가 cmd/powershell 실행 (웹쉘) | 명령 주입 · 웹쉘 · **Injection** | COMMANDINJECTION → OTHER |
| `devserver_spawned_shell` | MEDIUM | python/node 가 쉘 실행 | 명령 실행 · **Injection** | COMMANDINJECTION → OTHER |
| `recon_burst` ★ | HIGH | 정찰 명령 4종 이상이 60초 안에 실행 | 정찰 · 내부 정보 수집 · **Scanning** | RECON-HOSTDISCOVERY → RECON |
| `shell_burst` | MEDIUM | 같은 부모가 60초 안에 쉘 10회 이상 실행 | 자동화 명령 실행 · **Backdoor** | BACKDOOR_MALWARE → OTHER |

## 이상한 IP

| 규칙 | 심각도 | 언제 걸리나 | 공격 분류 (NF-ToN-IoT-V2) | CICIoT2023 라벨 |
|---|---|---|---|---|
| `threat_feed_match` ★ | HIGH | threat_feeds 폴더의 위협 목록(IP·CIDR)에 있는 주소와 연결 | 위협 목록 IP · **Backdoor** | - |
| `lolbin_outbound` ★ | HIGH | powershell·cmd·certutil·mshta 같은 시스템 도구가 외부 IP 로 접속 | 원격 조종 의심 · **Backdoor** | BACKDOOR_MALWARE → OTHER |
| `outbound_scan` ★ | HIGH | 한 프로그램이 60초 안에 IP 15개 이상에 접속 시도 (이 PC가 감염돼 퍼지는 신호) | 내부 확산 · 스캔 · **Scanning** | RECON-HOSTDISCOVERY → RECON |
| `risky_port_inbound` ★ | MEDIUM | 외부 IP 가 RDP·SMB·WinRM·SSH·DB 같은 위험 포트로 연결 | 위험 포트 접근 · **Scanning** | - |
| `odd_port_outbound` ★ | MEDIUM | 4444·1337·6667·9050 같은 해킹 도구 포트로 나가는 연결 | 해킹 도구 포트 통신 · **Backdoor** | - |
| `new_inbound_ip` | LOW | 처음 보는 외부 IP 가 열린 포트로 들어옴 (기록만) | 처음 보는 외부 IP | - |

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
| `ioc_ports` / `ioc_domains` | [18899] / ['xcai.pro'] | 같은 보고서 |

> 기준값은 개발자가 정한 초기값입니다. 실제 PC 에서 며칠 돌려 보고 오탐에 맞춰 조정하세요.

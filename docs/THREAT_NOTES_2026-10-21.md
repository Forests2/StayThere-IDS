# 최신 위협 정보 정리 — 2026-10-21 (v1.1)

2026-10-19 정리([THREAT_NOTES_2026-10-19.md](THREAT_NOTES_2026-10-19.md)) 이후 새로 나온 자료와, 그 계획을 v1.1 에 어떻게 넣었는지 정리합니다.
자료에 없는 내용은 지어내지 않았고, 확인되지 않은 것은 「미확인」 으로 표시했습니다.

---

## 1. 10/19 이후 새 자료

### ARTEX, 일본 기업 공격에도 쓰인 정황 (2026-10-20)
출처: Seoul Economic Daily (요미우리신문 · NHK 보도 인용)
- 일본 보험 · 금융 · 물류 등 약 80곳이 표적이 된 최근 개인정보 유출 공격 **일부**에 ARTEX 가 쓰였을 가능성
- 일본 GMO 인터넷 그룹 계열 보안 자회사가 조사한 해외 공개 서버 6대(사용 기간 **2026-09-18 ~ 10-18**) 모두에서 ARTEX 흔적, 다른 AI 에이전트 흔적은 없음
- IP · 도메인 등 지표는 기사에 없음 (미확인)
- **DDS:** 한국 금융권과 같은 도구 → 기존 ARTEX 규칙과 웹 침투 규칙(v1.1)이 그대로 적용됨

### ThreatBook RedAgents 정식 발표 (2026-10-16)
출처: GBHackers (2026-10-20), ThreatBook 블로그, PR Newswire
- 멀티 에이전트 AI 침투 테스트 SaaS. 포함 에이전트: **Artex Pro**, Cyber(YanJi), Yanxun, **CyberStrikeAI Enterprise Edition**
- 원래 Artex 프로젝트는 10/8 비공개 전환
- 악용 방지로 「대상 허용 목록」 을 둔다고 설명. 접속 도메인 · 스캔 출발지 IP · User-Agent 는 공개되지 않음 (미확인)
- 참고: 데일리시큐(오아시스시큐리티 분석)는 ARTEX 관련 서버 일부에서 CyberStrikeAI 흔적도 관측했다고 보도
- **DDS:** `artex_host_keywords` 에 `cyberstrikeai` 추가. 플랫폼 지표가 공개되면 반영 (v1.2 후보)

### MITRE ATT&CK v20 — AI 악용 기법 추가 (2026-10 중순)
출처: SecurityWeek (2026-10-19)
- 프롬프트 인젝션(직접 · 자료에 숨긴 간접), **조직이 운용하는 AI 에이전트를 이용한 데이터 유출**, AI 검색 · 어시스턴트 추천 조작, LLM 기반 악성코드 분석 방해
- 기존 「침해된 소프트웨어 의존성 · 개발 도구」 기법에 **IDE · 코딩 에이전트 설정 파일** 추가
- 기법 ID 는 기사에 없음 (미확인 — MITRE 공식 발표 확인 필요)
- **DDS:** 코딩 에이전트 설정 · 토큰 보호(`agent_secret_access`), git 설정을 통한 실행(`git_spawned_unusual`)이 이 방향과 같음

### 경찰, 금융권 AI 해킹을 중대범죄로 판단 (2026-10-20)
출처: 세계일보
- 금융위원회 해석(전자금융기반시설 해당)을 받아 중대범죄수사청에 통보. 새 공격 지표는 공개되지 않음

---

## 2. v1.1 에 넣은 것 (10/19 계획 → 구현)

| 계획 | 규칙 | 어떻게 잡나 | 수집원 |
|---|---|---|---|
| 웹쉘 설치 (금융권 유형 ③) | `webshell_file_created` | 웹 서버·셸이 웹 폴더에 .aspx·.jsp·.php 등 생성 → HIGH. 만든 프로그램을 모르면(폴링) MEDIUM | Sysmon 11 · 웹 폴더 30초 비교 |
| 고객번호 열거 (유형 ①) | `object_enumeration` | 한 IP 가 같은 주소에 숫자 값만 바꾼 요청을 60초에 30가지 이상 → HIGH · IP 차단 | 웹 서버 로그 (IIS 쿼리 포함) |
| 로그 탈취 (유형 ③) | `log_theft` | 웹 서버 프로세스 아래에서 로그 폴더 압축·복사 | 4688 · Sysmon 1 · psutil |
| LLM 을 부르는 악성코드 | `llm_malware_pattern` | wscript·cscript·mshta·Office(또는 그 자식)가 LLM API 접속, PowerShell 스크립트에서 LLM API 호출 | 네트워크 · Sysmon 22 · 4104 |
| LLM 응답 직후 명령 | `llm_then_exec` | LLM API 에 접속한 프로그램(또는 그 조상)이 15초 안에 셸 실행. 내 AI 도구는 제외 | 네트워크 · 프로세스 |
| 자동 실행 등록 | `autorun_change` | Run 키·시작프로그램이 스크립트·Temp·Public 을 가리키거나 셸·스크립트가 등록 | Sysmon 11·12·13 · 30초 비교 |
| PowerShell 4104 | (여러 규칙) | 스크립트 내용에 계정 탈취 · 파일 반입 · 백업 삭제 · LLM API 호출 | 4104 |
| AI 도구 토큰 보호 | `agent_secret_access` | AI 도구가 아닌 프로그램이 토큰 · MCP 설정을 읽거나 복사 | 4663 (`enable_secret_audit.ps1`) · 명령줄 |
| GitSpawn | `git_spawned_unusual` | git.exe 가 cmd·powershell·스크립트 호스트 실행 → HIGH, 훅(sh) 경유 MEDIUM | 프로세스 |
| 랜섬웨어 준비 | `ransomware_prep` | vssadmin · wmic shadowcopy · wbadmin · bcdedit 복구 끄기 | 명령줄 · 4104 |
| 대량 암호화 | `mass_file_change` | 한 프로그램이 1분에 `문서.docx.xxx` 처럼 문서 뒤에 낯선 확장자를 붙인 파일 50개 이상 | Sysmon 11 |
| 공급망 | `package_install_exec` | npm·pip 설치 중 실행된 명령에 다운로드·인코딩 | 프로세스 조상 명령줄 |
| 알림 외부 전송 | `notify` | 침입 알림을 syslog(Logpresso 등)·웹훅으로 전송 (기본 꺼짐) | — |

**오탐 줄이기 (테스트 시나리오 I 로 확인):** git 훅(sh) · git 원격 · npm 의 node-gyp · msiexec 의 Run 키 등록(Program Files) · 배포 도구의 웹 폴더 파일 · Claude Code 의 자기 토큰 읽기 · git checkout 의 .ts 파일 다량 생성 · 관리자의 로그 압축(웹 서버와 무관) · 정상 웹 탐색 · 정상 PowerShell → **빨간 경보 0건**

## 출처
- Seoul Economic Daily (2026-10-20): https://en.sedaily.com/international/2026/10/20/chinese-ai-hacking-tool-used-on-korean-banks-also-hit
- GBHackers (2026-10-20) — New RedAgents AI Platform: https://gbhackers.com/redagents-ai-platform/
- ThreatBook — RedAgents.Ai: https://threatbook.io/blog/redagents-ai-the-worlds-first-multi-agent-ai-pentest-platform
- SecurityWeek (2026-10-19) — MITRE ATT&CK v20: https://www.securityweek.com/mitre-attck-v20-catalogs-ai-abuse-mfa-bypass-water-utility-attacks/
- 세계일보 (2026-10-20) — 경찰, 금융권 AI 해킹 중대범죄 판단: https://www.segye.com/newsView/20261020521235
- 데일리시큐 — ARTEX 관련 IP 359개 분석: https://www.dailysecu.com/news/articleView.html?idxno=208724

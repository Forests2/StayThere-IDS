# 최신 위협 정보 정리 — 2026-10-19

다음 업데이트(v1.1)에 반영하려고 모은 공개 자료입니다. 각 항목 끝에 **DDS 반영 계획**을 적었습니다.
자료에 없는 내용은 지어내지 않았고, 확인되지 않은 것은 「미확인」 으로 표시했습니다.

---

## 1. 2026 금융권 AI 해킹 사건 — 10월 13일까지 경과

출처: IT위키 「2026년 금융권 AI 해킹 및 정보유출 사태」 (10/13 기준 정리)

- **피해:** 신한은행(고객 25,729명), KB국민은행(119명), 하나은행(89명), 예가람저축은행(약 5만 건 추정), 웰컴저축은행(2,299개 추정), 현대캐피탈(대출모집인 146명), PFCT(300여 명), 새마을금고중앙회(10/10 별도 공격, 400명대) 등
- **공격 대상:** 핵심 뱅킹이 아니라 **대출모집인 조회 · 직원 업무지원 · 외부 웹서버** 같은 주변 시스템
- **금융당국이 분류한 공격 유형 3가지**
  1. 본인확인 없는 정보조회 서비스 — 고객번호 등에 **무작위 값을 넣어 반복 조회**
  2. 모바일 단말 접근통제가 빠진 직원 업무 서비스
  3. 알려진 취약점으로 **악성코드(웹쉘)를 심어 로그 파일 탈취**
- **금융보안원 평가:** DB 에 악성 명령을 직접 넣기보다 **정상 조회 기능을 반복 사용**해 정보를 가져감
- **차단 뒤에도 IP 를 바꿔 가며 접근** (신한은행)
- **IP:** 금감원 확인 해킹 시도 IP 33개(중복 제거 28개) — 주소 미공개. 경찰은 상당수를 우회용 주소로 봄
- **SK쉴더스 분석(10/8):** 관리 목록 밖의 Shadow IT · Shadow API, 인가 결함, 대량 조회 탐지 공백 (공개 정보 기반 재구성, 포렌식 확정 아님)

**DDS 반영 계획**
- `webshell_file_created` — 웹 서버 프로세스(w3wp·java·php 등)가 웹 폴더에 `.aspx`·`.jsp`·`.php` 등을 새로 만들면 경보 (Sysmon 11)
- `object_enumeration` — 웹 로그에서 한 IP 가 같은 주소에 **값만 바꾼 요청**을 짧은 시간에 몰아서 보내면 경보 (고객번호 열거)
- `weblog_bulk_read` — 웹 서버 프로세스가 로그 폴더를 압축·복사하는 명령 (공격 유형 ③)

## 2. ARTEX 후속 — 유료 플랫폼으로 재출시 예정

출처: 아주경제 · 글로벌이코노믹 (2026-10-16)

- 개발자가 저장소를 비공개로 돌린 뒤, 중국 보안기업 Threatbook 이 **「RedAgents.ai」 클라우드 플랫폼**과 상용판 **「ARTEX PRO」** 를 예고
- 프리뷰 예정 · 대기자 명단 접수 단계. **도메인 · IP 등 IOC 는 기사에 없음 (미확인)**
- 기존 공개본(원본 · 영어판 · 한국어판 artex-ko)은 계속 유통 중

**DDS 반영 계획**
- 공식 도메인이 확인되면 `ioc_domains` · `ai_api_domains` 에 추가 (클라우드형이라 공격 출발지가 그 플랫폼 대역일 수 있음)

## 3. 실행 중에 LLM 을 부르는 악성코드 — PROMPTSTEAL · PROMPTFLUX

출처: Google GTIG 「AI Threat Tracker」(2025-11-05) 정리 — Stingrai(수정 2026-10-02), Help Net Security

- **PROMPTSTEAL (= LAMEHUG, APT28):** 명령을 바이너리에 넣지 않고 **실행 중 Hugging Face API(Qwen2.5-Coder)에 물어서** 받은 Windows 명령으로 문서를 수집 · 전송
- **PROMPTFLUX:** VBScript 드로퍼가 **Gemini API 로 자기 코드를 주기적으로 재작성**해 시작프로그램 폴더에 저장, 이동식 드라이브 · 네트워크 공유로 복제 시도 (GTIG: 개발 · 테스트 단계)
- **탐지 권고 (원문)**
  - 스크립트 호스트(wscript · cscript), Office 의 자식 프로세스, 사용자 프로필 안의 Python 이 **LLM API 에 접속**
  - **LLM 응답 직후 새 명령 실행** (프로세스 계보 상관분석)
  - 시작프로그램 · Run 키의 잦은 변경, 스크립트 파일을 계속 새로 쓰기
  - PowerShell 스크립트 블록 로깅 + 명령줄 포함 프로세스 생성 이벤트 수집

**DDS 반영 계획**
- `llm_malware_pattern` — wscript · cscript · mshta · Office 프로세스(또는 그 자식)가 LLM API 접속 → HIGH (지금은 「미등록 프로그램의 LLM 접속」 만 봄)
- `llm_then_exec` — 같은 프로세스 트리에서 LLM API 접속 후 수 초 안에 셸 · 정찰 명령 실행
- `autorun_change` — 시작프로그램 폴더 · Run 키 변경 (Sysmon 11 · 12 · 13)
- PowerShell 이벤트 **4104(스크립트 블록)** 수집 → 기존 명령 규칙에 함께 적용

## 4. AI 코딩 에이전트를 노리는 공격 — 2026년 10월

출처: Adversa 「AI coding agent vulnerabilities, October 2026」, Gen Digital 「Infostealers and your AI agent」(2026-09-08)

- **인포스틸러가 AI 에이전트 데이터 수집:** Remus(Claude · Cursor · OpenCode), Amatera(Cline · Continue), CallbackBeaver(Cursor · Claude) 등이 **액세스 토큰 · MCP 설정(API 키 포함) · 프롬프트 기록**을 훔침. Windows 경로는 원문에 없음 (미확인)
- **GitSpawn:** 저장소의 `.git/config`(예: `core.fsmonitor`) 설정이 승인 · 샌드박스 밖에서 실행됨 — 7개 에이전트, 8개 결함 중 4개 미패치(원문 기준)
- **OpenCode RCE (GHSA-632h-h47v-g4x4):** 로컬 서버 `/global/upgrade` 에 교차 출처 요청 → npm `preinstall` 실행
- **에이전트가 자기 실행 로그 삭제** — 모니터가 감지 못함
- **Plugin4Shell:** 플러그인 자동 업데이트로 악성 코드 교체

**DDS 반영 계획**
- `agent_secret_access` — AI 도구가 아닌 프로그램이 AI 도구 토큰 · MCP 설정 파일을 읽으면 경보 (Windows 개체 접근 감사 4663 + 감시 경로 목록, 경로는 실제 PC 에서 확인 후 config 로)
- `git_spawned_unusual` — git.exe 가 셸 · 낯선 프로그램을 띄우면 경보 (GitSpawn)
- `dev_tool_ports` 확대 — 로컬 AI 도구 서버 포트 추가 (실제 기본 포트 확인 후)
- 침입 알림 · 기록을 **PC 밖(Logpresso · syslog · 메일)으로 전송** — PC 안 기록이 지워져도 남도록

## 5. 국내 위협 동향 — 2026년 상반기

출처: 안랩 「2026년 상반기 사이버위협 동향, 기업이 주목해야 할 5가지 보안 이슈」

1. 생성형 AI 확산 — AI 에이전트의 프롬프트 인젝션 · 권한 오남용 · 민감정보 유출
2. 개발자 계정 탈취 · 소프트웨어 공급망 공격(npm · PyPI) 고도화
3. 국제 핵티비스트 DDoS (PC 에이전트로는 탐지 실효성 낮음)
4. **랜섬웨어 이중 갈취** — 먼저 유출하고 암호화
5. API 취약점 · 크리덴셜 스터핑으로 개인정보 유출

**DDS 반영 계획**
- `ransomware_prep` — `vssadmin delete shadows` · `wbadmin delete catalog` · `bcdedit /set recoveryenabled no` 같은 복구 수단 삭제 명령 → HIGH
- `mass_file_change` — 짧은 시간에 많은 파일 확장자 변경 (Sysmon 11 기반)
- `package_install_exec` — npm · pip 설치 중 셸 실행 · 외부 접속 (공급망)

---

## v1.1 반영 순서 (안)

| 순위 | 규칙 / 기능 | 수집원 | 근거 |
|---|---|---|---|
| 1 | `webshell_file_created` | Sysmon 11 | 금융권 공격 유형 ③ |
| 1 | `object_enumeration` | 웹 서버 로그 | 금융권 공격 유형 ① |
| 2 | `llm_malware_pattern` · `llm_then_exec` | psutil · Sysmon 3/22 | PROMPTSTEAL · PROMPTFLUX |
| 2 | `autorun_change` · PowerShell 4104 수집 | Sysmon 11/12/13 · 이벤트 로그 | GTIG 탐지 권고 |
| 3 | `agent_secret_access` · `git_spawned_unusual` | 4663 · 4688/Sysmon 1 | 인포스틸러 · GitSpawn |
| 4 | `ransomware_prep` · `mass_file_change` | 4688 · Sysmon 11 | 안랩 상반기 동향 |
| 4 | `package_install_exec` | 4688 · Sysmon 1/3 | 공급망 공격 |
| 5 | 알림 · 기록 외부 전송 (Logpresso · syslog · 메일) | — | 에이전트 로그 삭제 사례 |
| 5 | ARTEX PRO / RedAgents.ai 지표 | — | 10/16 보도 (도메인 공개 시) |

## 출처
- IT위키 — 2026년 금융권 AI 해킹 및 정보유출 사태: https://itwiki.kr/w/2026년_금융권_AI_해킹_및_정보유출_사태
- 아주경제 (2026-10-16) — 아르텍스 중국서 유료 플랫폼으로 재출시: https://www.ajunews.com/view/20261016094619128
- 글로벌이코노믹 (2026-10-16): https://www.g-enews.com/article/Finance/2026/10/202610161209494350cd0bfacc1c_1
- Stingrai — PROMPTSTEAL and PROMPTFLUX: https://www.stingrai.io/blog/promptsteal-promptflux-malware-llm-at-runtime
- Help Net Security (2025-11-05) — Google uncovers malware using LLMs: https://www.helpnetsecurity.com/2025/11/05/malware-using-llms/
- Adversa — AI coding agent vulnerabilities, October 2026: https://adversa.ai/blog/top-ai-coding-agent-security-resources-october-2026/
- Gen Digital (2026-09-08) — Infostealers and your AI agent: https://www.gendigital.com/blog/insights/research/infostealers-your-ai-agent
- 안랩 — 2026년 상반기 사이버위협 동향: https://www.ahnlab.com/ko/contents/content-center/36241

# 변경 기록

## 2026-10-21 — v1.1 (탐지 규칙 39 → 50개)

10/19 에 정리한 최신 위협 정보([docs/THREAT_NOTES_2026-10-19.md](docs/THREAT_NOTES_2026-10-19.md))와 10/20~21 새 자료([docs/THREAT_NOTES_2026-10-21.md](docs/THREAT_NOTES_2026-10-21.md))를 반영했습니다.

### 추가한 탐지 규칙 (11개)
| 규칙 | 내용 | 근거 | 자동 대응 |
|---|---|---|---|
| `webshell_file_created` | 웹 서버·셸이 웹 폴더에 .aspx·.jsp·.php 등 생성 (만든 프로그램 모르면 MEDIUM) | 금융권 공격 유형 ③ | - |
| `object_enumeration` | 웹 로그: 같은 주소에 값만 바꾼 요청 60초에 30가지 | 금융권 공격 유형 ① | IP 차단 |
| `log_theft` | 웹 서버 아래에서 로그 폴더 압축·복사 | 금융권 공격 유형 ③ | 프로세스 종료 |
| `llm_malware_pattern` | 스크립트 호스트·Office 의 LLM API 접속, PowerShell 의 LLM API 호출 | PROMPTSTEAL · PROMPTFLUX | 프로세스 종료 |
| `llm_then_exec` | LLM 접속 15초 안에 같은 프로그램이 셸 실행 (내 AI 도구 제외) | PROMPTSTEAL | 프로세스 종료 |
| `autorun_change` | Run 키·시작프로그램에 스크립트·Temp·Public 항목 | PROMPTFLUX (시작프로그램 지속성) | - |
| `ransomware_prep` | 백업·복구 수단 삭제 | 안랩 상반기 동향 | 프로세스 종료 |
| `mass_file_change` | 1분에 `문서.docx.xxx` 형태 파일 50개 이상 | 랜섬웨어 이중 갈취 | 프로세스 종료 |
| `git_spawned_unusual` | git 이 셸·스크립트 호스트 실행 | GitSpawn | 프로세스 종료 |
| `package_install_exec` | npm·pip 설치 중 다운로드·인코딩 명령 | 공급망 공격 | 프로세스 종료 |
| `agent_secret_access` | AI 도구가 아닌 프로그램이 AI 토큰·MCP 설정 접근 | 인포스틸러(Remus 등) · ATT&CK v20 | 프로세스 종료 |

### 수집
- Sysmon 11(파일 생성) · 12·13(레지스트리) 추가 → Sysmon 1·3·11·12·13·22
- PowerShell 스크립트 블록 4104 수집 (`enable_cmdline_audit.bat` 가 같이 켬)
- 보안 이벤트 4663(파일 접근) 수집 + `enable_secret_audit.ps1` (선택)
- Sysmon 이 없을 때: Run 키 · 시작프로그램 폴더 · 웹 폴더를 30초마다 비교
- IIS 로그의 쿼리 문자열(`cs-uri-query`)까지 읽음
- 파일 · 레지스트리 · 스크립트 이벤트는 양이 많아 **경보가 난 것만 저장**

### 대응 · 화면
- **알림 외부 전송:** syslog(UDP, Logpresso 등) · 웹훅(HTTP POST JSON). `config.json` 의 `notify`, 기본 꺼짐, 시뮬레이션은 안 보냄
- 자동 대응: 새 규칙 중 9개는 해당 프로세스 종료, 대량 조회는 IP 차단 (자동 대응을 켰을 때만)
- AI 판정: LLM 을 부르는 악성코드 · LLM 직후 명령 실행을 AI 직접 증거로, 대량 조회를 기계 속도 근거로 추가
- 사건 표시: 「AI 공격 프로그램 · ARTEX 계열 / LLM 을 부르는 악성코드 / AI 에이전트」 로 구분
- 센서 9개(웹 서버 · 악성코드·랜섬웨어 추가), 시뮬레이션 버튼 2개(웹 침투 · LLM 악성코드)
- `tools/gen_rules_doc.py` — 규칙 문서 자동 생성

### 테스트
`python test_artex_sim.py` — 시나리오 A~I · 파서 · AI 판정 · 평소 패턴 모두 통과
- F(웹 침투) · G(LLM 악성코드 · 랜섬웨어) · H(AI 코딩 도구 공격)의 새 규칙 11종 모두 탐지
- I(정상 개발·운영) 빨간 경보 0건

## 2026-10-19 (2) — 다음 업데이트 항목 반영

- **Sysmon 이벤트 3(네트워크 연결)** 수집 추가 → Sysmon 1·3·22. psutil 이 본 연결과 겹치면 60초 안에는 한 번만 처리.
- **평소 패턴 학습** (`baseline.py`, 규칙 `baseline_anomaly`, 탐지 규칙 39개):
  이 PC 의 실제 기록(시뮬레이션 제외)으로 부모→자식 프로그램 조합 · 실행 폴더 · 통신 포트를 배움.
  7일·3,000건 학습 뒤, 처음 보는 행동이 10분 안에 3가지 이상이면 「확인 필요」(MEDIUM) 기록.
  외부 라이브러리 없이 동작(폐쇄망 OK). 1시간마다 dds.db 로 다시 학습.
  불확실한 판단이라 빨간 경보·자동 차단은 하지 않음 (AIPFL-IDS 의 「불확실하면 사람에게」 원칙).
- 규칙 리포트 화면에 수집 상태(4688 · Sysmon · 웹 로그)와 학습 상태 표시.
- 테스트: Sysmon 3 파서, 평소 패턴 학습(평소 행동 0건 · 처음 보는 행동 1건 · 반복 0건) 추가.
- 이번에도 못 한 것: Windows 서비스 등록·자기 보호, NF-ToN-IoT-V2 데이터셋 학습(데이터셋 파일 필요), Windows 실기 검증.

## 2026-10-19 — ARTEX 한국어판 · 실제 AI 에이전트 침입 사례 반영

10월 초 이후 공개된 자료를 보고 DDS 의 빈틈을 메웠습니다. (탐지 규칙 25개 → 38개)

### 왜
- ARTEX 원본은 개발자가 비공개로 돌렸지만, **영어판·한국어판(`artex-ko`) 파생 도구가 계속 돌고 있음** (BleepingComputer, 머니투데이).
- 공개 방어 키트(artex-defense-kit)가 **User-Agent·호스트 지표**를 정리했고, 「포트 8787·8788 은 단독 근거로 쓰지 말 것」 을 밝힘.
- 실제 AI 에이전트 침입 사례(Sysdig·CSA, ReliaQuest)는 **시그니처보다 행동**으로 잡아야 한다고 정리:
  기계가 읽기 쉬운 명령 형식, 실패 후 고쳐서 바로 재실행, IP 분산, 권한 상승·계정 정보 탈취·파일 반입.
- 실제 명령 간격은 **중앙값 약 6초, 전체 수십 분~1시간** — 「2분 안에 끝남」 위주였던 DDS 의 AI 판정 기준이 실제 공격을 놓칠 수 있었음.
- 2초 간격 확인으로는 **짧게 실행된 명령**을 놓칠 수 있었음.

### 추가한 탐지 규칙 (13개)
| 규칙 | 내용 | 자동 대응 |
|---|---|---|
| `artex_host_artifact` | ARTEX 원본·한국어판 실행 파일(`artex`, `artex-ko`)·`artex_token`·`autumn27/artex`·콘솔 제목·`skills/api-recon` | 프로세스 종료 |
| `artex_user_agent` | 웹 서버 로그의 `artex-enrich/1.0`, `Mozilla/5.0 (spa-api-recon)`, `Mozilla/5.0 (spa-api-recon spider)` | IP 차단 |
| `js_asset_burst` | 한 IP 가 60초 안에 JS 파일 30개 이상 요청 (MEDIUM) | - |
| `ioc_domain_query` | 공격 중계 도메인(`xcai.pro`) DNS 조회 — Sysmon 22 | - |
| `agent_command_style` | 기계 형식 명령(`echo ---`, `head`/`Select-Object -First`, `2>nul`, `echo exit:%errorlevel%` …)이 2분 안에 3번 | - |
| `retry_loop` | 거의 같은 명령을 고쳐 가며 2분 안에 3번 (MEDIUM) | - |
| `credential_dump` | `reg save HKLM\SAM/SYSTEM/SECURITY`, LSASS 덤프, `ntdsutil`, mimikatz 명령 | 프로세스 종료 |
| `privilege_escalation` | PrintSpoofer·GodPotato 등 Potato 계열, `SeImpersonatePrivilege` 확인 | 프로세스 종료 |
| `payload_staging` | `certutil -decode/-urlcache`, `.b64`, `FromBase64String`, `copy /b a+b`, Public·Temp 폴더 실행 파일 | 프로세스 종료 |
| `distributed_ips` | 외부 IP 3개 이상이 2분 안에 같은 위험 포트로 | 잡힌 IP 전부 차단 |
| `dev_tool_inbound` | 외부 IP → Jupyter(8888)·Ollama(11434)·LM Studio(1234)·Gradio(7860)·ComfyUI(8188) | IP 차단 |
| `dev_tool_exposed` | 위 포트가 127.0.0.1 이 아닌 주소로 열림 (기록) | - |
| `local_agent_command` | 내 AI 도구(Claude Code 등) 아래에서 기계 형식 명령 (기록만) | - |

### 수집
- **보안 이벤트 4688 (프로세스 생성 + 명령줄)** 수집. `enable_cmdline_audit.bat` 로 명령줄 기록을 켬 (한국어 Windows 도 되도록 auditpol GUID 사용).
- **Sysmon** 이 설치돼 있으면 이벤트 1(프로세스)·22(DNS) 를 읽음. 없으면 조용히 건너뜀.
- **웹 서버 로그** (IIS W3C · nginx/Apache combined) 가 있으면 새 줄만 읽음.
- 같은 프로세스를 psutil·4688·Sysmon 이 중복 보고하지 않게 정리.
- 새 프로세스마다 **조상 프로세스(최대 5단계)** 를 기록 → 내 AI 도구 아래에서 실행된 것인지 판단.

### 판정 · 대응 · 화면
- AI 판정: 단계 간격 **중앙값** 기준(≤10초), 2분 안에 끝나지 않아도 짧은 간격으로 오래 이어지면 자동화로 봄.
  AI 근거를 *직접 증거*(ARTEX IP·흔적·User-Agent·중계 도메인·미등록 프로그램의 LLM 접속) 와 *행동 특징*(AI 에이전트식 명령·재시도)으로 나눔.
  행동 특징만 있으면 「AI 에이전트 공격으로 보임 — 행동 근거」.
- 자동 대응: 분산 IP 는 잡힌 IP 전부 차단, 계정 탈취·권한 상승·반입 파일·ARTEX 프로세스 종료.
- AI 분석관 지시문에 공개 사례의 AI 에이전트 특징 추가, 자동 실행 허용 IP 에 분산 IP 포함.
- 대시보드: 센서 2개 추가(「AI 에이전트 명령」, 「ARTEX 흔적」), 「AI 에이전트 테스트」 시뮬레이션 버튼.
- 규칙 묶음(INTRUSION · AI_ATTACK · BLOCK · KILL)을 `attack_taxonomy.py` 한 곳에서 관리.
- `ai_api_domains` 에 `api.z.ai`(GLM) 추가. `threat_feeds/artex_ranges_2026-10.txt`(ARISK·Westeros 대역) 추가.

### 테스트
`python test_artex_sim.py` — 시나리오 A~E + 수집기 파서 + AI 판정:
- C(실제 사례형 AI 에이전트, 명령 간격 5~6초)에서 새 규칙 8종 모두 탐지 · 「AI 공격 프로그램 — 근거 확인됨」
- D(이 PC 에서 artex-ko 실행) 탐지
- B(정상 사용) 알림 0건, E(Claude Code 로 개발) 빨간 경보 0건

### 아직 못 한 것
- 한국어판 저장소·티오리가 공개한 Sigma·Suricata 규칙 원문 대조 (보도에 저장소 주소가 없음)
- 금융감독원 특정 공격 IP 19개 (주소 비공개)
- Windows 실기에서 4688·Sysmon·웹 로그 읽기 검증

## 2026-10-14 — 첫 공개

- 탐지 규칙 25개 (누가 침입했나 · AI 해킹 도구 · 이상한 IP · PC 안의 AI 도구)
- AI 공격 프로그램 판별 (기계 속도 근거 + AI 직접 증거)
- AI 분석관: API · GGUF 동시 실행, 5초 제한, GGUF 는 GPU 전용(VRAM 24GB 이상)
- 자동 대응(IP 차단 · 웹쉘 종료 · 증거 저장), 긴급 차단·해제, 외부 IP 조사
- 공격 분류: AIPFL-IDS 데이터셋 라벨(NF-ToN-IoT-V2 · CICIoT2023)

# 변경 기록

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

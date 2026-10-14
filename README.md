# StayThere-IDS (DDS) — 개인 PC 침입 · AI 해킹 도구 탐지 시스템

> **누가 들어왔는지**, **어떤 프로그램(AI 해킹 도구 포함)이 무엇을 했는지** 실시간으로 잡고, 확실한 침입은 바로 막는 Windows 개인 PC용 보안 에이전트입니다.
> 2026년 10월 한국 금융권 공격에 쓰인 중국산 AI 침투 도구 **ARTEX** 같은 'AI 가 지휘하는 자동 해킹' 을 막는 것을 목표로 만들었습니다.

> 📚 **참고 프로젝트:** 이 프로젝트는 [**AIPFL-IDS**](https://github.com/PrathamWankhade/AIPFL-IDS) (Pratham Wankhade, MIT License)를 참고해서 만들었습니다. 공격 분류 체계(NF-ToN-IoT-V2 · CICIoT2023 라벨), 데이터 전처리 방식, 「불확실한 판단은 자동 차단하지 않고 사람에게 넘긴다」는 설계 원칙을 가져왔습니다. 자세한 내용은 [참고 자료와 출처](#참고-자료와-출처)에 있습니다.

![실시간 감시 — AI 해킹 도구 침입 경보](docs/images/02_ai_alert.png)

---

## 목차
- [왜 만들었나](#왜-만들었나)
- [주요 기능](#주요-기능)
- [화면](#화면)
- [동작 구조](#동작-구조)
- [설치와 실행](#설치와-실행)
- [AI 분석관 (API · GGUF)](#ai-분석관-api--gguf)
- [폴더 구조](#폴더-구조)
- [설정](#설정)
- [안전 설계](#안전-설계)
- [다음 업데이트와 한계](#다음-업데이트와-한계)
- [참고 자료와 출처](#참고-자료와-출처)
- [주의](#주의)

---

## 왜 만들었나

CrowdStrike 는 2026년 9월 말~10월 초 한국 금융기관 공격에서 중국에서 공개된 **AI 기반 자동 침투 도구 ARTEX** 가 쓰였다고 보고했습니다. 공격자는 LLM(DeepSeek 등)을 붙인 ARTEX 로 웹 서비스를 찾아 들어가 데이터를 빼냈습니다. ([출처](#참고-자료와-출처))

이런 공격은 **사람보다 훨씬 빠르고**(DDS 시뮬레이션에서는 스캔 → 웹쉘 → 정찰 → 역접속 6단계가 7초), **IP·수법을 계속 바꿉니다.** 그래서 DDS 는

1. **규칙**으로 확실한 침입을 2초 단위로 잡아 바로 막고,
2. **'AI 공격 프로그램인가?'** 를 기계 속도·AI 직접 증거로 따로 판별하고,
3. **AI 분석관(LLM)** 이 사건을 읽고 판단하는 — *AI 는 AI 로 대응하는* 구조로 만들었습니다.

---

## 주요 기능

| 기능 | 설명 |
|---|---|
| **실시간 감시** | 2초마다 프로세스 · 네트워크 연결 · Windows 로그인 기록(보안 이벤트 4624/4625/4648/4672/4720/4732)을 수집 |
| **외부 침입만 경보** | 포트 스캔, ARTEX 공격 IP, 웹쉘, 정찰 명령 연속 실행, 비밀번호 대입, 외부 RDP 로그인, 계정 생성·관리자 권한 획득 등 **외부에서 들어온 흔적**만 빨간 경보. 사용자가 쓰는 AI 프로그램(ChatGPT·Claude·Cursor 등)은 침입이 아니므로 기록만 |
| **이상한 IP 감시** | 위험 포트(RDP·SMB·WinRM 등)로 들어온 외부 IP, powershell·certutil 같은 시스템 도구의 외부 접속(원격 조종 의심), 해킹 도구 포트(4444·1337·9050 등), 이 PC 가 다른 PC 들을 스캔(감염·확산 신호), 위협 목록 파일(IP·CIDR) 대조 |
| **AI 공격 프로그램 판별** | *기계 속도 근거*(단계 간격·소요 시간·스캔 속도) + *AI 직접 증거*(ARTEX IP·LLM 중계 서버 통신·미등록 프로그램의 LLM 접속)로 「AI 공격 프로그램 / 자동화 도구 / 사람」 판정 |
| **AI 분석관** | 침입이 잡히면 1.5초 뒤 자동으로 LLM 이 사건을 분석해 판정·확신·근거·추천 조치를 냄. **API 와 GGUF 를 동시에 돌려 먼저 끝난 답을 사용 (5초 제한)** |
| **GGUF 바로 실행** | `GGUF` 폴더에 모델을 넣으면 시작과 동시에 1개를 항상 GPU 에 로드(llama-cpp-python 직접 로드, Ollama 불필요). API 주소·키가 없거나 끊기면 GGUF 가 바로 대신함. **GPU 전용 — NVIDIA VRAM 24GB 이상, CPU 실행은 지원하지 않음** |
| **즉각 대응 (자동 대응 스위치)** | 확실한 외부 침입은 출발지 IP 를 Windows 방화벽으로 즉시 차단 · 웹쉘 프로세스 종료 · 증거 자동 저장. 내부망·신뢰 IP 는 자동 차단 안 함 |
| **긴급 차단 / 해제** | 버튼 하나로 PC 네트워크 전체 격리(들어옴·나감 차단) + 공격 프로세스 종료 + 증거 저장. 해제 버튼 · `emergency_release.bat` 로 격리 전 방화벽 정책 복구 |
| **외부 IP 조사** | IP 하나를 넣으면 ARTEX IP 여부 · 지금 연결 · 탐지 기록 · 로그인 시도 · 차단 여부를 한 번에 보고, 그 IP 가 채워진 CMD 명령어를 줌 (`check_ip.bat` 로 CMD 에서도 가능) |
| **공격 분류** | 탐지 규칙마다 AIPFL-IDS 데이터셋 라벨(NF-ToN-IoT-V2 / CICIoT2023)을 붙여 「Scanning → Injection → Backdoor」 처럼 공격 단계를 보여줌 |
| **알림** | 외부 침입이면 Windows 알림 + 경고음 + 대시보드 자동 열림. AI 분석은 「API 실행 중… → 끝났어요」 진행 상황 표시 |

전체 탐지 규칙 25개와 기준값은 **[docs/DETECTION_RULES.md](docs/DETECTION_RULES.md)** 에 있습니다.

---

## 화면

> 아래 화면은 개발 환경(Linux)에서 **시뮬레이션 버튼**으로 만든 것입니다. 그래서 위쪽에 「pywin32 미설치 → 로그인 탐지 꺼짐」 줄이 보이고, AI 분석 결과는 테스트용 API 의 응답입니다. Windows 에서 관리자 권한으로 실행하면 이 경고줄은 사라집니다.

| 평상시 | 해커 침입 경보 |
|---|---|
| ![평상시](docs/images/01_live.png) | ![해커 침입](docs/images/04_hacker_alert.png) |

| AI 공격 프로그램 판별 + AI 분석관 | 이상한 IP 경보 |
|---|---|
| ![판별](docs/images/03_ai_judge_and_analyst.png) | ![이상 IP](docs/images/05_suspicious_ip_alert.png) |

| 외부 IP 조사 | AI 분석관 설정 (API · GGUF) |
|---|---|
| ![IP 조사](docs/images/06_ip_check.png) | ![AI 분석관](docs/images/08_ai_analyst.png) |

| 침입 기록 | 규칙 리포트 |
|---|---|
| ![침입 기록](docs/images/07_history.png) | ![규칙 리포트](docs/images/09_rules.png) |

| 조치 가이드 | 긴급 차단 중 |
|---|---|
| ![조치 가이드](docs/images/10_guide.png) | ![긴급 차단](docs/images/11_emergency.png) |

---

## 동작 구조

```mermaid
flowchart LR
  subgraph PC["Windows PC"]
    C1["프로세스<br/>(psutil)"] --> M
    C2["네트워크 연결<br/>(psutil)"] --> M
    C3["로그인 기록<br/>(Security 이벤트 · pywin32)"] --> M
    M["monitor.py<br/>2초 주기 수집"] --> D["detectors.py<br/>탐지 규칙 25개"]
    D --> DB[("dds.db<br/>SQLite")]
    D --> R["responder.py<br/>알림 · 자동 차단 · 긴급 격리"]
    R --> FW["Windows 방화벽<br/>(netsh)"]
    R --> A["llm.py<br/>AI 분석관"]
    A -->|동시 실행| API["LLM API<br/>(OpenAI 호환 · Anthropic)"]
    A -->|동시 실행| G["GGUF 폴더 모델<br/>(llama-cpp-python)"]
    DB --> W["webui.py<br/>127.0.0.1:8765 대시보드"]
    A --> W
  end
```

**대응 순서 — 해킹은 속도전이라 AI 판단을 기다리지 않습니다.**

1. **규칙 탐지 (2초 주기)** → 확실한 외부 침입이면 자동 대응이 바로 차단·종료 (스위치를 켰을 때)
2. **AI 공격 프로그램 판별** → 기계 속도 + AI 직접 증거로 즉시 계산 (LLM 불필요)
3. **AI 분석관 (5초 제한)** → API·GGUF 동시 실행, 먼저 끝난 답으로 판정·추천 조치. 「AI 판단 자동 실행」을 켜면 확신 80 이상일 때 실행
4. **긴급 차단** → 사람이 판단해 PC 전체 격리

---

## 설치와 실행

### 필요한 것
- Windows 10 / 11
- Python 3.9 이상
- **관리자 권한** (로그인 기록 읽기 · 방화벽 차단에 필요)
- **AI 분석관을 GGUF 로 쓸 때만:** NVIDIA GPU **VRAM 24GB 이상** + llama-cpp-python **CUDA 빌드**. **CPU 로는 GGUF 를 실행하지 않습니다.**
  (탐지 · 차단 · 자동 대응 · 긴급 차단은 GPU 없이 동작합니다)

### 실행
```bat
git clone https://github.com/junryge/python_StayThere-IDS.git
cd python_StayThere-IDS
run_dds.bat
```
`run_dds.bat` 를 더블클릭해도 됩니다. 관리자 권한을 요청하고, `psutil`·`pywin32` 가 없으면 설치한 뒤 대시보드(http://127.0.0.1:8765)를 엽니다. 끄려면 검은 창에서 `Ctrl+C`.

직접 실행:
```bat
python -m pip install -r requirements.txt
python dds_agent.py            :: 감시 시작 + 대시보드 자동 열림
python dds_agent.py --alerts   :: 최근 알림만 출력
```

폐쇄망(사내 PyPI 미러)이라면:
```bat
python -m pip install -r requirements.txt --index-url <사내 PyPI 주소> --trusted-host <호스트>
```

### 동작 확인 (시뮬레이션)
대시보드의 **AI 도구 침입 테스트 / 해커 침입 테스트 / 이상 IP 테스트** 버튼은 가짜 공격 기록을 탐지기에 넣어 화면이 어떻게 바뀌는지 보여 줍니다. 시뮬레이션 중의 차단·종료는 **실제로 실행되지 않고** 「[시뮬레이션]」 으로만 표시됩니다.

화면 없이 규칙만 확인:
```bat
python test_artex_sim.py
```

### 그 밖의 도구
| 파일 | 용도 |
|---|---|
| `check_ip.bat` / `python ip_check.py <IP>` | 외부 IP 조사 (DDS 가 꺼져 있어도 동작) |
| `emergency_release.bat` | 대시보드가 안 열릴 때 긴급 차단 해제. `--all-ip` 를 붙이면 DDS 가 넣은 IP 차단 규칙도 전부 삭제 |

---

## AI 분석관 (API · GGUF)

자세한 내용: **[docs/AI_ANALYST.md](docs/AI_ANALYST.md)**

- **GGUF 없이도 DDS 는 그대로 동작합니다.** 탐지 · AI 공격 프로그램 판별 · 자동 대응 · 긴급 차단은 LLM 과 상관없이 돌아가고, AI 분석관만 「꺼짐 (모델 없음)」 으로 표시됩니다.
- **GGUF 사용 — GPU 전용 (NVIDIA VRAM 24GB 이상, CPU 지원 안 함):** `GGUF` 폴더에 `.gguf` 파일을 넣으면 끝. 작은(빠른) 모델이 1번으로 항상 GPU 에 올라가고, 큰 모델은 2번(1번 실패 시 교체)으로 배정됩니다. VRAM 이 모자라면 GPU 레이어를 40 → 20 으로 줄여 다시 시도하고, CPU 로는 내려가지 않습니다. llama-cpp-python 은 **CUDA 빌드**가 필요합니다 (설치 방법: [docs/AI_ANALYST.md](docs/AI_ANALYST.md)). CPU 빌드면 GGUF 는 실행하지 않고 화면에 이유를 표시합니다.
- **API 사용:** 대시보드 → AI 분석관 → 주소 · 키 · 모델 입력. OpenAI 호환(OpenAI · vLLM · Ollama · LM Studio · 사내 게이트웨이) 과 Anthropic 형식을 지원합니다. 키는 이 PC 의 `llm_config.json` 에만 저장되고 저장소에는 올라가지 않습니다(`.gitignore`).
- **5초 안에:** API 와 GGUF 를 동시에 돌려 먼저 끝난 정상 답을 씁니다. API 는 5초 넘으면 버리고, GGUF 는 5초에서 생성을 끊고 판정·확신만이라도 살립니다. GGUF 는 기본으로 모든 레이어를 GPU 에 올립니다(`GPU 레이어 = -1`).

---

## 폴더 구조

```
DDS/
├─ dds_agent.py          실행 진입점 (감시 시작 + 대시보드 서버)
├─ monitor.py            수집 루프 · 침입 시뮬레이션 시나리오 3종
├─ collectors.py         프로세스 · 네트워크 · Windows 로그인 기록 수집
├─ detectors.py          탐지 규칙 25개 (+ 위협 목록 파일 대조)
├─ attack_taxonomy.py    규칙 설명 · AIPFL-IDS 공격 분류 연결표
├─ responder.py          알림 · 자동 대응 · 방화벽 차단/해제 · 긴급 격리
├─ llm.py                AI 분석관 (API · GGUF 동시 실행, 폴더 감시, 진행 상황)
├─ webui.py              대시보드 서버 · API (127.0.0.1 전용)
├─ storage.py            SQLite 저장소
├─ ip_check.py           외부 IP 조사 (CMD 겸용)
├─ emergency_release.py  긴급 차단 비상 해제
├─ test_artex_sim.py     ARTEX 공격 흐름 규칙 테스트
├─ config.json           탐지 기준 · ARTEX IOC · 감시 목록
├─ static/               대시보드 화면 (index.html, A1_D.jpg)
├─ GGUF/                 ← .gguf 모델을 넣는 곳 (저장소에는 안 올라감)
├─ threat_feeds/         ← 위협 IP·CIDR 목록 .txt (예시만 올라감)
├─ ml/                   NF-ToN-IoT-V2 학습 스크립트 (AIPFL-IDS 전처리 참고)
├─ docs/                 규칙 목록 · AI 분석관 설명 · 화면 캡처
├─ run_dds.bat · check_ip.bat · emergency_release.bat
└─ requirements.txt · requirements-ai.txt
```

실행하면 생기는 `dds.db`(수집 기록), `evidence/`(증거 파일), `llm_config.json`(API 키)은 **실제 PC 정보가 들어 있어 `.gitignore` 로 올리지 않습니다.**

---

## 설정

`config.json` 주요 항목 (전체는 [docs/DETECTION_RULES.md](docs/DETECTION_RULES.md))

| 항목 | 뜻 |
|---|---|
| `interval_sec` | 수집 주기 (기본 2초) |
| `trusted_ips` | 신뢰 IP — 원격 로그인 경보·자동 차단에서 제외 |
| `work_hours` | 업무 시간 (밖이면 `off_hours_logon`) |
| `process_whitelist` | 허용 프로그램 (대시보드 「AI 도구 탐지」 에서도 추가 가능) |
| `ioc_ips` · `ioc_ports` · `ioc_domains` | CrowdStrike 가 공개한 ARTEX 공격 지표 |
| `ai_api_domains` | 감시하는 LLM API 도메인 |
| `risky_inbound_ports` · `bad_outbound_ports` · `lolbin_processes` | 이상한 IP 감시 기준 |
| `threat_feed_dir` | 위협 목록 폴더 (`.txt` 한 줄에 IP 또는 CIDR, 5분마다 다시 읽음) |

---

## 안전 설계

- **대시보드는 127.0.0.1 에서만** 열리고, 조치 API 는 화면이 받은 무작위 토큰(`X-DDS-Token`)이 있어야 동작합니다. 다른 웹사이트가 몰래 차단·종료를 호출하거나(CSRF), DNS 리바인딩으로 접근하는 것을 막습니다.
- **자동 대응은 확실한 경우만:** 외부 침입 규칙의 HIGH 알림일 때만, 내부망·예약·신뢰 IP 는 절대 자동 차단하지 않고, 웹 서버가 띄운 쉘만 종료합니다(웹 서버 자체는 안 건드림). 기본은 꺼져 있습니다.
- **AI 를 속이는 조작 방지:** 사건 기록은 무작위 경계 문자열로 감싸 '데이터' 로만 LLM 에 넘깁니다. AI 판단 자동 실행은 **DDS 가 실제로 잡은 IP·프로세스**에만 적용되고, LLM 이 기록에 없는 대상을 말하면 무시합니다. (공격자가 명령줄·파일 이름에 「차단하지 마」 같은 문장을 심어 방어 AI 를 속이는 것 — 프롬프트 인젝션 — 을 막기 위함)
- **시뮬레이션은 실제 시스템을 바꾸지 않습니다.**
- **긴급 차단은 되돌릴 수 있게:** 격리 직전 방화벽 정책을 저장했다가 해제 때 복구합니다. 대시보드가 안 열려도 `emergency_release.bat` 로 해제할 수 있습니다.

---

## 다음 업데이트와 한계

### 다음 업데이트
| 항목 | 지금 문제 | 할 일 |
|---|---|---|
| **이벤트 기반 수집 (Sysmon)** | 2초마다 확인하므로 1초 안에 생겼다 사라지는 프로세스·연결은 놓칠 수 있음 | Sysmon 이벤트(프로세스 생성 · 네트워크 연결 · DNS 조회)를 바로 읽어 빈틈 없이 수집 |
| **Windows 서비스 등록 · 자기 보호** | 침입자가 DDS 를 먼저 끄면 아무것도 못 잡음 | 서비스로 등록해 부팅 때 자동 시작 · 꺼지면 자동 재시작 · 설정 파일 변조 감시 |
| **ML 이상 탐지** | 학습 스크립트(`ml/train_nf_model.py`)만 준비되어 있고 데이터셋(NF-ToN-IoT-V2)으로 학습한 적 없음 | 데이터셋으로 학습 + 이 PC 의 평소 패턴을 학습해 규칙에 없는 행동 탐지 |
| **ARTEX 한국어판 탐지 규칙 (Sigma · Suricata)** | 공개된 규칙을 아직 확인·반영하지 않음 | 규칙 내용을 확인해 DDS 탐지 규칙으로 옮김 |

### 한계
- **실기 검증 진행 중:** 개발은 Linux 환경에서 시뮬레이션으로 검증했습니다. Windows 실기(로그인 기록 파싱, netsh 차단, 알림, 긴급 격리)는 검증 중입니다.
- **AI 분석관(GGUF)은 GPU 전용:** NVIDIA GPU VRAM 24GB 이상이 필요하고 CPU 실행은 지원하지 않습니다.
- **PC 단위:** 이 PC 에서 일어난 일만 봅니다. ARTEX 처럼 서버를 노리는 공격은 서버에도 설치해야 합니다.
- **기준값은 초기값:** 탐지 기준(포트 수·시간 창 등)은 실제 데이터로 조정이 필요합니다.
- **IOC 는 공개 보고서 1건 기준:** 위협 목록 파일(`threat_feeds/`)로 보강하세요.

---

## 참고 자료와 출처

### 위협 정보 (ARTEX)
- **CrowdStrike** — *Unknown Threat Actor Uses AI-Driven ARTEX to Target South Korean Finance* (2026-10)
  https://www.crowdstrike.com/en-us/blog/unknown-threat-actor-uses-artex-to-target-south-korean-finance/
  → `config.json` 의 `ioc_ips`(공격자 서버 1개 + 프록시 9개), `ioc_ports`(18899), `ioc_domains`(xcai.pro), 공격 흐름(웹 서비스 침투 · LLM 백엔드 사용) 은 이 보고서의 공개 지표입니다. 보고서는 공격 IP 를 `38.244.50[.]120` 처럼 표기하며, DDS 는 대조를 위해 `[.]` 를 `.` 로 바꿔 넣었습니다.
- **supple.kr** — 「금융권 해킹 도구 '아르텍스' 한국어판 등장…탐지규칙도 공개」
  https://supple.kr/news/cmuxv26le00cj12b3dbbnnk8n
  → ARTEX 한국어판 공개와 「수정 없이 쓰면 탐지되지만, AI 가 방법을 바꾸면 100% 탐지는 어렵다」 는 전문가 의견. DDS 가 IOC 대조만이 아니라 **행동 기반 규칙**(속도·웹쉘·정찰·이상 IP)을 중심에 둔 이유입니다.
- **supple.kr** — 「한국 금융권 해킹에 등장한 '아르텍스' 결국 공개 중단」
  https://supple.kr/news/cmv1r347y001joesfedzu1o00

### 침입 탐지 연구 · 데이터셋
- **AIPFL-IDS** (Pratham Wankhade, MIT License) — https://github.com/PrathamWankhade/AIPFL-IDS (참고 시점 커밋 `dbcbad7`, 2026-10-14)
  참고한 부분:
  - 공격 라벨 체계 — NF-ToN-IoT-V2 10종(`Attack` 컬럼), CICIoT2023 34종 → 10종 병합표(`backend/train.py` 의 `CICIOT_CLASS_MAP`) → `attack_taxonomy.py` 의 공격 분류
  - 전처리 방식 — 클래스당 최대 50,000행 균형 샘플링, inf/NaN 처리, 극단값 1e15 클리핑, 상수 컬럼 제거, 식별자 컬럼 제외, 20% 층화 분할(`backend/config.py`, `backend/src/preprocessing.py`) → `ml/train_nf_model.py` 에서 다시 구현 (모델은 TensorFlow DNN 대신 scikit-learn HistGradientBoosting)
  - 설계 원칙 — 「불확실한 판단은 자동 차단하지 말고 사람에게 넘긴다」(`backend/src/drift.py` 설명) → 자동 대응을 확실한 경우로 제한한 근거
  - 이 저장소의 코드를 그대로 복사해 넣지는 않았습니다.
- **NF-ToN-IoT-V2** · **CICIoT2023** 데이터셋 — AIPFL-IDS 가 사용하는 Kaggle 배포본(`dhoogla/nftoniotv2`, `dhoogla/ciciot2023`)을 기준으로 했습니다. 원 데이터셋은 각각 University of Queensland 연구진, Canadian Institute for Cybersecurity(UNB)가 공개했습니다. 데이터셋 파일은 이 저장소에 포함되어 있지 않습니다.

### 보안 지식
- **Microsoft Windows 보안 감사 이벤트** — 4624(로그인 성공) · 4625(실패) · 4648(명시적 자격 증명) · 4672(관리자 권한 로그인) · 4720(계정 생성) · 4732(그룹 추가), `netsh advfirewall` 방화벽 명령
- **LOLBAS 프로젝트** — 공격자가 악용하는 Windows 기본 도구(LOLBins) 개념 https://lolbas-project.github.io/ → `lolbin_processes`
- **MITRE ATT&CK** — https://attack.mitre.org/ (CrowdStrike 보고서의 기법 분류 T1583.003 · T1588.007 · T1090)

### 사용한 오픈소스
| 이름 | 용도 | 라이선스 |
|---|---|---|
| [psutil](https://github.com/giampaolo/psutil) | 프로세스·네트워크 수집 | BSD-3-Clause |
| [pywin32](https://github.com/mhammond/pywin32) | Windows 보안 이벤트 로그 읽기 | PSF |
| [llama-cpp-python](https://github.com/abetlen/llama-cpp-python) | GGUF 모델 직접 실행 | MIT |
| scikit-learn · pandas · pyarrow · joblib | ML 학습 스크립트 (선택) | BSD-3-Clause / Apache-2.0 |
| Google Fonts — Do Hyeon · IBM Plex Sans KR · IBM Plex Mono | 대시보드 글꼴 (인터넷이 없으면 맑은 고딕으로 표시) | SIL OFL 1.1 |

### 디자인 · 이미지
- 대시보드 디자인: 프로젝트 제작자가 만든 UI 샘플(「StayThere」)의 색·글꼴·배치를 바탕으로 제작
- 침입 경보 이미지(`static/A1_D.jpg`, 원본 `A1_D.png`): 프로젝트 제작자 제공 이미지

---

## 주의

- **방어 목적 전용**입니다. 자신이 관리하는 PC 에서만 사용하세요.
- 자동 대응 · 긴급 차단은 실제로 방화벽을 바꾸고 프로세스를 종료합니다. 처음에는 **자동 대응을 끈 상태**로 며칠 돌려 오탐을 확인한 뒤 켜는 것을 권합니다.
- 공개 IOC 는 시간이 지나면 다른 사람에게 재할당될 수 있습니다. 「미리 차단」 은 필요할 때만 쓰세요.

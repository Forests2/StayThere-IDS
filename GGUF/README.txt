이 폴더에 .gguf 모델 파일을 넣으면 DDS 가 시작할 때 자동으로 1개를 실행합니다.
- 작은(빠른) 모델 → 1번 (항상 실행 · 5초 안 판단)
- 큰 모델 → 2번 (1번이 실패하면 교체)
- 모델이 없어도 DDS 의 탐지 · 차단은 그대로 동작합니다 (AI 분석관만 꺼짐).
- GPU 전용: NVIDIA GPU VRAM 24GB 이상 + llama-cpp-python CUDA 빌드 필요. CPU 실행은 지원하지 않습니다.
  (설치 방법: docs/AI_ANALYST.md)
.gguf 파일은 용량이 커서 GitHub 에 올리지 않습니다 (.gitignore).

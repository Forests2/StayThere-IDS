#!/usr/bin/env bash
# DDS (StayThere-IDS) — Linux 실행 (화면에 계속 띄워 두는 방식, 끄려면 Ctrl+C)
#   sudo ./run_dds.sh
# psutil 이 없으면 설치: ./wheels 폴더가 있으면 그걸로(인터넷 불필요), 아니면 pip (PIP_INDEX 로 사내 미러 지정 가능)
set -e
cd "$(dirname "$0")"
if [ "$(id -u)" -ne 0 ]; then
  echo "root 권한이 필요해요 → sudo 로 다시 실행합니다"
  exec sudo -E "$0" "$@"
fi
PY=$(command -v python3 || true)
if [ -z "$PY" ]; then echo "python3 가 없어요 (Python 3.9 이상 필요)"; exit 1; fi
if ! "$PY" -c "import psutil" 2>/dev/null; then
  echo "psutil 설치 중..."
  if [ -d wheels ]; then
    "$PY" -m pip install --no-index --find-links wheels psutil
  elif [ -n "$PIP_INDEX" ]; then
    "$PY" -m pip install psutil --index-url "$PIP_INDEX" ${PIP_HOST:+--trusted-host "$PIP_HOST"}
  else
    "$PY" -m pip install psutil || { echo "설치 실패 — 폐쇄망이면 PIP_INDEX=<사내 PyPI 주소> 를 지정하세요"; exit 1; }
  fi
fi
command -v iptables >/dev/null || echo "[주의] iptables 가 없어서 IP 차단 · 긴급 격리는 동작하지 않아요"
PORT=$("$PY" -c "import json;print(json.load(open('config.json')).get('dashboard',{}).get('port',8765))")
HOST=$("$PY" -c "import json;print(json.load(open('config.json')).get('dashboard',{}).get('host','127.0.0.1'))")
if [ "$HOST" = "127.0.0.1" ]; then
  echo "대시보드: http://127.0.0.1:$PORT  (이 서버 안에서만 열림)"
  echo "  내 PC 에서 보려면:  ssh -L $PORT:127.0.0.1:$PORT <계정>@<이 서버>  → 내 PC 브라우저에서 http://127.0.0.1:$PORT"
else
  echo "대시보드: http://<이 서버 IP>:$PORT  (내부망 · 허용 IP · 비밀번호)"
fi
NB=""
if [ -z "$DISPLAY" ] && [ -z "$WAYLAND_DISPLAY" ]; then NB="--no-browser"; fi
exec "$PY" dds_agent.py $NB "$@"

#!/usr/bin/env bash
# 긴급 격리 해제 (대시보드가 안 열릴 때 · SSH 가 끊겼을 때 서버 콘솔에서)
#   sudo ./emergency_release.sh           격리만 해제
#   sudo ./emergency_release.sh --all-ip  DDS 가 넣은 IP 차단 규칙도 전부 삭제
cd "$(dirname "$0")"
if [ "$(id -u)" -ne 0 ]; then exec sudo "$0" "$@"; fi
exec python3 emergency_release.py "$@"

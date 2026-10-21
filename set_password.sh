#!/usr/bin/env bash
# 대시보드 비밀번호 설정 (내부망 다른 PC 에서 접속할 때 물어봄)
cd "$(dirname "$0")"
if [ "$(id -u)" -ne 0 ]; then exec sudo "$0" "$@"; fi
exec python3 dashauth.py

#!/usr/bin/env bash
# 외부 IP 조사 (DDS 가 꺼져 있어도 동작):  ./check_ip.sh 45.9.7.33
cd "$(dirname "$0")"
if [ -z "$1" ]; then read -r -p "조사할 IP: " IP; else IP="$1"; fi
exec python3 ip_check.py "$IP"

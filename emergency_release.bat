@echo off
chcp 65001 >nul
cd /d "%~dp0"
net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
  exit /b
)
echo ==== DDS 긴급 차단 해제 ====
python emergency_release.py %*
if %errorlevel% neq 0 (
  echo.
  echo python 실행이 안 되면 아래 명령으로 Windows 기본값 복구:
  echo   netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
  netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
)
pause

@echo off
chcp 65001 >nul
cd /d "%~dp0"
if "%~1"=="" (
  set /p TARGET=조사할 IP:
) else (
  set TARGET=%~1
)
python ip_check.py %TARGET%
pause

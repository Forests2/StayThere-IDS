@echo off
chcp 65001 >nul
:: DDS - 명령줄 기록 켜기 (보안 이벤트 4688 에 명령줄 포함 + PowerShell 스크립트 블록 4104)
:: 2초 사이에 생겼다 사라지는 명령(AI 에이전트가 자주 씀)까지 DDS 가 잡을 수 있게 합니다.
:: 끄기: enable_cmdline_audit.bat off
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo 관리자 권한을 요청합니다...
  if "%1"=="" (powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs") else (powershell -Command "Start-Process -FilePath '%~f0' -ArgumentList '%1' -Verb RunAs")
  exit /b
)
if /i "%1"=="off" goto off
:: 프로세스 만들기 감사 (한국어 Windows 에서도 되도록 GUID 사용)
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
:: PowerShell 스크립트 블록 기록 (이벤트 4104) — 난독화된 스크립트 내용까지 DDS 가 봄
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
echo.
echo 명령줄 기록(4688)과 PowerShell 스크립트 기록(4104)을 켰습니다. DDS 를 다시 시작하세요.
pause
exit /b
:off
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:disable
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /f
echo 명령줄 기록을 껐습니다.
pause

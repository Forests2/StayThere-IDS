# DDS - AI 도구 토큰 · MCP 설정 파일 접근 감사 켜기 (선택)
# 인포스틸러가 Claude · Cursor · Codex 토큰과 MCP 설정을 훔치는지 보려고, 이 파일들을 "읽으면 기록" 하도록 설정합니다.
# 관리자 PowerShell 에서:  powershell -ExecutionPolicy Bypass -File enable_secret_audit.ps1
# 끄기:                    powershell -ExecutionPolicy Bypass -File enable_secret_audit.ps1 -Off
param([switch]$Off)

# 파일 시스템 감사 (한국어 Windows 에서도 되도록 GUID 사용)
$guid = "{0CCE921D-69AE-11D9-BED3-505054503030}"
auditpol /set /subcategory:$guid /success:$(if ($Off) {"disable"} else {"enable"}) | Out-Null

# 감시할 경로 — 실제로 있는 것만 (config.json 의 secret_markers 와 맞춰 고치세요)
$targets = @(
  "$env:USERPROFILE\.claude", "$env:USERPROFILE\.claude.json", "$env:USERPROFILE\.cursor",
  "$env:USERPROFILE\.codex", "$env:USERPROFILE\.gemini", "$env:APPDATA\Claude\claude_desktop_config.json",
  "$env:USERPROFILE\.aws\credentials", "$env:USERPROFILE\.ssh"
) | Where-Object { Test-Path $_ }

$rule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone", "ReadData", "ContainerInherit,ObjectInherit", "None", "Success")
$ruleFile = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone", "ReadData", "Success")
foreach ($t in $targets) {
  $acl = Get-Acl -Path $t -Audit
  $r = if ((Get-Item $t).PSIsContainer) { $rule } else { $ruleFile }
  if ($Off) { [void]$acl.RemoveAuditRule($r) } else { $acl.AddAuditRule($r) }
  Set-Acl -Path $t -AclObject $acl
  Write-Host ($(if ($Off) {"감사 해제: "} else {"감사 설정: "}) + $t)
}
Write-Host "완료. DDS 는 보안 이벤트 4663 으로 이 파일들을 읽은 프로그램을 확인합니다 (AI 도구 자신은 제외)."

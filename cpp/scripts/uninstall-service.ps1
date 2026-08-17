# 卸载 Bulwark 用户态服务(需管理员)。停止并注销 BulwarkService,可选删除安装目录。
# 遵循产品原则:始终保留用户主动卸载路径,绝不做成"无法卸载"。
#
# 用法(管理员 PowerShell):
#   powershell -ExecutionPolicy Bypass -File cpp\scripts\uninstall-service.ps1
#   powershell -ExecutionPolicy Bypass -File cpp\scripts\uninstall-service.ps1 -RemoveFiles
[CmdletBinding()]
param(
  [string]$InstallDir = "$env:ProgramFiles\Bulwark",
  [switch]$RemoveFiles
)
$ErrorActionPreference = 'Stop'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw '请以管理员身份运行本脚本。'
}

Write-Host '== 停止服务 ==' -ForegroundColor Cyan
& sc.exe stop BulwarkService 2>&1 | Out-Host
Start-Sleep -Seconds 2

$exe = Join-Path $InstallDir 'bulwark_service.exe'
if (Test-Path $exe) {
  Write-Host '== 注销服务 (--uninstall) ==' -ForegroundColor Cyan
  & $exe --uninstall
} else {
  # 安装目录已不在,直接用 sc 删除服务登记项作为兜底。
  Write-Host '== 未找到 exe,直接 sc delete 兜底 ==' -ForegroundColor Yellow
  & sc.exe delete BulwarkService 2>&1 | Out-Host
}

# 也停掉可能在运行的 UI。
Get-Process -Name bulwark_ui -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

if ($RemoveFiles) {
  Write-Host "== 删除安装目录 $InstallDir ==" -ForegroundColor Cyan
  if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
  Write-Host '注意:%ProgramData%\Bulwark 下的日志/规则/隔离区已保留(如需彻底清理请手动删除)。' -ForegroundColor Yellow
}

Write-Host "`n完成。BulwarkService 已停止并注销。" -ForegroundColor Green

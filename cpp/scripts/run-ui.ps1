# 启动 Bulwark 桌面 UI。UI 通过命名管道 Bulwark.Control 连接后台服务,
# 因此请先确保 BulwarkService 已在运行(install-service.ps1),否则 UI 会显示未连接。
#
# 用法(普通权限即可):
#   powershell -ExecutionPolicy Bypass -File cpp\scripts\run-ui.ps1
# 优先启动已安装目录的 UI;未安装则回退到 cpp\dist\。
[CmdletBinding()]
param([string]$InstallDir = "$env:ProgramFiles\Bulwark")

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$cppDir = Split-Path -Parent $scriptDir
$candidates = @(
  (Join-Path $InstallDir 'bulwark_ui.exe'),
  (Join-Path $cppDir 'dist\bulwark_ui.exe')
)
$ui = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $ui) {
  Write-Host '未找到 bulwark_ui.exe。请先运行 package.ps1(生成 cpp\dist\)或 install-service.ps1。' -ForegroundColor Red
  exit 1
}

$svc = Get-Service -Name BulwarkService -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
  Write-Host '提示:BulwarkService 未运行,UI 将显示"未连接"。可先运行 install-service.ps1。' -ForegroundColor Yellow
}

Write-Host "启动 UI: $ui" -ForegroundColor Green
Start-Process -FilePath $ui

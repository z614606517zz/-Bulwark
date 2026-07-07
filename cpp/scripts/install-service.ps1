# 安装 Bulwark 用户态服务(需管理员)。把 cpp\dist\ 拷到 Program Files 并注册为自启动
# Windows 服务(SvcName=BulwarkService,与内核驱动服务 Bulwark 区分),随后启动。
#
# 前置:先跑 cpp\scripts\package.ps1 生成 cpp\dist\。
# 用法(管理员 PowerShell):
#   powershell -ExecutionPolicy Bypass -File cpp\scripts\install-service.ps1
[CmdletBinding()]
param([string]$InstallDir = "$env:ProgramFiles\Bulwark")
$ErrorActionPreference = 'Stop'

# 需要管理员权限(注册服务 + 写 Program Files)。
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw '请以管理员身份运行本脚本。'
}

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$cppDir = Split-Path -Parent $scriptDir
$distDir = Join-Path $cppDir 'dist'
$svc = Join-Path $distDir 'bulwark_service.exe'
if (-not (Test-Path $svc)) { throw "未找到 $svc,请先运行 package.ps1。" }

Write-Host "== 复制到 $InstallDir ==" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item (Join-Path $distDir '*') $InstallDir -Recurse -Force

Write-Host '== 注册并启动服务 BulwarkService ==' -ForegroundColor Cyan
$exe = Join-Path $InstallDir 'bulwark_service.exe'
& $exe --install
Start-Sleep -Seconds 1
& sc.exe start BulwarkService | Out-Host

Write-Host "`n完成。服务已安装为自启动。UI 可运行: `"$($InstallDir)\bulwark_ui.exe`"" -ForegroundColor Green
Write-Host '内核驱动(行为前拦截)默认关闭,需另行签名并加载 Bulwark.sys 后在设置里开启。' -ForegroundColor Yellow

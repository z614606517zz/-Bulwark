# Bulwark C++/Qt 打包脚本:Release 构建 + windeployqt 收集 Qt 运行时 -> cpp\dist\
#
# 产出一个自包含目录 cpp\dist\,内含 bulwark_service.exe + bulwark_ui.exe + 全部 Qt 运行时
# DLL/插件 + appsettings.json,可直接拷到目标机运行(无需装 Qt)。
#
# 用法(普通权限即可,构建不需管理员):
#   powershell -ExecutionPolicy Bypass -File cpp\scripts\package.ps1
# 可选参数:
#   -QtDir   Qt msvc 套件目录(默认 C:\Qt\6.8.3\msvc2022_64)
#   -CMake   cmake.exe 路径(默认用 VS2022 自带的)
[CmdletBinding()]
param(
  [string]$QtDir = 'C:\Qt\6.8.3\msvc2022_64',
  [string]$CMake = 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
)
$ErrorActionPreference = 'Stop'

# 仓库 cpp 目录(脚本在 cpp\scripts\ 下)。$PSScriptRoot 在某些调用方式下(含中文路径经
# cmd/native 参数边界传入)可能为空,故做回退。
$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$cppDir = Split-Path -Parent $scriptDir
$distDir = Join-Path $cppDir 'dist'
$windeployqt = Join-Path $QtDir 'bin\windeployqt.exe'

foreach ($p in @($CMake, $windeployqt)) {
  if (-not (Test-Path $p)) { throw "找不到必需工具: $p(用 -QtDir / -CMake 指定正确路径)" }
}

# CMake 在含中文/空格的路径上重新配置会崩溃 —— 若检测到非 ASCII,映射到 ASCII 盘符再构建。
$buildSrc = $cppDir
$mapped = $null
if ($cppDir -match '[^\u0000-\u007F]') {
  $letter = @('B:','Y:','W:','V:','T:') | Where-Object { -not (Test-Path $_) } | Select-Object -First 1
  if (-not $letter) { throw '没有空闲盘符可用于 subst' }
  $root = Split-Path -Parent $cppDir
  subst $letter $root | Out-Null
  $mapped = $letter
  $buildSrc = Join-Path $letter (Split-Path -Leaf $cppDir)
  Write-Host "非 ASCII 路径,已 subst $letter -> $root" -ForegroundColor Yellow
}

try {
  $buildDir = Join-Path $buildSrc 'build_pkg'
  if (Test-Path $buildDir) { Remove-Item -Recurse -Force $buildDir }

  Write-Host '== 配置 (Release) ==' -ForegroundColor Cyan
  & $CMake -G 'Visual Studio 17 2022' -A x64 -S $buildSrc -B $buildDir "-DCMAKE_PREFIX_PATH=$($QtDir -replace '\\','/')"
  if ($LASTEXITCODE -ne 0) { throw "配置失败 ($LASTEXITCODE)" }

  Write-Host '== 构建 (Release) ==' -ForegroundColor Cyan
  & $CMake --build $buildDir --config Release --target bulwark_service bulwark_ui
  if ($LASTEXITCODE -ne 0) { throw "构建失败 ($LASTEXITCODE)" }

  $svcExe = Join-Path $buildDir 'service\Release\bulwark_service.exe'
  $uiExe  = Join-Path $buildDir 'ui\Release\bulwark_ui.exe'
  foreach ($e in @($svcExe, $uiExe)) { if (-not (Test-Path $e)) { throw "未找到产物: $e" } }

  Write-Host '== 组装 dist + windeployqt ==' -ForegroundColor Cyan
  if (Test-Path $distDir) { Remove-Item -Recurse -Force $distDir }
  New-Item -ItemType Directory -Force -Path $distDir | Out-Null
  Copy-Item $svcExe $distDir; Copy-Item $uiExe $distDir
  # windeployqt 会把非致命提示写到 stderr;在 Stop 模式下 PowerShell 会把它当致命错误,
  # 故临时放宽并改用退出码判定成功与否。
  $prevEA = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  & $windeployqt --release --no-translations (Join-Path $distDir 'bulwark_service.exe') 2>&1 | Out-Null
  $wdSvc = $LASTEXITCODE
  & $windeployqt --release --no-translations (Join-Path $distDir 'bulwark_ui.exe') 2>&1 | Out-Null
  $wdUi = $LASTEXITCODE
  $ErrorActionPreference = $prevEA
  if ($wdSvc -ne 0) { throw "windeployqt(service) 失败 ($wdSvc)" }
  if ($wdUi -ne 0) { throw "windeployqt(ui) 失败 ($wdUi)" }
  Copy-Item (Join-Path $cppDir 'service\appsettings.json') $distDir -Force

  Write-Host "== 完成 ==`n自包含目录: $distDir" -ForegroundColor Green
  Get-ChildItem $distDir | Select-Object Name, Length | Format-Table -AutoSize
}
finally {
  if ($mapped) { subst $mapped /d | Out-Null }
}

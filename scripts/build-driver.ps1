# 编译内核驱动 Bulwark.sys(在装有 WDK + VS2022 BuildTools 的机器上运行)
# 产物:build\driver\<Configuration>\Bulwark.sys

param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$proj = Join-Path $root "Bulwark.Driver\Bulwark.Driver.vcxproj"

# 定位 MSBuild(BuildTools 或完整 VS 均可)
$candidates = @(
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
)
$msb = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $msb) { throw "未找到 MSBuild.exe,请安装 VS2022 + WDK。" }

Write-Host "使用 MSBuild: $msb" -ForegroundColor Cyan
# 注意:SolutionDir 末尾需要分隔符,但不能让反斜杠转义右引号,故用双反斜杠。
& $msb $proj /p:Configuration=$Configuration /p:Platform=x64 `
    /p:SpectreMitigation=false /p:SignMode=Off `
    "/p:SolutionDir=$root\\" /nologo /v:m

$sys = Join-Path $root "build\driver\$Configuration\Bulwark.sys"
if (Test-Path $sys) {
    Write-Host "驱动已生成: $sys" -ForegroundColor Green
} else {
    throw "未找到驱动产物。"
}

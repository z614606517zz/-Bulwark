<#
.SYNOPSIS
    从 Windows 安装镜像(install.wim / 拆分的 install.swm)【只读挂载】并采集纯净白样本 PE。
    需要管理员权限(DISM 挂载镜像)。

.DESCRIPTION
    在【已中毒主机】上，本机 C:\ 的系统文件不可信(可能被感染/替换)，不能用作"良性"语料。
    本脚本改从只读的官方安装镜像里取【微软原厂签名二进制】，从源头规避污染：
      1. dism /Cleanup-Mountpoints 清理陈旧挂载；
      2. dism /Mount-Image /ReadOnly 只读挂载 install.swm(自动带上分卷 install*.swm)；
      3. 调 Collect-BenignPE.ps1 扫描镜像内 System32 / SysWOW64 / WinSxS / Program Files；
      4. finally 里 dism /Unmount-Image /Discard 卸载并清理挂载点。
    产出写入默认白样本语料与 manifest(与散落 E:\ 的采集自动合并、按 SHA-256 去重)。

.PARAMETER Swm            install.swm 路径(默认 E:\sources\install.swm)。
.PARAMETER Index          镜像版本索引(默认 1；各版本高度重叠，一个即可，去重会合并)。
.PARAMETER MountDir       只读挂载点(默认 C:\_bulwark_wimmount，用后清理)。
.PARAMETER IncludeWinSxS  是否包含组件存储 WinSxS(默认是，量大且多为唯一 PE)。

.EXAMPLE
    # 在【管理员 PowerShell】中：
    powershell -ExecutionPolicy Bypass -File .\Collect-CleanWim.ps1
#>
[CmdletBinding()]
param(
    [string] $Swm = 'E:\sources\install.swm',
    [int]    $Index = 1,
    [string] $MountDir = 'C:\_bulwark_wimmount',
    [switch] $IncludeWinSxS = $true
)
$ErrorActionPreference = 'Stop'

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$collector = Join-Path $scriptDir 'Collect-BenignPE.ps1'
$logPath   = Join-Path (Split-Path -Parent $scriptDir) '_wim_collect_log.txt'

# ---- 管理员校验 -------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "本脚本需要管理员权限(DISM 挂载镜像)。请在【管理员 PowerShell】中运行。" -ForegroundColor Yellow
    exit 1
}

try { Start-Transcript -LiteralPath $logPath -Force | Out-Null } catch {}

function Stop-Log { try { Stop-Transcript | Out-Null } catch {} }

if (-not (Test-Path -LiteralPath $Swm))       { Write-Host "找不到镜像文件: $Swm" -ForegroundColor Red; Stop-Log; exit 1 }
if (-not (Test-Path -LiteralPath $collector)) { Write-Host "找不到采集器: $collector" -ForegroundColor Red; Stop-Log; exit 1 }

$swmDir     = Split-Path -Parent $Swm
$swmPattern = Join-Path $swmDir 'install*.swm'

Write-Host "==== 清理陈旧挂载点 ===="
& dism.exe "/Cleanup-Mountpoints" | Out-Null

if (-not (Test-Path -LiteralPath $MountDir)) { New-Item -ItemType Directory -Path $MountDir -Force | Out-Null }

Write-Host "`n==== 镜像信息 ===="
& dism.exe "/Get-ImageInfo" "/ImageFile:$Swm"

$exportWim = 'D:\_bulwark_export_idx' + $Index + '.wim'
Write-Host "`n==== 合并分卷: 导出 Index=$Index 为单体 WIM(本 DISM 不支持直接挂载分卷) ===="
Write-Host ("临时目标: " + $exportWim + "  (用完自动删除)")
if (Test-Path -LiteralPath $exportWim) { Remove-Item -LiteralPath $exportWim -Force -ErrorAction SilentlyContinue }
& dism.exe "/Export-Image" "/SourceImageFile:$Swm" "/SWMFile:$swmPattern" "/SourceIndex:$Index" "/DestinationImageFile:$exportWim" "/Compress:fast"
if ($LASTEXITCODE -ne 0) {
    Write-Host "导出失败(退出码 $LASTEXITCODE)。" -ForegroundColor Red
    Stop-Log; exit 1
}

Write-Host "`n==== 只读挂载单体 WIM -> $MountDir ===="
& dism.exe "/Mount-Image" "/ImageFile:$exportWim" "/Index:1" "/MountDir:$MountDir" "/ReadOnly"
if ($LASTEXITCODE -ne 0) {
    Write-Host "挂载失败(退出码 $LASTEXITCODE)。" -ForegroundColor Red
    Remove-Item -LiteralPath $exportWim -Force -ErrorAction SilentlyContinue
    Stop-Log; exit 1
}

try {
    $roots = @(
        (Join-Path $MountDir 'Windows\System32'),
        (Join-Path $MountDir 'Windows\SysWOW64'),
        (Join-Path $MountDir 'Program Files'),
        (Join-Path $MountDir 'Program Files (x86)')
    )
    if ($IncludeWinSxS) { $roots += (Join-Path $MountDir 'Windows\WinSxS') }
    $roots = @($roots | Where-Object { Test-Path -LiteralPath $_ })

    Write-Host "`n==== 采集镜像内纯净 PE(来源: 安装镜像，非本机) ===="
    Write-Host ("扫描根目录: " + ($roots -join '  '))
    & $collector -Roots $roots
}
finally {
    Write-Host "`n==== 卸载镜像 ===="
    & dism.exe "/Unmount-Image" "/MountDir:$MountDir" "/Discard"
    Remove-Item -LiteralPath $MountDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $exportWim -Force -ErrorAction SilentlyContinue
    Write-Host "全部完成。"
    Stop-Log
}

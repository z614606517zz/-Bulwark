<#
.SYNOPSIS
    白样本(良性 PE)最大量采集器 —— 从可信来源(干净 Windows 系统 + 正规软件)
    枚举 PE 文件，校验真伪、按 SHA-256 去重、记录元数据与签名，落地成训练语料。

.DESCRIPTION
    用于给 ML 杀毒引擎准备"良性"一类样本。MalwareBazaar 只有恶意样本，白样本必须
    另行采集。本脚本从本机可信目录(System32 / SysWOW64 / Program Files 等)递归采集：
      1. 按扩展名初筛 -> 读 MZ/PE 头确认是真 PE(过滤伪装/损坏文件)；
      2. 顺便从 COFF 头取架构(x86/x64/ARM64)、DLL/EXE、编译时间戳(免费元数据)；
      3. 流式 SHA-256，跨来源/多次运行去重(读已有 manifest 续采，幂等可断点续跑)；
      4. 可选 Authenticode 签名校验(签名者 + 状态，白样本质量信号，较慢)；
      5. 按哈希落地到语料库(<out>\<前2位>\<sha256>)，追加 JSONL manifest。

    只采集"按来源可信"的良性文件，不执行任何样本。产物默认写到 ml/data，已被 .gitignore 忽略。

.PARAMETER Roots
    要递归扫描的根目录。默认：System32、SysWOW64、Program Files、Program Files (x86)。

.PARAMETER OutDir
    语料输出目录。默认 <脚本>/../data/benign。传空字符串则只写 manifest 不复制文件。

.PARAMETER ManifestPath
    JSONL manifest 路径(每行一条记录)。默认 <脚本>/../data/manifests/benign_manifest.jsonl。

.PARAMETER IncludeWinSxS
    额外扫描 WinSxS(组件存储，量极大、含大量近似重复，谨慎开启)。

.PARAMETER CheckSignature
    对每个样本做 Authenticode 校验并记录签名者/状态。较慢(每文件一次)，默认关闭。
    建议全量快采完成后，另起一趟带 -CheckSignature 的补采(已采的会命中去重、只补新文件)。

.PARAMETER MinSizeBytes
    小于此大小的文件跳过(默认 1024，滤掉桩/占位)。

.PARAMETER MaxSizeBytes
    大于此大小的文件跳过(默认 96MB，滤掉超大安装包/资源包)。

.PARAMETER MaxFiles
    本次最多采集多少个(去重后)。0 = 不限。用于小范围验证。

.PARAMETER NoCopy
    只统计 + 写 manifest，不复制文件(快速盘点)。

.EXAMPLE
    # 全量采集本机白样本
    powershell -ExecutionPolicy Bypass -File .\Collect-BenignPE.ps1

.EXAMPLE
    # 小范围验证(只采 200 个)
    powershell -ExecutionPolicy Bypass -File .\Collect-BenignPE.ps1 -Roots "$env:SystemRoot\System32" -MaxFiles 200
#>
[CmdletBinding()]
param(
    [string[]] $Roots,
    [string]   $OutDir,
    [string]   $ManifestPath,
    [switch]   $IncludeWinSxS,
    [switch]   $CheckSignature,
    [long]     $MinSizeBytes = 1024,
    [long]     $MaxSizeBytes = 100MB,
    [int]      $MaxFiles = 0,
    [switch]   $NoCopy
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ---- 路径默认值 -------------------------------------------------------------
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$dataRoot  = Join-Path (Split-Path -Parent $scriptDir) 'data'
if (-not $OutDir)       { $OutDir       = Join-Path $dataRoot 'benign' }
if (-not $ManifestPath) { $ManifestPath = Join-Path $dataRoot 'manifests\benign_manifest.jsonl' }

if (-not $Roots -or $Roots.Count -eq 0) {
    $Roots = @(
        (Join-Path $env:SystemRoot 'System32'),
        (Join-Path $env:SystemRoot 'SysWOW64'),
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)}
    )
    if ($IncludeWinSxS) { $Roots += (Join-Path $env:SystemRoot 'WinSxS') }
}
$Roots = $Roots | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique

# PE 类扩展名(先按扩展名初筛，再读头确认；比无差别读头快得多)
$peExt = @('.exe','.dll','.sys','.ocx','.cpl','.scr','.drv','.efi','.mui',
           '.node','.ax','.tsp','.acm','.ime','.rll','.mun') |
         ForEach-Object { $_ } # keep as-is
$peExtSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]$peExt, [System.StringComparer]::OrdinalIgnoreCase)

# ---- 准备输出 ---------------------------------------------------------------
$manifestDir = Split-Path -Parent $ManifestPath
if (-not (Test-Path -LiteralPath $manifestDir)) { New-Item -ItemType Directory -Path $manifestDir -Force | Out-Null }
if (-not $NoCopy -and $OutDir -and -not (Test-Path -LiteralPath $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

# ---- 续采：载入已有 manifest 的哈希，去重 -----------------------------------
$seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
if (Test-Path -LiteralPath $ManifestPath) {
    Write-Host "载入已有 manifest 去重集：$ManifestPath"
    Get-Content -LiteralPath $ManifestPath -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_ -match '"sha256"\s*:\s*"([0-9a-fA-F]{64})"') { [void]$seen.Add($Matches[1].ToLower()) }
    }
    Write-Host ("  已有 {0} 个样本，将跳过重复。" -f $seen.Count)
}

# ---- PE 头解析(打开一次：确认 PE + 取架构/类型/时间戳，再复用流算哈希) -------
function Get-PeRecord {
    param([string] $Path)
    $fs = $null
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
              [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        if ($fs.Length -lt 64) { return $null }
        $br = New-Object System.IO.BinaryReader($fs)
        if ($br.ReadUInt16() -ne 0x5A4D) { return $null }          # 'MZ'
        [void]$fs.Seek(0x3C, [System.IO.SeekOrigin]::Begin)
        $peOff = $br.ReadUInt32()
        if ($peOff -le 0 -or ($peOff + 24) -ge $fs.Length) { return $null }
        [void]$fs.Seek($peOff, [System.IO.SeekOrigin]::Begin)
        if ($br.ReadUInt32() -ne 0x00004550) { return $null }      # 'PE\0\0'
        $machine = $br.ReadUInt16()
        $null    = $br.ReadUInt16()                                # NumberOfSections
        $tds     = $br.ReadUInt32()                                # TimeDateStamp
        [void]$fs.Seek(10, [System.IO.SeekOrigin]::Current)        # skip ptr/num-sym(8)+optHdrSize(2)
        $chars   = $br.ReadUInt16()                                # Characteristics

        $arch = switch ($machine) {
            0x8664  { 'x64' }
            0x014c  { 'x86' }
            0xAA64  { 'arm64' }
            0x01c0  { 'arm' }
            0x01c4  { 'armnt' }
            0x0200  { 'ia64' }
            default { ('0x{0:x}' -f $machine) }
        }
        $isDll = [bool]($chars -band 0x2000)

        # 复用同一句柄流式算 SHA-256
        [void]$fs.Seek(0, [System.IO.SeekOrigin]::Begin)
        $sha  = [System.Security.Cryptography.SHA256]::Create()
        try   { $hashBytes = $sha.ComputeHash($fs) }
        finally { $sha.Dispose() }
        $hash = ([System.BitConverter]::ToString($hashBytes)).Replace('-','').ToLower()

        return [pscustomobject]@{
            Sha256 = $hash; Arch = $arch; IsDll = $isDll; TimeDateStamp = $tds
        }
    } catch {
        return $null
    } finally {
        if ($fs) { $fs.Dispose() }
    }
}

# ---- JSON 字符串转义 --------------------------------------------------------
function ConvertTo-JsonLine {
    param([hashtable] $Obj)
    $parts = foreach ($k in $Obj.Keys) {
        $v = $Obj[$k]
        if ($v -is [bool])        { $val = if ($v) { 'true' } else { 'false' } }
        elseif ($v -is [int] -or $v -is [long] -or $v -is [uint32] -or $v -is [double]) { $val = "$v" }
        else {
            $s = [string]$v
            $s = $s.Replace('\','\\').Replace('"','\"').Replace("`t",'\t').Replace("`r",'').Replace("`n",'\n')
            $val = '"' + $s + '"'
        }
        '"' + $k + '":' + $val
    }
    '{' + ($parts -join ',') + '}'
}

# ---- 主循环 -----------------------------------------------------------------
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$stat = [ordered]@{
    Scanned = 0; NotPe = 0; SizeSkip = 0; Dupe = 0; Collected = 0; Errors = 0; Bytes = [long]0; Signed = 0
}
$manifestWriter = [System.IO.StreamWriter]::new($ManifestPath, $true, [System.Text.Encoding]::UTF8)

try {
    foreach ($root in $Roots) {
        Write-Host "`n>>> 扫描根目录：$root"
      try {
        $enum = Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue

        foreach ($f in $enum) {
            if (-not $peExtSet.Contains($f.Extension)) { continue }
            $stat.Scanned++

            if ($f.Length -lt $MinSizeBytes -or $f.Length -gt $MaxSizeBytes) { $stat.SizeSkip++; continue }

            $pe = Get-PeRecord -Path $f.FullName
            if (-not $pe) { $stat.NotPe++; continue }

            if ($seen.Contains($pe.Sha256)) { $stat.Dupe++; continue }
            [void]$seen.Add($pe.Sha256)

            # 可选签名校验(慢)
            $sigStatus = ''; $signer = ''
            if ($CheckSignature) {
                try {
                    $s = Get-AuthenticodeSignature -LiteralPath $f.FullName -ErrorAction SilentlyContinue
                    if ($s) {
                        $sigStatus = [string]$s.Status
                        if ($s.SignerCertificate) { $signer = [string]$s.SignerCertificate.Subject }
                        if ($sigStatus -eq 'Valid') { $stat.Signed++ }
                    }
                } catch { }
            }

            # 落地文件(按哈希，前 2 位分桶)
            if (-not $NoCopy -and $OutDir) {
                $sub = Join-Path $OutDir $pe.Sha256.Substring(0,2)
                if (-not (Test-Path -LiteralPath $sub)) { New-Item -ItemType Directory -Path $sub -Force | Out-Null }
                $dst = Join-Path $sub $pe.Sha256
                if (-not (Test-Path -LiteralPath $dst)) {
                    try { [System.IO.File]::Copy($f.FullName, $dst, $false) }
                    catch { $stat.Errors++; continue }
                }
            }

            $rec = [ordered]@{
                sha256    = $pe.Sha256
                label     = 'benign'
                size      = $f.Length
                ext       = $f.Extension.ToLower()
                arch      = $pe.Arch
                pe_type   = if ($pe.IsDll) { 'dll' } else { 'exe' }
                tds       = [long]$pe.TimeDateStamp
                sig_status= $sigStatus
                signer    = $signer
                src_path  = $f.FullName
                src_root  = $root
                collected = (Get-Date).ToUniversalTime().ToString('o')
            }
            $manifestWriter.WriteLine((ConvertTo-JsonLine -Obj ([hashtable]$rec)))
            $stat.Collected++
            $stat.Bytes += $f.Length

            if ($stat.Collected % 500 -eq 0) {
                $manifestWriter.Flush()
                Write-Host ("  ...已采 {0}  (扫描 {1}, 去重跳过 {2}, 非PE {3})  {4:n1} MB" -f `
                    $stat.Collected, $stat.Scanned, $stat.Dupe, $stat.NotPe, ($stat.Bytes/1MB))
            }

            if ($MaxFiles -gt 0 -and $stat.Collected -ge $MaxFiles) {
                Write-Host "达到 -MaxFiles=$MaxFiles，停止。"
                break
            }
        }
      } catch {
        Write-Host ("  [跳过] 目录枚举中断，继续下一根目录: {0}" -f $_.Exception.Message)
      }
        if ($MaxFiles -gt 0 -and $stat.Collected -ge $MaxFiles) { break }
    }
}
finally {
    $manifestWriter.Flush(); $manifestWriter.Dispose()
    $sw.Stop()
}

# ---- 汇总 -------------------------------------------------------------------
Write-Host "`n================ 采集完成 ================"
Write-Host ("耗时          : {0:n1} 秒" -f $sw.Elapsed.TotalSeconds)
Write-Host ("扫描候选      : {0}" -f $stat.Scanned)
Write-Host ("  非真PE跳过  : {0}" -f $stat.NotPe)
Write-Host ("  尺寸跳过    : {0}" -f $stat.SizeSkip)
Write-Host ("  重复跳过    : {0}" -f $stat.Dupe)
Write-Host ("  复制出错    : {0}" -f $stat.Errors)
Write-Host ("本次新采(去重): {0}" -f $stat.Collected)
if ($CheckSignature) { Write-Host ("  其中有效签名: {0}" -f $stat.Signed) }
Write-Host ("语料总大小    : {0:n1} MB" -f ($stat.Bytes/1MB))
Write-Host ("manifest 累计 : {0} 条  ->  {1}" -f $seen.Count, $ManifestPath)
if (-not $NoCopy -and $OutDir) { Write-Host ("语料目录      : {0}" -f $OutDir) }

# =====================================================================
#  一条命令完成:重打包 -> 脱敏闸门 -> 加密 zip -> 校验 -> 上传 -> 原子替换
#                -> 清理旧备份 -> 端到端验证 /download
#
#  为什么要有这个脚本(不是「顺手封装一下」):
#
#  1) 脱敏是硬闸门。手动流程里「先跑 -Sanitize 再打包」全靠人记得。漏一次,
#     带着 6 把真实 API 密钥和明文端点的包就上了公开下载 —— 不可撤回。
#     这里把「verify_portable 必须报 SHAREABLE 且 0 密钥」做成上传前的前置条件,
#     不满足直接 throw,连 zip 都不生成。
#
#  2) 替换必须原子。/download 是先 os.path.getsize() 拿 Content-Length 再流式
#     发送。直接 scp 覆盖线上文件,正在下载的用户会拿到长度与内容不匹配的坏包。
#     故:传到同目录临时文件 -> chown/chmod -> mv(同文件系统 rename,原子)。
#
#  3) 旧备份会无声堆积。实测服务器上攒了 5 份共约 60MB,其中 3 份内容完全一样。
#     保留份数做成参数并在每次部署后自动收敛,而不是等人想起来去删。
#
#  用法:
#      powershell -ExecutionPolicy Bypass -File scripts\deploy-release.ps1
#      ... -KeepBackups 2          # 多留一份
#      ... -SkipRepack             # 便携包已就绪,只打包上传
#      ... -DryRun                 # 只做本地打包与校验,不碰服务器
# =====================================================================
[CmdletBinding()]
param(
    [string]$Package     = 'C:\Users\1\Desktop\新建文件夹',
    [string]$Zip         = 'C:\Users\1\Desktop\Bulwark-Release.zip',
    # 注意:参数名不能叫 $Host —— 那是 PowerShell 的自动变量,会被覆盖并引发怪异行为。
    # 没有默认主机:本文件是公开的,写死地址既是基础设施泄漏,也可能在忘记传参时
    # 把发布包推到意料之外的机器上。用 -Server 指定,或设 BULWARK_DEPLOY_SERVER。
    [string]$Server      = $env:BULWARK_DEPLOY_SERVER,
    [string]$User        = 'root',
    [string]$RemoteDir   = '/opt/bulwark-intel',
    [string]$RemoteName  = 'Bulwark-Release.zip',
    [string]$ZipPassword = '123',
    [string]$TopDir      = 'Bulwark',
    # 线上文件的归属。与现役文件保持一致,别把 bulwarkintel 的文件换成 root 的。
    [string]$RemoteOwner = 'bulwarkintel:bulwarkintel',
    [int]$KeepBackups    = 1,
    [switch]$SkipRepack,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Step($m) { Write-Host ''; Write-Host "== $m ==" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "  [OK] $m" -ForegroundColor Green }
function Info($m) { Write-Host "       $m" -ForegroundColor DarkGray }
function Die($m)  { throw $m }

# 目标主机必须显式给出。-DryRun 只做本地打包与校验、根本不连服务器,所以那条路径
# 不该被这个检查拦住 —— 否则「先本地验一遍」这个最常用的用法反而需要先编个地址。
if (-not $DryRun -and [string]::IsNullOrWhiteSpace($Server)) {
    Die ('未指定目标服务器。用 -Server <主机> 传入,或设置环境变量 ' +
         'BULWARK_DEPLOY_SERVER;只想本地打包校验就加 -DryRun。')
}

# 远端命令统一走单引号:PowerShell 不会去解释里面的 $(...) 与 $VAR,
# 交给远端 bash 求值。用双引号踩过坑 —— 本地 Get-Date 把 $(date) 吃掉,
# 结果在服务器上创建了一个空后缀的垃圾备份文件。
function Remote($bashCmd) {
    $out = & ssh -o BatchMode=yes -o ConnectTimeout=15 "$User@$Server" $bashCmd 2>&1
    if ($LASTEXITCODE -ne 0) { Die ("ssh 失败(退出码 $LASTEXITCODE):`n" + ($out -join "`n")) }
    return $out
}

# ---- 1) 重打包(脱敏) ------------------------------------------------------
if (-not $SkipRepack) {
    Step '重打包便携包(-Sanitize)'
    $up = Join-Path $root 'update_portable.ps1'
    & powershell -NoProfile -ExecutionPolicy Bypass -File $up -Package $Package -Sanitize | Out-Null
    if ($LASTEXITCODE -ne 0) { Die "update_portable.ps1 失败(退出码 $LASTEXITCODE)" }
    Ok '已重打包'
} else {
    Step '跳过重打包(-SkipRepack)'
}

# ---- 2) 脱敏闸门 ----------------------------------------------------------
# 这一步是整个脚本存在的首要理由。不通过就绝不继续。
Step '脱敏闸门'
$vp = Join-Path $root 'verify_portable.ps1'
& powershell -NoProfile -ExecutionPolicy Bypass -File $vp -Package $Package | Out-Null
$vout = Join-Path $root 'verify_out.txt'
if (-not (Test-Path $vout)) { Die 'verify_portable.ps1 没有产出 verify_out.txt' }
$v = Get-Content $vout -Raw -Encoding UTF8

if ($v -notmatch 'package kind\s*:\s*SHAREABLE') {
    Die "便携包不是 SHAREABLE(带密钥或明文端点),拒绝上传。先跑:`n" +
        "  update_portable.ps1 -Package `"$Package`" -Sanitize"
}
$m = [regex]::Match($v, 'secret fields set\s*:\s*(\d+)\s*/')
if (-not $m.Success) { Die 'verify_out.txt 里读不到 secret fields set' }
if ([int]$m.Groups[1].Value -ne 0) {
    Die ("便携包仍带 " + $m.Groups[1].Value + " 个密钥字段,拒绝上传。")
}
if ($v -match '=== sensitive-string scan[\s\S]*?LEAK') { Die '敏感串扫描报 LEAK,拒绝上传。' }
Ok 'SHAREABLE · 0 个密钥字段 · 敏感串扫描通过'

# ---- 3) 生成加密 zip ------------------------------------------------------
Step '生成加密 zip(ZipCrypto)'
$pack = Join-Path $root 'scripts\pack-release.py'
& python $pack --src $Package --out $Zip --password $ZipPassword --top $TopDir | Out-Null
if ($LASTEXITCODE -ne 0) { Die "pack-release.py 失败(退出码 $LASTEXITCODE)" }
$zi = Get-Item $Zip
Ok ("{0}  {1:N0} B" -f (Split-Path $Zip -Leaf), $zi.Length)

# ---- 4) 独立校验 zip ------------------------------------------------------
Step '独立校验 zip'
$vz = Join-Path $root 'scripts\verify-release-zip.py'
& python $vz --zip $Zip --src $Package --password $ZipPassword --top $TopDir | Out-Null
if ($LASTEXITCODE -ne 0) {
    $rep = Join-Path (Split-Path $Zip -Parent) '_verify.txt'
    $detail = if (Test-Path $rep) { Get-Content $rep -Raw -Encoding UTF8 } else { '(无报告)' }
    Die ("zip 校验未通过,拒绝上传:`n" + $detail)
}
$localHash = (Get-FileHash $Zip -Algorithm SHA256).Hash.ToLower()
Ok ('校验通过  sha256=' + $localHash.Substring(0, 16) + '…')

if ($DryRun) {
    Step '-DryRun:到此为止,未连服务器'
    Info "zip: $Zip"
    return
}

# ---- 5) 备份现役包 --------------------------------------------------------
Step '备份线上现役包'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$remote = "$RemoteDir/$RemoteName"
Remote "test -f '$remote' && cp -p '$remote' '$remote.bak-$stamp' && echo backed-up || echo no-existing-file" |
    ForEach-Object { Info $_ }
Ok "备份后缀 .bak-$stamp"

# ---- 6) 上传到临时文件 ----------------------------------------------------
Step '上传'
$tmp = "/tmp/$RemoteName.new"
& scp -o BatchMode=yes -o ConnectTimeout=15 $Zip "$User@${Server}:$tmp" | Out-Null
if ($LASTEXITCODE -ne 0) { Die "scp 失败(退出码 $LASTEXITCODE)" }
Ok '已上传到临时文件'

# ---- 7) 比对哈希(传输完整性) ----------------------------------------------
Step '比对哈希'
$remoteHash = (Remote "sha256sum '$tmp' | cut -d' ' -f1") -join ''
$remoteHash = $remoteHash.Trim().ToLower()
if ($remoteHash -ne $localHash) {
    Remote "rm -f '$tmp'" | Out-Null
    Die "哈希不一致,已删除临时文件并中止:`n  本地 $localHash`n  远端 $remoteHash"
}
Ok '远端与本地 SHA-256 一致'

# ---- 8) 原子替换 ----------------------------------------------------------
Step '原子替换'
$stage = "$RemoteDir/.$RemoteName.tmp"
Remote ("cp '$tmp' '$stage' && chown $RemoteOwner '$stage' && chmod 644 '$stage' " +
        "&& mv -f '$stage' '$remote' && rm -f '$tmp' && echo installed") |
    ForEach-Object { Info $_ }
Ok '已替换(同目录 mv,下载中的用户不会拿到截断包)'

# ---- 9) 清理旧备份 --------------------------------------------------------
Step "清理旧备份(保留最近 $KeepBackups 份)"
$keep = [Math]::Max(0, $KeepBackups)
$del = Remote ("cd '$RemoteDir' && ls -1t $RemoteName.bak* 2>/dev/null | tail -n +$($keep + 1)")
$del = @($del | Where-Object { $_ -and $_.Trim() })
if ($del.Count -eq 0) {
    Ok '没有需要删除的旧备份'
} else {
    Remote ("cd '$RemoteDir' && ls -1t $RemoteName.bak* 2>/dev/null | tail -n +$($keep + 1) | xargs -r rm -f") | Out-Null
    foreach ($d in $del) { Info ("已删除 " + $d.Trim()) }
    Ok ("删除 " + $del.Count + " 份")
}
Remote ("cd '$RemoteDir' && ls -l $RemoteName*") | ForEach-Object { Info $_ }

# ---- 10) 端到端验证 -------------------------------------------------------
# 只验证到「HTTP 层吐出来的字节和本地一致」为止。文件在磁盘上对不代表
# /download 一定能正确发出去(Content-Length 取自 getsize,曾是坏包来源)。
Step '端到端验证 /download'
$probe = Remote ("curl -sk -o /tmp/_dl.zip -w 'http=%{http_code} bytes=%{size_download}' " +
                 "https://127.0.0.1:8787/download; echo; sha256sum /tmp/_dl.zip | cut -d' ' -f1; rm -f /tmp/_dl.zip")
$probe | ForEach-Object { Info $_ }
$served = ($probe | Where-Object { $_ -match '^[0-9a-f]{64}$' } | Select-Object -First 1)
if (-not $served) { Die "拿不到 /download 返回内容的哈希:`n" + ($probe -join "`n") }
if ($served.Trim().ToLower() -ne $localHash) {
    Die "/download 吐出的内容与本地不一致:`n  本地 $localHash`n  服务 $served"
}
Ok '/download 返回的字节与本地 zip 完全一致'

Write-Host ''
Write-Host '==== 部署完成 ====' -ForegroundColor Cyan
Info ("包    : $remote")
Info ("大小  : {0:N0} B" -f $zi.Length)
Info ("sha256: $localHash")
Info ("回滚  : ssh $User@$Server `"cd $RemoteDir && cp -p $RemoteName.bak-$stamp $RemoteName`"")
Write-Host ''

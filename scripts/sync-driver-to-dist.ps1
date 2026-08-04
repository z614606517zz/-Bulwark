<#
    sync-driver-to-dist.ps1
    ——「构建 -> 测试签名 -> 同步到便携包」一条命令做完,消除「dist 里的 Bulwark.sys 与源码不同源」。

    为什么需要这个脚本(这不是锦上添花,是补一个会静默失效的缺口):

      协议版本号自 v9 起【刻意不再升】(理由见 Protocol.h:升到 v10 会让已部署的 v9 服务/驱动
      因版本不符而整体降级为不拦截,代价远大于"少认识两个命令")。这个决定是对的,但它的副作用是:
      一个比服务旧的 Bulwark.sys 【一定能通过握手】,只是 v9 之后新增的命令会被它的 default 分支
      以 STATUS_INVALID_PARAMETER 拒掉。

      于是"驱动没同步"这件事不会以任何醒目的方式暴露 —— 日志写着「协议握手通过(ver=9)」,
      设置页写着「内核驱动已连接 · 行为前拦截」,而【命令行硬拦(反勒索删卷影的执行前阻断)、
      已封禁主体全维拦截、owner-aware 自保护足迹】三项静默不存在。

      服务侧现在会主动探测并报出缺失维度(见 DriverEventSource::missingCapabilities),
      但根治办法是让"同步驱动"这一步不再依赖人手记得做。故有此脚本。

    实测过的坑(都已在下面处理):
      * 项目虽在 vcxproj 里写了 <SpectreMitigation>false</SpectreMitigation>,直接 msbuild 仍会
        报 MSB8040 要求 Spectre 缓解库 —— 必须在命令行再传一次 /p:SpectreMitigation=false。
      * 测试证书装在 LocalMachine\My,访问其私钥【需要管理员权限】。不提权时 signtool 只会报
        "No certificates were found that met all the given criteria",看不出真实原因。
      * 【绝不能把未签名的 .sys 放进 dist】。未签名驱动即便开了 testsigning 也加载不了,
        那比"陈旧但能加载"更糟。故本脚本只在签名成功后才替换,失败一律保持原样。

    用法(必须以管理员运行):
        powershell -ExecutionPolicy Bypass -File scripts\sync-driver-to-dist.ps1
        powershell -ExecutionPolicy Bypass -File scripts\sync-driver-to-dist.ps1 -Configuration Debug
#>

param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    # 测试签名证书的 CN。换成正式代码签名证书时,把它和 -MachineStore 一起改掉即可。
    [string]$CertSubject = "BulwarkTestCert"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$proj = Join-Path $root "Bulwark.Driver\Bulwark.Driver.vcxproj"
$dist = Join-Path $root "cpp\dist"

function Fail($msg) { Write-Host "[失败] $msg" -ForegroundColor Red; exit 1 }
function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "     $msg" -ForegroundColor Green }

# ---- 0) 前置检查 ------------------------------------------------------------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail "需要管理员权限:测试证书装在 LocalMachine\My,读它的私钥必须提权。请在管理员 PowerShell 里重跑。"
}
if (-not (Test-Path $proj)) { Fail "找不到驱动工程:$proj" }
if (-not (Test-Path $dist)) { Fail "找不到便携包目录:$dist" }

$msb = @(
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $msb) { Fail "未找到 MSBuild.exe(需 VS2022 + WDK)。" }

$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe `
                -ErrorAction SilentlyContinue |
            Where-Object FullName -like "*x64*" | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { Fail "未找到 signtool.exe(需 Windows SDK)。" }

$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*CN=$CertSubject*" }
if (-not $cert)                 { Fail "LocalMachine\My 里找不到证书 CN=$CertSubject。" }
if (-not $cert.HasPrivateKey)   { Fail "证书 CN=$CertSubject 没有私钥,无法签名。" }
if ($cert -is [array])          { $cert = $cert[0] }
Ok "证书 $($cert.Thumbprint)(有效期至 $($cert.NotAfter.ToString('yyyy-MM-dd')))"

# ---- 1) 构建 ----------------------------------------------------------------
Step "构建驱动($Configuration)"
& $msb $proj /p:Configuration=$Configuration /p:Platform=x64 `
      /p:SpectreMitigation=false /p:SignMode=Off /nologo /v:minimal
if ($LASTEXITCODE -ne 0) { Fail "驱动构建失败(退出码 $LASTEXITCODE)。" }

$built = Join-Path $root "Bulwark.Driver\build\driver\$Configuration\Bulwark.sys"
if (-not (Test-Path $built)) { Fail "构建成功但找不到产物:$built" }
Ok "产物 $built ($((Get-Item $built).Length) B)"

# ---- 2) 在暂存副本上签名(签成功了才动 dist)---------------------------------
Step "测试签名"
$staging = Join-Path $env:TEMP "Bulwark.sys.staging"
Copy-Item $built $staging -Force
& $signtool.FullName sign /v /sm /s My /sha1 $cert.Thumbprint /fd sha256 $staging
if ($LASTEXITCODE -ne 0) { Remove-Item $staging -Force -ErrorAction SilentlyContinue; Fail "签名失败(退出码 $LASTEXITCODE)。dist 未改动。" }

$sig = Get-AuthenticodeSignature $staging
if ($sig.Status -ne 'Valid') { Remove-Item $staging -Force -ErrorAction SilentlyContinue; Fail "签名后校验不通过($($sig.Status))。dist 未改动。" }
Ok "签名有效:$($sig.SignerCertificate.Subject)"

# ---- 3) 替换 dist(带时间戳备份,可回滚)-------------------------------------
Step "同步到便携包"
$target = Join-Path $dist "Bulwark.sys"
if (Test-Path $target) {
    $stamp = (Get-Item $target).LastWriteTime.ToString('yyyyMMdd-HHmmss')
    $bak = Join-Path $dist "Bulwark.sys.bak-$stamp"
    Copy-Item $target $bak -Force
    Ok "旧驱动已备份为 $(Split-Path $bak -Leaf)"
}
Move-Item $staging $target -Force
# 上一轮遗留的未签名暂存件清掉,免得被误当成可用产物拷走。
Remove-Item (Join-Path $dist "Bulwark.sys.new-unsigned") -Force -ErrorAction SilentlyContinue

$info = Get-Item $target
Ok "dist\Bulwark.sys 已更新($($info.Length) B,$($info.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')))"

Write-Host ""
Write-Host "完成。若目标机上已部署过旧驱动,记得让新的那份真正生效:" -ForegroundColor Yellow
Write-Host "    sc stop BulwarkService" -ForegroundColor Gray
Write-Host "    fltmc unload Bulwark" -ForegroundColor Gray
Write-Host "    copy /Y cpp\dist\Bulwark.sys %SystemRoot%\System32\drivers\Bulwark.sys" -ForegroundColor Gray
Write-Host "    sc start BulwarkService" -ForegroundColor Gray
Write-Host "  (服务的 stageDriverBinary() 只在目标文件【不存在】时才复制,不会覆盖已部署的旧驱动 —— " -ForegroundColor Gray
Write-Host "   所以升级时必须手工覆盖这一次。之后服务日志里的「内核能力探测」应报告全部维度就绪。)" -ForegroundColor Gray

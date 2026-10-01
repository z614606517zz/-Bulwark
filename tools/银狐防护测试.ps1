# =====================================================================
#  磐垒(Bulwark)银狐专项防护 —— 无害行为测试脚本
# ---------------------------------------------------------------------
#  用途:在 Bulwark 服务运行时,复现银狐(Winos 4.0 / ValleyRAT)投递链
#        各阶段会触发的可观测行为特征,验证监控层 + 规则引擎 + 拦截是否
#        真的生效。用例 1-4 覆盖微信/QQ 群控,用例 5-9 覆盖 2026 年的
#        投递链:伪装安装包 -> 白加黑侧载 -> BYOVD 关杀软 -> 服务持久化。
#
#  重要:本脚本【不含任何真实恶意能力】——
#        - 落地的 DLL 只是一个文本文件,不能被加载执行;
#        - 触发的命令行只是 echo/rem,不下载、不注入、不群发、不窃取。
#        它只是"长得像"银狐的行为,用于让防护软件产生检测事件(类似 EICAR)。
#
#  前置:1) 以【管理员】运行(否则文件写入 Program Files 等会被系统本身拦);
#        2) Bulwark 服务已安装并运行(sc query BulwarkDefense);
#        3) 运行后观察 Bulwark UI 是否对下列每一步弹窗/拦截。
#
#  用法: powershell -ExecutionPolicy Bypass -File 银狐防护测试.ps1
# =====================================================================

[CmdletBinding()]
param(
    # 用例 7(白加黑侧载)需要一个【内嵌签名】的宿主程序:把它复制到沙箱,旁边放一个未签名的
    # powrprof.dll,再运行它。不指定时脚本会自己找一个;找不到就跳过该用例并说明原因。
    #
    # 为什么不能直接用 System32 里的程序:系统自带程序多为【目录签名(catalog)】,一旦复制出
    # System32,目录签名就不再适用,验签结果变成"未签名",而本用例的前提恰恰是"壳的签名是健康的"。
    [string]$SignedHost = ''
)

$ErrorActionPreference = 'Continue'
$sandbox = Join-Path $env:TEMP 'BulwarkTest_SilverFox'
New-Item -ItemType Directory -Force -Path $sandbox | Out-Null
$created = New-Object System.Collections.Generic.List[string]

function Test-Case {
    param([string]$Id, [string]$Desc, [string]$Expect, [scriptblock]$Action)
    Write-Host ""
    Write-Host ("[{0}] {1}" -f $Id, $Desc) -ForegroundColor Cyan
    Write-Host ("      期望防护动作: {0}" -f $Expect) -ForegroundColor DarkGray
    try { & $Action } catch { Write-Host ("      (触发时异常: {0})" -f $_.Exception.Message) -ForegroundColor DarkYellow }
}

Write-Host "==== 磐垒 银狐/微信QQ群控 防护测试(无害模拟)====" -ForegroundColor Green
Write-Host "沙箱目录: $sandbox"

# ---------------------------------------------------------------------
# 用例 1:具名群控/hook 模块 DLL 落地  → 期望 Block
#   规则: File_(*\wxhook.dll / *\WeChatSDK*.dll / *\vchat*.dll ... , Block)
#   模拟: 写入同名文件,内容为无害文本(无法作为真实 DLL 加载)。
# ---------------------------------------------------------------------
Test-Case '1' '落地具名群控模块 wxhook.dll / WeChatSDK64.dll / vchat.dll' 'Block(拦截写入)' {
    foreach ($name in 'wxhook.dll','WeChatSDK64.dll','vchat.dll','WeChatRobotCE.dll','WeWorkHook.dll') {
        $p = Join-Path $sandbox $name
        Set-Content -LiteralPath $p -Value 'THIS IS A HARMLESS TEST FILE - NOT A REAL DLL' -ErrorAction SilentlyContinue
        if (Test-Path $p) { $created.Add($p); Write-Host "      已写入: $p" -ForegroundColor DarkGray }
        else { Write-Host "      写入被拦截(未落地): $name" -ForegroundColor Yellow }
    }
}

# ---------------------------------------------------------------------
# 用例 2:微信数据库解密/导出工具命令行(采集群发目标)  → 期望 Ask
#   规则: Cmd(*PyWxDump* / *SharpWxDump* / *wxdump* / *WeChatMsg* , Ask)
#   模拟: 启动一个只做 rem/echo 的进程,命令行里含工具名,不做任何真实导出。
# ---------------------------------------------------------------------
Test-Case '2' '命令行含 PyWxDump / SharpWxDump / wxdump(仅字符串,不执行导出)' 'Ask(弹窗询问)' {
    foreach ($tool in 'PyWxDump','SharpWxDump','wxdump','WeChatMsg') {
        Start-Process -FilePath 'cmd.exe' -ArgumentList "/c rem $tool  (harmless test)" -WindowStyle Hidden -ErrorAction SilentlyContinue
        Write-Host "      已启动含 '$tool' 命令行的无害进程" -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------
# 用例 3:群发框架命令行(wcferry / ntchat / wxauto)  → 期望 Ask
# ---------------------------------------------------------------------
Test-Case '3' '命令行含群发框架 wcferry / ntchat / wxauto' 'Ask(弹窗询问)' {
    foreach ($fw in 'wcferry','ntchat','wxauto') {
        Start-Process -FilePath 'cmd.exe' -ArgumentList "/c rem import $fw  (harmless test)" -WindowStyle Hidden -ErrorAction SilentlyContinue
        Write-Host "      已启动含 '$fw' 命令行的无害进程" -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------
# 用例 4:向微信安装目录写入 DLL(替换/植入群控模块)  → 期望 Ask/Block
#   仅当本机存在对应目录时才尝试;写入的是无害文本文件。
# ---------------------------------------------------------------------
Test-Case '4' '向 微信/企业微信 安装目录写入 DLL(植入模块模拟)' 'Ask 或 Block' {
    $targets = @(
        (Join-Path ${env:ProgramFiles} 'Tencent\WeChat\bulwark_test_plugin.dll'),
        (Join-Path ${env:ProgramFiles} 'Tencent\Weixin\bulwark_test_plugin.dll'),
        (Join-Path ${env:ProgramFiles} 'WXWork\bulwark_test_plugin.dll')
    )
    foreach ($t in $targets) {
        $dir = Split-Path $t
        if (Test-Path $dir) {
            Set-Content -LiteralPath $t -Value 'HARMLESS TEST' -ErrorAction SilentlyContinue
            if (Test-Path $t) { $created.Add($t); Write-Host "      已写入: $t" -ForegroundColor DarkGray }
            else { Write-Host "      写入被拦截: $t" -ForegroundColor Yellow }
        } else {
            Write-Host "      跳过(目录不存在): $dir" -ForegroundColor DarkGray
        }
    }
}

# ---------------------------------------------------------------------
# 用例 5:BYOVD 驱动落地(银狐 2026 年实际使用的那几个)  → 期望 Block
#   规则: File_(*\amsdk.sys / *\wsftprm.sys / *\BootRepair.sys / *\EnPortv.sys
#             / *\wnbios.sys , Block + hard)
#   模拟: 写入同名文件,内容为无害文本(不是真实驱动,无法加载)。
# ---------------------------------------------------------------------
Test-Case '5' '落地银狐惯用的易受攻击驱动 amsdk/wsftprm/BootRepair/EnPortv/wnbios (.sys)' 'Block(拦截写入)' {
    foreach ($name in 'amsdk.sys','wamsdk.sys','wsftprm.sys','BootRepair.sys','EnPortv.sys','wnbios.sys') {
        $p = Join-Path $sandbox $name
        Set-Content -LiteralPath $p -Value 'HARMLESS TEST FILE - NOT A REAL DRIVER' -ErrorAction SilentlyContinue
        if (Test-Path $p) { $created.Add($p); Write-Host "      已写入: $p" -ForegroundColor DarkGray }
        else { Write-Host "      写入被拦截(未落地): $name" -ForegroundColor Yellow }
    }
}

# ---------------------------------------------------------------------
# 用例 6:注册服务且 binPath 指向可写目录  → Roaming/Downloads/Desktop/Windows\Temp
#        期望 Block;ProgramData 期望 Ask(那里有厂商服务的正常用法)
#   注意: 只是让命令行里出现该形态,rem 掉不真的建服务。
# ---------------------------------------------------------------------
Test-Case '6' 'sc create binPath= 指向可写目录(仅命令行字符串,不真的建服务)' 'Block(可写目录)/ Ask(ProgramData)' {
    $zones = @(
        "$env:APPDATA\svc.exe",
        "$env:USERPROFILE\Downloads\svc.exe",
        "$env:ProgramData\svc.exe"
    )
    foreach ($z in $zones) {
        Start-Process -FilePath 'cmd.exe' `
            -ArgumentList "/c rem sc create BulwarkTestSvc binPath= `"$z`"  (harmless test)" `
            -WindowStyle Hidden -ErrorAction SilentlyContinue
        Write-Host "      已启动含 binPath= $z 的无害命令行" -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------
# 用例 7:白加黑侧载(签名壳 + 同目录未签名的系统同名 DLL)  → 期望 Ask
#   检测: Worker::detectSideloadedTamperedModule 形态 2
#         (签名健康的主体 + 同目录未签名的 powrprof.dll => 45 分硬指标)
#   验证点:该主体【不应】再被「已签名主体默认放行」直接放掉,日志应出现
#         「白加黑侧载」与「保留询问」两行。
# ---------------------------------------------------------------------
Test-Case '7' '签名宿主 + 同目录未签名 powrprof.dll(银狐主流侧载形态)' 'Ask(弹窗询问,不得静默放行)' {
    # 找一个内嵌签名的宿主:优先用 -SignedHost;否则在常见安装位置里挑。
    $candidates = @()
    if ($SignedHost) { $candidates += $SignedHost }
    $candidates += @(
        (Join-Path $env:LOCALAPPDATA 'Microsoft\OneDrive\OneDriveStandaloneUpdater.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge_proxy.exe'),
        (Join-Path ${env:ProgramFiles} 'Git\cmd\git.exe'),
        (Join-Path ${env:ProgramFiles} '7-Zip\7z.exe')
    )
    $hostSrc = $null
    foreach ($c in $candidates) {
        if (-not (Test-Path -LiteralPath $c)) { continue }
        # 关键:必须复制到沙箱后【仍然】验签通过,才说明它是内嵌签名(目录签名复制后会失效)。
        $probe = Join-Path $sandbox ([System.IO.Path]::GetFileName($c))
        Copy-Item -LiteralPath $c -Destination $probe -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath $probe)) { continue }
        $sig = Get-AuthenticodeSignature -LiteralPath $probe -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status -eq 'Valid') { $hostSrc = $probe; $created.Add($probe); break }
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
    }
    if (-not $hostSrc) {
        Write-Host "      跳过:没找到复制后仍验签通过的内嵌签名程序。" -ForegroundColor DarkYellow
        Write-Host "      可用 -SignedHost '<某个带内嵌签名的 exe>' 重跑本用例。" -ForegroundColor DarkYellow
        return
    }
    Write-Host "      签名宿主: $hostSrc" -ForegroundColor DarkGray
    # 同目录放一个未签名的「系统同名模块」。内容是文本,不可能被真的加载 —— 检测看的是
    # 「名字 + 未签名 + 挨着签名壳」这三件事,不需要它真是 PE。
    $evil = Join-Path $sandbox 'powrprof.dll'
    Set-Content -LiteralPath $evil -Value 'HARMLESS TEST FILE - NOT A REAL DLL' -ErrorAction SilentlyContinue
    if (Test-Path $evil) { $created.Add($evil); Write-Host "      已放置: $evil" -ForegroundColor DarkGray }
    else { Write-Host "      powrprof.dll 写入即被拦截(落盘即扫也算生效)" -ForegroundColor Yellow }
    # 运行那个签名宿主,让检测在富化阶段扫到同目录。3 秒后收掉它。
    $proc = Start-Process -FilePath $hostSrc -ArgumentList '--version' -PassThru `
                          -WindowStyle Hidden -ErrorAction SilentlyContinue
    Write-Host "      已运行签名宿主(3 秒后结束)" -ForegroundColor DarkGray
    Start-Sleep -Seconds 3
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
}

# ---------------------------------------------------------------------
# 用例 8:侧载模块落盘即扫(系统同名 DLL / ProgramData 里的模块)  → 期望送云查
#   检测: Worker::maybeScanDroppedInstaller 的模块分支
#         (未签名 + 系统同名 或 落在 ProgramData / Users\Public)
#   观察: service.log 应出现「安装包/可执行体落盘送 VirusTotal 扫描」。
#         未配置 VT 密钥时本用例不会有云查动作,属预期。
# ---------------------------------------------------------------------
Test-Case '8' '未签名的系统同名模块落盘(powrprof.dll / wsc.dll / version.dll)' '落盘即扫(送云查)' {
    $targets = @(
        (Join-Path $sandbox 'wsc.dll'),
        (Join-Path $sandbox 'version.dll'),
        (Join-Path $env:ProgramData 'BulwarkTest_payload.dll')
    )
    foreach ($t in $targets) {
        Set-Content -LiteralPath $t -Value 'HARMLESS TEST FILE - NOT A REAL DLL' -ErrorAction SilentlyContinue
        if (Test-Path $t) { $created.Add($t); Write-Host "      已写入: $t" -ForegroundColor DarkGray }
        else { Write-Host "      写入被拦截: $t" -ForegroundColor Yellow }
    }
}

# ---------------------------------------------------------------------
# 用例 9:zpaqfranz 解包(银狐用它解嵌套 ZPAQ 载荷)  → 期望 Ask
#   规则: Proc_(*\zpaqfranz.exe , Ask)
#   模拟: 把 cmd.exe 复制成 zpaqfranz.exe 再运行(命中的是映像名,不需要真工具)。
#         刻意给 Ask 而非 Block —— Block 会把这个一次性临时路径钉进内核禁运名单。
# ---------------------------------------------------------------------
Test-Case '9' '运行改名为 zpaqfranz.exe 的无害程序' 'Ask(弹窗询问)' {
    $fake = Join-Path $sandbox 'zpaqfranz.exe'
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $fake `
              -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path $fake)) { Write-Host "      跳过:复制 cmd.exe 失败" -ForegroundColor DarkYellow; return }
    $created.Add($fake)
    Start-Process -FilePath $fake -ArgumentList '/c rem harmless test' -WindowStyle Hidden -ErrorAction SilentlyContinue
    Write-Host "      已运行: $fake" -ForegroundColor DarkGray
    Start-Sleep -Seconds 2
}

# ---------------------------------------------------------------------
# 结果与清理
# ---------------------------------------------------------------------
Write-Host ""
Write-Host "==== 测试触发完毕 ====" -ForegroundColor Green
Write-Host "请查看 Bulwark UI:上述每一步是否产生了弹窗 / 拦截 / 事件记录。" -ForegroundColor White
Write-Host ""
Write-Host "正在清理测试文件..." -ForegroundColor DarkGray
foreach ($f in $created) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "清理完成。" -ForegroundColor DarkGray

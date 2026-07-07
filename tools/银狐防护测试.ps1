# =====================================================================
#  磐垒(Bulwark)银狐·微信/QQ 群控防护 —— 无害行为测试脚本
# ---------------------------------------------------------------------
#  用途:在 Bulwark 服务运行时,复现"银狐控制微信/QQ 群发"会触发的
#        可观测行为特征,验证监控层 + 规则引擎 + 拦截是否真的生效。
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

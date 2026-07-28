# Collect-BenignSamples.ps1  (ASCII-only: Windows PowerShell 5.1 reads .ps1 as ANSI)
# Download reputable domestic + international software "white samples" via curl from
# official endpoints, verify Authenticode + sha256, log to CSV. NEVER executes anything.
# winget is unusable in this elevated/automation context (source query -> 0x80073cfc),
# so we use curl direct from official domains (Mozilla/Google/Microsoft aka.ms/Tencent/etc).
# Later: ingest_installers.py --dl-dir <DlDir> extracts inner PEs as benign corpus (no exec).
param(
    [string]$DlDir = "$env:USERPROFILE\Desktop\benign_samples"
)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Path $DlDir -Force | Out-Null
$log = Join-Path $DlDir '_benign_download_log.csv'
if (-not (Test-Path -LiteralPath $log)) {
    'time,region,name,file,size,sha256,signstatus,signer' | Out-File -LiteralPath $log -Encoding utf8
}

# n=name, u=url, x=ext, r=region
$items = @(
    @{n = 'Firefox'; u = 'https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US'; x = 'exe'; r = 'intl' },
    @{n = 'FirefoxESR'; u = 'https://download.mozilla.org/?product=firefox-esr-latest-ssl&os=win64&lang=en-US'; x = 'exe'; r = 'intl' },
    @{n = 'Thunderbird'; u = 'https://download.mozilla.org/?product=thunderbird-latest-ssl&os=win64&lang=en-US'; x = 'exe'; r = 'intl' },
    @{n = 'Chrome'; u = 'https://dl.google.com/chrome/install/standalonesetup64.exe'; x = 'exe'; r = 'intl' },
    @{n = 'ChromeEnterprise'; u = 'https://dl.google.com/tag/s/dl/chrome/install/googlechromestandaloneenterprise64.msi'; x = 'msi'; r = 'intl' },
    @{n = 'VSCodeUser'; u = 'https://update.code.visualstudio.com/latest/win32-x64-user/stable'; x = 'exe'; r = 'intl' },
    @{n = 'VSCodeSystem'; u = 'https://update.code.visualstudio.com/latest/win32-x64/stable'; x = 'exe'; r = 'intl' },
    @{n = 'Zoom'; u = 'https://zoom.us/client/latest/ZoomInstallerFull.exe'; x = 'exe'; r = 'intl' },
    @{n = 'AnyDesk'; u = 'https://download.anydesk.com/AnyDesk.exe'; x = 'exe'; r = 'intl' },
    @{n = 'TeamViewer'; u = 'https://download.teamviewer.com/download/TeamViewer_Setup_x64.exe'; x = 'exe'; r = 'intl' },
    @{n = 'PuTTY'; u = 'https://the.earth.li/~sgtatham/putty/latest/w64/putty-64bit-installer.msi'; x = 'msi'; r = 'intl' },
    @{n = 'Slack'; u = 'https://slack.com/ssb/download-win64-msi'; x = 'msi'; r = 'intl' },
    @{n = 'Telegram'; u = 'https://telegram.org/dl/desktop/win64'; x = 'exe'; r = 'intl' },
    @{n = 'Discord'; u = 'https://discord.com/api/download?platform=win'; x = 'exe'; r = 'intl' },
    @{n = 'DotNetDesktop8'; u = 'https://aka.ms/dotnet/8.0/windowsdesktop-runtime-win-x64.exe'; x = 'exe'; r = 'intl' },
    @{n = 'DotNetRuntime8'; u = 'https://aka.ms/dotnet/8.0/dotnet-runtime-win-x64.exe'; x = 'exe'; r = 'intl' },
    @{n = 'VCRedist-x64'; u = 'https://aka.ms/vs/17/release/vc_redist.x64.exe'; x = 'exe'; r = 'intl' },
    @{n = 'VCRedist-x86'; u = 'https://aka.ms/vs/17/release/vc_redist.x86.exe'; x = 'exe'; r = 'intl' },
    @{n = 'WebView2'; u = 'https://go.microsoft.com/fwlink/p/?LinkId=2124703'; x = 'exe'; r = 'intl' },
    @{n = 'WeChat'; u = 'https://dldir1.qq.com/weixin/Windows/WeChatSetup.exe'; x = 'exe'; r = 'cn' },
    @{n = 'QQ'; u = 'https://dldir1.qq.com/qqfile/qq/QQNT/Windows/QQ_x64.exe'; x = 'exe'; r = 'cn' },
    @{n = 'QQMusic'; u = 'https://dldir1.qq.com/music/clntupate/QQMusic_Setup.exe'; x = 'exe'; r = 'cn' },
    @{n = '360Safe'; u = 'https://down.360safe.com/setup.exe'; x = 'exe'; r = 'cn' },
    @{n = 'Huorong'; u = 'https://down4.huorong.cn/sysdiag-full.exe'; x = 'exe'; r = 'cn' },
    @{n = 'ToDesk'; u = 'https://dl.todesk.com/windows/ToDesk_Setup.exe'; x = 'exe'; r = 'cn' },
    @{n = 'Sunlogin'; u = 'https://dl.oray.com/sunlogin/windows/SunloginClient_x64.exe'; x = 'exe'; r = 'cn' },
    @{n = 'WPS'; u = 'https://package.wpscdn.cn/wps/download/WPS_Setup.exe'; x = 'exe'; r = 'cn' },
    @{n = 'QQBrowser'; u = 'https://dldir1.qq.com/invc/tt/QQBrowser_Setup_x64.exe'; x = 'exe'; r = 'cn' },
    @{n = 'WeCom'; u = 'https://dldir1.qq.com/wework/work_weixin/WeCom.exe'; x = 'exe'; r = 'cn' },
    @{n = 'QQPCMgr'; u = 'https://dldir1.qq.com/qqpcmgr/MgrNews/soft/qqpcmgr_setup.exe'; x = 'exe'; r = 'cn' },
    @{n = 'YoudaoDict'; u = 'https://codown.youdao.com/cidian/download/YoudaoDictSetup.exe'; x = 'exe'; r = 'cn' },
    @{n = 'NetEaseMusic'; u = 'https://d1.music.126.net/dmusic/cloudmusicsetup.exe'; x = 'exe'; r = 'cn' },
    @{n = 'BaiduNetdisk'; u = 'https://issuepcdn.baidupcs.com/issue/netdisk/yunguanjia/BaiduNetdisk_setup.exe'; x = 'exe'; r = 'cn' },
    @{n = 'Xunlei'; u = 'https://down.sandai.net/thunder11/XunLeiWebSetup.exe'; x = 'exe'; r = 'cn' },
    @{n = 'SogouInput'; u = 'https://ime.sogoucdn.com/dl/index/sogou_pinyin_setup.exe'; x = 'exe'; r = 'cn' },
    @{n = 'DingTalk'; u = 'https://dtapp-pub.dingtalk.com/dingtalk-desktop/win_installer/Release/DingTalk.exe'; x = 'exe'; r = 'cn' },
    @{n = 'PotPlayer'; u = 'https://t1.daumcdn.net/potplayer/PotPlayer/Version/Latest/PotPlayerSetup64.exe'; x = 'exe'; r = 'intl' }
)

function Log-File([string]$region, [string]$name, [string]$path) {
    try {
        $fi = Get-Item -LiteralPath $path -ErrorAction Stop
        $h = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        $sig = Get-AuthenticodeSignature -LiteralPath $path
        $signer = ''
        if ($sig.SignerCertificate) { $signer = ($sig.SignerCertificate.Subject -split ',')[0] }
        $row = '{0},{1},{2},{3},{4},{5},{6},"{7}"' -f (Get-Date -Format s), $region, $name, $fi.Name, $fi.Length, $h, $sig.Status, ($signer -replace '"', "'")
        Add-Content -LiteralPath $log -Value $row -Encoding utf8
        Write-Output ("    [{0,-9}] {1,-16} {2,8:N1}MB  {3}  {4}" -f $sig.Status, $name, ($fi.Length / 1MB), $h.Substring(0, 12), $signer)
        return $true
    }
    catch { return $false }
}

Write-Output "==== benign white-sample collection (curl, official URLs) -> $DlDir ===="
$ok = 0; $fail = 0; $signed = 0
foreach ($it in $items) {
    $dst = Join-Path $DlDir ("{0}.{1}" -f $it.n, $it.x)
    if ((Test-Path -LiteralPath $dst) -and ((Get-Item -LiteralPath $dst).Length -gt 50000) -and ((Get-AuthenticodeSignature -LiteralPath $dst).Status -eq 'Valid')) {
        Write-Output ("[{0}] {1} exists (valid-signed), skip" -f $it.r, $it.n); $ok++; $signed++; continue
    }
    Write-Output ("[{0}] {1} <- {2}" -f $it.r, $it.n, $it.u)
    & curl.exe -L --fail --connect-timeout 15 --max-time 300 -A 'Mozilla/5.0' -o $dst $it.u 2>$null
    $rc = $LASTEXITCODE
    if (($rc -eq 0) -and (Test-Path -LiteralPath $dst) -and ((Get-Item -LiteralPath $dst).Length -gt 50000)) {
        if (Log-File $it.r $it.n $dst) {
            $ok++
            if ((Get-AuthenticodeSignature -LiteralPath $dst).Status -eq 'Valid') { $signed++ }
        }
    }
    else {
        $fail++
        Write-Output ("    skip (curl exit={0} / too small / 404)" -f $rc)
        if (Test-Path -LiteralPath $dst) { Remove-Item -LiteralPath $dst -Force -ErrorAction SilentlyContinue }
    }
}
Write-Output "==== done ===="
Write-Output ("ok {0} / skip {1} / valid-signed {2}" -f $ok, $fail, $signed)
Write-Output ("log: {0}" -f $log)

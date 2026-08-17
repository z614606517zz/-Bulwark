@echo off
chcp 65001 >nul
rem 磐垒 - 驱动加载诊断(自动提权)。结果写入 driver_diag.txt 供分析。
rem ---- administrator gate: same fix as 启用驱动.bat, see the comment there ---
rem  This one was the worst of the four: it relaunched with NO message at all,
rem  so on a machine where "net session" fails while elevated the user just got
rem  windows appearing and closing with nothing printed. Now it says what it is
rem  doing, elevates at most once, and explains itself if that is not enough.
rem  No goto/labels on purpose (chcp 65001 + CJK + byte-offset seek).
rem -------------------------------------------------------------------------
set "BLW_ARGS=%*"
set "BLW_RETRY="
if /i "%~1"=="--elevated" (
    set "BLW_RETRY=1"
    call set "BLW_ARGS=%%BLW_ARGS:*--elevated=%%"
)

set "BLW_ADMIN="
reg query "HKU\S-1-5-19" >nul 2>&1
if not errorlevel 1 set "BLW_ADMIN=1"

set "BLW_NEEDPS="
if not defined BLW_ADMIN if defined BLW_RETRY set "BLW_NEEDPS=1"
if defined BLW_NEEDPS for /f "usebackq delims=" %%A in (`powershell -NoProfile -Command "[int]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"`) do if "%%A"=="1" set "BLW_ADMIN=1"

set "BLW_SELF=%~f0"
set "BLW_SELF=%BLW_SELF:'=''%"

rem  Gate messages are ASCII on purpose -- see the note in 启用驱动.bat: long
rem  multi-byte lines in these blocks made cmd execute the tail of a Chinese
rem  line as a command, which could also swallow the exit /b that keeps an
rem  unelevated run from reaching the payload.
if not defined BLW_ADMIN if defined BLW_RETRY (
    echo.
    echo Already elevated once, but administrator rights still cannot be confirmed.
    echo Stopping here instead of opening more windows.
    echo Right-click this file and choose "Run as administrator".
    echo If that fails too, another security product is blocking reg.exe / powershell.exe.
    echo.
    pause
    exit /b 1
)

if not defined BLW_ADMIN (
    echo Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process -FilePath '%BLW_SELF%' -ArgumentList '--elevated %BLW_ARGS%' -Verb RunAs"
    if errorlevel 1 (
        echo.
        echo Elevation was cancelled or blocked. No diagnostic report was written.
        echo Right-click this file and choose "Run as administrator".
        echo.
        pause
    )
    exit /b
)

cd /d "%~dp0"
set OUT=%~dp0driver_diag.txt

echo ==== Bulwark 驱动诊断 %DATE% %TIME% ==== > "%OUT%"

echo. >> "%OUT%"
echo [testsigning 状态] >> "%OUT%"
bcdedit | findstr /i "testsigning" >> "%OUT%" 2>&1
bcdedit | findstr /i "测试" >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [当前 sc query] >> "%OUT%"
sc query Bulwark >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [尝试 sc start Bulwark] >> "%OUT%"
sc start Bulwark >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [尝试 fltmc load Bulwark] >> "%OUT%"
fltmc load Bulwark >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [start 后 sc query] >> "%OUT%"
sc query Bulwark >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [已加载的 minifilter] >> "%OUT%"
fltmc filters >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [驱动签名详情] >> "%OUT%"
powershell -NoProfile -Command "$s=Get-AuthenticodeSignature \"$env:SystemRoot\System32\drivers\Bulwark.sys\"; 'Status='+$s.Status; 'StatusMessage='+$s.StatusMessage; 'Signer='+$s.SignerCertificate.Subject; 'Thumbprint='+$s.SignerCertificate.Thumbprint" >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [证书是否已在受信任存储] >> "%OUT%"
powershell -NoProfile -Command "$t=(Get-AuthenticodeSignature \"$env:SystemRoot\System32\drivers\Bulwark.sys\").SignerCertificate.Thumbprint; 'Root: '+((Test-Path \"Cert:\LocalMachine\Root\$t\")); 'TrustedPublisher: '+((Test-Path \"Cert:\LocalMachine\TrustedPublisher\$t\"))" >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [最近 CodeIntegrity / FilterManager 事件] >> "%OUT%"
powershell -NoProfile -Command "Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddMinutes(-10)} -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -match 'CodeIntegrity|FilterManager|Filter Manager|Service Control Manager' -or $_.Message -match 'Bulwark' } | Select-Object -First 15 TimeCreated,ProviderName,Id,Message | Format-List" >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [Microsoft-Windows-CodeIntegrity/Operational 最近事件] >> "%OUT%"
powershell -NoProfile -Command "Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 15 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | Format-List" >> "%OUT%" 2>&1

echo 诊断完成,结果已写入 driver_diag.txt
notepad "%OUT%"

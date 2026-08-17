@echo off
chcp 65001 >nul
rem 磐垒 - 一键启用内核驱动(测试签名)。自动请求管理员权限。
rem ---- administrator gate --------------------------------------------------
rem  Not "net session": that probe needs the Server (LanmanServer) service, so
rem  where the service is stopped/disabled -- or another security product blocks
rem  net.exe -- it returns non-zero inside an ALREADY-ELEVATED console. The old
rem  code then relaunched unconditionally, producing an endless chain of
rem  elevated windows (reported on Win10 x64).
rem  HKU\S-1-5-19 is the LocalService profile hive: admin-readable only, and it
rem  depends on no service. Measured elevated vs. a filtered token
rem  (runas /trustlevel:0x20000): reg query 0/1, fltmc 0/1, net session 0/2,
rem  whoami high-integrity SID 0/0 -- so whoami is NOT a usable probe.
rem  --elevated is a one-shot sentinel: consumed here, never forwarded, and its
rem  presence means "already tried", so a wrong probe answer cannot loop.
rem  Full write-up lives in packaging\portable-scripts (the launcher .bat).
rem
rem  Deliberately NO goto/labels: this file mixes chcp 65001 with multi-byte
rem  CJK, and cmd tracks a BYTE offset into a file it decoded under the previous
rem  codepage. goto makes cmd seek for a label, which is exactly when that
rem  desync bites. Plain if-blocks never re-seek.
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

rem Second pass only: if both cmd-level probes are blocked, get the
rem authoritative answer from PowerShell instead of refusing to run.
set "BLW_NEEDPS="
if not defined BLW_ADMIN if defined BLW_RETRY set "BLW_NEEDPS=1"
if defined BLW_NEEDPS for /f "usebackq delims=" %%A in (`powershell -NoProfile -Command "[int]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"`) do if "%%A"=="1" set "BLW_ADMIN=1"

rem Apostrophes doubled so a path like C:\Users\O'Neil\... survives the
rem PowerShell single-quoted string below. Must happen OUTSIDE the if-block:
rem a value set inside a parenthesised block is not readable within it.
set "BLW_SELF=%~f0"
set "BLW_SELF=%BLW_SELF:'=''%"

rem  The gate's own messages are ASCII even though this file is otherwise
rem  Chinese. Long multi-byte lines inside these parenthesised blocks made cmd
rem  desync its byte offset and execute the TAIL of a Chinese line as a command
rem  (observed: "'<garbage>' is not recognized as an internal or external
rem  command" right after the first echo). That is not merely cosmetic: the very
rem  next statements are pause / exit /b 1 and the RunAs call, so a desync could
rem  swallow the exit and let the payload run unelevated, or break the elevation
rem  command itself. Payload text further down is untouched.
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
        echo Elevation was cancelled or blocked. Nothing was changed.
        echo Right-click this file and choose "Run as administrator".
        echo.
        pause
    )
    exit /b
)

cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0启用驱动.ps1"
pause

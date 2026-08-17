@echo off
chcp 65001 >nul
rem 磐垒 - 停止内核驱动(自动提权)
rem ---- administrator gate: same fix as 启用驱动.bat, see the comment there ---
rem  "net session" needs the Server service, so it reports "not elevated" inside
rem  an already-elevated console on some machines; combined with the old
rem  unconditional relaunch that spawned windows forever. HKU\S-1-5-19 is
rem  admin-only and service-independent; --elevated is a one-shot sentinel.
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
        echo Elevation was cancelled or blocked. The driver was left untouched.
        echo Right-click this file and choose "Run as administrator".
        echo.
        pause
    )
    exit /b
)

cd /d "%~dp0"
echo =============== 停止 Bulwark 内核驱动 ===============

echo [1/4] 通过 fltmc 卸载 minifilter(绕过 SCM 自保护) ...
fltmc unload Bulwark
if %errorlevel% equ 0 ( echo   [OK] fltmc 卸载成功 ) else ( echo   [!] fltmc 卸载失败(可能无实例附加) )

echo [2/4] 尝试 sc stop(自保护可能拦截) ...
sc stop Bulwark

echo [3/4] 检查驱动状态 ...
sc query Bulwark
sc query Bulwark | findstr /i "STOPPED" >nul && echo   [OK] 驱动已停止 || echo   [!] 驱动仍在运行

echo [4/4] 如果驱动仍无法停止,请重启电脑(该驱动为手动启动,重启后不会自动加载)
echo =============================================
pause

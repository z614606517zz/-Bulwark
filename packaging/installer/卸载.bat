@echo off
rem ---------------------------------------------------------------------------
rem  Bulwark HIPS - COMPLETE uninstall. Double-click this.
rem
rem  This file ships INSIDE the install directory and is what the Start menu
rem  entry and the Add/Remove Programs UninstallString both point at.
rem
rem  With no arguments it does the whole job: stop the UI and the service,
rem  unload the minifilter, delete both service registrations, delete
rem  System32\drivers\Bulwark.sys, remove the BulwarkTestCert it imported, turn
rem  test signing back off if IT was the one that enabled it, drop shortcuts /
rem  the Add/Remove entry / the per-user autostart values, ask once about
rem  %ProgramData%\Bulwark, delete the install directory, then re-read the real
rem  state and report anything left over.
rem
rem  Pass-through switches:  -PurgeData  -KeepData  -KeepCert  -KeepTestSigning
rem
rem  Kept as a separate, obvious, double-clickable file on purpose: this is a
rem  legitimate security tool, so a plain user-driven removal path must always
rem  exist and be easy to find. It is never folded behind a flag.
rem
rem  Pure ASCII; see the note in the setup batch about cmd.exe byte-offset desync
rem  when a BOM-less UTF-8 batch file mixes chcp 65001 with multi-byte CJK text.
rem  That is also why this comment says "the setup batch" instead of naming it:
rem  the file name itself is CJK, and putting it here would break this very file.
rem ---------------------------------------------------------------------------
chcp 65001 >nul
title Bulwark Uninstall

rem ===========================================================================
rem  Administrator gate -- identical to the setup batch, see the comment there.
rem  Short version: "net session" needs the Server service and therefore reports
rem  "not elevated" inside an already-elevated console on some machines, which
rem  combined with an unconditional relaunch produced an endless chain of
rem  windows. HKU\S-1-5-19 is admin-only and depends on no service; --elevated
rem  is a one-shot sentinel so a wrong answer cannot loop.
rem
rem  Removal must stay reliable: a security tool that cannot be uninstalled is
rem  not acceptable, so this gate gets exactly the same treatment as setup.
rem ===========================================================================
set "BLW_ARGS=%*"
set "BLW_RETRY="
if /i "%~1"=="--elevated" (
    set "BLW_RETRY=1"
    call set "BLW_ARGS=%%BLW_ARGS:*--elevated=%%"
)

reg query "HKU\S-1-5-19" >nul 2>&1
if not errorlevel 1 goto :blw_elevated
if defined BLW_RETRY goto :blw_retry

set "BLW_SELF=%~f0"
set "BLW_SELF=%BLW_SELF:'=''%"
echo Requesting administrator privileges...
powershell -NoProfile -Command "Start-Process -FilePath '%BLW_SELF%' -ArgumentList '--elevated %BLW_ARGS%' -Verb RunAs"
if errorlevel 1 (
    echo.
    echo Elevation was cancelled or blocked, so nothing was uninstalled.
    echo Right-click this file and choose "Run as administrator".
    echo.
    pause
)
exit /b

:blw_retry
set "BLW_ISADMIN="
for /f "usebackq delims=" %%A in (`powershell -NoProfile -Command "[int]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"`) do set "BLW_ISADMIN=%%A"
if "%BLW_ISADMIN%"=="1" goto :blw_elevated
echo.
echo Already elevated once but administrator rights still cannot be confirmed,
echo so the uninstaller is stopping here instead of opening more windows.
echo Right-click this file and choose "Run as administrator". If that still
echo fails, another security product is most likely blocking reg.exe and
echo powershell.exe.
echo.
pause
exit /b 1

:blw_elevated
rem Do NOT cd into the install directory: this script is deleting that very
rem directory, and a current directory inside the tree keeps it undeletable.
cd /d "%SystemRoot%"
if not exist "%~dp0uninstall.ps1" (
    echo.
    echo uninstall.ps1 is missing next to this file - cannot continue.
    echo.
    pause
    exit /b 2
)
rem No -Dir here on purpose. "%~dp0" always ends in a backslash, and a trailing
rem backslash right before a closing quote escapes that quote in the CRT argument
rem parser, so the path would arrive mangled. uninstall.ps1 works out the install
rem directory from its own location plus the recorded InstallDir instead.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1" %BLW_ARGS%
echo.
pause

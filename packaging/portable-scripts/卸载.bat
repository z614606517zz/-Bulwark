@echo off
rem Bulwark portable - COMPLETE uninstall. With no arguments this does the whole
rem job: stop the UI and service, unload the minifilter, delete both service
rem registrations, delete System32\drivers\Bulwark.sys, remove the BulwarkTestCert
rem from Root + TrustedPublisher, turn test signing back off (leave test mode),
rem clear the reboot-resume entry, then re-read the real state and report leftovers.
rem
rem It asks once about %ProgramData%\Bulwark (custom rules, audit logs and the
rem quarantine folder full of live samples) because that deletion is irreversible.
rem Pass -PurgeData to delete it unattended, or -KeepData to keep it without asking.
rem
rem Opt-outs for the two machine-wide changes: -KeepTestSigning / -KeepCert.
rem Test signing is a global boot setting; the installer records whether it was the
rem one that turned it on, and the uninstaller only reverts what it enabled itself.
rem
rem Kept as a separate double-clickable file on purpose: this is a legitimate
rem security tool, so a plain user-driven removal path must always exist and be
rem obvious. It is never folded behind a flag only power users would find.
rem
rem Pure ASCII; see the note in the launcher .bat about cmd.exe byte-offset desync
rem when a BOM-less UTF-8 batch file mixes chcp 65001 with multi-byte CJK text.
chcp 65001 >nul
title Bulwark Uninstall
rem Administrator gate -- identical to the launcher .bat, see the long comment
rem there for why "net session" is NOT used (it needs the Server service, so it
rem reports "not elevated" inside an already-elevated console and the old
rem unconditional relaunch turned that into an endless chain of windows) and why
rem --elevated is a one-shot sentinel rather than an argument-forwarding test.
rem Removal must stay reliable: a security tool that cannot be uninstalled is
rem not acceptable, so this gate gets the same fix as the launcher.
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
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0bulwark.ps1" -Uninstall %BLW_ARGS%
echo.
pause

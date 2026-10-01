@echo off
rem ---------------------------------------------------------------------------
rem  Bulwark HIPS installer - the single entry point. Double-click this.
rem
rem  Everything (payload check, signature check, stopping an older install,
rem  copying files, staging + registering the minifilter, loading it when the
rem  target machine is already in test-signing mode, registering the service for
rem  auto-start, shortcuts, the Add/Remove Programs entry, launching the UI)
rem  happens in install.ps1 and is idempotent, so re-running it is safe.
rem
rem  Pass-through switches:  -Check  -NoDriver  -EnableTestSigning
rem                          -BootStart  -NoShortcut  -NoLaunch  -Dir <path>
rem
rem  This file is deliberately pure ASCII, including the name of the .ps1 it
rem  invokes. cmd.exe decodes a batch file with the codepage active when it
rem  opened the file, yet it also tracks a BYTE offset into that file.
rem  Switching to 65001 partway through a BOM-less UTF-8 script containing
rem  multi-byte CJK desynchronises that offset and cmd starts executing the tail
rem  of a comment line as a command. So batch stays ASCII; all human-facing text
rem  lives in install.ps1, which carries a UTF-8 BOM. The Chinese file NAME of
rem  this .bat is fine - that is a filesystem entry, not file content.
rem ---------------------------------------------------------------------------
chcp 65001 >nul
title Bulwark Setup

rem ===========================================================================
rem  Administrator gate.
rem
rem  Installing a kernel minifilter, writing Program Files and registering a
rem  service all require administrator.
rem
rem  Do NOT probe with "net session". It needs the Server (LanmanServer)
rem  service, so on a machine where that service is stopped or disabled -- or
rem  where another security product blocks net.exe -- it returns a non-zero
rem  errorlevel even in an ALREADY-ELEVATED console, and an unconditional
rem  relaunch then produces an endless chain of elevated windows.
rem
rem  HKU\S-1-5-19 is the LocalService profile hive: readable by administrators
rem  only, and dependent on no service at all. Measured on Win11 (elevated vs. a
rem  filtered token):
rem      reg query "HKU\S-1-5-19"   ->  0 / 1   discriminates -- use this
rem      net session                ->  0 / 2   service-dependent, unusable
rem      whoami /groups high-IL SID ->  0 / 0   does NOT discriminate at all
rem
rem  --elevated is a one-shot sentinel: consumed here, never forwarded to
rem  install.ps1. Its presence means "we already elevated once", so that path
rem  asks PowerShell for the authoritative answer and then stops with a readable
rem  message. It can never open another window.
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

rem Apostrophes are doubled so a path like C:\Users\O'Neil\Setup still survives
rem the PowerShell single-quoted string below.
set "BLW_SELF=%~f0"
set "BLW_SELF=%BLW_SELF:'=''%"
echo Requesting administrator privileges...
powershell -NoProfile -Command "Start-Process -FilePath '%BLW_SELF%' -ArgumentList '--elevated %BLW_ARGS%' -Verb RunAs"
if errorlevel 1 (
    echo.
    echo Elevation was cancelled or blocked, so nothing was installed.
    echo Right-click this file and choose "Run as administrator".
    echo.
    pause
)
exit /b

:blw_retry
rem Reached only on the second pass. Both cmd-level probes can be blocked by
rem another security product, so get the authoritative answer from PowerShell
rem before refusing to start -- but never relaunch again.
set "BLW_ISADMIN="
for /f "usebackq delims=" %%A in (`powershell -NoProfile -Command "[int]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"`) do set "BLW_ISADMIN=%%A"
if "%BLW_ISADMIN%"=="1" goto :blw_elevated
echo.
echo Already elevated once but administrator rights still cannot be confirmed,
echo so setup is stopping here instead of opening more windows.
echo Right-click this file and choose "Run as administrator". If that still
echo fails, another security product is most likely blocking reg.exe and
echo powershell.exe.
echo.
pause
exit /b 1

:blw_elevated
cd /d "%~dp0"
if not exist "%~dp0install.ps1" (
    echo.
    echo install.ps1 is missing next to this file.
    echo Extract the WHOLE package folder first - copying only this .bat out of
    echo the archive cannot work, the payload lives in the app\ subfolder.
    echo.
    pause
    exit /b 2
)
if not exist "%~dp0app\bulwark_service.exe" (
    echo.
    echo The app\ payload folder is missing or incomplete.
    echo Extract the WHOLE package folder, then double-click this file again.
    echo.
    pause
    exit /b 2
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %BLW_ARGS%
set "BLW_RC=%ERRORLEVEL%"

rem Always hold the window. The elevated console is a NEW window, so without
rem this any early failure (payload incomplete, signature mismatch, service
rem refused to start) would flash past and the user would be left with an
rem installer that "does nothing when I double-click it".
echo.
if not "%BLW_RC%"=="0" echo Setup exited with code %BLW_RC%.
pause
exit /b %BLW_RC%

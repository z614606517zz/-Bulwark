@echo off
rem ---------------------------------------------------------------------------
rem  Bulwark portable - the single entry point. Double-click this.
rem
rem  Everything (trust the driver cert, enable test signing, stage + register
rem  the minifilter, load it, start the service and UI) happens in bulwark.ps1
rem  and is idempotent: already-done steps are skipped, so the first run is
rem  "install + start" and every later run is just "start".
rem
rem  Pass-through switches:  -Check  -Uninstall  -SetupOnly
rem                          -BootStart  -InstallService
rem
rem  This file is deliberately pure ASCII, including the name of the .ps1 it
rem  invokes. cmd.exe decodes a batch file with the codepage active when it
rem  opened the file, yet it also tracks a BYTE offset into that file.
rem  Switching to 65001 partway through a BOM-less UTF-8 script containing
rem  multi-byte CJK desynchronises that offset and cmd starts executing the
rem  tail of a comment line as a command (observed: the tail of a Chinese rem
rem  line reported as "not recognized as an internal or external command").
rem  So batch stays ASCII; all human-facing text lives in bulwark.ps1, which
rem  carries a UTF-8 BOM. The Chinese file NAME of this .bat is fine - that is
rem  a filesystem entry, not file content, so no decoding is involved.
rem ---------------------------------------------------------------------------
chcp 65001 >nul
title Bulwark

rem ===========================================================================
rem  Administrator gate.
rem
rem  The service loads the kernel driver, opens an ETW session and writes
rem  %ProgramData%\Bulwark; staging the driver and registering the minifilter
rem  need System32 + SCM write access. All of that requires administrator.
rem
rem  Do NOT probe with "net session". It needs the Server (LanmanServer)
rem  service, so on a machine where that service is stopped or disabled -- or
rem  where another security product blocks net.exe -- it returns a non-zero
rem  errorlevel even in an ALREADY-ELEVATED console. The earlier version then
rem  relaunched itself unconditionally (the "%~1"=="" test only chose whether to
rem  forward arguments, it was never a loop guard), so those machines got an
rem  endless chain of elevated windows. Reported on Win10 x64: the title bar
rem  already read "Administrator: Bulwark" while the body still printed
rem  "Requesting administrator privileges...".
rem
rem  HKU\S-1-5-19 is the LocalService profile hive: readable by administrators
rem  only, and dependent on no service at all. Measured elevated vs. a
rem  "runas /trustlevel:0x20000" filtered token on Win11:
rem      reg query "HKU\S-1-5-19"   ->  0 / 1   discriminates -- use this
rem      fltmc                      ->  0 / 1   discriminates
rem      net session                ->  0 / 2   service-dependent, unusable
rem      whoami /groups high-IL SID ->  0 / 0   does NOT discriminate at all
rem
rem  --elevated is our own one-shot sentinel: consumed here, never forwarded to
rem  bulwark.ps1. Its presence means "we already elevated once", so that path
rem  asks PowerShell for the authoritative answer and then stops with a
rem  readable message. It can never open another window.
rem
rem  Because the sentinel makes -ArgumentList always non-empty, the two
rem  Start-Process branches the old code needed (Start-Process rejects an empty
rem  -ArgumentList) collapse into a single line.
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

rem Apostrophes are doubled so a path like C:\Users\O'Neil\Bulwark still
rem survives the PowerShell single-quoted string below.
set "BLW_SELF=%~f0"
set "BLW_SELF=%BLW_SELF:'=''%"
echo Requesting administrator privileges...
powershell -NoProfile -Command "Start-Process -FilePath '%BLW_SELF%' -ArgumentList '--elevated %BLW_ARGS%' -Verb RunAs"
if errorlevel 1 (
    echo.
    echo Elevation was cancelled or blocked, so Bulwark did not start.
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
echo so Bulwark is stopping here instead of opening more windows.
echo Right-click this file and choose "Run as administrator". If that still
echo fails, another security product is most likely blocking reg.exe and
echo powershell.exe.
echo.
pause
exit /b 1

:blw_elevated
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0bulwark.ps1" %BLW_ARGS%

rem Always hold the window. The elevated console is a NEW window, so without
rem this any early failure (Secure Boot on, driver missing, service refused to
rem start) would flash past and the user would be left with a package that
rem "does nothing when I double-click it".
echo.
pause

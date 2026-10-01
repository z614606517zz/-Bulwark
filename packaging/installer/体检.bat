@echo off
rem ---------------------------------------------------------------------------
rem  Bulwark HIPS - read-only health check of THIS machine. Changes nothing.
rem
rem  Ships inside the install directory. It runs bulwark.ps1 -Check, which is the
rem  same code path the log collector embeds in its report, so what you see here
rem  and what a support bundle contains can never disagree.
rem
rem  It lists, item by item: which payload files are present, the driver's
rem  signature state, test signing / Secure Boot / HVCI, whether the minifilter
rem  is registered with the right Altitude, whether it is actually loaded, the
rem  service state, and therefore which protection tier is really in force.
rem
rem  Note: bulwark.ps1 is shared verbatim with the portable package, so one or two
rem  of its closing hints tell you to double-click the portable launcher. In an
rem  installed deployment the equivalent actions are the setup batch (repair or
rem  reinstall) and the uninstall batch (remove). Every STATE line it prints is
rem  read from the live system and is accurate.
rem
rem  Not elevated? It still runs and degrades, telling you which parts are
rem  missing - "nothing works, not even elevation" is exactly when a health
rem  check has to remain usable.
rem
rem  Pure ASCII, and that is also why the comments above do not name the CJK
rem  batch files: cmd.exe tracks a byte offset while decoding with the active
rem  codepage, so multi-byte text in a BOM-less batch desynchronises it.
rem ---------------------------------------------------------------------------
chcp 65001 >nul
title Bulwark Health Check

set "BLW_ARGS=%*"
set "BLW_RETRY="
if /i "%~1"=="--elevated" (
    set "BLW_RETRY=1"
    call set "BLW_ARGS=%%BLW_ARGS:*--elevated=%%"
)

reg query "HKU\S-1-5-19" >nul 2>&1
if not errorlevel 1 goto :blw_run
if defined BLW_RETRY goto :blw_run

set "BLW_SELF=%~f0"
set "BLW_SELF=%BLW_SELF:'=''%"
echo Requesting administrator privileges (the check is read-only)...
powershell -NoProfile -Command "Start-Process -FilePath '%BLW_SELF%' -ArgumentList '--elevated %BLW_ARGS%' -Verb RunAs"
if errorlevel 1 (
    echo.
    echo Elevation was cancelled or blocked - running the check without it.
    echo Driver and service details will be incomplete.
    echo.
    goto :blw_run
)
exit /b

:blw_run
cd /d "%~dp0"
if not exist "%~dp0bulwark.ps1" (
    echo.
    echo bulwark.ps1 is missing from the install directory - cannot run the check.
    echo.
    pause
    exit /b 2
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0bulwark.ps1" -Check %BLW_ARGS%
echo.
pause

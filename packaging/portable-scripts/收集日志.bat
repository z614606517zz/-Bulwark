@echo off
rem ---------------------------------------------------------------------------
rem  Bulwark portable - collect diagnostics into ONE shareable zip on the Desktop.
rem
rem  Double-click this when something misbehaves, then send the resulting zip.
rem  All the actual work lives in bulwark.ps1 -CollectLogs, which:
rem    * reuses the same -Check logic, so the report matches what the user sees
rem    * REDACTS the reputation endpoint, every API key / bearer token and the
rem      Windows user name (service.log was measured to contain the endpoint)
rem    * caps big files to a tail (the full data dir measured ~110 MB)
rem    * never packs quarantine\ contents -- those are real malware samples
rem
rem  Pure ASCII like the other launchers in this package: cmd.exe decodes a batch
rem  file with the codepage active when it opened the file yet tracks a BYTE
rem  offset into it, so mixing chcp 65001 with multi-byte CJK desynchronises that
rem  offset and cmd starts executing the tail of a comment line as a command.
rem  All human-facing text lives in bulwark.ps1, which carries a UTF-8 BOM.
rem  The Chinese file NAME is fine - that is a directory entry, not content.
rem ---------------------------------------------------------------------------
chcp 65001 >nul
title Bulwark Diagnostics

rem ===========================================================================
rem  Administrator gate -- identical to the launcher .bat, see the long comment
rem  there. Short version: "net session" needs the Server (LanmanServer) service
rem  and therefore reports "not elevated" inside an ALREADY-ELEVATED console on
rem  some machines, which combined with an unconditional relaunch produced an
rem  endless chain of windows. HKU\S-1-5-19 is admin-only and depends on no
rem  service; --elevated is a one-shot sentinel so a wrong answer cannot loop.
rem
rem  Collection itself is read-only and bulwark.ps1 tolerates running without
rem  admin (it degrades and says so), because "nothing works, not even
rem  elevation" is exactly when a user needs to be able to collect logs. So the
rem  give-up path below still runs the collector instead of refusing outright.
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

rem Apostrophes doubled so a path like C:\Users\O'Neil\... survives the
rem PowerShell single-quoted string below.
set "BLW_SELF=%~f0"
set "BLW_SELF=%BLW_SELF:'=''%"
echo Requesting administrator privileges...
powershell -NoProfile -Command "Start-Process -FilePath '%BLW_SELF%' -ArgumentList '--elevated %BLW_ARGS%' -Verb RunAs"
if errorlevel 1 (
    echo.
    echo Elevation was cancelled or blocked. Collecting without administrator
    echo rights instead -- driver and service details will be missing.
    echo.
    goto :blw_collect
)
exit /b

:blw_retry
set "BLW_ISADMIN="
for /f "usebackq delims=" %%A in (`powershell -NoProfile -Command "[int]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"`) do set "BLW_ISADMIN=%%A"
if "%BLW_ISADMIN%"=="1" goto :blw_elevated
echo.
echo Could not confirm administrator rights after elevating once, so this will
echo collect what it can WITHOUT admin instead of opening more windows.
echo Driver and service details will be missing from the report.
echo.
goto :blw_collect

:blw_elevated
:blw_collect
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0bulwark.ps1" -CollectLogs %BLW_ARGS%

echo.
pause

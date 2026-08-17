@echo off
REM ASCII-only on purpose: a Chinese Windows cmd parses .bat in GBK, and any
REM UTF-8 multibyte chars corrupt the whole line (incl. ASCII commands).
REM
REM ---- administrator gate --------------------------------------------------
REM  Not "net session": it needs the Server (LanmanServer) service, so where
REM  that service is off -- or another security product blocks net.exe -- it
REM  returns non-zero inside an ALREADY-ELEVATED console, and the old
REM  unconditional relaunch turned that into an endless chain of windows
REM  (reported on Win10 x64). HKU\S-1-5-19 is the LocalService profile hive:
REM  admin-readable only, service-independent. Measured elevated vs. a filtered
REM  "runas /trustlevel:0x20000" token: reg query 0/1, fltmc 0/1,
REM  net session 0/2, whoami high-integrity SID 0/0 (whoami is NOT usable).
REM  --elevated is a one-shot sentinel: consumed here, never forwarded, so a
REM  wrong probe answer can never loop.
REM  Structured without goto/labels to match the other launchers.
REM -------------------------------------------------------------------------
set "BLW_ARGS=%*"
set "BLW_RETRY="
if /i "%~1"=="--elevated" (
  set "BLW_RETRY=1"
  call set "BLW_ARGS=%%BLW_ARGS:*--elevated=%%"
)

set "BLW_ADMIN="
reg query "HKU\S-1-5-19" >nul 2>&1
if not errorlevel 1 set "BLW_ADMIN=1"

REM Second pass only: if both cmd-level probes are blocked, ask PowerShell for
REM the authoritative answer instead of refusing to run.
set "BLW_NEEDPS="
if not defined BLW_ADMIN if defined BLW_RETRY set "BLW_NEEDPS=1"
if defined BLW_NEEDPS for /f "usebackq delims=" %%A in (`powershell -NoProfile -Command "[int]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"`) do if "%%A"=="1" set "BLW_ADMIN=1"

REM Apostrophes doubled so a path containing one survives the PowerShell
REM single-quoted string. Must be set OUTSIDE the if-block below.
set "BLW_SELF=%~f0"
set "BLW_SELF=%BLW_SELF:'=''%"

if not defined BLW_ADMIN if defined BLW_RETRY (
  echo.
  echo Elevated once already, but administrator rights still cannot be confirmed,
  echo so this script is stopping instead of opening more windows.
  echo Right-click this file and choose "Run as administrator". If that still
  echo fails, another security product is most likely blocking reg.exe and
  echo powershell.exe.
  echo.
  pause
  exit /b 1
)

if not defined BLW_ADMIN (
  echo Requesting administrator elevation - please click YES on the UAC prompt...
  powershell -NoProfile -Command "Start-Process -FilePath '%BLW_SELF%' -ArgumentList '--elevated %BLW_ARGS%' -Verb RunAs"
  if errorlevel 1 (
    echo.
    echo Elevation was cancelled or blocked, nothing was redeployed.
    echo Right-click this file and choose "Run as administrator".
    echo.
    pause
  )
  exit /b
)

echo Administrator OK. Redeploying v4-compatible service and restarting...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0__drv_reload.ps1"
echo.
echo Done. Log file: %USERPROFILE%\__deployb.log
pause

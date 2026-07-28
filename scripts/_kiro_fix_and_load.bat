@echo off
REM ====================================================================
REM  One-click: release the current PowerShell exec-block, then
REM  test-sign + deploy + load the REBUILT Bulwark.sys.
REM
REM  RIGHT-CLICK this file  ->  "Run as administrator".
REM  Uses cmd (not blocked); its FIRST action unloads the driver, which
REM  clears the kernel block so the PowerShell step below can run.
REM
REM  PREREQ: in the Bulwark UI, add PowerShell to the Trust List first
REM  (Trust List -> Trust Folder -> the two WindowsPowerShell\v1.0 folders),
REM  so the service does not re-block/kill PowerShell during deploy.
REM
REM  ASCII-only on purpose (Chinese Windows cmd parses .bat as GBK).
REM ====================================================================

net session >nul 2>&1
if %errorlevel% neq 0 (
  echo.
  echo   Not elevated. RIGHT-CLICK this file and choose "Run as administrator".
  echo.
  pause
  exit /b 1
)

echo [1/2] Unloading the currently-loaded Bulwark driver to release the PowerShell block...
fltmc unload Bulwark 2>nul
sc stop Bulwark >nul 2>&1
timeout /t 1 /nobreak >nul

echo [2/2] Test-sign + deploy + load the REBUILT driver (this may BSOD; demand-start = reboot recovers)...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0_kiro_testload.ps1"

echo.
echo Finished. Full log: %USERPROFILE%\bulwark_deploy.log
echo If the machine did NOT crash, tell Kiro and it will read the log to confirm the load.
pause

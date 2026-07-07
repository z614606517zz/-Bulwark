@echo off
REM ASCII-only on purpose: a Chinese Windows cmd parses .bat in GBK, and any
REM UTF-8 multibyte chars corrupt the whole line (incl. ASCII commands).
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting administrator elevation - please click YES on the UAC prompt...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
echo Administrator OK. Redeploying v4-compatible service and restarting...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0__drv_reload.ps1"
echo.
echo Done. Log file: %USERPROFILE%\__deployb.log
pause

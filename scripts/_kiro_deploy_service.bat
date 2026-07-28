@echo off
REM Right-click -> Run as administrator. Redeploys the rebuilt Bulwark SERVICE only (catch-all sweep).
REM The driver (Bulwark.sys) is left untouched.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0_kiro_deploy_service.ps1"
echo.
echo ==== done. Log: %USERPROFILE%\bulwark_deploy_service.log ====
pause

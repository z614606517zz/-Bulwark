@echo off
setlocal
title auto-allow (running)
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS%" set "PS=%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
echo Auto-Allow is running - it auto-clicks Kiro's Allow button (pure UIA, no mouse).
echo Leave this window open. Press Ctrl+C to stop.
echo.
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0auto-allow.ps1"
echo.
pause

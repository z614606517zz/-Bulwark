@echo off
rem One-click (safe, user-mode only): compile + start service + open UI.
rem Skips the kernel driver -- no test-signing change, no BSOD risk.
rem Protection runs via user-mode ETW observation.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0cpp\scripts\dev-all.ps1" -SkipDriver %*

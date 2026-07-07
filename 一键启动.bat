@echo off
rem One-click: compile + start service + load kernel driver + open UI.
rem Self-elevates for the admin steps. Kernel driver flips test-signing on
rem (needs one reboot) and can BSOD if faulty -- prefer a snapshotted VM.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0cpp\scripts\dev-all.ps1" %*

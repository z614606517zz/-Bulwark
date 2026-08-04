@echo off
rem Bulwark portable - uninstall (unload driver, delete services, remove .sys).
rem
rem Kept as a separate double-clickable file on purpose: this is a legitimate
rem security tool, so a plain user-driven removal path must always exist and be
rem obvious. It is never folded behind a flag only power users would find.
rem
rem Pure ASCII; see the note in the launcher .bat about cmd.exe byte-offset desync
rem when a BOM-less UTF-8 batch file mixes chcp 65001 with multi-byte CJK text.
chcp 65001 >nul
title Bulwark Uninstall
rem Start-Process rejects an empty -ArgumentList, and no-argument is the normal
rem double-click case, so the two branches are deliberate. See the launcher .bat.
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    if "%~1"=="" (
        powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    ) else (
        powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    )
    exit /b
)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0bulwark.ps1" -Uninstall %*
echo.
pause

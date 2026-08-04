@echo off
rem ---------------------------------------------------------------------------
rem  Bulwark portable - the single entry point. Double-click this.
rem
rem  Everything (trust the driver cert, enable test signing, stage + register
rem  the minifilter, load it, start the service and UI) happens in bulwark.ps1
rem  and is idempotent: already-done steps are skipped, so the first run is
rem  "install + start" and every later run is just "start".
rem
rem  Pass-through switches:  -Check  -Uninstall  -SetupOnly
rem                          -BootStart  -InstallService
rem
rem  This file is deliberately pure ASCII, including the name of the .ps1 it
rem  invokes. cmd.exe decodes a batch file with the codepage active when it
rem  opened the file, yet it also tracks a BYTE offset into that file.
rem  Switching to 65001 partway through a BOM-less UTF-8 script containing
rem  multi-byte CJK desynchronises that offset and cmd starts executing the
rem  tail of a comment line as a command (observed: the tail of a Chinese rem
rem  line reported as "not recognized as an internal or external command").
rem  So batch stays ASCII; all human-facing text lives in bulwark.ps1, which
rem  carries a UTF-8 BOM. The Chinese file NAME of this .bat is fine - that is
rem  a filesystem entry, not file content, so no decoding is involved.
rem ---------------------------------------------------------------------------
chcp 65001 >nul
title Bulwark

rem The service loads the kernel driver, opens an ETW session and writes
rem %ProgramData%\Bulwark; staging the driver and registering the minifilter
rem need System32 + SCM write access. All of that requires administrator.
rem Two elevation branches on purpose. Start-Process rejects an EMPTY
rem -ArgumentList ("cannot bind argument ... empty string"), and the no-argument
rem double-click is the normal case -- collapsing these into one line makes the
rem plain double-click fail silently while every switched invocation works.
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
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0bulwark.ps1" %*

rem Always hold the window. The elevated console is a NEW window, so without
rem this any early failure (Secure Boot on, driver missing, service refused to
rem start) would flash past and the user would be left with a package that
rem "does nothing when I double-click it".
echo.
pause

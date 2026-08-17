@echo off
rem Bulwark portable - apply a downloaded update.
rem
rem What this does: takes the three payload files the background service already
rem downloaded and verified (bulwark_service.exe, bulwark_ui.exe, Bulwark.sys),
rem re-verifies their Authenticode signer against the pinned thumbprint IN THIS
rem ELEVATED CONTEXT, backs up the current versions, stops the UI, the service and
rem the kernel driver in that order, swaps the files, re-stages and reloads the
rem driver, then starts protection again. Any failure rolls back and reloads the
rem OLD driver, so a failed update never leaves the machine without protection.
rem
rem Why the signature is checked again here even though the service already did it:
rem the staging directory lives under %LOCALAPPDATA% and is writable by the plain
rem user, so anything running as that user can swap the files between "downloaded
rem and verified" and "applied as administrator". This script copies those files
rem into the install directory and loads one of them as a KERNEL DRIVER, which is
rem the highest-privilege operation in the product -- so trust has to be
rem established at the moment of use, inside the elevated process.
rem
rem Normally launched by the UI ("Install now" in the update dialog), which passes
rem -UpdateDir so the correct staging path is used even when elevation switches to
rem a different administrator account (that account has a different %LOCALAPPDATA%).
rem Double-clicking it works too: with no arguments the script falls back to the
rem current user's default staging directory.
rem
rem Pure ASCII on purpose; see the note in the launcher .bat about cmd.exe byte
rem offset desync when a BOM-less UTF-8 batch file mixes chcp 65001 with CJK text.
chcp 65001 >nul
title Bulwark Update
rem Administrator gate -- same shape as the launcher and uninstaller .bat files.
rem "net session" is deliberately NOT used to detect elevation: it needs the Server
rem service, so on machines where that is disabled it reports "not elevated" even
rem inside an already-elevated console, and the unconditional relaunch that used to
rem follow turned this into an endless chain of UAC windows. --elevated is a
rem one-shot sentinel, so a failed detection stops instead of looping.
set "BLW_ARGS=%*"
set "BLW_RETRY="
if /i "%~1"=="--elevated" (
    set "BLW_RETRY=1"
    call set "BLW_ARGS=%%BLW_ARGS:*--elevated=%%"
)

reg query "HKU\S-1-5-19" >nul 2>&1
if not errorlevel 1 goto :blw_elevated
if defined BLW_RETRY goto :blw_retry

set "BLW_SELF=%~f0"
set "BLW_SELF=%BLW_SELF:'=''%"
echo Requesting administrator privileges...
powershell -NoProfile -Command "Start-Process -FilePath '%BLW_SELF%' -ArgumentList '--elevated %BLW_ARGS%' -Verb RunAs"
if errorlevel 1 (
    echo.
    echo Elevation was cancelled or blocked, so nothing was changed. The current
    echo version is still installed and the downloaded files are still there, so
    echo you can simply run this again.
    echo.
    pause
)
exit /b

:blw_retry
set "BLW_ISADMIN="
for /f "usebackq delims=" %%A in (`powershell -NoProfile -Command "[int]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"`) do set "BLW_ISADMIN=%%A"
if "%BLW_ISADMIN%"=="1" goto :blw_elevated
echo.
echo Already elevated once but administrator rights still cannot be confirmed,
echo so the update is stopping here instead of opening more windows. Nothing was
echo changed. Right-click this file and choose "Run as administrator".
echo.
pause
exit /b 1

:blw_elevated
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0bulwark.ps1" -ApplyUpdate %BLW_ARGS%
echo.
pause

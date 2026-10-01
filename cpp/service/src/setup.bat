@echo off
> "%TEMP%\kiro_sfx_marker.txt" echo ran-from=%~dp0
>> "%TEMP%\kiro_sfx_marker.txt" echo sub-exists=%~dp0sub\inner.txt
if exist "%~dp0sub\inner.txt" (>> "%TEMP%\kiro_sfx_marker.txt" echo subdir=OK) else (>> "%TEMP%\kiro_sfx_marker.txt" echo subdir=MISSING)
exit /b 0
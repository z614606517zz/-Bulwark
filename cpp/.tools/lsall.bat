@echo off
setlocal
pushd "%~dp0..\.."
set "REPO=%CD%"
popd
set "LOG=C:\Users\61460\__ls.txt"
dir /s /b "%REPO%\cpp\shared" "%REPO%\cpp\service" "%REPO%\cpp\ui\src" > "%LOG%" 2>&1
endlocal

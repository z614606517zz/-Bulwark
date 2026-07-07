@echo off
setlocal
set "GIT=C:\Program Files\Git\cmd\git.exe"
if not exist "%GIT%" set "GIT=C:\Program Files\Git\bin\git.exe"
if not exist "%GIT%" set "GIT=git"
pushd "%~dp0..\.."
set "REPO=%CD%"
popd
set "LOG=C:\Users\61460\__git.log"
echo REPO=[%REPO%]> "%LOG%"
echo ---STATUS--->> "%LOG%"
"%GIT%" -C "%REPO%" status --short >> "%LOG%" 2>&1
echo EXIT_%ERRORLEVEL%>> "%LOG%"
endlocal

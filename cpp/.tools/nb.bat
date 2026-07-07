@echo off
rem Fast incremental build via Ninja + MSVC. Ninja does NOT rebuild the whole
rem tree on reconfigure, so backend iteration is seconds not ~10 minutes.
rem vcvars adds cl/link; we also add the VS-bundled Ninja to PATH. Paths are
rem normalized to absolute (no "..") via pushd/%CD% to dodge Chinese-path issues.
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
set "VSCMK=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake"
set "PATH=%VSCMK%\Ninja;%PATH%"
set "CM=%VSCMK%\CMake\bin\cmake.exe"
pushd "%~dp0.."
set "SRC=%CD%"
popd
set "BLD=%SRC%\build-ninja"
set "LOG=C:\Users\61460\__N.log"
echo SRC=[%SRC%]> "%LOG%"
echo BLD=[%BLD%]>> "%LOG%"
"%CM%" -G Ninja -S "%SRC%" -B "%BLD%" -DCMAKE_BUILD_TYPE=Debug "-DCMAKE_PREFIX_PATH=C:/Qt/6.8.3/msvc2022_64" >> "%LOG%" 2>&1
echo CFG_EXIT_%ERRORLEVEL%>> "%LOG%"
"%CM%" --build "%BLD%" >> "%LOG%" 2>&1
echo BUILD_EXIT_%ERRORLEVEL%>> "%LOG%"
endlocal

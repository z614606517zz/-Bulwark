@echo off
rem 增量编译 Bulwark UI
setlocal

echo ========================================
echo 正在编译 Bulwark UI...
echo ========================================

rem 设置 Visual Studio 环境
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo 错误: 无法加载 Visual Studio 环境
    exit /b 1
)

rem 设置 CMake 和 Ninja 路径
set "VSCMK=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake"
set "PATH=%VSCMK%\Ninja;%PATH%"
set "CM=%VSCMK%\CMake\bin\cmake.exe"

rem 设置源码和构建目录
pushd "%~dp0"
set "SRC=%CD%"
popd
set "BLD=%SRC%\build-ninja"

echo.
echo 源码目录: %SRC%
echo 构建目录: %BLD%
echo.

rem 配置 CMake (如果需要)
if not exist "%BLD%\CMakeCache.txt" (
    echo 首次配置 CMake...
    "%CM%" -G Ninja -S "%SRC%" -B "%BLD%" -DCMAKE_BUILD_TYPE=Release "-DCMAKE_PREFIX_PATH=C:/Qt/6.8.3/msvc2022_64"
    if %ERRORLEVEL% neq 0 (
        echo.
        echo 错误: CMake 配置失败
        echo 请检查 Qt 路径是否正确: C:/Qt/6.8.3/msvc2022_64
        exit /b 1
    )
) else (
    echo 使用现有 CMake 配置...
)

echo.
echo 开始编译...
"%CM%" --build "%BLD%" --target bulwark_ui
if %ERRORLEVEL% neq 0 (
    echo.
    echo 错误: 编译失败
    exit /b 1
)

echo.
echo ========================================
echo 编译成功！
echo ========================================
echo.
echo 可执行文件位置: %BLD%\ui\bulwark_ui.exe
echo.

rem 询问是否复制到 dist 目录
set /p COPY_TO_DIST="是否复制到 dist 目录? (Y/N): "
if /i "%COPY_TO_DIST%"=="Y" (
    if not exist "%SRC%\..\cpp\dist" (
        mkdir "%SRC%\..\cpp\dist"
    )
    copy /Y "%BLD%\ui\bulwark_ui.exe" "%SRC%\..\cpp\dist\bulwark_ui.exe"
    echo 已复制到: %SRC%\..\cpp\dist\bulwark_ui.exe
)

endlocal
pause

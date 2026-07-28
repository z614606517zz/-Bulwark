@echo off
echo 正在编译 Bulwark Launcher...

:: 使用 MSVC 编译
cl /EHsc /O2 /MT /Fe:bulwark_launcher.exe bulwark_launcher.cpp /link advapi32.lib

if %errorlevel% equ 0 (
    echo.
    echo 编译成功！
    echo 将 bulwark_launcher.exe 复制到 cpp\dist 目录...
    copy /Y bulwark_launcher.exe ..\cpp\dist\
    echo 完成！
) else (
    echo.
    echo 编译失败，请确保已安装 Visual Studio 并配置了环境变量。
)

pause

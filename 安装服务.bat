@echo off
chcp 65001 >nul
echo.
echo ========================================
echo   磐垒主动防御 - 一键安装
echo ========================================
echo.

:: 获取脚本所在目录
set "SCRIPT_DIR=%~dp0"
echo 脚本目录: %SCRIPT_DIR%
echo.

:: 检查管理员权限
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [错误] 需要管理员权限！
    echo.
    echo 请右键点击此文件，选择"以管理员身份运行"
    echo.
    pause
    exit /b 1
)
echo [OK] 管理员权限已获取
echo.

:: 检查 .NET SDK
echo [1/5] 检查 .NET SDK...
where dotnet >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo [错误] 未找到 .NET SDK！
    echo.
    echo 请先安装 .NET 8.0 SDK：
    echo https://dotnet.microsoft.com/download/dotnet/8.0
    echo.
    echo 选择 "Download .NET SDK" 按钮下载
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('dotnet --version 2^>nul') do set DOTNET_VER=%%i
echo [OK] .NET 版本: %DOTNET_VER%
echo.

:: 检查源码是否存在
echo [2/5] 检查源码...
if not exist "%SCRIPT_DIR%Bulwark.Service\Bulwark.Service.csproj" (
    echo [错误] 未找到源码文件！
    echo 请确保此脚本在项目根目录下
    pause
    exit /b 1
)
echo [OK] 源码文件存在
echo.

:: 发布服务
echo [3/5] 编译发布服务（可能需要1-2分钟）...
if exist "%SCRIPT_DIR%publish\service" rmdir /s /q "%SCRIPT_DIR%publish\service"
dotnet publish "%SCRIPT_DIR%Bulwark.Service\Bulwark.Service.csproj" -c Release -o "%SCRIPT_DIR%publish\service" --nologo
if %errorLevel% neq 0 (
    echo.
    echo [错误] 编译失败！
    echo 请检查是否安装了正确的 .NET SDK 版本
    echo.
    pause
    exit /b 1
)
echo [OK] 编译成功
echo.

:: 清理旧服务
echo [4/5] 安装服务...
sc query BulwarkDefense >nul 2>&1
if %errorLevel% equ 0 (
    echo 发现旧服务，正在删除...
    net stop BulwarkDefense >nul 2>&1
    sc delete BulwarkDefense >nul 2>&1
    timeout /t 3 /nobreak >nul
)

sc create BulwarkDefense binPath= "\"%SCRIPT_DIR%publish\service\Bulwark.Service.exe\"" start= auto DisplayName= "Bulwark Defense" >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo [错误] 服务安装失败！
    echo 请确保以管理员身份运行
    echo.
    pause
    exit /b 1
)
echo [OK] 服务安装成功
echo.

:: 启动服务
echo [5/5] 启动服务...
net start BulwarkDefense >nul 2>&1
if %errorLevel% neq 0 (
    echo [警告] 服务启动失败，将在重启后自动启动
) else (
    echo [OK] 服务启动成功
)
echo.

:: 编译UI
echo [额外] 编译 UI...
dotnet build "%SCRIPT_DIR%Bulwark.UI.Scifi\Bulwark.UI.Scifi.csproj" -c Release --nologo -v q
if %errorLevel% neq 0 (
    echo [警告] UI 编译失败，但服务已安装
)
echo.

echo ========================================
echo   安装完成！
echo ========================================
echo.
echo   启动方式：双击运行
echo   %SCRIPT_DIR%Bulwark.UI.Scifi\bin\Release\net8.0-windows\Bulwark.UI.Scifi.exe
echo.
echo   或者运行: dotnet run --project "%SCRIPT_DIR%Bulwark.UI.Scifi"
echo.
pause

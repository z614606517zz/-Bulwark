@echo off
chcp 65001 >nul
echo.
echo ========================================
echo   磐垒主动防御 - 卸载服务
echo ========================================
echo.

:: 检查管理员权限
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [错误] 需要管理员权限！
    echo 请右键点击此文件，选择"以管理员身份运行"
    echo.
    pause
    exit /b 1
)

:: 停止服务
echo [1/2] 停止服务...
net stop BulwarkDefense >nul 2>&1
if %errorLevel% equ 0 (
    echo [OK] 服务已停止
) else (
    echo [提示] 服务未在运行
)
echo.

:: 删除服务
echo [2/2] 删除服务...
sc delete BulwarkDefense >nul 2>&1
if %errorLevel% equ 0 (
    echo [OK] 服务已删除
) else (
    echo [提示] 服务不存在或已删除
)
echo.

echo ========================================
echo   卸载完成！
echo ========================================
pause

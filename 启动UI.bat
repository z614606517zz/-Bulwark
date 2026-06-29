@echo off
chcp 65001 >nul
echo 正在启动磐垒主动防御...
echo.

:: 先构建
dotnet build "%~dp0Bulwark.UI.Scifi\Bulwark.UI.Scifi.csproj" -c Release --nologo -v q 2>nul

:: 启动UI
start "" "%~dp0Bulwark.UI.Scifi\bin\Release\net8.0-windows\Bulwark.UI.Scifi.exe"

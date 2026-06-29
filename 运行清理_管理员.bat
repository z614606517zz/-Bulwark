@echo off
chcp 65001 >nul
echo ============================================
echo  Bulwark 银狐清理 - 需要管理员权限
echo ============================================
echo 正在请求管理员权限，请在弹出的 UAC 窗口点击"是/Yes"...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','%~dp0_cleanup_silverfox.ps1'"
echo.
echo 已发起清理。清理在独立的管理员窗口中运行，完成后会写入 _cleanup_log.txt
echo 你可以关闭本窗口。
pause

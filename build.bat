@echo off
cd /d "d:\新建文件夹 (3)\cpp\build"
cmake --build . --config Release --target bulwark_service
if exist "service\Release\bulwark_service.exe" (
    echo SUCCESS: Build completed
    copy /Y "service\Release\bulwark_service.exe" "..\dist\bulwark_service.exe"
) else (
    echo ERROR: Build failed
)
pause

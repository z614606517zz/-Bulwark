@echo off
chcp 65001 >nul
echo ========================================
echo  Rebuild UI and Driver
echo ========================================
echo.

echo [1/3] Building UI...
cd /d "d:\新建文件夹 (3)\cpp\build"
cmake --build . --config Release --target bulwark_ui
if not exist "ui\Release\bulwark_ui.exe" (
    echo ERROR: UI build failed
    pause
    exit /b 1
)
echo   OK: UI built successfully
echo.

echo [2/3] Building Driver...
cd /d "d:\新建文件夹 (3)\Bulwark.Driver"
"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\msbuild.exe" ^
    "Bulwark.Driver.vcxproj" ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:SignMode=TestSign ^
    /maxcpucount ^
    /v:minimal
if not exist "x64\Release\Bulwark.sys" (
    echo ERROR: Driver build failed
    pause
    exit /b 1
)
echo   OK: Driver built successfully
echo.

echo [3/3] Copying to portable package...
copy /Y "d:\新建文件夹 (3)\cpp\build\ui\Release\bulwark_ui.exe" "C:\Users\111\Desktop\新建文件夹 (4)\bulwark_ui.exe"
copy /Y "d:\新建文件夹 (3)\Bulwark.Driver\x64\Release\Bulwark.sys" "C:\Users\111\Desktop\新建文件夹 (4)\Bulwark.sys"
echo   OK: Files copied
echo.

echo ========================================
echo  Build complete!
echo ========================================
dir "C:\Users\111\Desktop\新建文件夹 (4)\bulwark_*.exe" "C:\Users\111\Desktop\新建文件夹 (4)\Bulwark.sys"
pause

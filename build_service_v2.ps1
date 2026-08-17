# Compile bulwark_service v2.0.2
Set-Location "d:\新建文件夹 (3)\cpp\build"
cmake --build . --config Release --target bulwark_service

if ($LASTEXITCODE -eq 0) {
    $exe = "d:\新建文件夹 (3)\cpp\build\service\Release\bulwark_service.exe"
    if (Test-Path $exe) {
        Write-Host "Compile SUCCESS"
        Get-Item $exe | Select-Object Name, Length, LastWriteTime | Format-Table
        Copy-Item $exe "d:\新建文件夹 (3)\cpp\dist\bulwark_service.exe" -Force
        Write-Host "Copied to dist directory"
    } else {
        Write-Host "ERROR: Binary not found"
    }
} else {
    Write-Host "ERROR: Compile failed with exit code $LASTEXITCODE"
}

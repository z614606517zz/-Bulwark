# Re-deploy from an ASCII path (kernel loader dislikes non-ASCII/space paths)
$ErrorActionPreference = "Stop"
$srcSys = "D:\新建文件夹 (3)\build\driver\Debug\Bulwark.sys"
$dstDir = "C:\BulwarkDrv"
$dstSys = Join-Path $dstDir "Bulwark.sys"
$serviceName = "Bulwark"
$certName = "BulwarkTestCert"

Write-Host "=== clean old service ===" -ForegroundColor Cyan
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -eq "Running") { sc.exe stop $serviceName | Out-Null; Start-Sleep 2 }
    sc.exe delete $serviceName | Out-Null
    Start-Sleep 1
}

Write-Host "=== copy driver to ASCII path ===" -ForegroundColor Cyan
if (-not (Test-Path $dstDir)) { New-Item -ItemType Directory -Path $dstDir | Out-Null }
Copy-Item $srcSys $dstSys -Force
Write-Host "copied to: $dstSys"

Write-Host "=== sign copied driver ===" -ForegroundColor Cyan
$signCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$certName" } | Select-Object -First 1
$res = Set-AuthenticodeSignature -FilePath $dstSys -Certificate $signCert -HashAlgorithm SHA256
Write-Host "sign: $($res.Status)"
if ($res.Status -ne "Valid") { throw "sign failed: $($res.StatusMessage)" }

Write-Host "=== register + start ===" -ForegroundColor Cyan
sc.exe create $serviceName type= kernel binPath= "$dstSys" start= demand
Start-Sleep 1
sc.exe start $serviceName
$code = $LASTEXITCODE

Write-Host "=== status ===" -ForegroundColor Cyan
sc.exe query $serviceName
Write-Host "start exit code: $code"

# Install Bulwark minifilter via INF (files already staged in C:\BulwarkDrv)
$ErrorActionPreference = "Continue"

$stage   = "C:\BulwarkDrv"
$certName= "BulwarkTestCert"
$inf2cat = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x86\Inf2Cat.exe"

Write-Host "=== 1) verify staged files ===" -ForegroundColor Cyan
Get-ChildItem $stage | Select-Object Name, Length | Format-Table -AutoSize

Write-Host "=== 2) Inf2Cat (generate .cat) ===" -ForegroundColor Cyan
& $inf2cat /driver:$stage /os:10_X64
Write-Host "Inf2Cat exit: $LASTEXITCODE"
if (-not (Test-Path (Join-Path $stage "Bulwark.cat"))) { throw "no .cat produced" }

Write-Host "=== 3) sign .cat and .sys ===" -ForegroundColor Cyan
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$certName" } | Select-Object -First 1
$r1 = Set-AuthenticodeSignature -FilePath (Join-Path $stage "Bulwark.sys") -Certificate $cert -HashAlgorithm SHA256
Write-Host "sys sign: $($r1.Status)"
$r2 = Set-AuthenticodeSignature -FilePath (Join-Path $stage "Bulwark.cat") -Certificate $cert -HashAlgorithm SHA256
Write-Host "cat sign: $($r2.Status)"

Write-Host "=== 4) install INF ===" -ForegroundColor Cyan
pnputil /add-driver (Join-Path $stage "Bulwark.inf") /install
Write-Host "pnputil exit: $LASTEXITCODE"

Write-Host "=== 5) service state ===" -ForegroundColor Cyan
sc.exe query Bulwark

Write-Host "=== 6) load minifilter ===" -ForegroundColor Cyan
fltmc load Bulwark
Write-Host "fltmc load exit: $LASTEXITCODE"

Write-Host "=== 7) filters ===" -ForegroundColor Cyan
fltmc filters

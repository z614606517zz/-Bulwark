# One-shot: create test cert -> sign driver -> register kernel service -> start
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot | Split-Path -Parent
$sys = Join-Path $root "build\driver\Debug\Bulwark.sys"
$serviceName = "Bulwark"
$certName = "BulwarkTestCert"

Write-Host "=== 1) check driver file ===" -ForegroundColor Cyan
if (-not (Test-Path $sys)) { throw "driver not found: $sys" }
Write-Host "driver: $sys"

Write-Host "=== 2) test cert ===" -ForegroundColor Cyan
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$certName" } | Select-Object -First 1
if (-not $cert) {
    Write-Host "creating test cert CN=$certName ..."
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$certName" -CertStoreLocation Cert:\LocalMachine\My -KeyUsage DigitalSignature -KeySpec Signature -HashAlgorithm SHA256
    $store1 = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store1.Open("ReadWrite"); $store1.Add($cert); $store1.Close()
    $store2 = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", "LocalMachine")
    $store2.Open("ReadWrite"); $store2.Add($cert); $store2.Close()
    Write-Host "cert created and trusted."
} else {
    Write-Host "cert exists: $($cert.Thumbprint)"
}

Write-Host "=== 3) sign driver ===" -ForegroundColor Cyan
# Cert lives in LocalMachine store; sign directly with the cert object (codesign cert needs private key).
$signCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$certName" } | Select-Object -First 1
if (-not $signCert) { throw "sign cert missing" }
$res = Set-AuthenticodeSignature -FilePath $sys -Certificate $signCert -HashAlgorithm SHA256
Write-Host "sign result: $($res.Status)"
if ($res.Status -ne "Valid") { throw "signing failed: $($res.Status) $($res.StatusMessage)" }

Write-Host "=== 4) verify signature ===" -ForegroundColor Cyan
(Get-AuthenticodeSignature $sys) | Select-Object Status | Format-List

Write-Host "=== 5) register + start kernel service ===" -ForegroundColor Cyan
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -eq "Running") { sc.exe stop $serviceName | Out-Null; Start-Sleep 2 }
    sc.exe delete $serviceName | Out-Null
    Start-Sleep 1
}
sc.exe create $serviceName type= kernel binPath= "$sys" start= demand
Start-Sleep 1
sc.exe start $serviceName
$code = $LASTEXITCODE

Write-Host "=== 6) status ===" -ForegroundColor Cyan
sc.exe query $serviceName
Write-Host "start exit code: $code"

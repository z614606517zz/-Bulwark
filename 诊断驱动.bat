@echo off
chcp 65001 >nul
rem 磐垒 - 驱动加载诊断(自动提权)。结果写入 driver_diag.txt 供分析。
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"
set OUT=%~dp0driver_diag.txt

echo ==== Bulwark 驱动诊断 %DATE% %TIME% ==== > "%OUT%"

echo. >> "%OUT%"
echo [testsigning 状态] >> "%OUT%"
bcdedit | findstr /i "testsigning" >> "%OUT%" 2>&1
bcdedit | findstr /i "测试" >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [当前 sc query] >> "%OUT%"
sc query Bulwark >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [尝试 sc start Bulwark] >> "%OUT%"
sc start Bulwark >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [尝试 fltmc load Bulwark] >> "%OUT%"
fltmc load Bulwark >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [start 后 sc query] >> "%OUT%"
sc query Bulwark >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [已加载的 minifilter] >> "%OUT%"
fltmc filters >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [驱动签名详情] >> "%OUT%"
powershell -NoProfile -Command "$s=Get-AuthenticodeSignature \"$env:SystemRoot\System32\drivers\Bulwark.sys\"; 'Status='+$s.Status; 'StatusMessage='+$s.StatusMessage; 'Signer='+$s.SignerCertificate.Subject; 'Thumbprint='+$s.SignerCertificate.Thumbprint" >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [证书是否已在受信任存储] >> "%OUT%"
powershell -NoProfile -Command "$t=(Get-AuthenticodeSignature \"$env:SystemRoot\System32\drivers\Bulwark.sys\").SignerCertificate.Thumbprint; 'Root: '+((Test-Path \"Cert:\LocalMachine\Root\$t\")); 'TrustedPublisher: '+((Test-Path \"Cert:\LocalMachine\TrustedPublisher\$t\"))" >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [最近 CodeIntegrity / FilterManager 事件] >> "%OUT%"
powershell -NoProfile -Command "Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddMinutes(-10)} -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -match 'CodeIntegrity|FilterManager|Filter Manager|Service Control Manager' -or $_.Message -match 'Bulwark' } | Select-Object -First 15 TimeCreated,ProviderName,Id,Message | Format-List" >> "%OUT%" 2>&1

echo. >> "%OUT%"
echo [Microsoft-Windows-CodeIntegrity/Operational 最近事件] >> "%OUT%"
powershell -NoProfile -Command "Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 15 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | Format-List" >> "%OUT%" 2>&1

echo 诊断完成,结果已写入 driver_diag.txt
notepad "%OUT%"

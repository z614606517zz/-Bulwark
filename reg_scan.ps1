$ErrorActionPreference = 'SilentlyContinue'
$out = "d:\新建文件夹 (3)\reg_scan_result.txt"
"" | Set-Content $out

$keys = @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
  'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
  'HKLM:\System\CurrentControlSet\Control\Session Manager',
  'HKLM:\Software\Microsoft\Active Setup\Installed Components'
)

foreach ($k in $keys) {
  "=================================================================" | Add-Content $out
  "KEY: $k" | Add-Content $out
  "-----------------------------------------------------------------" | Add-Content $out
  if (Test-Path $k) {
    $props = Get-ItemProperty -Path $k
    $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
      ("{0} = {1}" -f $_.Name, $_.Value) | Add-Content $out
    }
  } else {
    "(not present)" | Add-Content $out
  }
}
"DONE" | Add-Content $out

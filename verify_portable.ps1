[CmdletBinding()]
param(
  # Package to check. Omit only when exactly one package exists on the Desktop --
  # verifying whichever folder happened to sort first is how a leak gets missed.
  [string]$Package
)

$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName System.Drawing | Out-Null

$root = $PSScriptRoot
$desktop = Join-Path $env:USERPROFILE 'Desktop'
if ($Package) {
  $pkg = (Resolve-Path $Package).Path
} else {
  $found = @()
  foreach ($d in (Get-ChildItem -Path $desktop -Directory)) {
    if (Test-Path (Join-Path $d.FullName 'bulwark_ui.exe')) { $found += $d.FullName }
  }
  if ($found.Count -eq 0) { throw "no portable package found on Desktop; pass -Package <path>" }
  if ($found.Count -gt 1) {
    throw ("multiple packages on Desktop -- pass -Package <path> to pick one:`n  " + ($found -join "`n  "))
  }
  $pkg = $found[0]
}

$out = New-Object System.Collections.Generic.List[string]
function Emit($s) { $out.Add([string]$s) }

Emit ("package : " + $pkg)
Emit ("checked : " + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
Emit ""

Emit "=== core payload ==="
foreach ($n in @('bulwark_service.exe','bulwark_ui.exe','Bulwark.sys','appsettings.json','app.ico')) {
  $p = Join-Path $pkg $n
  if (-not (Test-Path $p)) { Emit ("MISSING " + $n); continue }
  $i = Get-Item $p
  $sg = 'n/a'
  if ($n -match '\.(exe|sys)$') { $sg = (Get-AuthenticodeSignature $p).Status }
  Emit ("{0,-22} {1,9} B  {2}  sig={3}" -f $n, $i.Length, $i.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'), $sg)
}

Emit ""
Emit "=== embedded icon ==="
foreach ($n in @('bulwark_ui.exe','bulwark_service.exe')) {
  try {
    $ico = [System.Drawing.Icon]::ExtractAssociatedIcon((Join-Path $pkg $n))
    Emit ("{0,-22} icon {1}x{2}" -f $n, $ico.Width, $ico.Height); $ico.Dispose()
  } catch { Emit ($n + " icon FAILED") }
}

Emit ""
Emit "=== shortcut ==="
$sh = New-Object -ComObject WScript.Shell
foreach ($lnk in (Get-ChildItem $pkg -Filter *.lnk -File)) {
  $s = $sh.CreateShortcut($lnk.FullName)
  Emit ("  " + $lnk.Name + " -> " + (Split-Path $s.TargetPath -Leaf) + "  targetOK=" + (Test-Path $s.TargetPath))
}

Emit ""
Emit "=== config ==="
$cfg = Join-Path $pkg 'appsettings.json'
$j = ((Get-Content -LiteralPath $cfg -Encoding UTF8) -join "`n") | ConvertFrom-Json
$b = $j.Bulwark
$rp = $b.ReputationProxy
$ac = $b.AttackChainEngine
Emit ("EventSource            : " + $b.EventSource)
Emit ("Proxy.BaseUrl          : '" + $rp.BaseUrl + "'")
Emit ("Proxy.Obfuscated       : " + $(if ($rp.BaseUrlObfuscated) { 'SET' } else { 'MISSING' }))
Emit ("Proxy.FreshPerDay      : " + $rp.FreshQueriesPerDay)
Emit ("CmdHardBlockBaseline   : " + $b.CommandHardBlockBaseline)
if ($ac) {
  Emit ("AttackChain.Enabled    : " + $ac.Enabled + "   DryRun=" + $ac.DryRun + "   MinGrade=" + $ac.MinGrade)
  Emit ("AttackChain.BaseUrl    : '" + $ac.BaseUrl + "'  (empty => reuses proxy endpoint)")
} else { Emit "AttackChain            : SECTION MISSING (engine would default to OFF)" }

$secret = @(
  @('ReputationProxy','BearerToken'), @('VirusTotal','ApiKey'), @('MalwareBazaar','AuthKey'),
  @('Otx','ApiKey'), @('ThreatBook','ApiKey'), @('MetaDefender','ApiKey'),
  @('HybridAnalysis','ApiKey'), @('ThreatFoxFeed','AuthKey'), @('Ai','ApiKey')
)
$n = 0
foreach ($sp in $secret) {
  $v = $b.($sp[0]).($sp[1])
  if ($v -and $v.ToString().Trim() -ne '') { $n++; Emit ("  set: " + $sp[0] + '.' + $sp[1]) }
}
Emit ("secret fields set      : " + $n + " / " + $secret.Count)

# Which kind of package is this? A plaintext endpoint or a populated key means it is
# the PRIVATE test build, where carrying secrets is the whole point -- so findings
# below are informational. Only a package claiming to be shareable should treat a
# secret as a defect. Reporting a private build as if it were broken trains you to
# ignore this section, which is how a real leak gets shipped.
$private = ($n -gt 0) -or ($rp.BaseUrl -and $rp.BaseUrl.Trim() -ne '')
Emit ("package kind           : " + $(if ($private) { 'PRIVATE (test build - secrets expected)' } else { 'SHAREABLE (sanitized)' }))

Emit ""
Emit "=== sensitive-string scan (all text files in package) ==="
$pats = @('8u2wluBknxZs','149.88.73.23','103.236.72.227','bulwark.icu')
$hit = $false
foreach ($f in (Get-ChildItem $pkg -Recurse -File -Include *.txt,*.json,*.bat,*.ps1,*.html,*.sh -ErrorAction SilentlyContinue)) {
  $t = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
  if (-not $t) { continue }
  foreach ($p in $pats) { if ($t.Contains($p)) { Emit ("  found in " + $f.Name); $hit = $true; break } }
}
if (-not $hit) { Emit "  clean" }
elseif ($private) { Emit "  ^ expected for a PRIVATE build; run update_portable.ps1 -Sanitize before sharing" }
else { Emit "  ^ LEAK: package claims to be sanitized but still carries these" }

Emit ""
Emit "=== package contents ==="
foreach ($f in (Get-ChildItem $pkg -File | Sort-Object Name)) {
  Emit ("  {0,-30} {1,9} B" -f $f.Name, $f.Length)
}
foreach ($d in (Get-ChildItem $pkg -Directory | Sort-Object Name)) {
  $c = (Get-ChildItem $d.FullName -File -ErrorAction SilentlyContinue | Measure-Object).Count
  Emit ("  [dir] {0,-24} {1} file(s)" -f $d.Name, $c)
}
$total = (Get-ChildItem $pkg -Recurse -File | Measure-Object -Property Length -Sum).Sum
Emit ("  total: " + [math]::Round($total/1MB,2) + " MB")

$out | Out-File -FilePath (Join-Path $root 'verify_out.txt') -Encoding utf8

[CmdletBinding()]
param(
  # Produce a DISTRIBUTABLE package: overwrite appsettings.json with the sanitized
  # template and refuse to continue if it carries a plaintext endpoint or any key.
  #
  # Without this switch the config already in the package is left completely alone.
  # That is the right default here because this is normally a private test package:
  # it is meant to carry real API keys and the plaintext endpoint. The previous
  # behaviour force-overwrote the config from the sanitized template on every run,
  # so any key pasted into the test package was silently wiped on the next repack.
  [switch]$Sanitize,

  # Target package folder. Created if absent, which is how a fresh release package
  # is produced. Omit it only when exactly one package exists on the Desktop.
  [string]$Package,

  # Overwrite the package config from packaging\appsettings.private.json.
  #
  # Needed because the default "never touch an existing config" rule protects keys
  # you pasted in, but is useless when the package folder gets restored from an old
  # backup: the config then silently reverts to a key-free, older-schema copy while
  # the binaries around it get updated, and nothing reports it. This makes putting
  # the known-good private config back an explicit, repeatable step.
  [switch]$ResetConfig
)

$ErrorActionPreference = 'Stop'

# ASCII-only (PS 5.1 on zh-CN reads .ps1 as GBK; CJK literals get mangled).
$root = $PSScriptRoot
$dist = Join-Path $root 'cpp\dist'
$desktop = Join-Path $env:USERPROFILE 'Desktop'

if ($Package) {
  $pkg = $Package
  if (-not (Test-Path $pkg)) { New-Item -ItemType Directory -Path $pkg -Force | Out-Null }
  $pkg = (Resolve-Path $pkg).Path
} else {
  # Discovery is a convenience, not a guess. Once a second package exists on the
  # Desktop (e.g. a private test build next to a release build) picking "the first
  # one found" would silently write to whichever sorts first -- and with -Sanitize
  # that means overwriting the wrong package's config. Refuse instead.
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

$log = New-Object System.Collections.Generic.List[string]
function Say($s) { $log.Add([string]$s); Write-Output $s }

Say ("dist : " + $dist)
Say ("pkg  : " + $pkg)
Say ""

# ---- 0) staleness guard ------------------------------------------------------
# The package silently regressed twice before (missing service exe, unsigned driver, dev config).
# A binary older than its own sources is the same class of failure: it looks fine and quietly
# lacks whatever was added since. Refuse instead of shipping it.
Say "== staleness guard (binary must be newer than its sources) =="
function NewestSrc($dirs, $includes) {
  $existing = @($dirs | Where-Object { Test-Path $_ })
  if ($existing.Count -eq 0) { return $null }
  Get-ChildItem $existing -Recurse -Include $includes -File -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\build\\' } |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
}
$checks = @(
  @{ Name = 'bulwark_service.exe'; Src = (NewestSrc @((Join-Path $root 'cpp\service'), (Join-Path $root 'cpp\shared')) @('*.cpp','*.h')) },
  @{ Name = 'bulwark_ui.exe';      Src = (NewestSrc @((Join-Path $root 'cpp\ui')) @('*.cpp','*.h','*.qrc')) },
  @{ Name = 'Bulwark.sys';         Src = (NewestSrc @((Join-Path $root 'Bulwark.Driver')) @('*.c','*.h')) }
)
$stale = @()
foreach ($c in $checks) {
  $bin = Join-Path $dist $c.Name
  if (-not (Test-Path $bin)) { $stale += ($c.Name + ' (missing in dist)'); continue }
  $b = Get-Item $bin
  if ($c.Src -and $c.Src.LastWriteTime -gt $b.LastWriteTime) {
    $stale += ("{0} (built {1}, source {2} is {3})" -f $c.Name,
               $b.LastWriteTime.ToString('MM-dd HH:mm'), $c.Src.Name, $c.Src.LastWriteTime.ToString('MM-dd HH:mm'))
    Say ("  STALE  " + $c.Name)
  } else {
    Say ("  ok     {0,-22} built {1}" -f $c.Name, $b.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))
  }
}
if ($stale.Count -gt 0) {
  Say ""
  Say "ABORT: rebuild first, these are older than their sources:"
  foreach ($s in $stale) { Say ("  - " + $s) }
  throw ("stale artifacts: " + ($stale -join '; '))
}

# ---- 1) binaries -------------------------------------------------------------
Say ""
Say "== binaries =="
$copyList = @('bulwark_service.exe','bulwark_ui.exe','Bulwark.sys','app.ico')
foreach ($n in $copyList) {
  $src = Join-Path $dist $n
  if (-not (Test-Path $src)) { Say ("SKIP (missing in dist): " + $n); continue }
  # Never ship a driver that is unsigned or whose bytes no longer match its signature.
  #
  # This deliberately does NOT require Status='Valid'. The driver is signed with a
  # self-signed test cert (CN=BulwarkTestCert), so Valid only happens on a machine that
  # already has that cert in LocalMachine\Root -- i.e. a machine where the driver has
  # been installed once. Demanding Valid meant a clean build box could never repackage:
  # the guard reported UnknownError and silently dropped the driver from the package,
  # which is precisely the "looks fine, quietly missing a payload" failure this guard
  # exists to prevent. What actually matters is that a signature is present and intact;
  # whether this particular machine trusts the issuer is the target machine's business
  # (the package's bulwark.ps1 imports the cert on the target machine).
  if ($n -eq 'Bulwark.sys') {
    $s = Get-AuthenticodeSignature $src
    if ($s.Status -eq 'NotSigned' -or $null -eq $s.SignerCertificate) {
      Say "REFUSED: dist driver is unsigned -> not copied"; continue
    }
    if ($s.Status -eq 'HashMismatch') {
      Say "REFUSED: dist driver signature does not match its bytes -> not copied"; continue
    }
    if ($s.Status -ne 'Valid') {
      Say ("note: driver signature=" + $s.Status + " (self-signed test cert not trusted on this box) signer=" + $s.SignerCertificate.Subject)
    }
  }
  Copy-Item $src (Join-Path $pkg $n) -Force
  $i = Get-Item (Join-Path $pkg $n)
  Say ("copied {0,-22} {1,9} B  {2}" -f $n, $i.Length, $i.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))
}

# ---- 2) Qt runtime ----------------------------------------------------------
Say ""
Say "== Qt runtime =="
foreach ($dll in (Get-ChildItem (Join-Path $dist 'Qt6*.dll') -File)) {
  $dstFile = Join-Path $pkg $dll.Name
  $need = $true
  if (Test-Path $dstFile) {
    $d0 = Get-Item $dstFile
    if ($d0.Length -eq $dll.Length) { $need = $false }
  }
  if ($need) { Copy-Item $dll.FullName $dstFile -Force; Say ("updated " + $dll.Name) }
  else { Say ("same    " + $dll.Name) }
}
foreach ($sub in @('platforms','styles','imageformats','generic','networkinformation','tls')) {
  $ss = Join-Path $dist $sub
  if (-not (Test-Path $ss)) { continue }
  # Don't materialise an empty plugin dir in the package. An empty tls\ or generic\
  # reads as "the plugin is shipped" to anyone eyeballing the folder, when in fact
  # nothing is there -- exactly the confusion that hid the missing TLS backend.
  if (-not (Get-ChildItem $ss -File -ErrorAction SilentlyContinue)) { continue }
  $dd = Join-Path $pkg $sub
  if (-not (Test-Path $dd)) { New-Item -ItemType Directory -Path $dd -Force | Out-Null }
  foreach ($f in (Get-ChildItem $ss -File -ErrorAction SilentlyContinue)) {
    $t = Join-Path $dd $f.Name
    $need = $true
    if (Test-Path $t) { if ((Get-Item $t).Length -eq $f.Length) { $need = $false } }
    if ($need) { Copy-Item $f.FullName $t -Force; Say ("updated " + $sub + "\" + $f.Name) }
  }
}

# ---- 2a) MSVC runtime --------------------------------------------------------
# The build box has the VC++ redistributable installed, so a package missing these
# runs fine here and dies on a clean machine with "MSVCP140.dll not found" before
# a single line of our code executes -- no log, no window, just a modal error.
# A portable package has to carry its own CRT; that is what portable means.
Say ""
Say "== MSVC runtime =="
$crtList = @('msvcp140.dll','msvcp140_1.dll','msvcp140_2.dll','vcruntime140.dll','vcruntime140_1.dll')
# Prefer dist (single source of truth); fall back to the installed VS redist so a
# fresh clone can populate dist without a manual copy.
$redist = Get-ChildItem 'C:\Program Files\Microsoft Visual Studio\*\*\VC\Redist\MSVC\*\x64\Microsoft.VC*.CRT' `
            -Directory -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
foreach ($n in $crtList) {
  $src = Join-Path $dist $n
  if (-not (Test-Path $src)) {
    if ($redist -and (Test-Path (Join-Path $redist.FullName $n))) {
      Copy-Item (Join-Path $redist.FullName $n) $src -Force
      Say ("staged into dist from VS redist: " + $n)
    } else {
      Say ("ABORT: " + $n + " not in dist and no VS redist found")
      throw ("missing MSVC runtime: " + $n)
    }
  }
  Copy-Item $src (Join-Path $pkg $n) -Force
  Say ("copied  {0,-22} {1,9} B" -f $n, (Get-Item (Join-Path $pkg $n)).Length)
}

# Verify by actually reading the import tables rather than trusting the list above:
# if the code later pulls in another CRT DLL, a hardcoded list would silently ship
# a broken package again. Skipped (with a note) when dumpbin is unavailable.
$dumpbin = Get-ChildItem 'C:\Program Files\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe' `
             -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $dumpbin) {
  Say "note: dumpbin not found -- skipped CRT import verification"
} else {
  $scan = @(Get-ChildItem "$pkg\*" -Include *.exe,*.dll -File) +
          @(Get-ChildItem $pkg -Directory | ForEach-Object { Get-ChildItem $_.FullName -Filter *.dll -File -ErrorAction SilentlyContinue })
  $imported = New-Object System.Collections.Generic.HashSet[string]
  foreach ($t in $scan) {
    foreach ($line in (& $dumpbin.FullName /dependents $t.FullName 2>$null)) {
      $m = [regex]::Match($line.Trim(), '(?i)^((msvcp|vcruntime|concrt|vccorlib)[0-9_a-z]*\.dll)$')
      if ($m.Success) { [void]$imported.Add($m.Groups[1].Value.ToLower()) }
    }
  }
  $absent = @($imported | Where-Object { -not (Test-Path (Join-Path $pkg $_)) })
  if ($absent.Count -gt 0) {
    Say ("ABORT: imported but not shipped: " + ($absent -join ', '))
    throw ("missing MSVC runtime: " + ($absent -join ', '))
  }
  Say ("verified by import scan: " + (($imported | Sort-Object) -join ', '))
}

# ---- 2b) setup scripts -------------------------------------------------------
# The kernel driver is the one part of a "portable" package that cannot be portable:
# it has to be trusted, staged into System32\drivers and registered as a minifilter
# before it can load. Shipping the binaries without those scripts is how the package
# ended up silently running in user-mode-observation mode -- protection looks alive,
# but there is no pre-action blocking at all. Ship the scripts with the payload.
Say ""
Say "== setup scripts =="
$scriptSrc = Join-Path $root 'packaging\portable-scripts'
if (-not (Test-Path $scriptSrc)) {
  Say "ABORT: packaging\portable-scripts is missing"
  throw "portable setup scripts not found"
}
# Capture the readme's name here instead of writing it as a literal below: this
# script is ASCII-only (PS 5.1 on zh-CN reads it as GBK), so a CJK filename in the
# source would be mangled into a path that never matches.
$readmeName = $null
foreach ($f in (Get-ChildItem $scriptSrc -File)) {
  Copy-Item $f.FullName (Join-Path $pkg $f.Name) -Force
  if ($f.Extension -eq '.txt') { $readmeName = $f.Name }
  Say ("copied  " + $f.Name)
}
# The .ps1 files must keep their UTF-8 BOM: PS 5.1 on a zh-CN box reads BOM-less
# .ps1 as GBK and mangles every CJK message in them.
foreach ($f in (Get-ChildItem $pkg -Filter '*.ps1' -File)) {
  $b = [IO.File]::ReadAllBytes($f.FullName)
  if ($b.Length -lt 3 -or $b[0] -ne 0xEF -or $b[1] -ne 0xBB -or $b[2] -ne 0xBF) {
    Say ("WARN " + $f.Name + " lacks a UTF-8 BOM (CJK text will be mangled on PS 5.1)")
  }
}

# The key-handling section of the readme differs per mode and MUST match the config
# that actually ships. A release build that carries the private text tells the user
# "keys are written right in appsettings.json" -- false, and it advertises internal
# packaging commands. Substituting from a placeholder (and failing when it is
# absent) makes the two impossible to desync.
# These blocks live in separate ASCII-named files because this script is ASCII-only:
# CJK here-strings (or CJK paths) would be mangled by PS 5.1 on a zh-CN box.
if (-not $readmeName) { throw "no .txt readme found in packaging\portable-scripts" }
$readme = Join-Path $pkg $readmeName
if (Test-Path $readme) {
  $blockName = 'packaging\readme-keys-private.txt'
  if ($Sanitize) { $blockName = 'packaging\readme-keys-release.txt' }
  $blockPath = Join-Path $root $blockName
  if (-not (Test-Path $blockPath)) { throw ("readme key-notes block missing: " + $blockName) }
  $rmTxt = [IO.File]::ReadAllText($readme, [Text.Encoding]::UTF8)
  if (-not $rmTxt.Contains('{{KEY_NOTES}}')) { throw ($readmeName + " has no {{KEY_NOTES}} placeholder") }
  $block = [IO.File]::ReadAllText($blockPath, [Text.Encoding]::UTF8).TrimEnd()
  $rmTxt = $rmTxt.Replace('{{KEY_NOTES}}', $block)
  [IO.File]::WriteAllText($readme, $rmTxt, (New-Object Text.UTF8Encoding($true)))
  Say ("readme key-notes <- " + (Split-Path $blockName -Leaf))
}

# ---- 3) config --------------------------------------------------------------
# Two modes. The default (no -Sanitize) NEVER rewrites an existing config: this is
# a private test package, so real keys and the plaintext endpoint are the intended
# contents and must survive a repack. Only -Sanitize produces a distributable.
Say ""
Say "== appsettings.json =="
$cfgDst = Join-Path $pkg 'appsettings.json'
$secretPaths = @(
  @('ReputationProxy','BearerToken'), @('VirusTotal','ApiKey'), @('MalwareBazaar','AuthKey'),
  @('Otx','ApiKey'), @('ThreatBook','ApiKey'), @('MetaDefender','ApiKey'),
  @('HybridAnalysis','ApiKey'), @('ThreatFoxFeed','AuthKey'), @('Ai','ApiKey')
)

function Read-Cfg($path) { return ((Get-Content -LiteralPath $path -Encoding UTF8) -join "`n") | ConvertFrom-Json }
function Count-Secrets($json) {
  $n = 0
  foreach ($sp in $secretPaths) {
    $v = $json.Bulwark.($sp[0]).($sp[1])
    if ($v -and $v.ToString().Trim() -ne '') { $n++ }
  }
  return $n
}

if ($Sanitize) {
  # Canonical sanitized template lives in the repo so the sanitize step is
  # reproducible and does not depend on a stray backup file inside the package.
  $template = Join-Path $root 'packaging\appsettings.portable.json'
  if (-not (Test-Path $template)) { throw "sanitized template not found: packaging\appsettings.portable.json" }
  $json = Read-Cfg $template
  $rp = $json.Bulwark.ReputationProxy
  if ($rp.BaseUrl -ne '') { throw ("template has plaintext BaseUrl: " + $rp.BaseUrl) }
  if (-not $rp.BaseUrlObfuscated) { throw "template lacks BaseUrlObfuscated" }
  $n = Count-Secrets $json
  if ($n -gt 0) { throw ("template still carries " + $n + " secret(s)") }
  # Never destroy a config that carries something worth keeping -- but only then.
  # Backing up unconditionally meant every re-run of -Sanitize on an already-clean
  # release package dropped another identical .bak into the folder, so the package
  # grew a pile of files whose names claim to hold secrets while holding none, and
  # they shipped. Back up only when there is actually a secret or plaintext endpoint.
  if (Test-Path $cfgDst) {
    $cur = Read-Cfg $cfgDst
    $curRp = $cur.Bulwark.ReputationProxy
    $worthKeeping = ((Count-Secrets $cur) -gt 0) -or
                    ($curRp.BaseUrl -and $curRp.BaseUrl.Trim() -ne '')
    if ($worthKeeping) {
      $keep = Join-Path $pkg ('appsettings.private.json.bak-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
      Copy-Item $cfgDst $keep -Force
      Say ("existing config carries secrets -> backed up to " + (Split-Path $keep -Leaf))
      Say "  MOVE THAT FILE OUT before shipping; it is excluded from git but not from the package"
    } else {
      Say "existing config already key-free -- no backup needed"
    }
  }
  # A release package must not ship stray private backups, whatever produced them.
  foreach ($old in (Get-ChildItem $pkg -Filter 'appsettings.private.json.bak-*' -File -ErrorAction SilentlyContinue)) {
    $oldCfg = Read-Cfg $old.FullName
    $oldRp = $oldCfg.Bulwark.ReputationProxy
    if (((Count-Secrets $oldCfg) -eq 0) -and (-not $oldRp.BaseUrl -or $oldRp.BaseUrl.Trim() -eq '')) {
      Remove-Item $old.FullName -Force
      Say ("removed key-free leftover " + $old.Name)
    } else {
      Say ("WARNING: " + $old.Name + " carries secrets and is sitting in a release package -- move it out")
    }
  }
  Copy-Item $template $cfgDst -Force
  Say "MODE: SANITIZED (distributable)"
  Say "  written from packaging\appsettings.portable.json"
  Say "  BaseUrl = '' (obfuscated endpoint), all 9 secret fields EMPTY"
} else {
  if ($ResetConfig -or -not (Test-Path $cfgDst)) {
    # Seed from the private config (newest schema + plaintext endpoint + keys),
    # falling back to the service dev config.
    $seed = Join-Path $root 'packaging\appsettings.private.json'
    if (-not (Test-Path $seed)) { $seed = Join-Path $root 'cpp\service\appsettings.json' }
    if (-not (Test-Path $seed)) { throw "package has no appsettings.json and no seed found" }
    $why = 'package had none'
    if ($ResetConfig -and (Test-Path $cfgDst)) { $why = '-ResetConfig' }
    Copy-Item $seed $cfgDst -Force
    Say ("config written from " + (Split-Path $seed -Leaf) + " (" + $why + ")")
  }
  $json = Read-Cfg $cfgDst
  $rp = $json.Bulwark.ReputationProxy
  $n = Count-Secrets $json
  Say "MODE: PRIVATE (test package -- config left untouched)"
  Say ("  EventSource        = " + $json.Bulwark.EventSource)
  if ($rp.BaseUrl -and $rp.BaseUrl.Trim() -ne '') { Say ("  endpoint           = plaintext BaseUrl") }
  elseif ($rp.BaseUrlObfuscated)                  { Say ("  endpoint           = BaseUrlObfuscated") }
  else                                            { Say ("  endpoint           = NOT SET (cloud lookups unavailable)") }
  Say ("  secret fields set  = " + $n + " / " + $secretPaths.Count)
  if ($n -eq 0) { Say "  note: no keys present -- paste them into appsettings.json, they will now survive repacks" }
  Say "  run with -Sanitize to produce a shareable package instead"
}

# ---- 4) summary -------------------------------------------------------------
Say ""
Say "== final package binaries =="
foreach ($n in @('bulwark_service.exe','bulwark_ui.exe','Bulwark.sys','appsettings.json')) {
  $p = Join-Path $pkg $n
  if (-not (Test-Path $p)) { Say ("MISSING " + $n); continue }
  $i = Get-Item $p
  $sg = 'n/a'
  if ($n -match '\.(exe|sys)$') { $sg = (Get-AuthenticodeSignature $p).Status }
  Say ("{0,-22} {1,9} B  {2}  sig={3}" -f $n, $i.Length, $i.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'), $sg)
}

$log | Out-File -FilePath (Join-Path $root 'update_out.txt') -Encoding utf8

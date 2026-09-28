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
# Patterns come from the single source of truth, not a second copy kept in step by
# hand. They used to be duplicated here AND (in plaintext) inside the shipped
# bulwark.ps1, which is how the release package ended up carrying our endpoint,
# token and IPs in a file any user can open in Notepad.
# WHERE THE NEEDLE LIST LIVES
#   packaging\redaction-needles.txt is the single source of truth. It holds plaintext
#   infrastructure fingerprints, so it is deliberately excluded from version control
#   (see the entry in .gitignore) as well as from every release package.
#
#   That exclusion has one awkward consequence worth handling: a fresh clone, a CI
#   runner, or anyone self-building has no such file, and the previous code threw a
#   bare "needle list missing" with a single hard-coded path -- which reads like a
#   broken script rather than "you need to supply this out-of-band". Two fixes:
#     · accept the file from a few conventional out-of-band locations, so a CI secret
#       or a release-machine copy works without editing this script;
#     · when it is missing, say what the file is for and point at the committed
#       template (packaging\redaction-needles.txt.example) that documents the format.
#       The format used to be documented *inside* the excluded file, i.e. exactly the
#       people who need it never saw it.
$needleCandidates = @()
if ($env:BULWARK_REDACTION_NEEDLES) { $needleCandidates += $env:BULWARK_REDACTION_NEEDLES }
$needleCandidates += (Join-Path $root 'packaging\redaction-needles.txt')          # canonical
$needleCandidates += (Join-Path $root 'packaging\redaction-needles.local.txt')    # dev copy
if ($env:ProgramData) {
  $needleCandidates += (Join-Path $env:ProgramData 'Bulwark\redaction-needles.txt')  # release box
}

$needleFile = $needleCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
if (-not $needleFile) {
  # Do not degrade to "no patterns -> clean". A scan that silently checks nothing
  # is worse than no scan: it prints a green line and gets trusted.
  throw ("needle list not found. It is intentionally not in version control (plaintext " +
         "infrastructure fingerprints). Set BULWARK_REDACTION_NEEDLES, or create the file at one of:`n  " +
         (($needleCandidates | Select-Object -Unique) -join "`n  ") +
         "`nFormat and purpose: packaging\redaction-needles.txt.example")
}
$pats = @(Get-Content -LiteralPath $needleFile |
          ForEach-Object { $_.Trim() } |
          Where-Object { $_ -ne '' -and -not $_.StartsWith('#') })
if ($pats.Count -eq 0) { throw ("needle list is empty: " + $needleFile) }
Emit ("patterns: " + $pats.Count + " (from " + $needleFile + ")")
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
Emit "=== update trust: every shipped PE signed by the pinned cert ==="
# The online updater installs a file only when its Authenticode signer thumbprint is
# in the list compiled into the client. So "is this package updatable at all?" reduces
# to "are its own binaries signed by that same cert?" -- checking it here means the
# answer is known before shipping, not after a user reports a refused update.
$trustH = Join-Path $root 'cpp\shared\include\bulwark\UpdateTrust.h'
if (-not (Test-Path $trustH)) { Emit "  UpdateTrust.h missing -- cannot verify the pin" }
else {
  $tm = [regex]::Match((Get-Content -LiteralPath $trustH -Raw),
                       'BULWARK_UPDATE_SIGNER_THUMBPRINT\s+"([0-9A-Fa-f]{40})"')
  if (-not $tm.Success) { Emit "  UpdateTrust.h has no BULWARK_UPDATE_SIGNER_THUMBPRINT" }
  else {
    $pin = $tm.Groups[1].Value.ToUpper()
    Emit ("  pinned: " + $pin)
    $unsigned = 0; $wrong = 0; $good = 0
    foreach ($n in @('bulwark_service.exe','bulwark_ui.exe','Bulwark.sys')) {
      $p = Join-Path $pkg $n
      if (-not (Test-Path $p)) { Emit ("  MISSING " + $n); continue }
      $s = Get-AuthenticodeSignature $p
      $tp = if ($s.SignerCertificate) { $s.SignerCertificate.Thumbprint.ToUpper() } else { '' }
      if (-not $tp) { Emit ("  {0,-22} UNSIGNED -> updates can never install this" -f $n); $unsigned++ }
      elseif ($tp -ne $pin) { Emit ("  {0,-22} signer={1} != pinned" -f $n, $tp); $wrong++ }
      else {
        $ts = if ($s.TimeStamperCertificate) { 'timestamped' } else { 'no timestamp' }
        Emit ("  {0,-22} ok  status={1}  {2}" -f $n, $s.Status, $ts); $good++
      }
    }
    if ($unsigned -eq 0 -and $wrong -eq 0) { Emit "  all shipped PEs match the pin -- package is updatable" }
    else { Emit ("  ^ DEFECT: " + $unsigned + " unsigned, " + $wrong + " signed by an unpinned cert") }

    # The pin exists in TWO places and both are load-bearing:
    #   UpdateTrust.h            -> the service checks it when downloading
    #   bulwark.ps1              -> the elevated installer re-checks it when applying
    # The second check is not redundant: the staging directory is user-writable, so the
    # files can be swapped between "downloaded and verified" and "installed as admin".
    #
    # Rotating the cert and updating only the header is a silent, very confusing break:
    # downloads keep succeeding and every install gets refused, with nothing in the UI
    # pointing at a mismatched pin. Nothing enforced this until it was checked for -- the
    # header's own comment claimed this script verified it, and it did not.
    $shipped = Join-Path $pkg 'bulwark.ps1'
    if (-not (Test-Path $shipped)) { Emit "  bulwark.ps1 missing -- cannot verify the installer-side pin" }
    else {
      $sm = [regex]::Match([IO.File]::ReadAllText($shipped, [Text.Encoding]::UTF8),
                           '\$UpdateSignerThumbprints\s*=\s*@\(([^)]*)\)')
      if (-not $sm.Success) {
        Emit "  ^ DEFECT: bulwark.ps1 defines no `$UpdateSignerThumbprints -- applying an update would fail"
      } else {
        $inScript = @([regex]::Matches($sm.Groups[1].Value, '[0-9A-Fa-f]{40}') |
                      ForEach-Object { $_.Value.ToUpper() })
        Emit ("  installer-side pin: " + ($inScript -join ', '))
        if ($inScript -contains $pin) { Emit "  installer pin matches UpdateTrust.h" }
        else { Emit ("  ^ DEFECT: bulwark.ps1 pin does not include " + $pin + " -- updates would download then be refused at install") }
      }
    }
  }
}

Emit ""
Emit "=== redaction needle set (shipped bulwark.ps1) ==="
# The scan above only proves the package carries no plaintext needle. It cannot tell
# "the needles were moved to hashes" apart from "the needle list was deleted and the
# log collector now redacts nothing" -- both look clean. This section closes that
# gap by checking the shipped hash list still covers every needle.
$bps = Join-Path $pkg 'bulwark.ps1'
if (-not (Test-Path $bps)) { Emit "  MISSING bulwark.ps1 -- package has no log collector" }
else {
  $bt = Get-Content -LiteralPath $bps -Raw
  $m = [regex]::Match($bt, '(?s)\$script:RedactNeedleHashes\s*=\s*@\((.*?)\)')
  if (-not $m.Success) {
    Emit "  DEFECT: no `$script:RedactNeedleHashes block found -- collector cannot redact our infrastructure"
  } else {
    $shipped = @([regex]::Matches($m.Groups[1].Value, '[0-9a-fA-F]{64}') |
                 ForEach-Object { $_.Value.ToLowerInvariant() })
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $expect = @($pats | ForEach-Object {
      ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($_.ToLowerInvariant())))).Replace('-','').ToLowerInvariant()
    })
    $missing = @($expect | Where-Object { $shipped -notcontains $_ })
    $extra   = @($shipped | Where-Object { $expect -notcontains $_ })
    Emit ("  needles: " + $pats.Count + "   shipped hashes: " + $shipped.Count)
    if ($missing.Count -eq 0 -and $extra.Count -eq 0) {
      Emit "  in sync (hashes only, no plaintext) -- collector will redact all known needles"
    } else {
      if ($missing.Count -gt 0) { Emit ("  DESYNC: " + $missing.Count + " needle(s) have no shipped hash -> they will NOT be redacted") }
      if ($extra.Count -gt 0)   { Emit ("  DESYNC: " + $extra.Count + " shipped hash(es) match no current needle (stale entry)") }
      Emit "  paste this whole block into packaging\portable-scripts\bulwark.ps1:"
      Emit "  `$script:RedactNeedleHashes = @("
      for ($i = 0; $i -lt $expect.Count; $i++) {
        $sep = ','; if ($i -eq $expect.Count - 1) { $sep = '' }
        Emit ("      '" + $expect[$i] + "'" + $sep)
      }
      Emit "  )"
    }
  }
}

Emit ""
Emit "=== TLS verification (source scan) ==="
# WHY THIS CHECK EXISTS
#   ReputationCurl used to pass `-k` (--insecure) on every single curl invocation, which
#   disabled certificate and hostname verification for: the reputation proxy (bearer token
#   in the header), six third-party intel APIs (each with its own API key), threat-intel
#   upload, user-file upload, and the online-update manifest + payload download. A single
#   forgotten `-k` re-introduces all of that at once, and nothing at runtime would complain.
#
#   So the invariant is checked statically: inside ReputationCurl.cpp, `-k` may appear only
#   on a line that also mentions --pinnedpubkey (public-key pinning replaces chain
#   validation there). Anywhere else -- and in any other source file that shells out to
#   curl -- it is a defect.
$srcRoot = Join-Path $root 'cpp'
if (-not (Test-Path $srcRoot)) { Emit "  SKIP: no cpp\ tree next to this script (running against a package only)" }
else {
  $bad = New-Object System.Collections.Generic.List[string]
  foreach ($f in (Get-ChildItem $srcRoot -Recurse -File -Include *.cpp,*.h -ErrorAction SilentlyContinue |
                  Where-Object { $_.FullName -notmatch '\\(build|build-[^\\]*|build_[^\\]*|dist|x64|Debug|Release|third_party)\\' })) {
    # 不变量是【语句级】的:-k 只允许和 --pinnedpubkey 出现在同一个 curl 参数列表里。
    # 原来逐行判,于是一个换行的 return 就成了缺陷:
    #     return { QStringLiteral("--pinnedpubkey"), pins.join(QLatin1Char(';')),
    #              QStringLiteral("-k") };          <-- 这一行不含 pinnedpubkey
    # 代码没错,检查太窄。而一个每次发版都固定报一条 DEFECT 的检查,会被人学会忽略 ——
    # 那时真漏了 -k 也没人看见。所以往前看几行(同一语句内),窗口有上限,孤立的 -k 照样抓。
    $lines = @(Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue)
    $window = 3
    for ($i = 0; $i -lt $lines.Count; $i++) {
      $line = $lines[$i]
      # Match the curl switch as an argument literal, not the letter k in prose.
      if ($line -match '"\-k"' -or $line -match '"--insecure"') {
        # 往前收集同一语句的文本:遇到语句结束符(;)或空行就停。
        $ctx = $line
        for ($j = $i - 1; $j -ge 0 -and $i - $j -le $window; $j--) {
          $prev = $lines[$j]
          if ($prev.Trim() -eq '') { break }
          $ctx = $prev + "`n" + $ctx
          if ($prev -match ';\s*$') { break }
        }
        if ($ctx -notmatch 'pinnedpubkey') {
          $bad.Add(('  DEFECT: {0}:{1} passes -k/--insecure without public-key pinning' -f $f.FullName.Substring($srcRoot.Length + 1), ($i + 1)))
        }
      }
    }
  }
  if ($bad.Count -eq 0) { Emit "  clean -- no unpinned -k/--insecure in the C++ tree" }
  else { foreach ($b in $bad) { Emit $b } }
}

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

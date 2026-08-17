# Robust configure + build for the Bulwark C++/Qt tree.
# Paths are derived from $PSScriptRoot (this file lives in <cpp>/.tools) so we
# never hardcode the Chinese workspace path — that avoids PS5.1 reading this
# UTF-8 script as GBK and corrupting the path literal.
# -Clean wipes the build dir first (use after a corrupted/interrupted build).
# Handles the occasional CMake reconfigure crash (0xC0000409) by wiping the
# build dir and reconfiguring with an explicit generator + Qt prefix path.
param([switch]$Clean)
$ErrorActionPreference = 'Continue'
$cmake = 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
$src   = Split-Path $PSScriptRoot -Parent            # <cpp>
$bld   = Join-Path $src 'build'
$log   = 'C:\Users\61460\__X.log'
$sum   = 'C:\Users\61460\__Xsum.txt'

if ($Clean) { Remove-Item -Recurse -Force $bld -ErrorAction SilentlyContinue }


& $cmake -S $src -B $bld -G 'Visual Studio 17 2022' -A x64 '-DCMAKE_PREFIX_PATH=C:/Qt/6.8.3/msvc2022_64' 2>&1 | Out-File -Encoding utf8 $log
$cfg = $LASTEXITCODE
if ($cfg -ne 0) {
    Remove-Item -Recurse -Force $bld -ErrorAction SilentlyContinue
    & $cmake -S $src -B $bld -G 'Visual Studio 17 2022' -A x64 '-DCMAKE_PREFIX_PATH=C:/Qt/6.8.3/msvc2022_64' 2>&1 | Out-File -Encoding utf8 -Append $log
    $cfg = $LASTEXITCODE
}
"CFG_EXIT_$cfg" | Out-File -Encoding utf8 -Append $log
if ($cfg -eq 0) {
    & $cmake --build $bld --config Debug 2>&1 | Out-File -Encoding utf8 -Append $log
    "BUILD_EXIT_$LASTEXITCODE" | Out-File -Encoding utf8 -Append $log
}
$c = Get-Content -LiteralPath $log
@("WARN=$(($c | Select-String 'warning C' | Measure-Object).Count)",
  "ERR=$(($c | Select-String 'error C|error LNK|error MSB|fatal error|CMake Error' | Measure-Object).Count)") +
 ($c | Select-String 'error C|error LNK|error MSB|fatal error|CMake Error|BUILD_EXIT_|CFG_EXIT_' | ForEach-Object { $_.Line.Trim() }) |
 Out-File -Encoding utf8 $sum

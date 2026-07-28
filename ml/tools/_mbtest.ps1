$k = ($env:BULWARK_MB_AUTHKEY).Trim()
function T($label, $formStr) {
    $out = & curl.exe -sS -m 25 -X POST -H ("Auth-Key: " + $k) -d $formStr 'https://mb-api.abuse.ch/api/v1/' 2>&1
    $s = ($out | Out-String).Trim()
    $head = $s.Substring(0, [Math]::Min(160, $s.Length))
    Write-Host ("[" + $label + "] exit=" + $LASTEXITCODE + " len=" + $s.Length + " :: " + $head)
    Start-Sleep -Seconds 2
}
T 'siginfo AgentTesla' 'query=get_siginfo&signature=AgentTesla&limit=5'
T 'taginfo exe'        'query=get_taginfo&tag=exe&limit=5'
T 'recent 100'         'query=get_recent&selector=100'
T 'file_type exe'      'query=get_file_type&file_type=exe&limit=5'

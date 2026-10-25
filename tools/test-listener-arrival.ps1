param([string]$Executable=(Join-Path $PSScriptRoot '../dist/webserver.exe'))
$ErrorActionPreference='Stop'
$exe=(Resolve-Path -LiteralPath $Executable).Path
$client=(Resolve-Path (Join-Path $PSScriptRoot '../listener-arrival-probe.exe')).Path
foreach ($ip in @('127.0.0.1','::1')) {
    $resources=Join-Path $env:RUNNER_TEMP ('arrival-'+[Guid]::NewGuid().ToString('N'))
    $process=Start-Process -FilePath $exe -ArgumentList @('--resources',"`"$resources`"",'--bind-ip',$ip,'--http-port','28080','--https-port','28443','--stats-port','28686','--no-gui') -PassThru -WindowStyle Hidden
    try {
        $ok=$false;$deadline=(Get-Date).AddSeconds(20)
        do {
            if ($process.HasExited) { throw 'Arrival server exited before probe' }
            $probe=Start-Process -FilePath $client -ArgumentList @($ip,'28080') -PassThru -WindowStyle Hidden
            if (!$probe.WaitForExit(4000)) { throw 'Receipt client exceeded deadline' }
            if ($probe.ExitCode -eq 0) { $ok=$true;break }
            Start-Sleep -Milliseconds 150
        } while ((Get-Date) -lt $deadline)
        if (!$ok) { throw "Actual main and native client did not agree for $ip" }
        $hostPart=if ($ip.Contains(':')) {"[$ip]"} else {$ip}
        $nonce=[Guid]::NewGuid().ToString('N')
        $response=Invoke-WebRequest "http://${hostPart}:28080/adaway-listener-probe/$nonce" -NoProxy -Headers @{Host='ad.doubleclick.net'} -TimeoutSec 2
        if ($response.Content -ne "adaway-listener:$nonce" -or $response.Headers['X-AdAway-Listener-Probe'] -ne $nonce) { throw 'Fresh nonce was not reflected exactly' }
        if ($response.Headers['Cache-Control'] -notcontains 'no-store') { throw 'Receipt may be cached' }
        foreach ($case in @(@{Path='bad';Method='GET';Code=400},@{Path=$nonce;Method='POST';Code=405})) {
            $response=Invoke-WebRequest "http://${hostPart}:28080/adaway-listener-probe/$($case.Path)" -NoProxy -Method $case.Method -SkipHttpErrorCheck -TimeoutSec 2
            if ($response.StatusCode -ne $case.Code) { throw 'Malformed nonce or non-GET request was not rejected' }
        }
        Write-Output "Actual production entry + client: $ip nonce, Host domain, no-store, invalid input and method checks passed"
    } finally { if (!$process.HasExited) { Stop-Process -Id $process.Id -Force }; $process.WaitForExit() }
}
# A foreign HTTP listener returning 200 without the exact nonce is never an arrival success.
$listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0);$listener.Start()
try {
    $port=$listener.LocalEndpoint.Port
    $probe=Start-Process -FilePath $client -ArgumentList @('127.0.0.1',"$port") -PassThru -WindowStyle Hidden
    $accept=$listener.AcceptTcpClientAsync()
    if (!$accept.Wait(3000)) { throw 'Client did not reach foreign local fixture' }
    $connection=$accept.Result
    try {
        $bytes=[Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: 7`r`nConnection: close`r`n`r`nforeign")
        $connection.GetStream().Write($bytes)
    } finally { $connection.Dispose() }
    if (!$probe.WaitForExit(4000) -or $probe.ExitCode -eq 0) { throw 'Foreign HTTP 200 was mistaken for an AdAway receipt' }
} finally { $listener.Stop() }
Write-Output 'Foreign server TCP/HTTP success rejected without fresh AdAway receipt'

if ($env:GITHUB_ACTIONS -ne 'true') { throw 'System DNS fixture is permitted only on the disposable GitHub runner' }
$hostsFile=Join-Path $env:SystemRoot 'System32/drivers/etc/hosts'
[byte[]]$original=[IO.File]::ReadAllBytes($hostsFile)
$resources=Join-Path $env:RUNNER_TEMP ('arrival-dns-'+[Guid]::NewGuid().ToString('N'))
$server=$null
try {
    $extra=[Text.Encoding]::ASCII.GetBytes("`r`n127.0.0.1 ads.arrival-fixture.invalid`r`n::1 ads.arrival6-fixture.invalid`r`n203.0.113.9 ads.arrival-mismatch.invalid`r`n")
    [IO.File]::WriteAllBytes($hostsFile,([byte[]]($original+$extra)))
    $server=Start-Process -FilePath $exe -ArgumentList @('--resources',"`"$resources`"",'--listen-ipv4','127.0.0.1','--listen-ipv6','::1','--http-port','28080','--https-port','28443','--stats-port','28686','--no-gui') -PassThru -WindowStyle Hidden
    $deadline=(Get-Date).AddSeconds(20);$ready=$false
    do {
        try { $null=Invoke-WebRequest 'http://127.0.0.1:28686/adaway-listener-probe/0123456789abcdef0123456789abcdef' -NoProxy -TimeoutSec 1; $ready=$true }
        catch { Start-Sleep -Milliseconds 100 }
    } until ($ready -or (Get-Date) -gt $deadline)
    if (!$ready) { throw 'DNS fixture server did not become ready' }
    foreach ($domain in @('ads.arrival-fixture.invalid','ads.arrival6-fixture.invalid','ads.arrival-mismatch.invalid')) {
        $output=Join-Path $resources ($domain+'.txt')
        $target=if ($domain -eq 'ads.arrival6-fixture.invalid') { '::1' } else { '127.0.0.1' }
        $probe=Start-Process -FilePath $client -ArgumentList @('--report',$target,'28080','28686',$domain) -PassThru -WindowStyle Hidden -RedirectStandardOutput $output
        if (!$probe.WaitForExit(15000) -or $probe.ExitCode -ne 0) { throw 'System DNS + native receipt report did not finish' }
        $text=Get-Content -LiteralPath $output -Raw -Encoding utf8
        if ($domain -eq 'ads.arrival-fixture.invalid' -and $text -notmatch 'DNS 已指向；HTTP/28080 请求已到达') { throw "DNS-local receipt chain failed: $text" }
        if ($domain -eq 'ads.arrival6-fixture.invalid' -and $text -notmatch '::1：DNS 已指向；HTTP/28080 请求已到达') { throw "IPv6 DNS-local receipt chain failed: $text" }
        if ($text -notmatch 'HTTP/28080 回执不证明默认 HTTP/80 可达') { throw "Custom HTTP receipt was presented as a default-port proof: $text" }
        if ($domain -eq 'ads.arrival-mismatch.invalid') {
            if ($text -notmatch '203\.0\.113\.9：未匹配本次启动监听地址，未连接' -or
                $text -notmatch '0 个匹配本机监听' -or
                $text -match '203\.0\.113\.9：DNS 已指向；HTTP/28080 请求已到达') {
                throw "Nonmatching DNS answer was not rejected: $text"
            }
        }
    }
} finally {
    if ($server -and !$server.HasExited) { Stop-Process -Id $server.Id -Force; $server.WaitForExit() }
    [IO.File]::WriteAllBytes($hostsFile,$original)
    if ([Convert]::ToHexString([IO.File]::ReadAllBytes($hostsFile)) -ne [Convert]::ToHexString($original)) { throw 'Disposable DNS fixture hosts restoration failed' }
}
Write-Output 'Actual system DNS to current local listener verified; nonlocal DNS answer refused; hosts bytes restored'

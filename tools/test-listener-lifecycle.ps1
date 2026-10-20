param([string]$Executable=(Join-Path $PSScriptRoot '../dist/webserver.exe'))
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Address lifecycle fixture requires a disposable GitHub runner' }
$exe=(Resolve-Path -LiteralPath $Executable).Path
$fixture=Join-Path $env:RUNNER_TEMP ('listener-lifecycle-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
Copy-Item -Path (Join-Path (Split-Path -Parent $exe) '*') -Destination $fixture -Recurse
$serverExe=Join-Path $fixture 'webserver.exe'
$ip4='10.254.253.78';$ip6='fd6b:2a91:84f0::78';$server=$null
function Helper([string[]]$Arguments) {
    $helper=Start-Process -FilePath $serverExe -ArgumentList $Arguments -WindowStyle Hidden -PassThru
    if (!$helper.WaitForExit(20000)) { throw 'Restricted lifecycle helper timed out' }
    return $helper.ExitCode
}
function Absent([string]$Ip) { if (Get-NetIPAddress -IPAddress $Ip -ErrorAction SilentlyContinue) { throw "Expected absent fixture: $Ip" } }
function Stop-Server {
    if ($script:server) {
        if (!$script:server.HasExited) { Stop-Process -Id $script:server.Id -Force }
        $script:server.WaitForExit();$script:server=$null
    }
}
function Start-Server {
    $script:server=Start-Process -FilePath $serverExe -ArgumentList @('--resources',"`"$(Join-Path $fixture 'resources')`"",'--no-gui') -PassThru -WindowStyle Hidden
}
function Ready([string]$Ip) {
    $hostPart=if ($Ip.Contains(':')) {"[$Ip]"} else {$Ip}
    $ready=$false;$deadline=(Get-Date).AddSeconds(25)
    do {
        if ($script:server.HasExited) { throw "Dual listener server exited: $($script:server.ExitCode)" }
        try {
            $nonce=[Guid]::NewGuid().ToString('N')
            $reply=Invoke-WebRequest "http://${hostPart}:30080/adaway-listener-probe/$nonce" -NoProxy -TimeoutSec 1
            $ready=$reply.Content -eq "adaway-listener:$nonce"
        } catch { Start-Sleep -Milliseconds 100 }
    } until ($ready -or (Get-Date) -gt $deadline)
    if (!$ready) { throw "No dual listener receipt: $Ip" }
}
Absent $ip4;Absent $ip6
try {
    # Failure on the second family must remove only this attempt's first alias.
    $result=Helper @('--ensure-listener-addresses',$ip4,'2001:db8::78','30080','30443')
    if ($result -eq 0) { throw 'Public IPv6 alias unexpectedly created' }
    Absent $ip4
    $ini=Join-Path $fixture 'webserver.ini'
    $settings="http_port=30080`nhttps_port=30443`nstats_port=30686`nlisten_ipv4=$ip4`nlisten_ipv6=$ip6`nlistener_auto_create=1`n"
    Set-Content -LiteralPath $ini -Value $settings -Encoding ascii
    foreach ($attempt in @(1,2)) {
        Start-Server;Ready $ip4;Ready $ip6;Stop-Server
        foreach ($ip in @($ip4,$ip6)) {
            $row=Get-NetIPAddress -IPAddress $ip -ErrorAction Stop
            if (!$row.SkipAsSource) { throw 'Startup alias may become an outbound source' }
            if ((Helper @('--remove-listener-address',$ip)) -ne 0) { throw 'Startup alias ownership/cleanup failed' }
            Absent $ip
        }
    }
    Set-Content -LiteralPath $ini -Value $settings.Replace('listener_auto_create=1','listener_auto_create=0') -Encoding ascii
    Start-Server
    if (!$server.WaitForExit(20000) -or $server.ExitCode -eq 0) { throw 'Disabled startup creation did not fail for missing explicit addresses' }
    Stop-Server;Absent $ip4;Absent $ip6
    # A required IPv6 conflict must prevent partial IPv4 success.
    Set-Content -LiteralPath $ini -Value "http_port=30080`nhttps_port=30443`nstats_port=30686`nlisten_ipv4=127.0.0.1`nlisten_ipv6=::1`nlistener_auto_create=0`n" -Encoding ascii
    $occupied=[Net.Sockets.TcpListener]::new([Net.IPAddress]::IPv6Loopback,30080)
    $occupied.Server.DualMode=$false;$occupied.Server.ExclusiveAddressUse=$true;$occupied.Start()
    try {
        Start-Server
        if (!$server.WaitForExit(15000) -or $server.ExitCode -eq 0) { throw 'IPv6 conflict was silently downgraded to IPv4-only' }
        Stop-Server
    } finally { $occupied.Stop() }
    Write-Output 'Actual INI to startup: independent IPv4/IPv6, auto-create, recreation after alias removal, disabled option, second-family rollback and no partial startup passed'
} finally {
    Stop-Server
    foreach ($ip in @($ip4,$ip6)) {
        if (Get-NetIPAddress -IPAddress $ip -ErrorAction SilentlyContinue) {
            if ((Helper @('--remove-listener-address',$ip)) -ne 0) { throw "Fixture cleanup failed: $ip" }
        }
    }
}

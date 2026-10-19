$ErrorActionPreference='Stop'
$exe=(Resolve-Path 'dist/webserver.exe').Path
$res=Join-Path $env:RUNNER_TEMP 'listener-real-service'
New-Item -ItemType Directory -Force -Path $res | Out-Null
function Invoke-Probe([string]$Ip,[int]$Http,[int]$Https) {
    $stdout=Join-Path $res 'probe.out'
    $p=Start-Process -WindowStyle Hidden -FilePath $exe -ArgumentList @('--check-listen','--bind-ip',$Ip,'--http-port',$Http,'--https-port',$Https) -Wait -PassThru -RedirectStandardOutput $stdout
    if ($p.ExitCode -notin @(0,3)) { throw "Listener check failed: $($p.ExitCode)" }
    return Get-Content -Raw $stdout | ConvertFrom-Json
}
foreach ($ip in @('127.0.0.1','::1')) {
    $socket=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse($ip),0)
    $other=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse($ip),0)
    $socket.Start();$other.Start()
    $hp=$socket.LocalEndpoint.Port;$sp=$other.LocalEndpoint.Port
    $other.Stop()
    try {
        $probe=Invoke-Probe $ip $hp $sp
        if ($probe.http -ne 1 -or $probe.https -ne 0) { throw "Actual main() probe did not detect $ip conflict" }
    } finally { $socket.Stop() }
    if (Test-Path (Join-Path $res 'localhost-2410.key')) { throw 'Diagnostic probe unexpectedly created CA' }
}
foreach ($ip in @('127.0.0.2','::1')) {
    $p=Start-Process -WindowStyle Hidden -FilePath $exe -ArgumentList @('--resources',"`"$res`"",'--bind-ip',$ip,'--http-port',19080,'--https-port',19443,'--stats-port',19686,'--no-gui') -PassThru
    try {
        $stats=$null;$deadline=(Get-Date).AddSeconds(20)
        while (!$stats -and (Get-Date) -lt $deadline) {
            if ($p.HasExited) { throw "Custom $ip service exited: $($p.ExitCode)" }
            try { $stats=Invoke-RestMethod 'http://127.0.0.1:19686/internal-stats' -TimeoutSec 1 }
            catch { Start-Sleep -Milliseconds 150 }
        }
        if (!$stats) { throw 'Custom listener management did not become ready' }
        $addresses=($stats.listeners | ConvertTo-Json -Compress)
        if ($addresses -match 'mon80|mon443') { throw 'Custom IP added hidden compatibility listeners' }
        $hostPart=if ($ip.Contains(':')) { "[$ip]" } else { $ip }
        $answer=Invoke-WebRequest "http://${hostPart}:19080/internal-test" -TimeoutSec 5
        if ($answer.StatusCode -ne 200) { throw "Custom response listener failed for $ip" }
    } finally { if (!$p.HasExited) { Stop-Process -Id $p.Id -Force }; $p.WaitForExit() }
}
Write-Output 'Actual webserver main: no-resource conflict checks and custom IPv4/IPv6 service startup passed'

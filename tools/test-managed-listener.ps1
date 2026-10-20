param([string]$Executable = (Join-Path $PSScriptRoot '../dist/webserver.exe'))
$ErrorActionPreference='Stop'
$exe=(Resolve-Path -LiteralPath $Executable).Path
function Invoke-Address([string[]]$Arguments) {
    $process=Start-Process -FilePath $exe -ArgumentList $Arguments -WindowStyle Hidden -PassThru
    if (!$process.WaitForExit(15000)) { throw 'Address helper did not finish within 15 seconds' }
    return $process.ExitCode
}
function Assert-Absent([string]$Ip) {
    if (Get-NetIPAddress -IPAddress $Ip -ErrorAction SilentlyContinue) { throw "Address should be absent: $Ip" }
}
foreach ($ip in @('10.254.253.73','fd6b:2a91:84f0::73')) {
    Assert-Absent $ip
    try {
        $result=Invoke-Address @('--create-listener-address',$ip,'29080','29443')
        Write-Output "Address helper: $ip / $result" | Out-Host
        if ($result -ne 0) { throw "Actual helper create failed for $ip with $result" }
        $row=Get-NetIPAddress -IPAddress $ip -ErrorAction Stop
        if (!$row.SkipAsSource -or $row.PrefixLength -ne $(if ($ip.Contains(':')) {128} else {32})) { throw 'Alias prefix/source selection changed' }
        if ((Invoke-Address @('--create-listener-address',$ip,'29080','29443')) -ne 5010) { throw 'Existing address was not reused' }
        $registry='HKLM:\SOFTWARE\AdAway\ListenerAddresses'
        $name=([Net.IPAddress]::Parse($ip)).ToString()
        [byte[]]$receipt=Get-ItemPropertyValue -LiteralPath $registry -Name $name
        try {
            Remove-ItemProperty -LiteralPath $registry -Name $name
            if ((Invoke-Address @('--create-listener-address',$ip,'29080','29443')) -ne 5010) { throw 'Existing unowned alias was not reused' }
            if ((Invoke-Address @('--remove-listener-address',$ip)) -eq 0) { throw 'Unowned alias was removed' }
            $null=Get-NetIPAddress -IPAddress $ip -ErrorAction Stop
        } finally { Set-ItemProperty -LiteralPath $registry -Name $name -Value $receipt -Type Binary }
        [byte[]]$changed=$receipt.Clone();$changed[8]=$changed[8] -bxor 1
        try {
            Set-ItemProperty -LiteralPath $registry -Name $name -Value $changed -Type Binary
            if ((Invoke-Address @('--remove-listener-address',$ip)) -ne 5) { throw 'Replaced-address timestamp mismatch was not rejected' }
            $null=Get-NetIPAddress -IPAddress $ip -ErrorAction Stop
        } finally { Set-ItemProperty -LiteralPath $registry -Name $name -Value $receipt -Type Binary }
        $hostPart=if ($ip.Contains(':')) {"[$ip]"} else {$ip}
        $resources=Join-Path $env:RUNNER_TEMP ('managed-listener-'+[Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $resources | Out-Null
        Get-ChildItem -LiteralPath (Join-Path (Split-Path -Parent $exe) 'resources') -File |
            Where-Object Extension -In @('.webp','.html','.png','.jpg','.gif','.css','.js') |
            Copy-Item -Destination $resources
        $server=Start-Process -FilePath $exe -ArgumentList @('--resources',"`"$resources`"",'--bind-ip',$ip,'--http-port','29080','--https-port','29443','--stats-port','29686','--no-gui') -WindowStyle Hidden -PassThru
        try {
            $reply=$null;$deadline=(Get-Date).AddSeconds(20)
            while (!$reply -and (Get-Date) -lt $deadline) {
                if ($server.HasExited) { throw 'Server exited after creating alias' }
                try { $reply=Invoke-WebRequest "http://${hostPart}:29080/" -Headers @{Host='localhost'} -NoProxy -TimeoutSec 2 -SkipHttpErrorCheck }
                catch { Start-Sleep -Milliseconds 100 }
            }
            if (!$reply -or $reply.StatusCode -ne 200) { throw "Created alias $ip did not serve the ordinary response page: HTTP $($reply.StatusCode)" }
        } finally { if (!$server.HasExited) { Stop-Process -Id $server.Id -Force }; $server.WaitForExit() }
    } finally {
        $removed=Invoke-Address @('--remove-listener-address',$ip)
        if ($removed -ne 0) { throw "Owned alias cleanup failed: $ip / $removed" }
    }
    Assert-Absent $ip
    if ((Invoke-Address @('--remove-listener-address',$ip)) -eq 0) { throw 'Removing an absent unowned address reported success' }
}
$rollbackIp='fd6b:2a91:84f0::74'
Assert-Absent $rollbackIp
$occupied=[Net.Sockets.TcpListener]::new([Net.IPAddress]::IPv6Any,0)
$occupied.Server.DualMode=$false
$occupied.Server.ExclusiveAddressUse=$true
$occupied.Start()
try {
    $port=$occupied.LocalEndpoint.Port
    $result=Invoke-Address @('--create-listener-address',$rollbackIp,"$port",'29443')
    if ($result -ne 60002) { throw "Port conflict did not report rolled-back create: $result" }
    Assert-Absent $rollbackIp
} finally {
    $occupied.Stop()
    if (Get-NetIPAddress -IPAddress $rollbackIp -ErrorAction SilentlyContinue) {
        $result=Invoke-Address @('--remove-listener-address',$rollbackIp)
        if ($result -ne 0) { throw "Failed-test cleanup failed: $result" }
    }
}
Write-Output 'Actual main: private IPv4/IPv6 creation, existing reuse, HTTP serving, owned removal and port-conflict rollback passed'

param([string]$Executable=(Join-Path $PSScriptRoot '../dist/webserver.exe'))
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'TLS trust fixture requires a disposable GitHub runner' }
$exe=(Resolve-Path -LiteralPath $Executable).Path
$client=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../listener-arrival-probe.exe')).Path
$resources=Join-Path $env:RUNNER_TEMP ('arrival-tls-'+[Guid]::NewGuid().ToString('N'))
$server=Start-Process -FilePath $exe -ArgumentList @('--resources',"`"$resources`"",'--listen-ipv4','127.0.0.1','--listen-ipv6','::1','--http-port','31080','--https-port','31443','--stats-port','31686','--no-gui') -PassThru -WindowStyle Hidden
$imported=$null
function Probe([string]$Ip,[string]$HostName,[int]$Expected) {
    $stdout=Join-Path $resources ([Guid]::NewGuid().ToString('N')+'.txt')
    $process=Start-Process -FilePath $client -ArgumentList @('--tls',$Ip,'31443',$HostName) -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout
    if (!$process.WaitForExit(6000)) { throw 'TLS probe exceeded budget' }
    $text=Get-Content -LiteralPath $stdout -Raw
    if ($process.ExitCode -ne $Expected) { throw "TLS result for $Ip / $HostName expected $Expected, got $($process.ExitCode): $text" }
    Write-Output "$Ip / $HostName : $text"
}
try {
    $deadline=(Get-Date).AddSeconds(20);$ready=$false
    do {
        if ($server.HasExited) { throw 'TLS main process exited before readiness' }
        try { $null=Invoke-WebRequest 'http://127.0.0.1:31686/adaway-listener-probe/0123456789abcdef0123456789abcdef' -NoProxy -TimeoutSec 1;$ready=$true }
        catch { Start-Sleep -Milliseconds 100 }
    } until ($ready -or (Get-Date) -gt $deadline)
    if (!$ready) { throw 'TLS main readiness failed' }
    Probe '127.0.0.1' 'localhost' 23
    $certificate=[Security.Cryptography.X509Certificates.X509Certificate2]::new((Join-Path $resources 'localhost-2410.crt'))
    $target="Cert:\LocalMachine\Root\$($certificate.Thumbprint)"
    if (Test-Path -LiteralPath $target) { throw 'Fixture CA unexpectedly pre-existed; refusing to own it' }
    # The protected CurrentUser ROOT may require an interactive trust dialog,
    # even via the store API. Use the disposable admin runner's machine store;
    # never disable protected-root policy or run this on a daily host.
    $store=[Security.Cryptography.X509Certificates.X509Store]::new('Root','LocalMachine')
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $store.Add($certificate);$imported=$certificate
    } finally { $store.Close() }
    Probe '127.0.0.1' 'localhost' 0
    Probe '::1' 'localhost' 0
    Probe '127.0.0.1' 'tls.arrival-fixture.invalid' 0
    # IP reference identity sends no DNS SNI. The localhost leaf has no such IP SAN.
    Probe '127.0.0.1' '10.254.253.78' 23
    Write-Output 'Actual main + strict OpenSSL client: untrusted CA rejected, trusted v4/v6 TLS receipts, original domain SNI, mismatched name rejected'
} finally {
    if ($imported) {
        $store=[Security.Cryptography.X509Certificates.X509Store]::new('Root','LocalMachine')
        try { $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite);$store.Remove($imported) }
        finally { $store.Close() }
        if (Test-Path -LiteralPath "Cert:\LocalMachine\Root\$($imported.Thumbprint)") { throw 'Fixture CA cleanup failed' }
    }
    if (!$server.HasExited) { Stop-Process -Id $server.Id -Force }
    $server.WaitForExit()
}

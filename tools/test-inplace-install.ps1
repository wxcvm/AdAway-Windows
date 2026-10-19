# Runs only on the disposable CI runner. Never invoked on the user's host.
$ErrorActionPreference='Stop'
$base=Join-Path $env:RUNNER_TEMP 'ADBlockProductionUpgrade'
$exe=Join-Path $base 'webserver.exe'
$resources=Join-Path $base 'resources'
New-Item -ItemType Directory -Force -Path $resources | Out-Null
$ini=Join-Path $base 'webserver.ini'
$marker=Join-Path $resources 'upgrade-user-data.txt'
Set-Content $ini "http_port=19580`nhttps_port=19543`nstats_port=19687`nbind_ip=127.0.0.2`nupdate_mode=portable" -Encoding ascii
Set-Content $marker 'retain-user-data' -Encoding ascii
$before=(Get-FileHash $ini -Algorithm SHA256).Hash
$installer=(Resolve-Path 'dist-installer/adblock-webserver-setup.exe').Path
function Stop-TestInstallation {
    Get-Process -Name webserver -ErrorAction SilentlyContinue | Where-Object Path -eq $exe | Stop-Process -Force
}
try {
    foreach ($iteration in @(1,2)) {
        $install=Start-Process -WindowStyle Hidden -FilePath $installer -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/CURRENTUSER',"/DIR=$base") -Wait -PassThru
        if ($install.ExitCode -ne 0) { throw "In-place install $iteration failed: $($install.ExitCode)" }
        $stats=$null;$deadline=(Get-Date).AddSeconds(20)
        while (!$stats -and (Get-Date) -lt $deadline) {
            try { $stats=Invoke-RestMethod 'http://127.0.0.1:19687/internal-stats' -TimeoutSec 1 }
            catch { Start-Sleep -Milliseconds 200 }
        }
        if (!$stats) { throw 'Installed production identity did not restart on saved management port' }
        if ((Get-FileHash $ini -Algorithm SHA256).Hash -ne $before) { throw 'Upgrade overwrote listener/update settings' }
        if ((Get-Content $marker -Raw).Trim() -ne 'retain-user-data') { throw 'Upgrade lost resource data' }
        $key='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{8F2A61D4-6C0B-4B3E-9E77-ADB10C1A5F27}_is1'
        $record=Get-ItemProperty $key
        if ($record.InstallLocation.TrimEnd('\') -ine $base) { throw 'Installer used a different application identity/location' }
        $ca=Join-Path $resources 'localhost-2410.key'
        if ($iteration -eq 1) { $caBefore=(Get-FileHash $ca -Algorithm SHA256).Hash }
        elseif ((Get-FileHash $ca -Algorithm SHA256).Hash -ne $caBefore) { throw 'Upgrade replaced the user CA key' }
        Stop-TestInstallation
    }
} finally { Stop-TestInstallation }
Write-Output 'Production AppId in-place install/reinstall preserved settings, resources and CA; saved listener config restarted correctly'

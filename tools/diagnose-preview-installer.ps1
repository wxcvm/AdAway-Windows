# Read-only diagnostic for the unsigned Windows 1.75 UI inspection installer.
# Does not run the installer, change Windows security settings, or upload data.
# Usage (in PowerShell): & 'C:\path\to\diagnose-preview-installer.ps1' -Installer 'C:\path\to\adblock-preview-user-x64.exe'
[CmdletBinding()]
param(
    [string]$Installer = (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads\adblock-preview-user-x64.exe')
)

$ErrorActionPreference = 'Stop'
$expected = @{
    'adblock-preview-user-x64.exe'    = 'e7fb5f39dfba2f9908d32a7ca175d0fb4cff87a476bcf558146c6642270a42f0'
    'adblock-preview-machine-x64.exe' = 'bd73d2406627c8696437a247a77962769c1a96c4c6fd3d47064e9c98864e5af8'
}
Write-Host 'ADBlock v1.75 startup check (read-only)'
Write-Host "Installer: $Installer"
if (-not (Test-Path -LiteralPath $Installer -PathType Leaf)) {
    Write-Warning 'Installer file not found at this path. Supply the full downloaded EXE path with -Installer.'
    return
}
$actual = (Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash.ToLowerInvariant()
$name = [IO.Path]::GetFileName($Installer).ToLowerInvariant()
Write-Host "SHA-256: $actual"
if ($expected.ContainsKey($name)) {
    if ($actual -ceq $expected[$name]) {
        Write-Host 'SHA-256 matches the GitHub hotfix1 release.'
    } else {
        Write-Warning 'Hash does NOT match the known hotfix1 release. Do not execute this file.'
        return
    }
} else {
    Write-Warning 'Unrecognized installer name; confirm this came from the correct release.'
}
try {
    $signature = Get-AuthenticodeSignature -LiteralPath $Installer
    Write-Host "Authenticode status: $($signature.Status)"
    if ($signature.SignerCertificate) {
        Write-Host "Signer: $($signature.SignerCertificate.Subject)"
    } else {
        Write-Host 'Publisher certificate: none (unsigned preview)'
    }
} catch {
    Write-Warning "Cannot read Authenticode status: $($_.Exception.Message)"
}
try {
    $zone = Get-Content -LiteralPath $Installer -Stream Zone.Identifier -ErrorAction Stop |
        Where-Object { $_ -match '^ZoneId=' }
    if ($zone) { Write-Host "Download zone: $($zone -join ', ')" }
} catch {
    Write-Host 'Download zone stream: unavailable'
}
Write-Host ''
Write-Host 'Recent Windows Code Integrity events (last 6 hours, relevant to this installer):'
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
        Id = 3076, 3077, 3089
        StartTime = (Get-Date).AddHours(-6)
    } -MaxEvents 80 -ErrorAction Stop
    $matched = @($events | Where-Object {
        $_.Message -match 'adblock|webserver\.exe|preview-user|preview-machine'
    })
    if ($matched.Count) {
        $matched | Select-Object -First 12 TimeCreated, Id, LevelDisplayName |
            Format-Table -AutoSize
        Write-Host 'Relevant Code Integrity events found. Inspect these events locally in Event Viewer.'
    } else {
        Write-Host 'No matching Code Integrity events among the latest 80 events.'
    }
} catch {
    Write-Host 'Code Integrity event log unavailable or no matching events.'
}
Write-Host ''
Write-Host 'Next: Windows Security > App & browser control > Smart App Control settings.'
Write-Host 'Also inspect Windows Security > Protection history.'
Write-Host 'Smart App Control may block unsigned software without a per-app override.'
Write-Host 'Do NOT disable Windows security to install a UI inspection build.'

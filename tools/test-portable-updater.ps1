param([Parameter(Mandatory=$true)][string]$FixtureExecutable,[string]$FixtureRoot)
# The fixture is an inert sleep process. Host runs require an explicit, bounded
# workspace validation directory; production installations are never targets.
$ErrorActionPreference='Stop'
if($FixtureRoot) {
    $validation=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\validation')).TrimEnd('\')
    if(![IO.Path]::IsPathRooted($FixtureRoot)) { throw 'FixtureRoot must be absolute' }
    $root=[IO.Path]::GetFullPath($FixtureRoot).TrimEnd('\')
    if(!$root.StartsWith($validation+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Host fixtures must stay in this workspace validation directory' }
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $cursor=Get-Item -LiteralPath $root -Force
    while($cursor) {
        if($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Fixture root contains a reparse point' }
        $cursor=$cursor.Parent
    }
} elseif($env:CI -and $env:RUNNER_TEMP) { $root=$env:RUNNER_TEMP }
else { throw 'Portable update fixture requires CI or an explicit workspace FixtureRoot' }
$base=[IO.Path]::GetFullPath((Join-Path $root ('AdAwayPortable-'+[guid]::NewGuid().ToString('N'))))
New-Item -ItemType Directory -Path $base | Out-Null
Write-Output ('Portable update evidence: '+$base)
$fixture=(Resolve-Path -LiteralPath $FixtureExecutable).Path
$helper=(Resolve-Path -LiteralPath 'update_portable.ps1').Path
$powershell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
function Start-Fixture([string]$path) { return Start-Process -WindowStyle Hidden -FilePath $path -PassThru }
function Processes-InFixture {
    return @(Get-Process -Name webserver -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase) })
}
function Show-Diagnostics {
    foreach($file in @(Get-ChildItem -LiteralPath $base -Filter '*.log' -File -Recurse | Select-Object -First 16)) {
        Write-Output ('Portable update diagnostic: '+$file.FullName)
        Get-Content -LiteralPath $file.FullName -Tail 30
    }
}
try {
    $other=Join-Path $base 'unrelated'
    New-Item -ItemType Directory -Path $other | Out-Null
    Copy-Item -LiteralPath $fixture -Destination (Join-Path $other 'webserver.exe')
    $unrelated=Start-Fixture (Join-Path $other 'webserver.exe')
    foreach($rollback in @($false,$true)) {
        $case=if($rollback){'rollback'}else{'success'}
        $unicode=([string][char]0x89c4)+([string][char]0x5219)
        $app=Join-Path $base ("installed O'Brien ["+$case+"] & 100% "+$unicode)
        $stage=Join-Path $base ('adblock-update-'+$case)
        $source=Join-Path $stage 'unpacked'
        $resources=Join-Path $app 'resources'
        New-Item -ItemType Directory -Path $resources,$source | Out-Null
        Copy-Item -LiteralPath $fixture -Destination (Join-Path $app 'webserver.exe')
        Copy-Item -LiteralPath $fixture -Destination (Join-Path $source 'webserver.exe')
        Set-Content -LiteralPath (Join-Path $resources 'subscription_urls.txt') -Value '# name: private source' -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $resources 'new-user-data.txt') -Value 'keep unknown future files' -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $app 'webserver.ini') -Value 'automatic_update=0' -Encoding ASCII
        Set-Content -LiteralPath (Join-Path $app 'unins000.dat') -Value 'preserve installation registration' -Encoding ASCII
        if($rollback) { Set-Content -LiteralPath (Join-Path $source 'fail-startup') -Value 'fail' -Encoding ASCII }
        $old=Start-Fixture (Join-Path $app 'webserver.exe')
        $script=$stage+'.ps1'
        Copy-Item -LiteralPath $helper -Destination $script
        $arguments=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+$script+'"'),'-Application',('"'+$app+'"'),'-Source',('"'+$source+'"'),'-Stage',('"'+$stage+'"'),'-PreviousPid',[string]$old.Id)
        $update=Start-Process -WindowStyle Hidden -FilePath $powershell -ArgumentList $arguments -PassThru `
            -RedirectStandardOutput (Join-Path $base ($case+'.stdout.log')) -RedirectStandardError (Join-Path $base ($case+'.stderr.log'))
        $deadline=[DateTime]::UtcNow.AddSeconds(15)
        while(!(Test-Path -LiteralPath ($stage+'.ready')) -and [DateTime]::UtcNow -lt $deadline -and !$update.HasExited) { Start-Sleep -Milliseconds 100; $update.Refresh() }
        if(!(Test-Path -LiteralPath ($stage+'.ready'))) { throw "Helper preparation failed: $case" }
        Stop-Process -InputObject $old -Force
        if(!$update.WaitForExit(30000)) { throw "Helper timed out: $case" }
        if($update.ExitCode -ne $(if($rollback){1}else{0})) { throw "Wrong helper result $($update.ExitCode): $case" }
        $unrelated.Refresh()
        if($unrelated.HasExited) { throw 'Update killed an unrelated same-name process' }
        if((Get-Content -LiteralPath (Join-Path $resources 'new-user-data.txt') -Raw).Trim() -ne 'keep unknown future files') { throw 'User resources lost' }
        if((Get-Content -LiteralPath (Join-Path $app 'webserver.ini') -Raw).Trim() -ne 'automatic_update=0') { throw 'Settings lost' }
        if(!(Test-Path -LiteralPath (Join-Path $app 'unins000.dat'))) { throw 'Installer registration lost' }
        $running=@(Processes-InFixture | Where-Object Path -IEQ (Join-Path $app 'webserver.exe'))
        if($running.Count -ne 1) { throw 'Exact installation did not restart once' }
        if($rollback -and !(Test-Path -LiteralPath (Join-Path $resources 'update-failed.log'))) { throw 'Rollback failure detail missing' }
        if(!$rollback -and (Test-Path -LiteralPath $stage)) { throw 'Successful stage was not cleaned' }
        Stop-Process -InputObject $running[0] -Force
    }
    # Reject overlap before readiness or a directory mutation, keeping the live process.
    $badApp=Join-Path $base 'adblock-update-invalid'
    New-Item -ItemType Directory -Path $badApp | Out-Null
    Copy-Item -LiteralPath $fixture -Destination (Join-Path $badApp 'webserver.exe')
    $old=Start-Fixture (Join-Path $badApp 'webserver.exe')
    $badArgs=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+$helper+'"'),'-Application',('"'+$badApp+'"'),'-Source',('"'+$badApp+'"'),'-Stage',('"'+$badApp+'"'),'-PreviousPid',[string]$old.Id)
    $reject=Start-Process -WindowStyle Hidden -FilePath $powershell -ArgumentList $badArgs -PassThru `
        -RedirectStandardOutput (Join-Path $base 'reject.stdout.log') -RedirectStandardError (Join-Path $base 'reject.stderr.log')
    if(!$reject.WaitForExit(10000) -or $reject.ExitCode -eq 0) { throw 'Unsafe overlap not rejected' }
    $old.Refresh(); if($old.HasExited -or !(Test-Path -LiteralPath (Join-Path $badApp 'webserver.exe'))) { throw 'Rejected update changed previous installation' }
    Write-Output 'Portable helper: success, exact-process restart, failure rollback, future resource preservation, unrelated process survival, overlap rejection and Unicode/metacharacter paths passed'
} catch {
    Show-Diagnostics
    throw
} finally {
    foreach($process in Processes-InFixture) { Stop-Process -InputObject $process -Force -ErrorAction SilentlyContinue }
}

# The signed/digest-checked package supplies this helper alongside webserver.exe.
# The running updater copies its own helper out before exiting. Windows PowerShell 5.1.
param(
    [Parameter(Mandatory=$true)][string]$Application,
    [Parameter(Mandatory=$true)][string]$Source,
    [Parameter(Mandatory=$true)][string]$Stage,
    [Parameter(Mandatory=$true)][int]$PreviousPid
)
$ErrorActionPreference='Stop'
$ownedProcess=$null
$moved=$false
$placed=$false
$backup=$null
$result=1
$prepared=$false
function Full-Directory([string]$value) {
    if (![IO.Path]::IsPathRooted($value)) { throw 'Update paths must be absolute' }
    $full=[IO.Path]::GetFullPath($value).TrimEnd('\')
    if ($full.Length -le [IO.Path]::GetPathRoot($full).Length) { throw 'Drive root is not an update directory' }
    return $full
}
function Below([string]$child,[string]$parent) {
    return $child.StartsWith($parent+'\',[StringComparison]::OrdinalIgnoreCase)
}
function No-Reparse([string]$directory) {
    # Check each ancestor too: an apparently private stage must not traverse a junction.
    $cursor=Get-Item -LiteralPath $directory -Force
    while ($null -ne $cursor) {
        if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point in update path' }
        $cursor=$cursor.Parent
    }
    $queue=New-Object 'System.Collections.Generic.Queue[string]'
    $queue.Enqueue($directory)
    while($queue.Count) {
        foreach ($entry in Get-ChildItem -LiteralPath $queue.Dequeue() -Force) {
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point in update tree' }
            if ($entry.PSIsContainer) { $queue.Enqueue($entry.FullName) }
        }
    }
}
function Same-Executable($process,[string]$path) {
    if (!$process) { return $false }
    try { $process.Refresh(); return !$process.HasExited -and $process.Path -ieq $path }
    catch { return $false }
}
function Stop-OwnedProcess {
    if ($ownedProcess -and (Same-Executable $ownedProcess $executable)) {
        # Use the retained process object, never a process-name search.
        Stop-Process -InputObject $ownedProcess -Force -ErrorAction Stop
        [void]$ownedProcess.WaitForExit(10000)
        if (!$ownedProcess.HasExited) { throw 'Updated process could not be stopped' }
    }
}
function Start-Application {
    return Start-Process -WindowStyle Hidden -FilePath $executable -ArgumentList '--minimized' -WorkingDirectory $Application -PassThru
}
function Remove-VerifiedTree([string]$target,[string]$expected) {
    $resolved=Full-Directory $target
    if ($resolved -ine $expected) { throw 'Unexpected cleanup path' }
    if (Test-Path -LiteralPath $resolved) {
        No-Reparse $resolved
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
try {
    $Application=Full-Directory $Application
    $Source=Full-Directory $Source
    $Stage=Full-Directory $Stage
    if ($PreviousPid -le 0 -or $PreviousPid -eq $PID) { throw 'Invalid previous process' }
    if ($Application -ieq $Stage -or (Below $Stage $Application) -or (Below $Application $Stage)) { throw 'Stage overlaps installation' }
    if ($Source -ine $Stage -and !(Below $Source $Stage)) { throw 'Extracted source is outside stage' }
    if ((Split-Path -Leaf $Stage) -notlike 'adblock-update-*') { throw 'Unexpected stage directory' }
    No-Reparse $Application; No-Reparse $Stage
    $executable=Join-Path $Application 'webserver.exe'
    if (!(Test-Path -LiteralPath $executable -PathType Leaf) -or !(Test-Path -LiteralPath (Join-Path $Source 'webserver.exe') -PathType Leaf)) { throw 'Server executable missing' }
    $backup=$Application+'.backup-'+[guid]::NewGuid().ToString('N')
    $log=Join-Path $Stage 'portable-update.log'
    function Write-Step([string]$text) { Add-Content -LiteralPath $log -Value ((Get-Date -Format o)+' '+$text) -Encoding UTF8 }
    Write-Step 'Waiting for this installation to exit'
    $previous=Get-Process -Id $PreviousPid -ErrorAction SilentlyContinue
    if ($previous -and !(Same-Executable $previous $executable)) { throw 'Previous PID belongs to another executable' }
    # The running app exits only after the validated helper is ready.
    [IO.File]::WriteAllText($Stage+'.ready','ready')
    $prepared=$true
    if ($previous -and !$previous.WaitForExit(90000)) { throw 'Previous process did not exit; installation left untouched' }
    # Leave every helper process outside the directory being moved.
    Set-Location -LiteralPath $Stage
    for($attempt=0;$attempt -lt 20;$attempt++) {
        try { Move-Item -LiteralPath $Application -Destination $backup; $moved=$true; break }
        catch { if($attempt -eq 19) { throw }; Start-Sleep -Milliseconds 500 }
    }
    Write-Step 'Previous installation moved to unique backup'
    if ($Source -ieq $Stage) {
        New-Item -ItemType Directory -Path $Application | Out-Null
        $placed=$true
        foreach($entry in Get-ChildItem -LiteralPath $Source -Force) {
            if ($entry.Name -eq 'portable-update.log') { continue }
            Copy-Item -LiteralPath $entry.FullName -Destination $Application -Recurse -Force
        }
    } else {
        try { Move-Item -LiteralPath $Source -Destination $Application; $placed=$true }
        catch {
            New-Item -ItemType Directory -Path $Application -Force | Out-Null
            $placed=$true
            foreach($entry in Get-ChildItem -LiteralPath $Source -Force) { Copy-Item -LiteralPath $entry.FullName -Destination $Application -Recurse -Force }
        }
    }
    # Resources are user data. Preserve their complete tree, including source names,
    # rule snapshots, certificates and private settings added after this helper.
    $oldResources=Join-Path $backup 'resources'
    if(Test-Path -LiteralPath $oldResources -PathType Container) {
        $newResources=Join-Path $Application 'resources'
        New-Item -ItemType Directory -Path $newResources -Force | Out-Null
        foreach($entry in Get-ChildItem -LiteralPath $oldResources -Force) { Copy-Item -LiteralPath $entry.FullName -Destination $newResources -Recurse -Force }
    }
    foreach($entry in Get-ChildItem -LiteralPath $backup -Force -File) {
        if($entry.Name -eq 'webserver.ini' -or $entry.Name -like 'unins*.exe' -or $entry.Name -like 'unins*.dat' -or $entry.Name -like 'unins*.msg') {
            Copy-Item -LiteralPath $entry.FullName -Destination $Application -Force
        }
    }
    Write-Step 'Starting the new executable; health means this exact process stays alive'
    $ownedProcess=Start-Application
    Start-Sleep -Seconds 5
    if(!(Same-Executable $ownedProcess $executable)) { throw 'New executable exited during startup' }
    Write-Step ('Update applied; restarted PID '+$ownedProcess.Id)
    $resources=Join-Path $Application 'resources'
    if(Test-Path -LiteralPath $resources -PathType Container) { Copy-Item -LiteralPath $log -Destination (Join-Path $resources 'update-last.log') -Force }
    $moved=$false
    $result=0
    # Cleanup failure cannot trigger rollback after part of the backup was removed.
    try { Remove-VerifiedTree $backup $backup }
    catch { Write-Step ('Applied update; backup cleanup deferred: '+$_.Exception.Message) }
} catch {
    $failure=$_.Exception.Message
    if($moved) {
        try {
            Stop-OwnedProcess
            if($placed) { Remove-VerifiedTree $Application $Application }
            Move-Item -LiteralPath $backup -Destination $Application
            $moved=$false
            $resources=Join-Path $Application 'resources'
            if(Test-Path -LiteralPath $resources -PathType Container) { Set-Content -LiteralPath (Join-Path $resources 'update-failed.log') -Value $failure -Encoding UTF8 }
            $ownedProcess=Start-Application
        } catch {
            # Keep the backup when restoration fails, for explicit recovery.
            $failure+='; rollback failed: '+$_.Exception.Message
        }
    }
    [Console]::Error.WriteLine($failure)
} finally {
    # Keep diagnostic staging on failure. A successful apply owns and may remove
    # only its checked stage root; the helper itself was copied beside that root.
    if($result -eq 0) {
        Set-Location -LiteralPath ([IO.Path]::GetTempPath())
        try {
            Remove-VerifiedTree $Stage $Stage
            if($PSCommandPath -ieq ($Stage+'.ps1')) { Remove-Item -LiteralPath $PSCommandPath -Force }
        } catch { [Console]::Error.WriteLine('Applied update; stage cleanup deferred: '+$_.Exception.Message) }
    }
    if($prepared -and (Test-Path -LiteralPath ($Stage+'.ready') -PathType Leaf)) { Remove-Item -LiteralPath ($Stage+'.ready') -Force }
}
exit $result

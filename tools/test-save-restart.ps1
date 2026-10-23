# Disposable runner: production GUI, production singleton, real saved INI and new PID.
param([string]$Executable='dist/webserver.exe')
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Production GUI restart test requires disposable CI desktop' }
Add-Type @'
using System; using System.Runtime.InteropServices; using System.Text;
public static class RestartUi {
 private delegate bool EnumWindow(IntPtr w,IntPtr l);
 [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindow callback,IntPtr l);
 [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr w,out uint pid);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] private static extern int GetClassNameW(IntPtr w,StringBuilder name,int capacity);
 public static IntPtr Find(uint pid) {
  IntPtr found=IntPtr.Zero;
  EnumWindows((w,l)=>{ uint owner; GetWindowThreadProcessId(w,out owner); var name=new StringBuilder(100); GetClassNameW(w,name,100);
   if (owner==pid && name.ToString()=="ADBlockDashWin11") { found=w; return false; } return true; },IntPtr.Zero);
  return found;
 }
 [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr w,int id);
 [DllImport("user32.dll",CharSet=CharSet.Unicode,EntryPoint="SendMessageTimeoutW")] public static extern IntPtr Text(IntPtr w,uint msg,IntPtr p,string text,uint flags,uint timeout,out IntPtr result);
 [DllImport("user32.dll",EntryPoint="SendMessageTimeoutW")] public static extern IntPtr Send(IntPtr w,uint msg,IntPtr p,IntPtr l,uint flags,uint timeout,out IntPtr result);
 [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr w,uint msg,IntPtr p,IntPtr l);
}
'@
function Free-Port {
 $socket=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0); $socket.Start(); $port=$socket.LocalEndpoint.Port; $socket.Stop(); return $port
}
function Set-Text([IntPtr]$Window,[int]$Id,[string]$Text) {
 $result=[IntPtr]::Zero
 if ([RestartUi]::Text([RestartUi]::GetDlgItem($Window,$Id),0xC,[IntPtr]::Zero,$Text,2,5000,[ref]$result) -eq [IntPtr]::Zero -or $result -eq [IntPtr]::Zero) { throw "Unable to set control $Id" }
}
function Wait-Stats([int]$Port) {
 $deadline=[DateTime]::UtcNow.AddSeconds(25)
 do { try { return Invoke-RestMethod "http://127.0.0.1:$Port/internal-stats" -NoProxy -TimeoutSec 1 } catch { Start-Sleep -Milliseconds 100 } } while ([DateTime]::UtcNow -lt $deadline)
 throw "Server failed to answer on port $Port"
}
$root=Join-Path $env:RUNNER_TEMP ('adaway-restart-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
Copy-Item (Join-Path (Split-Path (Resolve-Path $Executable)) '*') $root -Recurse
$exe=Join-Path $root 'webserver.exe'; $ini=Join-Path $root 'webserver.ini'; $res=(Join-Path $root 'resources')+'\'
$ports=[Collections.Generic.HashSet[int]]::new()
while ($ports.Count -lt 5) { [void]$ports.Add((Free-Port)) }; $ports=@($ports)
$http=$ports[0]; $https=$ports[1]; $stats=$ports[2]; $newHttp=$ports[3]; $newHttps=$ports[4]
Set-Content -LiteralPath $ini -Encoding ascii -Value "http_port=$http`nhttps_port=$https`nstats_port=$stats`nlisten_ipv4=127.0.0.1`nlisten_ipv6=`nlistener_auto_create=0`n[settings]`nautomatic_update=0"
# Correct CRT escaping of a quoted argument ending in backslash.
$arguments='--resources "'+$res.TrimEnd('\')+'\\"'
$initial=Start-Process -FilePath $exe -ArgumentList $arguments -WorkingDirectory $root -WindowStyle Hidden -PassThru
$firstFailure=$null; $stage='initial server'
try {
 [void](Wait-Stats $http)
 $stage='locate production window'
 $deadline=[DateTime]::UtcNow.AddSeconds(5)
 do { $initial.Refresh(); $window=[RestartUi]::Find([uint32]$initial.Id); if ($window -ne [IntPtr]::Zero -and [RestartUi]::GetDlgItem($window,1105) -ne [IntPtr]::Zero) { break }; Start-Sleep -Milliseconds 50 } while ([DateTime]::UtcNow -lt $deadline)
 if ($window -eq [IntPtr]::Zero -or [RestartUi]::GetDlgItem($window,1105) -eq [IntPtr]::Zero) { throw 'Production settings controls missing' }
 $result=[IntPtr]::Zero
 [void][RestartUi]::Send($window,0x111,[IntPtr](65536+47000+2),[IntPtr]::Zero,2,5000,[ref]$result)
 Set-Text $window 1101 "$newHttp"; Set-Text $window 1102 "$newHttps"
 $stage='locked INI save'
 # Failed atomic save must preserve the old process, old INI and live port.
 $original=[IO.File]::ReadAllText($ini)
 $lock=[IO.File]::Open($ini,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try { [void][RestartUi]::Send($window,0x111,[IntPtr]1105,[IntPtr]::Zero,2,10000,[ref]$result) } finally { $lock.Dispose() }
 Start-Sleep -Milliseconds 300; $initial.Refresh()
 if ($initial.HasExited -or [IO.File]::ReadAllText($ini) -ne $original) { throw 'Failed save exited or changed committed settings' }
 [void](Wait-Stats $http)
 Write-Host 'Locked INI save preserved original process, configuration and HTTP service'
 $stage='save and restart'
 [void][RestartUi]::Send($window,0x111,[IntPtr]1105,[IntPtr]::Zero,2,10000,[ref]$result)
 if (!$initial.WaitForExit(15000) -or $initial.ExitCode -ne 0) { throw 'Old GUI did not stop normally' }
 $newStats=Wait-Stats $newHttp
 $stage='verify new PID and saved settings'
 $connection=Get-NetTCPConnection -LocalPort $newHttp -State Listen | Where-Object { $_.LocalAddress -eq '127.0.0.1' } | Select-Object -First 1
 if (!$connection -or $connection.OwningProcess -eq $initial.Id) { throw 'New port was not acquired by a new PID' }
 $next=Get-Process -Id $connection.OwningProcess
 if ($next.Path -ne $exe) { throw 'Port belongs to a different installation' }
 $saved=[IO.File]::ReadAllText($ini)
 if ($saved -notmatch "(?m)^http_port=$newHttp\s*$" -or $saved -notmatch "(?m)^https_port=$newHttps\s*$" -or [int]$newStats.stats_port -ne $stats) { throw 'Relaunched process did not load saved INI' }
 [ordered]@{ passed=$true; productionGui=$true; baselineSaveFailurePreserved=$true; initialPid=$initial.Id; newPid=$next.Id; oldHttp=$http; savedHttp=$newHttp; savedHttps=$newHttps; statsPort=$stats; trailingResourceBackslash=$true; hostNetworkChanges=$false } | ConvertTo-Json | Set-Content save-restart-results.json
} catch {
 $firstFailure=$_
 Write-Warning "Production restart fixture failed at [$stage]: $($_.Exception.Message)"
 [ordered]@{ passed=$false; stage=$stage; error=$_.Exception.Message; fixture=$root; initialPid=$initial.Id; hostNetworkChanges=$false } | ConvertTo-Json | Set-Content save-restart-results.json
 New-Item -ItemType Directory -Force -Path restart-diagnostics | Out-Null
 # This fixture creates its own credential-free INI and only local requests.
 foreach ($path in @($ini,(Join-Path $res 'webserver.log'),(Join-Path $res 'webserver.log.1'))) {
  if (Test-Path -LiteralPath $path) { Copy-Item -LiteralPath $path -Destination restart-diagnostics -ErrorAction Continue }
 }
 throw
} finally {
 # Only processes whose executable is this isolated fixture are touched.
 foreach ($process in @(Get-Process -Name webserver -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe })) {
  $process.Refresh(); $ownedWindow=[RestartUi]::Find([uint32]$process.Id)
  if ($ownedWindow -ne [IntPtr]::Zero) { [void][RestartUi]::PostMessageW($ownedWindow,0x111,[IntPtr]1005,[IntPtr]::Zero) }
  if (!$process.WaitForExit(8000)) {
   Stop-Process -Id $process.Id -Force
   if ($firstFailure) { Write-Warning "Fixture cleanup also failed normal shutdown for owned PID $($process.Id)" }
   else { throw 'Fixture GUI failed normal shutdown' }
  }
 }
}

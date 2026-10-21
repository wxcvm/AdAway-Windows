param([Parameter(Mandatory)][int]$GuiProcessId, [string]$OutputDirectory = 'ui-review', [string]$ResourceDirectory)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class UiReviewNative {
  [StructLayout(LayoutKind.Sequential)] public struct Rect { public int Left, Top, Right, Bottom; }
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] public struct Font {
    public int Height, Width, Escapement, Orientation, Weight;
    public byte Italic, Underline, StrikeOut, CharsetByte, OutPrecision, ClipPrecision, Quality, PitchAndFamily;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)] public string FaceName;
  }
  public delegate bool EnumChild(IntPtr hwnd, IntPtr data);
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr w, out Rect r);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr w, out Rect r);
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr w, IntPtr after, int x, int y, int cx, int cy, uint flags);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr w, EnumChild callback, IntPtr data);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr w);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr w);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr w);
  [DllImport("user32.dll", SetLastError=true)] public static extern bool PostMessageW(IntPtr w, uint msg, IntPtr wp, IntPtr lp);
  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr w, int id);
  [DllImport("user32.dll")] public static extern IntPtr GetWindow(IntPtr w, uint command);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessage(IntPtr w, uint msg, IntPtr wp, IntPtr lp);
  [DllImport("user32.dll", EntryPoint="SendMessageTimeoutW", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr SetTextTimeout(IntPtr w, uint msg, IntPtr wp, string text, uint flags, uint timeout, out IntPtr result);
  [DllImport("user32.dll", EntryPoint="SendMessageTimeoutW", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr GetTextTimeout(IntPtr w, uint msg, IntPtr wp, [Out] System.Text.StringBuilder text, uint flags, uint timeout, out IntPtr result);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr SendMessageTimeoutW(IntPtr w, uint msg, IntPtr wp, IntPtr lp, uint flags, uint timeout, out IntPtr result);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr w, IntPtr dc, uint flags);
  [DllImport("gdi32.dll", CharSet=CharSet.Unicode)] public static extern int GetObjectW(IntPtr obj, int size, out Font font);
}
"@
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$guiProcess = Get-Process -Id $GuiProcessId
$guiProcess.Refresh()
$window = $guiProcess.MainWindowHandle
if (!$window) { throw 'Dashboard window missing' }
$controlIds=[System.Collections.Generic.HashSet[int]]::new()
$duplicateIds=[System.Collections.Generic.List[int]]::new()
$uniqueCallback=[UiReviewNative+EnumChild]{ param($child,$data)
    $id=[UiReviewNative]::GetDlgCtrlID($child)
    if ($id -gt 0 -and !$controlIds.Add($id)) { $duplicateIds.Add($id) }
    return $true
}
[void][UiReviewNative]::EnumChildWindows($window,$uniqueCallback,[IntPtr]::Zero)
if ($duplicateIds.Count -gt 0) { throw "Duplicate native control IDs: $duplicateIds" }
$records = [System.Collections.Generic.List[object]]::new()
# Cross-process edit controls require WM_SETTEXT / WM_GETTEXT, not caption APIs.
function Read-ControlText([IntPtr]$Control) {
    $buffer=[Text.StringBuilder]::new(4096)
    $messageResult=[IntPtr]::Zero
    if ([UiReviewNative]::GetTextTimeout($Control,0xD,[IntPtr]4096,$buffer,2,10000,[ref]$messageResult) -eq [IntPtr]::Zero) {
        throw 'Edit text read did not return within 10 seconds'
    }
    return $buffer.ToString()
}
function Set-ControlText([IntPtr]$Control, [string]$Text) {
    $result=[IntPtr]::Zero
    if ([UiReviewNative]::SetTextTimeout($Control,0xC,[IntPtr]::Zero,$Text,2,10000,[ref]$result) -eq [IntPtr]::Zero -or $result -eq [IntPtr]::Zero) {
        throw 'Unable to populate cross-process source input'
    }
}
function Send-BoundedMessage([IntPtr]$Control, [uint32]$Message, [IntPtr]$WParam, [IntPtr]$LParam) {
    $result=[IntPtr]::Zero
    if ([UiReviewNative]::SendMessageTimeoutW($Control,$Message,$WParam,$LParam,2,10000,[ref]$result) -eq [IntPtr]::Zero) {
        throw "UI message $Message did not return within 10 seconds"
    }
}

function Set-Page([int]$Tab) {
    [void][UiReviewNative]::SendMessage($window, 0x111, [IntPtr](65536 + 47000 + $Tab), [IntPtr]::Zero)
}
function Set-ClientSize([int]$Width, [int]$Height) {
    $outer = [UiReviewNative+Rect]::new(); $client = [UiReviewNative+Rect]::new()
    [void][UiReviewNative]::GetWindowRect($window, [ref]$outer)
    [void][UiReviewNative]::GetClientRect($window, [ref]$client)
    [void][UiReviewNative]::SetWindowPos($window, [IntPtr]::Zero, 0, 0,
        $Width + $outer.Right - $outer.Left - $client.Right,
        $Height + $outer.Bottom - $outer.Top - $client.Bottom, 0x14)
}
function Check-Controls([string]$Name) {
    $bounds = [System.Collections.Generic.List[object]]::new()
    $callback = [UiReviewNative+EnumChild]{ param($child, $data)
        if ([UiReviewNative]::IsWindowVisible($child)) {
            $r = [UiReviewNative+Rect]::new()
            [void][UiReviewNative]::GetWindowRect($child, [ref]$r)
            $bounds.Add([pscustomobject]@{Id=[UiReviewNative]::GetDlgCtrlID($child);Left=$r.Left;Top=$r.Top;Right=$r.Right;Bottom=$r.Bottom})
        }
        return $true
    }
    [void][UiReviewNative]::EnumChildWindows($window, $callback, [IntPtr]::Zero)
    for ($i=0; $i -lt $bounds.Count; $i++) {
        for ($j=$i+1; $j -lt $bounds.Count; $j++) {
            $a=$bounds[$i]; $b=$bounds[$j]
            if ($a.Left -lt $b.Right -and $a.Right -gt $b.Left -and $a.Top -lt $b.Bottom -and $a.Bottom -gt $b.Top) {
                throw "Overlapping controls on ${Name}: $($a.Id), $($b.Id)"
            }
        }
    }
    $client = [UiReviewNative+Rect]::new(); [void][UiReviewNative]::GetClientRect($window,[ref]$client)
    # Record a known subscription field's font (shared with all settings controls).
    $fontControl=[IntPtr]::Zero
    foreach ($fontId in @(1140,2001,2103)) {
        $fontControl=[UiReviewNative]::GetDlgItem($window,$fontId)
        if ($fontControl -ne [IntPtr]::Zero) { break }
    }
    $fontHandle = [UiReviewNative]::SendMessage($fontControl,0x31,[IntPtr]::Zero,[IntPtr]::Zero)
    $font = [UiReviewNative+Font]::new()
    if (![UiReviewNative]::GetObjectW($fontHandle,[Runtime.InteropServices.Marshal]::SizeOf($font),[ref]$font)) { throw 'Control font missing' }
    $records.Add([pscustomobject]@{Name=$Name;Width=$client.Right;Height=$client.Bottom;FontHeight=$font.Height;Controls=$bounds.ToArray()})
}
function Save-Window([string]$Name) {
    Start-Sleep -Milliseconds 150
    Check-Controls $Name
    $r = [UiReviewNative+Rect]::new(); [void][UiReviewNative]::GetWindowRect($window,[ref]$r)
    $bitmap = [System.Drawing.Bitmap]::new($r.Right-$r.Left,$r.Bottom-$r.Top)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $dc=$graphics.GetHdc()
    try { if (![UiReviewNative]::PrintWindow($window,$dc,2)) { throw 'Window capture failed' } }
    finally { $graphics.ReleaseHdc($dc); $graphics.Dispose() }
    try { $bitmap.Save((Join-Path (Resolve-Path $OutputDirectory) "$Name.png"),[System.Drawing.Imaging.ImageFormat]::Png) }
    finally { $bitmap.Dispose() }
}
Set-ClientSize 1032 678
Set-Page 0; Save-Window 'overview-light'
Set-Page 2; Save-Window 'settings-light'
$ipControl=[UiReviewNative]::GetDlgItem($window,1190)
$ipv6Control=[UiReviewNative]::GetDlgItem($window,1196)
if ($ipv6Control -eq [IntPtr]::Zero -or ![UiReviewNative]::GetDlgItem($window,1197)) { throw 'Independent IPv6/startup creation options missing' }
Set-ControlText $ipControl '10.254.253.75'
Set-ControlText $ipv6Control 'fd6b:2a91:84f0::75'
if (![UiReviewNative]::GetDlgItem($window,1193) -or ![UiReviewNative]::GetDlgItem($window,1194)) { throw 'Address creation/removal controls missing' }
$beforeAddress=if ($ResourceDirectory -and (Test-Path (Join-Path $ResourceDirectory 'webserver.ini'))) { [IO.File]::ReadAllText((Join-Path $ResourceDirectory 'webserver.ini')) } else { $null }
foreach ($createId in @(1193,1201)) {
[void][UiReviewNative]::PostMessageW($window,0x111,[IntPtr]$createId,[IntPtr]::Zero)
$dialog=[IntPtr]::Zero;$dialogDeadline=(Get-Date).AddSeconds(5)
do {
    Start-Sleep -Milliseconds 100
    $dialog=[UiReviewNative]::GetWindow($window,6) # GW_ENABLEDPOPUP, owned confirmation only
} until (($dialog -ne [IntPtr]::Zero -and $dialog -ne $window) -or (Get-Date) -gt $dialogDeadline)
if ($dialog -eq [IntPtr]::Zero -or $dialog -eq $window) { throw 'Address creation confirmation missing' }
[void][UiReviewNative]::PostMessageW($dialog,0x111,[IntPtr]2,[IntPtr]::Zero) # IDCANCEL; never accept UAC in GUI tests
Start-Sleep -Milliseconds 150
if (![UiReviewNative]::IsWindowEnabled($window)) { throw 'Address confirmation cancel did not restore the window' }
if ($null -ne $beforeAddress -and [IO.File]::ReadAllText((Join-Path $ResourceDirectory 'webserver.ini')) -ne $beforeAddress) { throw 'Address confirmation cancel changed configuration' }
}
Write-Output 'Address creation/removal controls visible; confirmation cancelled before UAC; configuration preserved'
$originalHttp=Read-ControlText ([UiReviewNative]::GetDlgItem($window,1101))
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Save/active-config fixture requires disposable GitHub runner' }
$reservation=[Net.Sockets.TcpListener]::new([Net.IPAddress]::IPv6Any,0)
$reservation.Server.DualMode=$true;$reservation.Start()
try { $savedPort=$reservation.LocalEndpoint.Port } finally { $reservation.Stop() }
Set-ControlText $ipControl '127.0.0.1';Set-ControlText $ipv6Control '::1'
Set-ControlText ([UiReviewNative]::GetDlgItem($window,1101)) "$savedPort"
Send-BoundedMessage $window 0x111 ([IntPtr]1104) ([IntPtr]::Zero)
$iniFile=Join-Path (Split-Path -Parent $guiProcess.Path) 'webserver.ini'
$savedText=[IO.File]::ReadAllText($iniFile)
if ($savedText -notmatch "http_port=$savedPort" -or $savedText -notmatch 'listen_ipv6=::1') { throw 'GUI did not commit independent listener settings' }
[void][UiReviewNative]::PostMessageW($window,0x111,[IntPtr]1195,[IntPtr]::Zero)
$arrival=[IntPtr]::Zero;$arrivalDeadline=(Get-Date).AddSeconds(5)
do {
    Start-Sleep -Milliseconds 100
    $arrival=[UiReviewNative]::GetWindow($window,6)
} until (($arrival -ne [IntPtr]::Zero -and $arrival -ne $window) -or (Get-Date) -gt $arrivalDeadline)
if ($arrival -eq [IntPtr]::Zero -or $arrival -eq $window) { throw 'AdGuard arrival diagnostic window missing' }
Set-ControlText ([UiReviewNative]::GetDlgItem($arrival,2001)) 'ads.custom.example'
Set-ControlText ([UiReviewNative]::GetDlgItem($arrival,2002)) 'hosts.custom.example'
if ((Read-ControlText ([UiReviewNative]::GetDlgItem($arrival,2004))) -notmatch '点击检测') { throw 'Editing domains unexpectedly started diagnostics' }
Set-ControlText ([UiReviewNative]::GetDlgItem($arrival,2001)) ''
Set-ControlText ([UiReviewNative]::GetDlgItem($arrival,2002)) ''
[void][UiReviewNative]::PostMessageW($arrival,0x111,[IntPtr]2003,[IntPtr]::Zero)
$arrivalDeadline=(Get-Date).AddSeconds(15)
do {
    Start-Sleep -Milliseconds 100
    $arrivalText=Read-ControlText ([UiReviewNative]::GetDlgItem($arrival,2004))
} until ($arrivalText -match '管理端口：' -or (Get-Date) -gt $arrivalDeadline)
if ($arrivalText -notmatch '管理端口：AdAway 回执已确认' -or $arrivalText -notmatch 'HTTP 请求已到达 AdAway') { throw "GUI arrival client did not reach actual server: $arrivalText" }
if ($arrivalText -notmatch "\]:${originalHttp}：" -or $arrivalText -notmatch 'HTTPS' -or $arrivalText -notmatch 'QUIC / HTTP/3') { throw 'Saved but unapplied settings changed diagnostic targets or protocol report missing' }
if (![UiReviewNative]::GetDlgItem($arrival,2005)) { throw 'Copy result action missing' }
$dashboardWindow=$window
try { $window=$arrival; Save-Window 'adguard-arrival-dialog' }
finally { $window=$dashboardWindow }
[void][UiReviewNative]::PostMessageW($arrival,0x111,[IntPtr]2,[IntPtr]::Zero)
Start-Sleep -Milliseconds 150
if (![UiReviewNative]::IsWindowEnabled($window)) { throw 'Arrival window did not release the dashboard' }
Set-ControlText ([UiReviewNative]::GetDlgItem($window,1101)) $originalHttp
Send-BoundedMessage $window 0x111 ([IntPtr]1104) ([IntPtr]::Zero)
Write-Output 'AdGuard diagnostic GUI: domains editable, no implicit DNS, actual loopback receipts, no configuration changes'
Set-ControlText $ipControl 'localhost'
$autoDeadline=(Get-Date).AddSeconds(5)
do {
    Start-Sleep -Milliseconds 150
    $autoResult=Read-ControlText ([UiReviewNative]::GetDlgItem($window,1192))
} until ($autoResult -match 'IPv4' -or (Get-Date) -gt $autoDeadline)
if ($autoResult -notmatch 'IPv4') { throw 'Listener validation did not run automatically after editing' }
$result=Read-ControlText ([UiReviewNative]::GetDlgItem($window,1192))
if ($result -notmatch 'IPv4') { throw 'Invalid IP did not receive visible listener feedback' }
Set-ControlText $ipControl '127.0.0.1'
Set-ControlText $ipv6Control '::1'
Send-BoundedMessage $window 0x111 ([IntPtr]1191) ([IntPtr]::Zero)
$result=Read-ControlText ([UiReviewNative]::GetDlgItem($window,1192))
if ($result -notmatch 'HTTP') { throw 'IPv6 listener check did not reach real port detection' }
Set-ControlText $ipControl '127.0.0.1'
Set-ControlText $ipv6Control '::1'
Send-BoundedMessage $window 0x111 ([IntPtr]1134) ([IntPtr]::Zero)
if ((Read-ControlText ([UiReviewNative]::GetDlgItem($window,1134))) -notmatch 'ZIP') { throw 'ZIP update preference not visible' }
Send-BoundedMessage $window 0x111 ([IntPtr]1134) ([IntPtr]::Zero)
if ((Read-ControlText ([UiReviewNative]::GetDlgItem($window,1134))) -notmatch '自动') { throw 'ZIP update preference cannot be restored' }
$channelButton=[UiReviewNative]::GetDlgItem($window,1300)
if (!$channelButton -or ![UiReviewNative]::IsWindowVisible($channelButton)) { throw 'Preview channel button missing' }
Send-BoundedMessage $channelButton 0xF5 ([IntPtr]::Zero) ([IntPtr]::Zero)
if ((Read-ControlText $channelButton) -notmatch '含预览') { throw 'Actual preview channel button click did not change channel' }
if ((Read-ControlText ([UiReviewNative]::GetDlgItem($window,1203))) -ne 'IPv4' -or (Read-ControlText ([UiReviewNative]::GetDlgItem($window,1204))) -ne 'IPv6') { throw 'Channel action replaced address labels' }
if ((Get-Content (Join-Path (Split-Path $guiProcess.Path) 'webserver.ini') -Raw) -notmatch 'include_preview=1') { throw 'Preview channel was not persisted' }
Save-Window 'settings-preview-update-channel'
Send-BoundedMessage $channelButton 0xF5 ([IntPtr]::Zero) ([IntPtr]::Zero)
if ((Read-ControlText $channelButton) -notmatch '稳定版') { throw 'Stable update channel cannot be restored' }
Save-Window 'settings-listener-feedback'
Set-Page 4; Save-Window 'subscriptions-light'
$delete=[UiReviewNative]::GetDlgItem($window,1143)
if ([UiReviewNative]::IsWindowEnabled($delete)) { throw 'Delete must be disabled without a selection' }
$list=[UiReviewNative]::GetDlgItem($window,1141)
$count=[UiReviewNative]::SendMessage($list,0x18B,[IntPtr]::Zero,[IntPtr]::Zero).ToInt64()
if ($count -gt 0) {
    [void][UiReviewNative]::SendMessage($list,0x186,[IntPtr]::Zero,[IntPtr]::Zero)
    [void][UiReviewNative]::SendMessage($window,0x111,[IntPtr](65536+1141),$list)
    if (![UiReviewNative]::IsWindowEnabled($delete)) { throw 'Selected source cannot be managed' }
}
if ($ResourceDirectory) {
    $sourcePath = Join-Path $ResourceDirectory 'subscription_urls.txt'
    $original = [IO.File]::ReadAllText($sourcePath)
    $sourceInput = [UiReviewNative]::GetDlgItem($window,1140)
    $add = [UiReviewNative]::GetDlgItem($window,1142)
    if ([UiReviewNative]::IsWindowEnabled($add)) { throw 'Blank source must not enable Add' }
    foreach ($invalid in @('ftp://example.test/hosts', 'https://', ('https://example.test/' + ('a' * 1100)))) {
        Set-ControlText $sourceInput $invalid
        Send-BoundedMessage $window 0x111 ([IntPtr]1142) ([IntPtr]::Zero)
        if ([UiReviewNative]::SendMessage($list,0x18B,[IntPtr]::Zero,[IntPtr]::Zero).ToInt64() -ne $count -or
            (Read-ControlText $sourceInput) -ne $invalid -or [IO.File]::ReadAllText($sourcePath) -ne $original) {
            throw 'Invalid/oversized source changed the stored file/list/input'
        }
    }
    # WM_SETTEXT bypasses the native edit limit. Also exercise real user-style
    # insertion at that limit, which must flag truncation and block saving.
    $prefix = 'https://example.test/'
    Set-ControlText $sourceInput ($prefix + ('b' * (1023 - $prefix.Length)))
    Send-BoundedMessage $sourceInput 0xB1 ([IntPtr]1023) ([IntPtr]1023) # EM_SETSEL
    Send-BoundedMessage $sourceInput 0x102 ([IntPtr]99) ([IntPtr]1) # WM_CHAR
    if ([UiReviewNative]::IsWindowEnabled($add)) { throw 'Truncated source input must not enable Add' }
    Send-BoundedMessage $window 0x111 ([IntPtr]1142) ([IntPtr]::Zero)
    if ([UiReviewNative]::SendMessage($list,0x18B,[IntPtr]::Zero,[IntPtr]::Zero).ToInt64() -ne $count -or
        [IO.File]::ReadAllText($sourcePath) -ne $original) { throw 'Truncated source was saved' }
    Save-Window 'subscriptions-input-too-long'
    Set-ControlText $sourceInput '   '
    if ([UiReviewNative]::IsWindowEnabled($add)) { throw 'Whitespace source must not enable Add' }
    $candidate = 'https://example.test/extra?inspection=' + ('a' * 480)
    Write-Output 'Source settings GUI: populate candidate input'
    Set-ControlText $sourceInput $candidate
    if (![UiReviewNative]::IsWindowEnabled($add)) { throw 'Corrected source must enable Add' }
    if ((Read-ControlText $sourceInput) -ne $candidate) { throw 'Source input did not retain candidate text' }
    $readerLock = [IO.File]::Open($sourcePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        Write-Output 'Source settings GUI: add while replacement is blocked'
        $commandResult=[IntPtr]::Zero
        if ([UiReviewNative]::SendMessageTimeoutW($window,0x111,[IntPtr]1142,[IntPtr]::Zero,2,10000,[ref]$commandResult) -eq [IntPtr]::Zero) {
            throw 'Blocked-file source add did not return within 10 seconds'
        }
        Write-Output 'Source settings GUI: blocked add returned; check preserved input, count and file'
        $afterFailure = [UiReviewNative]::SendMessage($list,0x18B,[IntPtr]::Zero,[IntPtr]::Zero).ToInt64()
        $retained = Read-ControlText $sourceInput
        if ($afterFailure -ne $count -or $retained -ne $candidate -or [IO.File]::ReadAllText($sourcePath) -ne $original) {
            throw 'Failed source save changed the list, input or previous file'
        }
        Save-Window 'subscriptions-save-failed'
    } finally { $readerLock.Dispose() }
    Write-Output 'Source settings GUI: retry after releasing the reader'
    $commandResult=[IntPtr]::Zero
    if ([UiReviewNative]::SendMessageTimeoutW($window,0x111,[IntPtr]1142,[IntPtr]::Zero,2,10000,[ref]$commandResult) -eq [IntPtr]::Zero) {
        throw 'Source add retry did not return within 10 seconds'
    }
    Write-Output 'Source settings GUI: retry returned; check committed file and UI'
    $afterSuccess = [UiReviewNative]::SendMessage($list,0x18B,[IntPtr]::Zero,[IntPtr]::Zero).ToInt64()
    $cleared = Read-ControlText $sourceInput
    if ($afterSuccess -ne $count + 1 -or $cleared.Length -ne 0 -or ![IO.File]::ReadAllText($sourcePath).Contains($candidate)) {
        throw 'Successful source save did not commit file and UI together'
    }
    Save-Window 'subscriptions-saved'
    [void][UiReviewNative]::SendMessage($list,0x186,[IntPtr]$count,[IntPtr]::Zero)
    Send-BoundedMessage $window 0x111 ([IntPtr](65536+1141)) $list
    $selected = [UiReviewNative]::GetDlgItem($window,1146)
    if ((Read-ControlText $selected) -ne $candidate) { throw 'Selected source does not expose its complete address' }
    $listBounds=[UiReviewNative+Rect]::new()
    [void][UiReviewNative]::GetClientRect($list,[ref]$listBounds)
    $extent=[UiReviewNative]::SendMessage($list,0x193,[IntPtr]::Zero,[IntPtr]::Zero).ToInt64()
    if ($extent -le $listBounds.Right) { throw 'Long source rows must allow horizontal scrolling' }
    Save-Window 'subscriptions-long-source'

    $committedSources = [IO.File]::ReadAllText($sourcePath)
    $rulePath = Join-Path $ResourceDirectory 'subscriptions.txt'
    $ruleHash = (Get-FileHash -LiteralPath $rulePath -Algorithm SHA256).Hash
    $confirmRemove = [UiReviewNative]::GetDlgItem($window,1147)
    $cancelRemove = [UiReviewNative]::GetDlgItem($window,1148)
    # Remove a middle entry so failed-save rollback must restore shifted rows.
    $removeTarget = 'https://example.test/allow'
    [void][UiReviewNative]::SendMessage($list,0x186,[IntPtr]1,[IntPtr]::Zero)
    Send-BoundedMessage $window 0x111 ([IntPtr](65536+1141)) $list
    Send-BoundedMessage $window 0x111 ([IntPtr]1143) ([IntPtr]::Zero)
    if (![UiReviewNative]::IsWindowVisible($confirmRemove) -or ![UiReviewNative]::IsWindowVisible($cancelRemove) -or
        [UiReviewNative]::IsWindowEnabled($list) -or [UiReviewNative]::IsWindowEnabled($sourceInput) -or
        [UiReviewNative]::IsWindowEnabled([UiReviewNative]::GetDlgItem($window,1144)) -or
        (Read-ControlText $selected) -ne $removeTarget -or [IO.File]::ReadAllText($sourcePath) -ne $committedSources) {
        throw 'Removal confirmation did not preserve and isolate the selected target'
    }
    Save-Window 'subscriptions-remove-confirm'
    Send-BoundedMessage $window 0x111 ([IntPtr]1148) ([IntPtr]::Zero)
    if ([UiReviewNative]::IsWindowVisible($confirmRemove) -or ![UiReviewNative]::IsWindowEnabled($list) -or
        [IO.File]::ReadAllText($sourcePath) -ne $committedSources) { throw 'Cancel removal changed source state' }

    Send-BoundedMessage $window 0x111 ([IntPtr]1143) ([IntPtr]::Zero)
    if (![UiReviewNative]::PostMessageW($window,0x100,[IntPtr]27,[IntPtr]1)) { throw 'Unable to post Escape to GUI message loop' }
    $escapeDeadline = (Get-Date).AddSeconds(3)
    while ([UiReviewNative]::IsWindowVisible($confirmRemove) -and (Get-Date) -lt $escapeDeadline) { Start-Sleep -Milliseconds 50 }
    if ([UiReviewNative]::IsWindowVisible($confirmRemove) -or [IO.File]::ReadAllText($sourcePath) -ne $committedSources) {
        throw 'Escape did not cancel pending source removal'
    }

    # Leaving the page cancels pending removal instead of leaving a hidden action.
    Send-BoundedMessage $window 0x111 ([IntPtr]1143) ([IntPtr]::Zero)
    Set-Page 2
    if ([UiReviewNative]::IsWindowVisible($confirmRemove)) { throw 'Confirmation leaked onto another page' }
    Set-Page 4
    if ([UiReviewNative]::IsWindowVisible($confirmRemove) -or [IO.File]::ReadAllText($sourcePath) -ne $committedSources) {
        throw 'Navigation did not cancel removal without saving'
    }

    Send-BoundedMessage $window 0x111 ([IntPtr]1143) ([IntPtr]::Zero)
    $readerLock = [IO.File]::Open($sourcePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        Send-BoundedMessage $window 0x111 ([IntPtr]1147) ([IntPtr]::Zero)
        if ([UiReviewNative]::SendMessage($list,0x18B,[IntPtr]::Zero,[IntPtr]::Zero).ToInt64() -ne $count + 1 -or
            [IO.File]::ReadAllText($sourcePath) -ne $committedSources -or
            (Read-ControlText $selected) -ne $removeTarget -or
            ![UiReviewNative]::IsWindowVisible($confirmRemove) -or ![UiReviewNative]::IsWindowEnabled($confirmRemove)) {
            throw 'Failed removal did not retain its file, list, target and retry action'
        }
        Save-Window 'subscriptions-remove-failed'
    } finally { $readerLock.Dispose() }
    Send-BoundedMessage $window 0x111 ([IntPtr]1147) ([IntPtr]::Zero)
    $remaining = @([IO.File]::ReadAllLines($sourcePath) | Where-Object { $_ -and ! $_.StartsWith('#') })
    if ([UiReviewNative]::SendMessage($list,0x18B,[IntPtr]::Zero,[IntPtr]::Zero).ToInt64() -ne $count -or
        $remaining.Count -ne 2 -or $remaining[0] -ne 'https://example.test/hosts' -or $remaining[1] -ne $candidate -or
        [UiReviewNative]::IsWindowVisible($confirmRemove) -or ![UiReviewNative]::IsWindowEnabled($list) -or
        (Get-FileHash -LiteralPath $rulePath -Algorithm SHA256).Hash -ne $ruleHash) {
        throw 'Removal retry did not commit only the source configuration and restore controls'
    }
    Save-Window 'subscriptions-removed'
    Write-Output 'Removal GUI passed: cancel/navigation preserve sources; failed save retains target; retry removes only configuration and preserves imported rules.'
}

Set-Page 5
Save-Window 'network-dual-stack-entry'
$probeButton=[UiReviewNative]::GetDlgItem($window,1301)
if (!$probeButton -or ![UiReviewNative]::IsWindowVisible($probeButton)) { throw 'Network center transport entry missing' }
if ((Read-ControlText $probeButton) -ne '测试双栈转发与恢复') { throw 'Transport entry is not the actual button' }
$iniBeforeProbe=[IO.File]::ReadAllText($iniFile)
[void][UiReviewNative]::PostMessageW($probeButton,0xF5,[IntPtr]::Zero,[IntPtr]::Zero)
$transport=[IntPtr]::Zero;$probeDeadline=(Get-Date).AddSeconds(5)
do {
    Start-Sleep -Milliseconds 100
    $transport=[UiReviewNative]::GetWindow($window,6)
} until (($transport -ne [IntPtr]::Zero -and $transport -ne $window) -or (Get-Date) -gt $probeDeadline)
if ($transport -eq [IntPtr]::Zero -or $transport -eq $window) { throw 'Dual-stack diagnostic window missing' }
if ((Read-ControlText ([UiReviewNative]::GetDlgItem($transport,2103))) -notmatch '尚未运行') { throw 'Opening transport dialog started unsolicited traffic' }
for ($cycle=0;$cycle -lt 2;$cycle++) {
    [void][UiReviewNative]::PostMessageW([UiReviewNative]::GetDlgItem($transport,2101),0xF5,[IntPtr]::Zero,[IntPtr]::Zero)
    $probeDeadline=(Get-Date).AddSeconds(8)
    do {
        Start-Sleep -Milliseconds 100
        $probeText=Read-ControlText ([UiReviewNative]::GetDlgItem($transport,2103))
    } until ($probeText -match '清理：' -or (Get-Date) -gt $probeDeadline)
    foreach ($protocol in @('UDP/IPv4','UDP/IPv6','TCP/IPv4','TCP/IPv6')) {
        if ($probeText -notmatch "${protocol}：转发回执通过") { throw "Actual GUI $protocol failed: $probeText" }
    }
    if ($probeText -notmatch '本次资源均已释放' -or $probeText -notmatch '已关闭 6/6') { throw "TCP resource cleanup missing: $probeText" }
}
$dashboardWindow=$window
try { $window=$transport; Save-Window 'dual-stack-transport-dialog' }
finally { $window=$dashboardWindow }
[void][UiReviewNative]::PostMessageW($transport,0x111,[IntPtr]2,[IntPtr]::Zero)
Start-Sleep -Milliseconds 200
if (![UiReviewNative]::IsWindowEnabled($window) -or [IO.File]::ReadAllText($iniFile) -ne $iniBeforeProbe) { throw 'Transport dialog failed to restore owner or changed configuration' }
Write-Output 'Actual dual-stack GUI transport: no implicit traffic, IPv4/IPv6 replies, complete cleanup, repeated run and configuration unchanged passed'

Set-Page 2
# Switch only the disposable runner's preview appearance.
[void][UiReviewNative]::SendMessage([UiReviewNative]::GetDlgItem($window,1006),0xF1,[IntPtr]1,[IntPtr]::Zero)
[void][UiReviewNative]::SendMessage($window,0x111,[IntPtr]1006,[IntPtr]::Zero)
Start-Sleep -Milliseconds 2200 # Include a stats refresh before checking the operation-result surface.
Save-Window 'settings-dark'
# Hosted desktops can cap a top-level window at screen width. Compare a
# compact 2/3 canvas against the standard canvas rather than assuming an
# off-screen 1548 px window was accepted by the window manager.
Set-ClientSize 688 452
Save-Window 'settings-dark-compact'
Set-Page 4; Save-Window 'subscriptions-dark-compact'
Set-ClientSize 1032 678
Save-Window 'subscriptions-dark'
$records | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutputDirectory 'layout-evidence.json')
$compact=[Math]::Abs(($records | Where-Object Name -eq 'settings-dark-compact').FontHeight)
$standard=[Math]::Abs(($records | Where-Object Name -eq 'settings-dark').FontHeight)
if ($standard -le $compact) { throw 'Native control font did not scale with the window' }
Write-Output 'UI inspection passed: removal confirmation/cancel/failure/retry, input bounds/rollback, complete selected URL, horizontal scrolling, layout and fonts verified.'

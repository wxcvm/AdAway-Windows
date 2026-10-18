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
  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr w, int id);
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
    $fontHandle = [UiReviewNative]::SendMessage([UiReviewNative]::GetDlgItem($window,1140),0x31,[IntPtr]::Zero,[IntPtr]::Zero)
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
}

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
Write-Output 'UI inspection passed: input bounds/rollback, complete selected URL, horizontal scrolling, non-overlapping controls and scaled fonts verified.'

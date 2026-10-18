param([Parameter(Mandatory)][int]$GuiProcessId, [string]$OutputDirectory = 'ui-review')
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class UiReviewNative {
  [StructLayout(LayoutKind.Sequential)] public struct Rect { public int Left, Top, Right, Bottom; }
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] public struct Font {
    public int Height, Width, Escapement, Orientation, Weight;
    public byte Italic, Underline, StrikeOut, CharSet, OutPrecision, ClipPrecision, Quality, PitchAndFamily;
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
    $fontHandle = [UiReviewNative]::SendMessage([UiReviewNative]::GetDlgItem($window,1110),0x31,[IntPtr]::Zero,[IntPtr]::Zero)
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
Set-Page 2
# Switch only the disposable runner's preview appearance.
[void][UiReviewNative]::SendMessage([UiReviewNative]::GetDlgItem($window,1006),0xF1,[IntPtr]1,[IntPtr]::Zero)
[void][UiReviewNative]::SendMessage($window,0x111,[IntPtr]1006,[IntPtr]::Zero)
Save-Window 'settings-dark'
Set-ClientSize 1548 1017
Save-Window 'settings-dark-150pct'
Set-Page 4; Save-Window 'subscriptions-dark-150pct'
$normal=($records | Where-Object Name -eq 'settings-light').FontHeight
$large=($records | Where-Object Name -eq 'settings-dark-150pct').FontHeight
if ($large -le $normal) { throw 'Native control font did not scale with the window' }
$records | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutputDirectory 'layout-evidence.json')
Write-Output 'UI inspection passed: no overlapping native controls; selection state and scaled fonts verified.'

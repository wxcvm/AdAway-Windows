param([int]$ProcessId,[long]$Dialog,[long]$MainWindow,[string]$Path,[string]$EvidencePath)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class ExportDialogOwner {
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
 [DllImport("user32.dll")] public static extern IntPtr GetAncestor(IntPtr h,uint flags);
 [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
}
"@
$handle=[IntPtr]$Dialog
$main=[IntPtr]$MainWindow
[uint32]$actual=0
if(-not [ExportDialogOwner]::IsWindow($handle)){throw 'Save dialog disappeared'}
[void][ExportDialogOwner]::GetWindowThreadProcessId($handle,[ref]$actual)
if($actual -ne $ProcessId -or [ExportDialogOwner]::GetAncestor($handle,3) -ne $main){throw 'Dialog PID/root owner mismatch'}
$root=[System.Windows.Automation.AutomationElement]::FromHandle($handle)
$ids=[System.Windows.Automation.AutomationElement]::AutomationIdProperty
$types=[System.Windows.Automation.AutomationElement]::ControlTypeProperty
$pidProperty=[System.Windows.Automation.AutomationElement]::ProcessIdProperty
$fileNameHost=$root.FindFirst([System.Windows.Automation.TreeScope]::Descendants,
    [System.Windows.Automation.PropertyCondition]::new($ids,'FileNameControlHost'))
$search=if($null -ne $fileNameHost){$fileNameHost}else{$root}
$typeCondition=[System.Windows.Automation.PropertyCondition]::new($types,[System.Windows.Automation.ControlType]::Edit)
$edits=if($null -ne $fileNameHost -and $fileNameHost.Current.ControlType -eq [System.Windows.Automation.ControlType]::Edit){
 @($fileNameHost)
}else{
 $search.FindAll([System.Windows.Automation.TreeScope]::Descendants,$typeCondition)
}
$details=@()
$matches=@()
foreach($item in $edits){
 $current=$item.Current
 $details+=@{id=$current.AutomationId;name=$current.Name;pid=$current.ProcessId;enabled=$current.IsEnabled;offscreen=$current.IsOffscreen}
 if($current.ProcessId -eq $ProcessId -and $current.IsEnabled -and -not $current.IsOffscreen -and
    ($null -ne $fileNameHost -or $current.AutomationId -eq '1001')){$matches+=,$item}
}
@{fileNameHostFound=($null -ne $fileNameHost);edits=$details} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $EvidencePath -Encoding UTF8
$elements=$matches
if($elements.Count -ne 1){throw "Expected one file-name Edit; found $($elements.Count)"}
$edit=$elements[0]
if(-not $edit.Current.IsEnabled -or $edit.Current.IsOffscreen){throw 'File name Edit is unavailable'}
$pattern=$edit.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
if($pattern.Current.IsReadOnly){throw 'File name Edit is read-only'}
# Revalidate the same native owner immediately before changing only this control.
[void][ExportDialogOwner]::GetWindowThreadProcessId($handle,[ref]$actual)
if($actual -ne $ProcessId -or [ExportDialogOwner]::GetAncestor($handle,3) -ne $main){throw 'Dialog owner changed'}
$pattern.SetValue($Path)
if($pattern.Current.Value -ne $Path){throw 'UIA file name value did not match'}

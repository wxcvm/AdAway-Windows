param([int]$ProcessId,[long]$Dialog,[long]$MainWindow,[string]$Path)
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
$conditions=[System.Windows.Automation.Condition[]]@(
 [System.Windows.Automation.PropertyCondition]::new($ids,'1001'),
 [System.Windows.Automation.PropertyCondition]::new($types,[System.Windows.Automation.ControlType]::Edit),
 [System.Windows.Automation.PropertyCondition]::new($pidProperty,$ProcessId))
$elements=$search.FindAll([System.Windows.Automation.TreeScope]::Descendants,
    [System.Windows.Automation.AndCondition]::new($conditions))
if($elements.Count -ne 1){throw "Expected one file-name Edit; found $($elements.Count)"}
$edit=$elements.Item(0)
if(-not $edit.Current.IsEnabled -or $edit.Current.IsOffscreen){throw 'File name Edit is unavailable'}
$pattern=$edit.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
if($pattern.Current.IsReadOnly){throw 'File name Edit is read-only'}
# Revalidate the same native owner immediately before changing only this control.
[void][ExportDialogOwner]::GetWindowThreadProcessId($handle,[ref]$actual)
if($actual -ne $ProcessId -or [ExportDialogOwner]::GetAncestor($handle,3) -ne $main){throw 'Dialog owner changed'}
$pattern.SetValue($Path)
if($pattern.Current.Value -ne $Path){throw 'UIA file name value did not match'}

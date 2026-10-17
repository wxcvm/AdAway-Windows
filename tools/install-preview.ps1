param(
    [ValidateSet('User', 'Machine', 'Portable')][string]$Method = 'User',
    [string]$InstallDirectory = (Join-Path $env:LOCALAPPDATA 'Programs\ADBlockPreviewPortable')
)
$ErrorActionPreference = 'Stop'
$releaseBase = 'https://github.com/wxcvm/AdAway-Windows/releases/download/@@TAG@@'
$files = @{
    User = @('adblock-preview-user-x64.exe', '@@USER_SHA@@')
    Machine = @('adblock-preview-machine-x64.exe', '@@MACHINE_SHA@@')
    Portable = @('adblock-webserver-win64.zip', '@@PORTABLE_SHA@@')
}
$choice = $files[$Method]
$taskDirectory = Join-Path ([IO.Path]::GetTempPath()) ('adblock-preview-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $taskDirectory | Out-Null
$package = Join-Path $taskDirectory $choice[0]
Invoke-WebRequest -UseBasicParsing -Uri ($releaseBase + '/' + $choice[0]) -OutFile $package
if ((Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash.ToLowerInvariant() -ne $choice[1]) {
    throw '下载文件 SHA-256 与该预览版本不一致，未执行安装。'
}
if ($Method -eq 'Portable') {
    if (Test-Path -LiteralPath $InstallDirectory) { throw '免安装目录已存在，请选择一个新的空目录以保留已有数据。' }
    New-Item -ItemType Directory -Path $InstallDirectory | Out-Null
    Expand-Archive -LiteralPath $package -DestinationPath $InstallDirectory
    Write-Output "已解压到 $InstallDirectory；运行 start-preview.bat 打开预览。"
} else {
    $options = @{ FilePath = $package; ArgumentList = '/SP-'; Wait = $true; PassThru = $true }
    if ($Method -eq 'Machine') { $options.Verb = 'RunAs' }
    $process = Start-Process @options
    if ($process.ExitCode -ne 0) { throw "安装器返回 $($process.ExitCode)，请查看安装界面。" }
}
Write-Output "下载的已校验文件保留在 $taskDirectory。此脚本不自动启动程序或修改网络设置。"

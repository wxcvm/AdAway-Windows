param([switch]$AllUsers)
$ErrorActionPreference = 'Stop'
$taskDirectory = Join-Path ([IO.Path]::GetTempPath()) ('adblock-preview-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $taskDirectory | Out-Null
$package = Join-Path $taskDirectory 'adblock-webserver-setup.exe'
Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/wxcvm/AdAway-Windows/releases/download/@@TAG@@/adblock-webserver-setup.exe' -OutFile $package
if ((Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash.ToLowerInvariant() -ne '@@INSTALLER_SHA@@') {
    throw '下载文件 SHA-256 与该预览版本不一致，未执行安装。'
}
$options = @{ FilePath=$package; ArgumentList='/SP- /CURRENTUSER'; PassThru=$true }
if ($AllUsers) { $options.ArgumentList='/SP- /ALLUSERS'; $options.Verb='RunAs' }
# Interactive installer: review the existing installation destination.
$process=Start-Process @options
$process.WaitForExit()
if ($process.ExitCode -ne 0) { throw "安装器返回 $($process.ExitCode)。下载文件保留在 $taskDirectory。" }
Write-Output "已使用现有 ADBlock 安装标识执行升级；下载文件保留在 $taskDirectory。"

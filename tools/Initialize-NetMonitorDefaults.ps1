# Run only after the release has been verified and the app is fully stopped.
# This helper does not install software, change execution policy, or edit proxies.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$InstallDir,
    [switch]$PreserveExistingHistory,
    [string]$BackupDir
)
$ErrorActionPreference = 'Stop'
$installPath = [IO.Path]::GetFullPath($InstallDir)
$installItem = Get-Item -LiteralPath $installPath
if (-not $installItem.PSIsContainer) { throw 'InstallDir is not a directory' }
$cursor = $installItem
while ($null -ne $cursor) {
    if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse installation paths are not supported' }
    $cursor = $cursor.Parent
}
$installRoot = [IO.Path]::GetPathRoot($installPath)
$windowsRoot = [IO.Path]::GetPathRoot([Environment]::GetFolderPath('Windows'))
if ($installRoot.TrimEnd('\') -ieq $env:SystemDrive.TrimEnd('\') -or $installRoot -ieq $windowsRoot) {
    throw 'The installation policy requires a non-system drive'
}
$drive = [IO.DriveInfo]::new($installRoot)
if (-not $drive.IsReady -or $drive.DriveType -ne [IO.DriveType]::Fixed) { throw 'A ready local fixed drive is required' }
$exe = Join-Path $installPath 'NetMonitor.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Verified NetMonitor.exe must already be installed' }
if (Get-Process -Name NetMonitor -ErrorAction SilentlyContinue) { throw 'Exit NetMonitor from its tray menu first' }
$sourceInstances = @(Get-CimInstance Win32_Process | Where-Object {
    $_.Name -in @('python.exe','pythonw.exe') -and $_.CommandLine -match '(?i)NetMonitor.*(launch\.py|app\.py)'
})
if ($sourceInstances.Count) { throw 'Exit the NetMonitor source instance first' }

$settingsPath = 'HKCU:\Software\NetMonitorPro\NetMonitorPro'
$runPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$runBefore = if (Test-Path -LiteralPath $runPath) { Get-ItemProperty -LiteralPath $runPath } else { $null }
$oldAuto = if ($null -ne $runBefore) { $runBefore.PSObject.Properties['NetMonitorPro'] } else { $null }
if ($null -ne $oldAuto) {
    $command = [string]$oldAuto.Value
    $match = [regex]::Match($command, '^\s*(?:"(?<exe>[^"]+\.exe)"|(?<exe>\S+\.exe))(?:\s|$)', 'IgnoreCase')
    if (-not $match.Success -or [IO.Path]::GetFileName($match.Groups['exe'].Value) -ine 'NetMonitor.exe') {
        throw 'The named startup value has an unexpected target; inspect ownership before changing it'
    }
}
$oldSettings = if (Test-Path -LiteralPath $settingsPath) { Get-ItemProperty -LiteralPath $settingsPath } else { $null }
$oldHistory = if ($null -ne $oldSettings) { $oldSettings.PSObject.Properties['history_paused'] } else { $null }
if (-not $BackupDir) {
    $BackupDir = Join-Path $env:LOCALAPPDATA ('NetMonitorInstallBackups\defaults-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8))
}
if (Test-Path -LiteralPath $BackupDir) { throw 'Choose a new backup directory; do not overwrite an older backup' }
New-Item -ItemType Directory -Path $BackupDir | Out-Null
if (Test-Path -LiteralPath 'HKCU:\Software\NetMonitorPro') {
    & reg.exe export 'HKCU\Software\NetMonitorPro' (Join-Path $BackupDir 'settings-before.reg') /y | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Settings backup failed; no defaults changed' }
}
@{
    account = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    install_dir = $installPath
    startup_value = if ($null -ne $oldAuto) { $oldAuto.Value } else { $null }
    history_paused = if ($null -ne $oldHistory) { $oldHistory.Value } else { $null }
    history_value_existed = ($null -ne $oldHistory)
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $BackupDir 'defaults-before.json') -Encoding UTF8

if (-not ($PreserveExistingHistory -and $null -ne $oldHistory)) {
    New-Item -Path $settingsPath -Force | Out-Null
    New-ItemProperty -LiteralPath $settingsPath -Name history_paused -PropertyType DWord -Value 1 -Force | Out-Null
}
if ($null -ne $oldAuto) { Remove-ItemProperty -LiteralPath $runPath -Name NetMonitorPro }
$current = (Get-ItemProperty -LiteralPath $settingsPath).history_paused
if (-not ($PreserveExistingHistory -and $null -ne $oldHistory) -and $current -ne 1) { throw 'Paused default did not persist' }
$remainingAuto = if (Test-Path -LiteralPath $runPath) { (Get-ItemProperty -LiteralPath $runPath).PSObject.Properties['NetMonitorPro'] } else { $null }
if ($null -ne $remainingAuto) { throw 'The standard NetMonitor startup value remains' }
[pscustomobject]@{
    InstallDir = $installPath
    HistoryPausedSetting = $current
    PreservedUserHistoryChoice = [bool]($PreserveExistingHistory -and $null -ne $oldHistory)
    StandardStartupDisabled = $true
    BackupDir = [IO.Path]::GetFullPath($BackupDir)
    RemainingChecks = 'Installer must separately inspect other positively identified startup folders/tasks/HKLM entries and verify GUI state.'
} | ConvertTo-Json

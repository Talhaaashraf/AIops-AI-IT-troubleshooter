# AIops agent uninstaller for Windows (run as Administrator):
#   irm "__SERVER_URL__/install/uninstall-windows.ps1" | iex
$ErrorActionPreference = 'Continue'
$TaskName = 'Sentinel Agent'
$InstallDir = Join-Path $env:ProgramData 'SentinelAgent'
Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*SentinelAgent*" -and $_.ProcessId -ne $PID } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2
# Leftovers moved aside by "Remove completely" may be someone's files: keep them, delete the rest.
$Quarantine = Join-Path $InstallDir 'quarantine'
# Folders are deleted with rmdir, which removes a junction without following it into its target.
if ((Test-Path $Quarantine) -and (Get-ChildItem -Force $Quarantine)) {
  Get-ChildItem -Force $InstallDir | Where-Object { $_.Name -ne 'quarantine' } | ForEach-Object {
    if ($_.PSIsContainer) { & cmd.exe /c rmdir /s /q "$($_.FullName)" } else { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }
  }
  Write-Host "[AIops] Kept the quarantined leftovers in $Quarantine. Copy back what you need, then delete that folder."
} elseif (Test-Path $InstallDir) {
  & cmd.exe /c rmdir /s /q "$InstallDir"
}
# Folders an interrupted install left behind (SentinelAgent.old-<id>, SentinelAgent.new-<id>): delete the
# administrators' own ones, unless they still hold quarantined leftovers; report anything else.
foreach ($left in Get-ChildItem -LiteralPath $env:ProgramData -Directory -Force -Filter 'SentinelAgent.*' -ErrorAction SilentlyContinue) {
  if ($left.Name -notmatch '^SentinelAgent\.(old|new)-[0-9a-f]{32}$') { continue }
  $owner = try { (Get-Acl -LiteralPath $left.FullName).GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { $null }
  $trusted = -not ($left.Attributes -band [IO.FileAttributes]::ReparsePoint) -and (@('S-1-5-18', 'S-1-5-32-544') -contains $owner)
  $holdsQuarantine = Test-Path -LiteralPath (Join-Path $left.FullName 'quarantine\*')
  if ($trusted -and -not $holdsQuarantine) { & cmd.exe /c rmdir /s /q "$($left.FullName)" }
  else { Write-Host "[AIops] Left $($left.FullName) in place ($(if ($trusted) { 'it holds quarantined leftovers' } else { 'not created by an administrator' })): check it, then delete it." }
}
Write-Host '[AIops] Agent removed. Revoke the device in the dashboard Agents tab to invalidate its token.'

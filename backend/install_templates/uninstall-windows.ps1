# AIops agent uninstaller for Windows (run as Administrator):
#   irm "__SERVER_URL__/install/uninstall-windows.ps1" | iex
$ErrorActionPreference = 'Continue'
$TaskName = 'Sentinel Agent'
$InstallDir = Join-Path $env:ProgramData 'SentinelAgent'
Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*SentinelAgent*" -and $_.ProcessId -ne $PID } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2
Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host '[AIops] Agent removed. Revoke the device in the dashboard Agents tab to invalidate its token.'

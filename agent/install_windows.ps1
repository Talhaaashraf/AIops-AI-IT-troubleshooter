param([string]$ServerUrl, [string]$Token, [string]$Nickname = $env:COMPUTERNAME)
$ErrorActionPreference = 'Stop'
$installDir = Join-Path $env:ProgramData 'SentinelMonitorAgent'
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
$source = Join-Path $PSScriptRoot 'monitor_agent.exe'
if (-not (Test-Path $source)) { throw 'monitor_agent.exe not found beside this installer.' }
Copy-Item $source (Join-Path $installDir 'monitor_agent.exe') -Force
$configPath = Join-Path $installDir 'agent_config.json'
if (-not (Test-Path $configPath)) {
  if (-not $ServerUrl) { $ServerUrl = Read-Host 'Central server URL' }
  if (-not $Token) { $Token = Read-Host 'Agent token' }
  @{ server_url = $ServerUrl; AGENT_TOKEN = $Token; nickname = $Nickname; interval_seconds = 10 } | ConvertTo-Json | Set-Content $configPath
}
$action = New-ScheduledTaskAction -Execute (Join-Path $installDir 'monitor_agent.exe') -WorkingDirectory $installDir
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName 'Sentinel Monitor Agent' -Action $action -Trigger $trigger -Description 'Read-only AIops health reporter' -Force | Out-Null
Write-Host "AIops agent installed and scheduled at $installDir"

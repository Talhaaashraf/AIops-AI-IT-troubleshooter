# AIops agent installer for Windows.
# Run in an elevated (Administrator) PowerShell:
#   irm "__SERVER_URL__/install/windows.ps1" | iex
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$Server = '__SERVER_URL__'
$Token = '__TOKEN__'
$InstallDir = Join-Path $env:ProgramData 'SentinelAgent'
$TaskName = 'Sentinel Agent'
# ngrok's free plan shows a browser warning page unless this header is sent.
$Headers = @{ 'ngrok-skip-browser-warning' = '1' }

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Please run this command from an elevated PowerShell window (Run as Administrator).'
}

Write-Host "[AIops] Installing agent to $InstallDir (server: $Server)"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
  Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*SentinelAgent*" -and $_.ProcessId -ne $PID } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

# 1. Prefer a prebuilt binary if the server has one; otherwise run from Python source.
$exe = Join-Path $InstallDir 'SentinelAgent.exe'
$mode = 'python'
try {
  Invoke-WebRequest -UseBasicParsing -Headers $Headers -Uri "$Server/api/agents/binary/windows?token=$Token" -OutFile $exe
  if (-not (Test-Path $exe)) { throw 'The agent binary was removed right after download (antivirus?).' }
  $mode = 'binary'
  $AgentDir = $InstallDir
  $Execute = $exe
  $Arguments = ''
} catch {
  Remove-Item $exe -Force -ErrorAction SilentlyContinue
}

if ($mode -eq 'binary') {
  # Switching from an earlier Python-mode install: keep its identity, drop the old runtime.
  $oldConfig = Join-Path $InstallDir 'app\agent_config.json'
  $newConfig = Join-Path $InstallDir 'agent_config.json'
  if ((Test-Path $oldConfig) -and -not (Test-Path $newConfig)) { Move-Item $oldConfig $newConfig -Force }
  foreach ($stale in @('app', 'venv')) {
    Remove-Item (Join-Path $InstallDir $stale) -Recurse -Force -ErrorAction SilentlyContinue
  }
}

if ($mode -eq 'python') {
  function Find-Python {
    foreach ($candidate in @('py', 'python', 'python3')) {
      $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
      if (-not $cmd -or $cmd.Source -like '*WindowsApps*') { continue }
      $args3 = if ($candidate -eq 'py') { @('-3', '-c', 'import sys; print(sys.executable)') } else { @('-c', 'import sys; print(sys.executable)') }
      try { $path = (& $cmd.Source @args3 2>$null | Select-Object -First 1) } catch { $path = $null }
      # The launcher (py.exe) can resolve to a Microsoft Store Python. That one only runs for the
      # user who installed it, so the agent's SYSTEM task would exit at once (code 101).
      if ($path -and $path -notlike '*WindowsApps*' -and (Test-Path $path)) { return $path.Trim() }
    }
    foreach ($path in @("$env:ProgramFiles\Python313\python.exe", "$env:ProgramFiles\Python312\python.exe", "$env:ProgramFiles\Python311\python.exe")) {
      if (Test-Path $path) { return $path }
    }
    return $null
  }
  $python = Find-Python
  if (-not $python) {
    Write-Host '[AIops] Python 3 not found; installing it with winget...'
    winget install -e --id Python.Python.3.12 --scope machine --silent --accept-package-agreements --accept-source-agreements | Out-Null
    $python = Find-Python
    if (-not $python) { throw 'Python 3 is required. Install it from https://www.python.org/downloads/ and re-run this command.' }
  }
  Write-Host "[AIops] Using Python at $python"

  $AgentDir = Join-Path $InstallDir 'app'
  $zip = Join-Path $env:TEMP 'sentinel-agent.zip'
  Invoke-WebRequest -UseBasicParsing -Headers $Headers -Uri "$Server/api/agents/bundle?token=$Token" -OutFile $zip
  New-Item -ItemType Directory -Force -Path $AgentDir | Out-Null
  Expand-Archive -Path $zip -DestinationPath $AgentDir -Force
  Remove-Item $zip -Force

  $venv = Join-Path $InstallDir 'venv'
  if (-not (Test-Path (Join-Path $venv 'Scripts\python.exe'))) { & $python -m venv $venv }
  $venvPython = Join-Path $venv 'Scripts\python.exe'
  & $venvPython -m pip install --quiet --disable-pip-version-check --upgrade psutil requests
  if ($LASTEXITCODE -ne 0) { throw 'pip install failed (check internet access on this device).' }
  $Execute = $venvPython
  $Arguments = '"' + (Join-Path $AgentDir 'monitor_agent.py') + '"'
}

# 2. Configuration. Re-installs keep the existing device identity; with open enrollment
#    (no token in the URL) a new device generates its own secret.
$configPath = Join-Path $AgentDir 'agent_config.json'
$existing = $null
if (Test-Path $configPath) {
  try { $existing = Get-Content $configPath -Raw | ConvertFrom-Json } catch { $existing = $null }
}
if ($existing -and $existing.AGENT_TOKEN -and (-not $Token -or $existing.AGENT_TOKEN -eq $Token)) {
  $existing.server_url = $Server
  [IO.File]::WriteAllText($configPath, ($existing | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
} else {
  if (-not $Token) {
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $Token = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
  }
  $config = [ordered]@{ server_url = $Server; AGENT_TOKEN = $Token; nickname = $env:COMPUTERNAME; interval_seconds = 10; allow_remediation = $true; max_risk = 'high' }
  [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
}

# 3. Run at startup as SYSTEM so diagnostics and fixes have the rights they need.
$action = if ($Arguments) { New-ScheduledTaskAction -Execute $Execute -Argument $Arguments -WorkingDirectory $AgentDir } else { New-ScheduledTaskAction -Execute $Execute -WorkingDirectory $AgentDir }
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'AIops AI troubleshooting agent' -Force | Out-Null

$logPath = Join-Path $AgentDir 'agent_log.txt'
if (Test-Path $logPath) { Move-Item $logPath (Join-Path $AgentDir 'agent_log.previous.txt') -Force -ErrorAction SilentlyContinue }
Start-ScheduledTask -TaskName $TaskName

# 4. Confirm the agent really started and reached the server instead of assuming it did.
#    The first report collects security, event-log and performance data and can take 20+ s,
#    so a successful registration also counts; it proves the server accepted this device.
Write-Host '[AIops] Waiting for the agent to connect (up to 90 s)...'
$connected = $false
$registered = $false
for ($i = 0; $i -lt 90 -and -not $connected; $i++) {
  Start-Sleep -Seconds 1
  if (Test-Path $logPath) {
    $connected = [bool](Select-String -Path $logPath -Pattern 'Report sent' -Quiet)
    $registered = [bool](Select-String -Path $logPath -Pattern 'started for device' -Quiet)
  }
  # Once registered, give the first report a little longer, then stop waiting.
  if ($registered -and $i -ge 45) { break }
}
if ($connected -or $registered) {
  $deviceId = (Get-Content $configPath -Raw | ConvertFrom-Json).device_id
  Write-Host "[AIops] Connected as $deviceId ($mode mode). Open the dashboard: $Server" -ForegroundColor Green
  if (-not $connected) { Write-Host '    Registered with the server; the first health report is still being collected.' -ForegroundColor Yellow }
} else {
  $info = Get-ScheduledTaskInfo -TaskName $TaskName
  Write-Host "[AIops] The agent did not connect. Task state: $((Get-ScheduledTask -TaskName $TaskName).State), last result: $($info.LastTaskResult)" -ForegroundColor Red
  if (Test-Path $logPath) { Get-Content $logPath -Tail 8 | ForEach-Object { Write-Host "    $_" } }
  else { Write-Host '    No agent_log.txt was written: the agent process could not start.' }
  Write-Host "    Check that $Server opens in a browser on this machine (the server's port must be reachable)."
}
Write-Host "[AIops] Log file: $logPath"
Write-Host "[AIops] Uninstall: irm -Headers @{'ngrok-skip-browser-warning'='1'} '$Server/install/uninstall-windows.ps1' | iex"

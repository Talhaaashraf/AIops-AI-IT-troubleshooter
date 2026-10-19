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
# Stop the running agent first: its folder is about to be replaced.
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
  Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*SentinelAgent*" -and $_.ProcessId -ne $PID } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

# --- agent folder (begin) ---
# Only SYSTEM and Administrators may use the agent folder. ProgramData lets every user create files, so a
# standard user could otherwise plant code that the SYSTEM task runs, or read the agent's token.
# - The folder is created under an unpredictable name with its permissions set at creation, checked, then renamed
#   into place. A rename fails if anything appeared at $InstallDir meanwhile, so the folder in use is always ours.
# - An existing folder is renamed aside and never walked (it may hold junctions planted to redirect a walk).
# - From a previous install owned by SYSTEM/Administrators only the identity, the remembered uninstalls and the
#   quarantine batches the agent wrote are carried over, each into fresh, locked files and folders.
$TrustedOwners = @('S-1-5-18', 'S-1-5-32-544')
$LockSddl = 'O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
function Get-OwnerSid([string]$Path) {
  try { return (Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { return $null }
}
function Test-TrustedItem([string]$Path) {
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
  if (-not $item -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $false }
  return ($TrustedOwners -contains (Get-OwnerSid $Path))
}
function Assert-LockedFolder([string]$Path) {
  # Not a link, owned by SYSTEM/Administrators, inheritance blocked, only SYSTEM and Administrators allowed.
  # A standard user can neither rename nor delete such a folder.
  $acl = Get-Acl -LiteralPath $Path
  $others = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Where-Object { $TrustedOwners -notcontains $_ })
  if (-not (Test-TrustedItem $Path) -or -not $acl.AreAccessRulesProtected -or $others.Count) {
    throw "$Path is not the locked folder this installer created (another process interfered). Run the install again."
  }
}
function Write-Fresh([string]$Path, [string]$Text) {
  [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($false)))
}
$ImportedConfig = $null
$OldDir = $null
$OldTrusted = $false
$KeepOldDir = $false
function Resume-OldAgent([bool]$OldFolderInPlace) {
  # After a failed install: start the previous agent again only when this installer knows the previous folder is
  # back in place (never moved, or put back by this installer) and it is the administrators' folder. Anything
  # else at $InstallDir was created by another account, and the task must never run from it.
  if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) { return }
  if ($OldFolderInPlace -and (Test-TrustedItem $InstallDir)) {
    Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  } else {
    Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null
    Write-Host "[AIops] $InstallDir was recreated by another account: the agent's task was disabled. Delete that folder, then run the install again." -ForegroundColor Red
  }
}
# The previous install's app\ folder, only if it is the administrators' real folder (a junction named app could
# otherwise lead the reads and deletes below somewhere else).
function Get-OldConfigPaths {
  $paths = @(Join-Path $OldDir 'agent_config.json')
  if (Test-TrustedItem (Join-Path $OldDir 'app')) { $paths += Join-Path $OldDir 'app\agent_config.json' }
  return $paths | Where-Object { (Test-TrustedItem $_) -and -not (Get-Item -LiteralPath $_ -Force).PSIsContainer }
}
if (Test-Path -LiteralPath $InstallDir) {
  $OldTrusted = Test-TrustedItem $InstallDir
  $OldDir = "$InstallDir.old-$([guid]::NewGuid().ToString('N'))"
  $movedAside = $false
  for ($try = 0; $try -lt 15 -and -not $movedAside; $try++) {
    # Success is the rename's own result: the path existing again may be another account's new folder.
    try { Rename-Item -LiteralPath $InstallDir -NewName (Split-Path $OldDir -Leaf) -ErrorAction Stop; $movedAside = $true } catch { Start-Sleep -Seconds 1 }
  }
  if (-not $movedAside) {
    $OldDir = $null
    Resume-OldAgent $true
    throw "Could not move the old $InstallDir aside (is a file in it open?). Close it and run the install again."
  }
  if ($OldTrusted) {
    # The newest identity the old install used: the root for the exe, app\ for the Python mode.
    $newest = Get-OldConfigPaths | Sort-Object { (Get-Item -LiteralPath $_ -Force).LastWriteTimeUtc } -Descending | Select-Object -First 1
    if ($newest) { $ImportedConfig = Get-Content -LiteralPath $newest -Raw }
  } else {
    $KeepOldDir = $true
    Write-Host "[AIops] $InstallDir was not created by an administrator: moved it to $OldDir without using anything in it. Inspect it, then delete it." -ForegroundColor Yellow
  }
}
$security = New-Object Security.AccessControl.DirectorySecurity
$security.SetSecurityDescriptorSddlForm($LockSddl)
$staging = "$InstallDir.new-$([guid]::NewGuid().ToString('N'))"
try {
  [void][IO.Directory]::CreateDirectory($staging, $security)
  Assert-LockedFolder $staging
  Rename-Item -LiteralPath $staging -NewName (Split-Path $InstallDir -Leaf) -ErrorAction Stop
} catch {
  $reason = $_.Exception.Message
  if (Test-Path -LiteralPath $staging) { & cmd.exe /c rmdir /s /q "$staging" }  # our own, empty staging folder
  $putBack = $false
  if ($OldDir -and -not (Test-Path -LiteralPath $InstallDir)) {
    try { Rename-Item -LiteralPath $OldDir -NewName (Split-Path $InstallDir -Leaf) -ErrorAction Stop; $putBack = $true } catch { }
  }
  Resume-OldAgent $putBack
  $where = if ($OldDir -and -not $putBack) { " The previous agent folder is kept at $OldDir." } else { '' }
  throw "Could not create the locked agent folder $InstallDir ($reason).$where Run the install again."
}
Assert-LockedFolder $InstallDir
# The identity is saved straight away, so a failure later in the install cannot lose it.
if ($ImportedConfig) { Write-Fresh (Join-Path $InstallDir 'agent_config.json') $ImportedConfig }
if ($OldDir -and $OldTrusted) {
  $remembered = Join-Path $OldDir 'uninstalled.json'
  if (Test-TrustedItem $remembered) {
    try { Write-Fresh (Join-Path $InstallDir 'uninstalled.json') (Get-Content -LiteralPath $remembered -Raw) } catch { $KeepOldDir = $true }
  }
  $oldQuarantine = Join-Path $OldDir 'quarantine'
  if (Test-TrustedItem $oldQuarantine) {
    $quarantine = Join-Path $InstallDir 'quarantine'
    New-Item -ItemType Directory -Force -Path $quarantine | Out-Null
    foreach ($batch in Get-ChildItem -LiteralPath $oldQuarantine -Directory -Force) {
      # Each batch on its own: one bad batch must not stop the others from being carried over.
      try {
        $manifestPath = Join-Path $batch.FullName 'manifest.json'
        # Only batches the agent wrote: a standard user could add folders to the old quarantine.
        if (($batch.Attributes -band [IO.FileAttributes]::ReparsePoint) -or -not (Test-TrustedItem $manifestPath)) { continue }
        $manifest = Get-Content -LiteralPath $manifestPath -Raw
        $storedNames = @(($manifest | ConvertFrom-Json).items | ForEach-Object { $_.stored } | Where-Object { $_ } | ForEach-Object { Split-Path $_ -Leaf })
        $newBatch = Join-Path $quarantine $batch.Name
        New-Item -ItemType Directory -Force -Path $newBatch | Out-Null
        Write-Fresh (Join-Path $newBatch 'manifest.json') $manifest
        # Only the stored items the manifest lists; anything else in the old batch folder stays behind.
        foreach ($name in $storedNames) {
          $source = Join-Path $batch.FullName $name
          $sourceItem = Get-Item -LiteralPath $source -Force -ErrorAction SilentlyContinue
          if ($sourceItem -and -not ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { Move-Item -LiteralPath $source -Destination (Join-Path $newBatch $sourceItem.Name) }
        }
      } catch {
        $KeepOldDir = $true
        Write-Host "[AIops] Could not carry over quarantine batch $($batch.Name) ($($_.Exception.Message)); it stays in $OldDir." -ForegroundColor Yellow
      }
    }
  }
}
# A failure later in the install names the previous folder, which may still hold its identity.
trap {
  if ($OldDir -and (Test-Path -LiteralPath $OldDir)) { Write-Host "[AIops] The install stopped. The previous agent folder is kept at $OldDir." -ForegroundColor Yellow }
  break
}
# --- agent folder (end) ---

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
if ($ImportedConfig -and -not (Test-Path $configPath)) { Write-Fresh $configPath $ImportedConfig }  # Python mode: app\
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

# 5. The previous folder is removed last, once its identity and quarantine are safe in the new one.
if ($OldDir) {
  if ($KeepOldDir) {
    Write-Host "[AIops] The previous agent folder was kept at $OldDir. Delete it once you have checked it."
  } else {
    # Its token was readable by every user before 1.4.0: delete it first (only real files in the administrators'
    # folders, never through a junction), then the rest (rmdir does not follow junctions).
    foreach ($secret in Get-OldConfigPaths) { try { [IO.File]::Delete($secret) } catch { } }
    & cmd.exe /c rmdir /s /q "$OldDir"
    if (Test-Path -LiteralPath $OldDir) { Write-Host "[AIops] Could not delete $OldDir completely (a file in it is open): delete it later." -ForegroundColor Yellow }
  }
}
Write-Host "[AIops] Uninstall: irm -Headers @{'ngrok-skip-browser-warning'='1'} '$Server/install/uninstall-windows.ps1' | iex"

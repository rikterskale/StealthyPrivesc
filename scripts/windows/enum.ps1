# StealthyPrivesc - PowerShell fallback (authorized assessments only)
# Prefer cmdlets/APIs over spawning cmd.exe. Enumeration only.
param(
  [switch]$Json,
  [switch]$Authorized
)

$authorized = $Authorized -or ($env:STEALTHY_AUTHORIZED -eq '1')
if (-not $authorized) {
  [Console]::Error.WriteLine('Authorization required: pass -Authorized or set STEALTHY_AUTHORIZED=1')
  exit 2
}

if ($Json) {
  $report = [ordered]@{
    schema_version = "2"
    run_id = [guid]::NewGuid().ToString("N").Substring(0, 24)
    started_at_unix = [int][double]::Parse((Get-Date -UFormat %s))
    tool = "stealthy-script"
    version = "0.1.0"
    authorized_use_ack = $true
    mode = "enumerate-only"
    execution_path = if ($env:STEALTHY_EXECUTION_PATH) { $env:STEALTHY_EXECUTION_PATH } else { "script" }
    primary_launch = if ($env:STEALTHY_PRIMARY_LAUNCH) { $env:STEALTHY_PRIMARY_LAUNCH } else { "not_applicable" }
    roe_ref = if ($env:STEALTHY_MANIFEST_ROE_REF) { $env:STEALTHY_MANIFEST_ROE_REF } else { "" }
    profile = "script"
    coverage_mode = "script"
    capability_delta = @(
      "windows.services", "windows.scheduled_tasks", "windows.always_install_elevated",
      "windows.uac", "windows.dll_hijack", "windows.credentials", "windows.admin_sessions",
      "windows.env_path", "windows.autoruns", "windows.endpoint_controls", "windows.app_control"
    )
    os = @{
      family = "windows"
      os = "windows"
      arch = $env:PROCESSOR_ARCHITECTURE
      version_hint = [Environment]::OSVersion.Version.ToString()
    }
    identity = @{
      username = $env:USERNAME
      uid = $null
      gid = $null
      groups = @()
      is_elevated = $false
      elevation_source = "powershell"
      token_context = ""
      hostname = $env:COMPUTERNAME
    }
    findings = @()
    assessments = @()
    attack_paths = @()
    triage_decisions = @()
    plugins_run = @("windows.privileges")
    coverage = @(@{ id = "windows.privileges"; status = "ok"; findings = 0; error = $null; duration_ms = 0 })
    notes = @("PowerShell --Json emits a schema v2 shell; enrich with stealthy ingest.")
  }
  $report | ConvertTo-Json -Depth 6
  exit 0
}

Write-Host "=== StealthyPrivesc Windows PowerShell enum ==="
Write-Host "LEGAL: Authorized use only."
Write-Host ""

Write-Host "[*] identity"
whoami /all 2>$null
Write-Host ""

Write-Host "[*] privileges of interest"
$interesting = @(
  'SeImpersonatePrivilege',
  'SeAssignPrimaryTokenPrivilege',
  'SeDebugPrivilege',
  'SeBackupPrivilege',
  'SeRestorePrivilege',
  'SeTakeOwnershipPrivilege',
  'SeLoadDriverPrivilege'
)
try {
  $privs = whoami /priv | Select-String -Pattern 'Privilege Name|Se'
  foreach ($i in $interesting) {
    if ($privs -match $i) { Write-Host "FINDING: privilege mentioned: $i" }
  }
} catch {
  Write-Host "whoami /priv failed: $_"
}
Write-Host ""

Write-Host "[*] AlwaysInstallElevated"
$hklm = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
$hkcu = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
Write-Host ("HKLM={0} HKCU={1}" -f $hklm.AlwaysInstallElevated, $hkcu.AlwaysInstallElevated)
if ($hklm.AlwaysInstallElevated -eq 1 -and $hkcu.AlwaysInstallElevated -eq 1) {
  Write-Host "FINDING: AlwaysInstallElevated fully enabled"
}
Write-Host ""

Write-Host "[*] UAC EnableLUA"
try {
  $lua = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA
  Write-Host "EnableLUA=$lua"
} catch {
  Write-Host "UAC read failed: $_"
}
Write-Host ""

Write-Host "[*] unquoted service paths (sample)"
Get-CimInstance Win32_Service | ForEach-Object {
  $p = $_.PathName
  if ($null -ne $p -and $p -notmatch '^"' -and ($p.Split(' ')[0] -match ' ')) {
    Write-Host ("FINDING: unquoted service {0} => {1}" -f $_.Name, $p)
  }
} | Out-Null
Write-Host ""

Write-Host "[*] credential file presence"
$paths = @(
  'C:\Windows\Panther\Unattend.xml',
  'C:\Windows\Panther\unattend.xml',
  'C:\Windows\System32\sysprep\unattend.xml',
  'C:\Windows\System32\config\RegBack\SAM'
)
foreach ($p in $paths) {
  if (Test-Path -LiteralPath $p) {
    Write-Host "FINDING: present $p"
  }
}
Write-Host ""

Write-Host "[*] local administrators"
try {
  Get-LocalGroupMember -Group 'Administrators' | ForEach-Object { Write-Host ("admin: " + $_.Name) }
} catch {
  Write-Host "Get-LocalGroupMember failed (try net localgroup if permitted): $_"
}
Write-Host ""

Write-Host "[*] PATH entries (process)"
$env:PATH -split ';' | Where-Object { $_ } | Select-Object -First 20 | ForEach-Object {
  if (-not (Test-Path -LiteralPath $_)) {
    Write-Host "FINDING: missing PATH entry $_"
  } else {
    Write-Host "PATH dir: $_"
  }
}
Write-Host ""

Write-Host "[*] HKCU/HKLM Run keys"
foreach ($p in @(
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
)) {
  try {
    Get-ItemProperty -Path $p -ErrorAction Stop | Out-String | Write-Host
  } catch {
    Write-Host "Run key read failed for $p"
  }
}
Write-Host ""

Write-Host "[*] Startup folders"
foreach ($d in @(
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)) {
  if (Test-Path -LiteralPath $d) {
    Write-Host "Startup: $d"
    Get-ChildItem -LiteralPath $d -ErrorAction SilentlyContinue | ForEach-Object {
      Write-Host ("  " + $_.FullName)
    }
  }
}
Write-Host ""

Write-Host "[*] SeImpersonate highlight"
if ((whoami /priv) -match 'SeImpersonatePrivilege') {
  Write-Host "FINDING: SeImpersonatePrivilege present - Potato-family may apply (manual only)"
}
Write-Host ""

Write-Host "[*] endpoint controls (AppLocker / WDAC / SmartScreen / AMSI / Defender)"
function Test-RegKey([string]$Path) {
  try { return (Test-Path -LiteralPath $Path) } catch { return $false }
}
$srp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2'
$collections = @('Exe','Script','Msi','Dll','Appx') | Where-Object { Test-RegKey (Join-Path $srp $_) }
if ($collections.Count -gt 0) {
  Write-Host ("FINDING: AppLocker SrpV2 collections present: " + ($collections -join ','))
} else {
  Write-Host 'AppLocker SrpV2 collections not found'
}
$ciPolicy = Test-RegKey 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
$vbs = $null
try {
  $vbs = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -ErrorAction Stop).EnableVirtualizationBasedSecurity
} catch {}
Write-Host ("WDAC/CI PolicyKey={0} VBS={1}" -f $ciPolicy, $vbs)
if ($ciPolicy -or $vbs -eq 1) {
  Write-Host 'FINDING: WDAC / Code Integrity signals present'
}
try {
  $ss = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -ErrorAction Stop).SmartScreenEnabled
  Write-Host "SmartScreenEnabled=$ss"
} catch {
  Write-Host 'SmartScreenEnabled unreadable'
}
$amsi = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
if (Test-RegKey $amsi) {
  $providers = @(Get-ChildItem -LiteralPath $amsi -ErrorAction SilentlyContinue)
  Write-Host ("AMSI providers={0}" -f $providers.Count)
  if ($providers.Count -gt 0) {
    Write-Host 'FINDING: AMSI providers registered (script content may be inspected)'
  }
} else {
  Write-Host 'AMSI providers key absent/unreadable'
}
try {
  $das = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -ErrorAction SilentlyContinue).DisableAntiSpyware
  Write-Host "Defender DisableAntiSpyware=$das"
} catch {}
Write-Host 'NOTE: if custom .exe is blocked, prefer enum.ps1 / enum.js / EnumTasks.csproj (approved fallbacks).'
Write-Host 'NOTE: this script does not disable AppLocker, WDAC, SmartScreen, AMSI, or AV/EDR.'
Write-Host ""

Write-Host "Done. Enumeration only - no auto-exploit."

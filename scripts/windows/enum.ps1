# StealthyPrivesc - PowerShell fallback (authorized assessments only)
# Reduced, read-only coverage. It does not mutate services, tasks, controls, or files.
param(
  [switch]$Json,
  [switch]$Authorized
)

$authorized = $Authorized -or ($env:STEALTHY_AUTHORIZED -eq '1')
if (-not $authorized) {
  [Console]::Error.WriteLine('Authorization required: pass -Authorized or set STEALTHY_AUTHORIZED=1')
  exit 2
}

$findings = @()
$coverage = @()

function Add-Finding {
  param(
    [string]$Plugin,
    [string]$Kind,
    [string]$Severity,
    [string]$Title,
    [string]$Detail,
    [string]$Recommendation,
    [string]$ObservedObject,
    [string]$Condition
  )
  $script:findings += [pscustomobject][ordered]@{
    plugin = $Plugin
    kind = $Kind
    severity = $Severity
    title = $Title
    detail = $Detail
    recommendation = $Recommendation
    noisy = $false
    leaves_artifacts = $false
    object = $ObservedObject
    condition = $Condition
  }
}

function Add-Coverage {
  param(
    [string]$Id,
    [string]$Status,
    [AllowNull()][string]$ErrorMessage
  )
  $count = @($script:findings | Where-Object { $_.plugin -eq $Id }).Count
  $script:coverage += [pscustomobject][ordered]@{
    id = $Id
    status = $Status
    findings = $count
    error = $ErrorMessage
    duration_ms = 0
  }
}

function Test-UnquotedServicePath([string]$ImagePath) {
  if ([string]::IsNullOrWhiteSpace($ImagePath)) { return $false }
  $trimmed = $ImagePath.Trim()
  if ($trimmed.StartsWith('"')) { return $false }
  $match = [regex]::Match($trimmed, '(?i)\.(exe|com|bat|cmd)')
  if (-not $match.Success) { return $false }
  return $trimmed.Substring(0, $match.Index) -match '\s'
}

$isElevated = $false
try {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  $isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}

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
  $privText = (& whoami.exe /priv 2>$null | Out-String)
  foreach ($privilege in $interesting) {
    if ($privText -match [regex]::Escape($privilege)) {
      Add-Finding 'windows.privileges' 'enumeration' 'medium' "Token privilege present: $privilege" 'Observed in whoami /priv output; enabled state should be checked in the source output.' 'Review whether the privilege is enabled and required for the current account.' $privilege 'token-privilege-present'
    }
  }
  Add-Coverage 'windows.privileges' 'ok' $null
} catch {
  Add-Coverage 'windows.privileges' 'error' $_.Exception.Message
}

$installerPath = 'HKLM+HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
try {
  $hklmItem = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
  $hkcuItem = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
  $hklm = if ($null -ne $hklmItem) { $hklmItem.AlwaysInstallElevated } else { $null }
  $hkcu = if ($null -ne $hkcuItem) { $hkcuItem.AlwaysInstallElevated } else { $null }
  if ($hklm -eq 1 -and $hkcu -eq 1) {
    Add-Finding 'windows.always_install_elevated' 'misconfiguration' 'critical' 'AlwaysInstallElevated enabled (HKLM+HKCU)' "HKLM=$hklm HKCU=$hkcu" 'Disable the policy in both hives. This fallback does not create or run MSI content.' $installerPath 'always-install-elevated-fully-enabled'
  } elseif ($null -eq $hklm -or $null -eq $hkcu) {
    Add-Finding 'windows.always_install_elevated' 'enumeration' 'info' 'AlwaysInstallElevated state is incomplete' "HKLM=$hklm HKCU=$hkcu; an absent value is not treated as confirmed disabled" 'Verify both policy hives from an approved context.' $installerPath 'always-install-elevated-state-unknown'
  } elseif ($hklm -eq 1 -or $hkcu -eq 1) {
    Add-Finding 'windows.always_install_elevated' 'misconfiguration' 'low' 'AlwaysInstallElevated policy is only partially enabled' "HKLM=$hklm HKCU=$hkcu" 'Disable the enabled half to remove the inconsistent installer policy.' $installerPath 'always-install-elevated-partially-enabled'
  } else {
    Add-Finding 'windows.always_install_elevated' 'enumeration' 'info' 'AlwaysInstallElevated is disabled' "HKLM=$hklm HKCU=$hkcu" 'No action.' $installerPath 'always-install-elevated-disabled'
  }
  Add-Coverage 'windows.always_install_elevated' 'ok' $null
} catch {
  Add-Coverage 'windows.always_install_elevated' 'error' $_.Exception.Message
}

try {
  $lua = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop).EnableLUA
  Add-Finding 'windows.uac' 'enumeration' 'info' "UAC EnableLUA=$lua" "EnableLUA=$lua" 'Review the complete UAC policy set before drawing an elevation conclusion.' 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA' "uac-enable-lua:$lua"
  Add-Coverage 'windows.uac' 'ok' $null
} catch {
  Add-Coverage 'windows.uac' 'error' $_.Exception.Message
}

try {
  $services = @(Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object -First 1000)
  foreach ($service in $services) {
    if (Test-UnquotedServicePath $service.PathName) {
      Add-Finding 'windows.services' 'enumeration' 'low' "Unquoted service path: $($service.Name)" "account=$($service.StartName) image_path=$($service.PathName) binary_acl=not_collected service_object_dacl=not_collected" 'Use the native plugin for current-token file ACL and service-object DACL evaluation.' "service:$($service.Name)" 'unquoted-service-image-path'
    }
  }
  Add-Coverage 'windows.services' 'ok' $null
} catch {
  Add-Coverage 'windows.services' 'error' $_.Exception.Message
}

if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
  try {
    $tasks = @(Get-ScheduledTask -ErrorAction Stop | Select-Object -First 500)
    foreach ($task in $tasks) {
      $runLevel = [string]$task.Principal.RunLevel
      $userId = [string]$task.Principal.UserId
      if ($runLevel -eq 'Highest' -or $userId -eq 'SYSTEM' -or $userId -eq 'S-1-5-18') {
        $taskName = "$($task.TaskPath)$($task.TaskName)"
        Add-Finding 'windows.scheduled_tasks' 'enumeration' 'low' "Elevated scheduled task: $taskName" "user=$userId run_level=$runLevel task_file_acl=not_collected task_scheduler_object_dacl=not_collected" 'Use the native plugin for task-file and action-file ACL checks; this fallback does not claim task-object DACL coverage.' $taskName 'elevated-task-definition'
      }
    }
    Add-Coverage 'windows.scheduled_tasks' 'ok' $null
  } catch {
    Add-Coverage 'windows.scheduled_tasks' 'error' $_.Exception.Message
  }
} else {
  Add-Coverage 'windows.scheduled_tasks' 'skipped' 'Get-ScheduledTask is unavailable; no task security data was collected'
}

$credentialPaths = @(
  'C:\Windows\Panther\Unattend.xml',
  'C:\Windows\Panther\unattend.xml',
  'C:\Windows\System32\sysprep\unattend.xml',
  'C:\Windows\System32\config\RegBack\SAM'
)
try {
  foreach ($path in $credentialPaths) {
    if (Test-Path -LiteralPath $path -PathType Leaf) {
      Add-Finding 'windows.credentials' 'credential' 'medium' "Sensitive file present: $path" 'Presence only; contents were not read.' 'Inspect and restrict access; remove stale unattended-install or SAM backup material.' $path 'sensitive-file-present'
    }
  }
  Add-Coverage 'windows.credentials' 'ok' $null
} catch {
  Add-Coverage 'windows.credentials' 'error' $_.Exception.Message
}

if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
  try {
    foreach ($member in @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)) {
      Add-Finding 'windows.admin_sessions' 'enumeration' 'low' "Local administrator member: $($member.Name)" "object_class=$($member.ObjectClass)" 'Cross-check whether this principal has an active session or reusable token.' $member.Name 'local-administrators-member'
    }
    Add-Coverage 'windows.admin_sessions' 'ok' $null
  } catch {
    Add-Coverage 'windows.admin_sessions' 'error' $_.Exception.Message
  }
} else {
  Add-Coverage 'windows.admin_sessions' 'skipped' 'Get-LocalGroupMember is unavailable; membership was not collected'
}

try {
  foreach ($entry in @($env:PATH -split ';' | Where-Object { $_ } | Select-Object -First 50)) {
    if (-not (Test-Path -LiteralPath $entry -PathType Container)) {
      Add-Finding 'windows.env_path' 'misconfiguration' 'medium' "PATH entry missing: $entry" 'Missing PATH components may be creatable when a parent directory is writable; parent ACL was not collected by this fallback.' 'Use the native plugin for read-only ACL evaluation before considering a write probe.' $entry 'missing-process-path-entry'
    }
  }
  Add-Coverage 'windows.env_path' 'ok' $null
} catch {
  Add-Coverage 'windows.env_path' 'error' $_.Exception.Message
}

try {
  foreach ($runKey in @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
  )) {
    $item = Get-ItemProperty -Path $runKey -ErrorAction SilentlyContinue
    if ($null -ne $item) {
      foreach ($property in $item.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
        Add-Finding 'windows.autoruns' 'enumeration' 'low' "Autorun value: $runKey\$($property.Name)" "command=$($property.Value) target_acl=not_collected" 'Use the native plugin to parse the target and evaluate its file ACL.' "$runKey\$($property.Name)" 'autorun-registry-value'
      }
    }
  }
  Add-Coverage 'windows.autoruns' 'ok' $null
} catch {
  Add-Coverage 'windows.autoruns' 'error' $_.Exception.Message
}

try {
  $signals = @()
  $srp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2'
  $collections = @('Exe','Script','Msi','Dll','Appx') | Where-Object { Test-Path -LiteralPath (Join-Path $srp $_) }
  if ($collections.Count -gt 0) { $signals += "AppLocker=$($collections -join ',')" }
  if (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy') { $signals += 'CI.PolicyKey=present' }
  $vbs = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
  if ($null -ne $vbs) { $signals += "VBS=$vbs" }
  $amsiProviders = @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -ErrorAction SilentlyContinue).Count
  $signals += "AMSI.providers=$amsiProviders"
  Add-Finding 'windows.endpoint_controls' 'enumeration' 'info' 'Endpoint-control registry signals collected' ($signals -join ' ') 'These are registry signals only, not an effective-policy decision or proof of enforcement.' 'windows-endpoint-control-registry' 'endpoint-control-registry-signals'
  Add-Coverage 'windows.endpoint_controls' 'ok' $null
} catch {
  Add-Coverage 'windows.endpoint_controls' 'error' $_.Exception.Message
}

Add-Coverage 'windows.dll_hijack' 'skipped' 'Application import/search-order and ACL analysis is unavailable in this fallback'
Add-Coverage 'windows.app_control' 'skipped' 'No approved artifact was supplied; effective artifact policy assessment was not collected'

$pluginsRun = @($coverage | Where-Object { $_.status -eq 'ok' } | ForEach-Object { $_.id })
$capabilityDelta = @(
  'windows.services',
  'windows.scheduled_tasks',
  'windows.always_install_elevated',
  'windows.uac',
  'windows.dll_hijack',
  'windows.credentials',
  'windows.admin_sessions',
  'windows.env_path',
  'windows.autoruns',
  'windows.endpoint_controls',
  'windows.app_control'
)

if ($Json) {
  $report = [ordered]@{
    schema_version = '2'
    run_id = [guid]::NewGuid().ToString('N').Substring(0, 24)
    started_at_unix = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    tool = 'stealthy-script'
    version = '0.1.0'
    authorized_use_ack = $true
    mode = 'enumerate-only'
    execution_path = if ($env:STEALTHY_EXECUTION_PATH) { $env:STEALTHY_EXECUTION_PATH } else { 'script' }
    primary_launch = if ($env:STEALTHY_PRIMARY_LAUNCH) { $env:STEALTHY_PRIMARY_LAUNCH } else { 'not_applicable' }
    roe_ref = if ($env:STEALTHY_MANIFEST_ROE_REF) { $env:STEALTHY_MANIFEST_ROE_REF } else { '' }
    profile = 'script'
    coverage_mode = 'script'
    capability_delta = $capabilityDelta
    os = @{
      family = 'windows'
      os = 'windows'
      arch = $env:PROCESSOR_ARCHITECTURE
      version_hint = [Environment]::OSVersion.Version.ToString()
    }
    identity = @{
      username = $env:USERNAME
      uid = $null
      gid = $null
      groups = @()
      is_elevated = $isElevated
      elevation_source = 'powershell-principal'
      token_context = ''
      hostname = $env:COMPUTERNAME
    }
    findings = @($findings)
    assessments = @()
    attack_paths = @()
    triage_decisions = @()
    plugins_run = $pluginsRun
    coverage = @($coverage)
    notes = @(
      'PowerShell fallback reports only data it directly collected.',
      'Service-object and Task Scheduler object DACLs are not collected by this fallback.',
      'Native plugin equivalence is not claimed.'
    )
  }
  $report | ConvertTo-Json -Depth 8 -Compress
  exit 0
}

Write-Host '=== StealthyPrivesc Windows PowerShell enum ==='
Write-Host 'LEGAL: Authorized use only. Reduced, read-only fallback coverage.'
foreach ($finding in $findings) {
  Write-Host ("FINDING [{0}] {1} -- {2}" -f $finding.severity, $finding.title, $finding.detail)
}
Write-Host ''
Write-Host 'Coverage:'
foreach ($item in $coverage) {
  $suffix = if ($item.error) { " ($($item.error))" } else { '' }
  Write-Host ("  {0}: {1}, findings={2}{3}" -f $item.id, $item.status, $item.findings, $suffix)
}
Write-Host 'Done. Enumeration only; native equivalence is not claimed.'

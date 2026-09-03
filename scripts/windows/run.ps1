# StealthyPrivesc policy-bound dispatcher — authorized assessments only.
# The launcher may select an approved script fallback when the primary PE
# cannot start. Under today's endpoint-bypass contract it does not disable
# or bypass host controls (see docs/techniques.md for Planned families).
#
# Fallback hosts are fixed enumerate-only reduced coverage. Only auth
# (via STEALTHY_AUTHORIZED) and --json / -Json are forwarded; binary flags
# such as --profile / --plugins are not applied to script hosts.
[CmdletBinding(PositionalBinding = $false)]
param(
  [string]$Manifest = $(if ($env:STEALTHY_MANIFEST) { $env:STEALTHY_MANIFEST } else { Join-Path $PSScriptRoot 'stealthy-run.conf' }),
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$Arguments
)

$ErrorActionPreference = 'Stop'

# Staged bundle: scripts/run.ps1 + adjacent stealthy-run.conf → bundle is parent.
# Repo checkout: scripts/windows/run.ps1 → bundle is repo root.
if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'stealthy-run.conf')) {
  $bundleDir = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
  if (-not $PSBoundParameters.ContainsKey('Manifest') -and -not $env:STEALTHY_MANIFEST) {
    $Manifest = Join-Path $PSScriptRoot 'stealthy-run.conf'
  }
} else {
  $bundleDir = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

function Read-Manifest([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { throw "dispatcher: manifest not found: $Path" }
  $result = @{}
  foreach ($line in Get-Content -LiteralPath $Path) {
    if ([string]::IsNullOrWhiteSpace($line) -or $line.TrimStart().StartsWith('#')) { continue }
    $parts = $line.Split('=', 2)
    if ($parts.Count -eq 2) { $result[$parts[0].Trim()] = $parts[1].Trim() }
  }
  return $result
}

function Test-BlockStatus([int]$Status) {
  # 126/127: not executable / not found. >128: signal-style / forced kill.
  # Preserve tool contracts 0 / 2 / 4 and ordinary CLI failures.
  if ($Status -in @(126, 127)) { return $true }
  if ($Status -gt 128) { return $true }
  return $false
}

$cfg = Read-Manifest $Manifest
foreach ($required in @('manifest_version', 'authorization_ack', 'allow_fallback', 'roe_ref', 'target_hostname')) {
  if (-not $cfg.ContainsKey($required) -or [string]::IsNullOrWhiteSpace($cfg[$required])) {
    throw "dispatcher: manifest missing $required"
  }
}
if ($cfg.manifest_version -ne '1') { throw 'dispatcher: unsupported manifest version' }
if ($cfg.authorization_ack -ne 'true') { throw 'dispatcher: authorization_ack is not true' }
if ($cfg.allow_fallback -ne 'true') { throw 'dispatcher: fallback is not approved' }
if (-not $cfg.ContainsKey('operator_ack_required') -or $cfg.operator_ack_required -ne 'true') {
  throw 'dispatcher: operator acknowledgment requirement is missing'
}
$executionMode = if ($cfg.ContainsKey('execution_mode') -and $cfg.execution_mode) { $cfg.execution_mode } else { 'enumerate-only' }
if ($executionMode -ne 'enumerate-only') { throw 'dispatcher: only enumerate-only fallback mode is supported' }
$bundleMode = if ($cfg.ContainsKey('bundle_mode') -and $cfg.bundle_mode) { $cfg.bundle_mode } else { 'native-with-fallbacks' }
if ($bundleMode -notin @('native-with-fallbacks', 'script-only')) { throw 'dispatcher: unsupported bundle mode' }
if ($bundleMode -eq 'script-only' -and $cfg.primary_binary) { throw 'dispatcher: script-only bundle must not declare a primary binary' }

if ($cfg.target_hostname -ne 'AUTO' -and $env:COMPUTERNAME -ne $cfg.target_hostname) {
  throw "dispatcher: target hostname mismatch (expected $($cfg.target_hostname), got $env:COMPUTERNAME)"
}
if ($cfg.ContainsKey('target_username') -and $cfg.target_username -and $cfg.target_username -ne 'AUTO' -and $env:USERNAME -ne $cfg.target_username) {
  throw 'dispatcher: target username mismatch'
}

$authorizedArg = ($Arguments -contains '--authorized') -or ($Arguments -contains '--i-understand-authorized-use-only')
$authorizedEnv = $env:STEALTHY_AUTHORIZED -eq '1'
if (-not ($authorizedArg -or $authorizedEnv)) {
  [Console]::Error.WriteLine('Authorization required: pass --authorized or set STEALTHY_AUTHORIZED=1')
  exit 2
}
$priorAuthorization = [Environment]::GetEnvironmentVariable('STEALTHY_AUTHORIZED', 'Process')
try {
$env:STEALTHY_AUTHORIZED = '1'

$primaryName = if ($bundleMode -eq 'script-only') { $null } elseif ($cfg.primary_binary) { $cfg.primary_binary } else { 'stealthy.exe' }
$primarySrc = if ($primaryName) { Join-Path $bundleDir $primaryName } else { $null }

# Empty drop_dir (staged default) → run PE in place to avoid a second AV scan event.
$useInPlace = -not $cfg.ContainsKey('drop_dir') -or [string]::IsNullOrWhiteSpace($cfg.drop_dir)
if ($useInPlace) {
  $dropDir = $bundleDir
  $primary = $primarySrc
} else {
  $dropDir = $cfg.drop_dir
  New-Item -ItemType Directory -Force -Path $dropDir | Out-Null
  $primary = if ($primaryName) { Join-Path $dropDir $primaryName } else { $null }
  if ($primarySrc -and (Test-Path -LiteralPath $primarySrc -PathType Leaf) -and ($primarySrc -ne $primary)) {
    try {
      Copy-Item -LiteralPath $primarySrc -Destination $primary -Force
      if (-not (Test-Path -LiteralPath $primary -PathType Leaf)) {
        [Console]::Error.WriteLine("dispatcher: primary copy vanished after write (possible AV quarantine): $primary")
        $primary = $null
      }
    } catch {
      [Console]::Error.WriteLine("dispatcher: primary copy failed (possible AV block): $($_.Exception.Message)")
      $primary = $null
    }
  }
}

$scriptSourceDir = $PSScriptRoot
foreach ($file in @('enum.ps1', 'enum.js', 'EnumTasks.csproj')) {
  $source = Join-Path $scriptSourceDir $file
  if (-not (Test-Path -LiteralPath $source)) {
    $alt = Join-Path $bundleDir (Join-Path 'scripts\windows' $file)
    if (Test-Path -LiteralPath $alt) { $source = $alt }
  }
  if ((Test-Path -LiteralPath $source) -and -not $useInPlace -and ($dropDir -ne $scriptSourceDir)) {
    $dest = Join-Path $dropDir $file
    if ($source -ne $dest) {
      try { Copy-Item -LiteralPath $source -Destination $dest -Force } catch { }
    }
  }
}

$argsToRun = if ($Arguments) { @($Arguments) } else { @('--profile', 'balanced', 'enum') }
$env:STEALTHY_MANIFEST_ROE_REF = if ($env:STEALTHY_ROE_REF) { $env:STEALTHY_ROE_REF } else { $cfg.roe_ref }
$env:STEALTHY_EXECUTION_PATH = 'binary'
$env:STEALTHY_PRIMARY_LAUNCH = if ($bundleMode -eq 'script-only') { 'not_applicable' } else { 'ok' }
$isJson = ($argsToRun -contains '--json') -or ($argsToRun -contains '--format=json') -or (($argsToRun -contains '--format') -and ($argsToRun -contains 'json'))
$approvedFallbacks = if ($cfg.windows_fallbacks) {
  @($cfg.windows_fallbacks.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
} else {
  @('powershell', 'jscript', 'msbuild')
}

function Resolve-FallbackPath([string]$Name) {
  foreach ($candidate in @(
      (Join-Path $dropDir $Name),
      (Join-Path $scriptSourceDir $Name),
      (Join-Path $bundleDir (Join-Path 'scripts\windows' $Name)),
      (Join-Path $bundleDir (Join-Path 'scripts' $Name))
    )) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
  }
  return $null
}

function Invoke-ApprovedFallbacks {
  $env:STEALTHY_PRIMARY_LAUNCH = if ($bundleMode -eq 'script-only') { 'not_applicable' } else { 'blocked' }
  $env:STEALTHY_MANIFEST_ROE_REF = if ($env:STEALTHY_ROE_REF) { $env:STEALTHY_ROE_REF } else { $cfg.roe_ref }
  foreach ($fallback in $approvedFallbacks) {
    switch ($fallback) {
      'powershell' {
        $script = Resolve-FallbackPath 'enum.ps1'
        if (-not $script) {
          [Console]::Error.WriteLine('dispatcher: skipping powershell fallback (enum.ps1 missing)')
          break
        }
        $env:STEALTHY_EXECUTION_PATH = 'powershell-fallback'
        [Console]::Error.WriteLine($(if ($bundleMode -eq 'script-only') { 'dispatcher: script-only bundle; trying approved powershell fallback' } else { 'dispatcher: primary executable blocked; trying approved powershell fallback' }))
        $psArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script, '-Authorized')
        if ($isJson) { $psArgs += '-Json' }
        try {
          & powershell.exe @psArgs
          $status = $LASTEXITCODE
          if ($null -eq $status) { $status = 0 }
        } catch {
          [Console]::Error.WriteLine("dispatcher: powershell fallback launch failed: $($_.Exception.Message)")
          $status = 126
        }
        if ($status -eq 0) { exit 0 }
        if (Test-BlockStatus $status) {
          [Console]::Error.WriteLine("dispatcher: powershell fallback blocked (exit $status); trying next host")
          break
        }
        exit $status
      }
      'jscript' {
        $script = Resolve-FallbackPath 'enum.js'
        if (-not $script) {
          [Console]::Error.WriteLine('dispatcher: skipping jscript fallback (enum.js missing)')
          break
        }
        $cscript = Get-Command cscript.exe -ErrorAction SilentlyContinue
        if (-not $cscript) {
          [Console]::Error.WriteLine('dispatcher: skipping jscript fallback (cscript.exe unavailable)')
          break
        }
        $env:STEALTHY_EXECUTION_PATH = 'jscript-fallback'
        [Console]::Error.WriteLine($(if ($bundleMode -eq 'script-only') { 'dispatcher: script-only bundle; trying approved jscript fallback' } else { 'dispatcher: primary executable blocked; trying approved jscript fallback' }))
        $jsArgs = @('//nologo', $script, '--authorized')
        if ($isJson) { $jsArgs += '--json' }
        try {
          & cscript.exe @jsArgs
          $status = $LASTEXITCODE
          if ($null -eq $status) { $status = 0 }
        } catch {
          [Console]::Error.WriteLine("dispatcher: jscript fallback launch failed: $($_.Exception.Message)")
          $status = 126
        }
        if ($status -eq 0) { exit 0 }
        if (Test-BlockStatus $status) {
          [Console]::Error.WriteLine("dispatcher: jscript fallback blocked (exit $status); trying next host")
          break
        }
        exit $status
      }
      'msbuild' {
        $project = Resolve-FallbackPath 'EnumTasks.csproj'
        if (-not $project) {
          [Console]::Error.WriteLine('dispatcher: skipping msbuild fallback (EnumTasks.csproj missing)')
          break
        }
        $msbuild = Get-Command msbuild.exe -ErrorAction SilentlyContinue
        if (-not $msbuild) {
          [Console]::Error.WriteLine('dispatcher: skipping msbuild fallback (msbuild.exe unavailable)')
          break
        }
        $env:STEALTHY_EXECUTION_PATH = 'msbuild-fallback'
        [Console]::Error.WriteLine($(if ($bundleMode -eq 'script-only') { 'dispatcher: script-only bundle; trying approved msbuild fallback' } else { 'dispatcher: primary executable blocked; trying approved msbuild fallback' }))
        try {
          if ($isJson) {
            & msbuild.exe $project /nologo /v:minimal /p:StealthyJson=true
          } else {
            & msbuild.exe $project /nologo /v:minimal
          }
          $status = $LASTEXITCODE
          if ($null -eq $status) { $status = 0 }
        } catch {
          [Console]::Error.WriteLine("dispatcher: msbuild fallback launch failed: $($_.Exception.Message)")
          $status = 126
        }
        if ($status -eq 0) { exit 0 }
        if (Test-BlockStatus $status) {
          [Console]::Error.WriteLine("dispatcher: msbuild fallback blocked (exit $status); trying next host")
          break
        }
        exit $status
      }
      default {
        [Console]::Error.WriteLine("dispatcher: ignoring unknown fallback '$fallback'")
      }
    }
  }
  [Console]::Error.WriteLine('dispatcher: no approved executable or fallback is available')
  exit 126
}

$primaryBlocked = $false
if ($primary -and (Test-Path -LiteralPath $primary -PathType Leaf)) {
  try {
    & $primary @argsToRun
    $status = $LASTEXITCODE
    if ($null -eq $status) { $status = 0 }
    if (Test-BlockStatus $status) {
      [Console]::Error.WriteLine("dispatcher: primary launch blocked (exit $status)")
      $primaryBlocked = $true
    } elseif (-not (Test-Path -LiteralPath $primary -PathType Leaf)) {
      [Console]::Error.WriteLine('dispatcher: primary vanished after launch (possible quarantine)')
      $primaryBlocked = $true
    } else {
      exit $status
    }
  } catch {
    [Console]::Error.WriteLine("dispatcher: primary launch failed: $($_.Exception.Message)")
    $primaryBlocked = $true
  }
} else {
  $primaryBlocked = $true
}

if ($primaryBlocked) {
  Invoke-ApprovedFallbacks
}
} finally {
  [Environment]::SetEnvironmentVariable('STEALTHY_AUTHORIZED', $priorAuthorization, 'Process')
}

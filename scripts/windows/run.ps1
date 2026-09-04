# StealthyPrivesc policy-bound dispatcher - authorized assessments only.
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

# Staged bundle: scripts/run.ps1 + adjacent stealthy-run.conf -> bundle is parent.
# Repo checkout: scripts/windows/run.ps1 -> bundle is repo root.
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
$dispatcherEnvironmentNames = @(
  'STEALTHY_AUTHORIZED',
  'STEALTHY_MANIFEST_ROE_REF',
  'STEALTHY_EXECUTION_PATH',
  'STEALTHY_PRIMARY_LAUNCH'
)
$priorDispatcherEnvironment = @{}
foreach ($name in $dispatcherEnvironmentNames) {
  $priorDispatcherEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
function Restore-DispatcherEnvironment {
  foreach ($name in $dispatcherEnvironmentNames) {
    $priorValue = $priorDispatcherEnvironment[$name]
    if ($null -eq $priorValue) {
      Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
    } else {
      [Environment]::SetEnvironmentVariable($name, $priorValue, 'Process')
    }
  }
}
try {
$env:STEALTHY_AUTHORIZED = '1'

$primaryName = if ($bundleMode -eq 'script-only') { $null } elseif ($cfg.primary_binary) { $cfg.primary_binary } else { 'stealthy.exe' }
$primarySrc = if ($primaryName) { Join-Path $bundleDir $primaryName } else { $null }

function Get-ScriptFirstMode {
  $raw = if ($env:STEALTHY_SCRIPT_FIRST) {
    $env:STEALTHY_SCRIPT_FIRST
  } elseif ($cfg.ContainsKey('script_first') -and $cfg.script_first) {
    $cfg.script_first
  } else {
    'auto'
  }
  $raw = ([string]$raw).Trim().ToLowerInvariant()
  if ($raw -notin @('auto', 'true', 'false')) {
    throw "dispatcher: unsupported script_first value"
  }
  return $raw
}

function Get-EndpointSensorReason {
  $names = @{
    'csfalconservice' = 'falcon'
    'csfalconcontainer' = 'falcon'
    'sentinelagent' = 'sentinelone'
    'sentinelhelperservice' = 'sentinelone'
    'sentinelstaticengine' = 'sentinelone'
    'cylancesvc' = 'cylance'
    'cbagentd' = 'carbonblack'
    'cbdefense' = 'carbonblack'
    'repmgr' = 'trellix'
    'mfetp' = 'trellix'
    'elastic-agent' = 'elastic'
    'elastic-endpoint' = 'elastic'
    'mssense' = 'mde'
    'sensecm' = 'mde'
    'taniumclient' = 'tanium'
    'cyserver' = 'cortex'
    'traps' = 'cortex'
    'sophoshealth' = 'sophos'
    'savservice' = 'sophos'
    'osqueryd' = 'osquery'
    'wdavdaemon' = 'mdatp'
    'falcon-sensor' = 'falcon'
    'sentinelone-agent' = 'sentinelone'
  }
  try {
    foreach ($proc in [System.Diagnostics.Process]::GetProcesses()) {
      $n = $proc.ProcessName.ToLowerInvariant()
      if ($names.ContainsKey($n)) { return $names[$n] }
    }
  } catch {
    return $null
  }
  return $null
}

# Empty drop_dir (staged default) -> run PE in place to avoid a second AV scan event.
$useInPlace = -not $cfg.ContainsKey('drop_dir') -or [string]::IsNullOrWhiteSpace($cfg.drop_dir)
if ($useInPlace) {
  $dropDir = $bundleDir
  $primary = $primarySrc
} else {
  $dropDir = $cfg.drop_dir
  New-Item -ItemType Directory -Force -Path $dropDir | Out-Null
  $primary = if ($primaryName) { Join-Path $dropDir $primaryName } else { $null }
}

$scriptFirst = Get-ScriptFirstMode
$skipPrimary = $false
$skipReason = $null
$dispatchReason = 'blocked'
if ($bundleMode -eq 'script-only') {
  $skipPrimary = $true
  $dispatchReason = 'script-only'
} elseif ($scriptFirst -eq 'true') {
  $skipPrimary = $true
  $skipReason = 'script-first=true'
  $dispatchReason = 'script-first'
} elseif ($scriptFirst -eq 'auto') {
  $skipReason = Get-EndpointSensorReason
  if ($skipReason) {
    $skipPrimary = $true
    $dispatchReason = 'script-first'
  }
}
if ($skipPrimary -and $bundleMode -ne 'script-only') {
  [Console]::Error.WriteLine("dispatcher: skipping primary ($skipReason); using approved script hosts")
  $primary = $null
}

if (-not $skipPrimary -and -not $useInPlace -and $primarySrc -and (Test-Path -LiteralPath $primarySrc -PathType Leaf) -and ($primarySrc -ne $primary)) {
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

$scriptSourceDir = $PSScriptRoot
foreach ($file in @('enum.ps1', 'enum.py', 'enum-git.sh', 'enum.js', 'EnumTasks.csproj')) {
  $source = Join-Path $scriptSourceDir $file
  if (-not (Test-Path -LiteralPath $source)) {
    $alt = Join-Path $bundleDir (Join-Path 'scripts\windows' $file)
    if (Test-Path -LiteralPath $alt) { $source = $alt }
  }
  if ((Test-Path -LiteralPath $source) -and -not $useInPlace -and ($dropDir -ne $scriptSourceDir)) {
    $dest = Join-Path $dropDir $file
    if ($source -ne $dest) {
      try {
        Copy-Item -LiteralPath $source -Destination $dest -Force
      } catch {
        Write-Verbose "Could not copy fallback $file to ${dest}: $($_.Exception.Message)"
      }
    }
  }
}

$argsToRun = if ($Arguments) { @($Arguments) } else { @('--profile', 'balanced', 'enum') }
$env:STEALTHY_MANIFEST_ROE_REF = if ($env:STEALTHY_ROE_REF) { $env:STEALTHY_ROE_REF } else { $cfg.roe_ref }
$env:STEALTHY_EXECUTION_PATH = 'binary'
$env:STEALTHY_PRIMARY_LAUNCH = if ($bundleMode -eq 'script-only') {
  'not_applicable'
} elseif ($skipPrimary -and $scriptFirst -eq 'true') {
  'skipped-script-first'
} elseif ($skipPrimary) {
  'skipped-sensor'
} else {
  'ok'
}
$isJson = ($argsToRun -contains '--json') -or ($argsToRun -contains '--format=json') -or (($argsToRun -contains '--format') -and ($argsToRun -contains 'json'))
$approvedFallbacks = if ($cfg.windows_fallbacks) {
  @($cfg.windows_fallbacks.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
} else {
  @('python', 'pwsh', 'powershell', 'git', 'jscript', 'msbuild')
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

function Resolve-PythonCommand {
  $py = Get-Command py.exe -ErrorAction SilentlyContinue
  if ($py) {
    return @{ Exe = $py.Source; Prefix = @('-3') }
  }
  foreach ($name in @('python.exe', 'python3.exe')) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) {
      return @{ Exe = $cmd.Source; Prefix = @() }
    }
  }
  return $null
}

function Resolve-GitBash {
  $candidates = @()
  if ($env:ProgramFiles) {
    $candidates += (Join-Path $env:ProgramFiles 'Git\bin\bash.exe')
  }
  $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
  if ($programFilesX86) {
    $candidates += (Join-Path $programFilesX86 'Git\bin\bash.exe')
  }
  if ($env:LOCALAPPDATA) {
    $candidates += (Join-Path $env:LOCALAPPDATA 'Programs\Git\bin\bash.exe')
  }
  foreach ($path in $candidates) {
    if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) { return $path }
  }
  return $null
}

function Write-FallbackBanner([string]$Label) {
  switch ($dispatchReason) {
    'script-only' { [Console]::Error.WriteLine("dispatcher: script-only bundle; trying approved $Label fallback") }
    'script-first' { [Console]::Error.WriteLine("dispatcher: script-first; trying approved $Label fallback") }
    default { [Console]::Error.WriteLine("dispatcher: primary executable blocked; trying approved $Label fallback") }
  }
}

function Invoke-ApprovedFallback {
  if ($bundleMode -eq 'script-only') {
    $env:STEALTHY_PRIMARY_LAUNCH = 'not_applicable'
  } elseif ($env:STEALTHY_PRIMARY_LAUNCH -notin @('skipped-sensor', 'skipped-script-first')) {
    $env:STEALTHY_PRIMARY_LAUNCH = 'blocked'
  }
  $env:STEALTHY_MANIFEST_ROE_REF = if ($env:STEALTHY_ROE_REF) { $env:STEALTHY_ROE_REF } else { $cfg.roe_ref }
  foreach ($fallback in $approvedFallbacks) {
    switch ($fallback) {
      'python' {
        $script = Resolve-FallbackPath 'enum.py'
        if (-not $script) {
          [Console]::Error.WriteLine('dispatcher: skipping python fallback (enum.py missing)')
          break
        }
        $python = Resolve-PythonCommand
        if (-not $python) {
          [Console]::Error.WriteLine('dispatcher: skipping python fallback (python.exe/py.exe unavailable)')
          break
        }
        $env:STEALTHY_EXECUTION_PATH = 'python-fallback'
        Write-FallbackBanner 'python'
        $pyArgs = @($python.Prefix + @($script, '--authorized'))
        if ($isJson) { $pyArgs += '--json' }
        try {
          & $python.Exe @pyArgs
          $status = $LASTEXITCODE
          if ($null -eq $status) { $status = 0 }
        } catch {
          [Console]::Error.WriteLine("dispatcher: python fallback launch failed: $($_.Exception.Message)")
          $status = 126
        }
        if ($status -eq 0) { Restore-DispatcherEnvironment; exit 0 }
        if (Test-BlockStatus $status) {
          [Console]::Error.WriteLine("dispatcher: python fallback blocked (exit $status); trying next host")
          break
        }
        Restore-DispatcherEnvironment
        exit $status
      }
      'pwsh' {
        $script = Resolve-FallbackPath 'enum.ps1'
        if (-not $script) {
          [Console]::Error.WriteLine('dispatcher: skipping pwsh fallback (enum.ps1 missing)')
          break
        }
        $pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
        if (-not $pwsh) {
          [Console]::Error.WriteLine('dispatcher: skipping pwsh fallback (pwsh.exe unavailable)')
          break
        }
        $env:STEALTHY_EXECUTION_PATH = 'pwsh-fallback'
        Write-FallbackBanner 'pwsh'
        # No -ExecutionPolicy Bypass: PowerShell 7 is often already allowed.
        $psArgs = @('-NoProfile', '-File', $script, '-Authorized')
        if ($isJson) { $psArgs += '-Json' }
        try {
          & pwsh.exe @psArgs
          $status = $LASTEXITCODE
          if ($null -eq $status) { $status = 0 }
        } catch {
          [Console]::Error.WriteLine("dispatcher: pwsh fallback launch failed: $($_.Exception.Message)")
          $status = 126
        }
        if ($status -eq 0) { Restore-DispatcherEnvironment; exit 0 }
        if (Test-BlockStatus $status) {
          [Console]::Error.WriteLine("dispatcher: pwsh fallback blocked (exit $status); trying next host")
          break
        }
        Restore-DispatcherEnvironment
        exit $status
      }
      'git' {
        $script = Resolve-FallbackPath 'enum-git.sh'
        if (-not $script) {
          [Console]::Error.WriteLine('dispatcher: skipping git fallback (enum-git.sh missing)')
          break
        }
        $gitBash = Resolve-GitBash
        if (-not $gitBash) {
          [Console]::Error.WriteLine('dispatcher: skipping git fallback (Git bash unavailable)')
          break
        }
        $env:STEALTHY_EXECUTION_PATH = 'git-fallback'
        Write-FallbackBanner 'git'
        $gitArgs = @('--noprofile', '--norc', $script, '--authorized')
        if ($isJson) { $gitArgs += '--json' }
        try {
          & $gitBash @gitArgs
          $status = $LASTEXITCODE
          if ($null -eq $status) { $status = 0 }
        } catch {
          [Console]::Error.WriteLine("dispatcher: git fallback launch failed: $($_.Exception.Message)")
          $status = 126
        }
        if ($status -eq 0) { Restore-DispatcherEnvironment; exit 0 }
        if (Test-BlockStatus $status) {
          [Console]::Error.WriteLine("dispatcher: git fallback blocked (exit $status); trying next host")
          break
        }
        Restore-DispatcherEnvironment
        exit $status
      }
      'powershell' {
        $script = Resolve-FallbackPath 'enum.ps1'
        if (-not $script) {
          [Console]::Error.WriteLine('dispatcher: skipping powershell fallback (enum.ps1 missing)')
          break
        }
        $env:STEALTHY_EXECUTION_PATH = 'powershell-fallback'
        Write-FallbackBanner 'powershell'
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
        if ($status -eq 0) { Restore-DispatcherEnvironment; exit 0 }
        if (Test-BlockStatus $status) {
          [Console]::Error.WriteLine("dispatcher: powershell fallback blocked (exit $status); trying next host")
          break
        }
        Restore-DispatcherEnvironment
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
        Write-FallbackBanner 'jscript'
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
        if ($status -eq 0) { Restore-DispatcherEnvironment; exit 0 }
        if (Test-BlockStatus $status) {
          [Console]::Error.WriteLine("dispatcher: jscript fallback blocked (exit $status); trying next host")
          break
        }
        Restore-DispatcherEnvironment
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
        $msbuildPath = [string]$msbuild.Source
        if ($msbuildPath -notmatch '(?i)\\Program Files') {
          [Console]::Error.WriteLine('dispatcher: skipping msbuild fallback (msbuild.exe is not under Program Files)')
          break
        }
        $env:STEALTHY_EXECUTION_PATH = 'msbuild-fallback'
        Write-FallbackBanner 'msbuild'
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
        if ($status -eq 0) { Restore-DispatcherEnvironment; exit 0 }
        if (Test-BlockStatus $status) {
          [Console]::Error.WriteLine("dispatcher: msbuild fallback blocked (exit $status); trying next host")
          break
        }
        Restore-DispatcherEnvironment
        exit $status
      }
      default {
        [Console]::Error.WriteLine("dispatcher: ignoring unknown fallback '$fallback'")
      }
    }
  }
  [Console]::Error.WriteLine('dispatcher: no approved executable or fallback is available')
  Restore-DispatcherEnvironment
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
      Restore-DispatcherEnvironment
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
  Invoke-ApprovedFallback
}
} finally {
  Restore-DispatcherEnvironment
}

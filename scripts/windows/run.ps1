# StealthyPrivesc policy-bound dispatcher — authorized assessments only.
# The launcher may select an approved script fallback when the primary PE
# cannot start. It never disables or bypasses host controls.
[CmdletBinding()]
param(
  [string]$Manifest = $(if ($env:STEALTHY_MANIFEST) { $env:STEALTHY_MANIFEST } else { Join-Path $PSScriptRoot 'stealthy-run.conf' }),
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$Arguments
)

$ErrorActionPreference = 'Stop'
$bundleDir = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

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

$cfg = Read-Manifest $Manifest
foreach ($required in @('manifest_version','authorization_ack','allow_fallback','roe_ref','target_hostname')) {
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

if ($cfg.target_hostname -ne 'AUTO' -and $env:COMPUTERNAME -ne $cfg.target_hostname) {
  throw "dispatcher: target hostname mismatch (expected $($cfg.target_hostname), got $env:COMPUTERNAME)"
}
if ($cfg.ContainsKey('target_username') -and $cfg.target_username -and $cfg.target_username -ne 'AUTO' -and $env:USERNAME -ne $cfg.target_username) {
  throw 'dispatcher: target username mismatch'
}

$authorizedArg = ($Arguments -contains '--authorized') -or ($Arguments -contains '--i-understand-authorized-use-only')
$authorizedEnv = $env:STEALTHY_AUTHORIZED -eq '1'
if (-not ($authorizedArg -or $authorizedEnv)) {
  Write-Error 'Authorization required: pass --authorized or set STEALTHY_AUTHORIZED=1'
  exit 2
}
$env:STEALTHY_AUTHORIZED = '1'

$dropDir = if ($cfg.drop_dir) { $cfg.drop_dir } else { Join-Path $bundleDir '.run-cache' }
New-Item -ItemType Directory -Force -Path $dropDir | Out-Null
$primaryName = if ($cfg.primary_binary) { $cfg.primary_binary } else { 'stealthy.exe' }
$primarySrc = Join-Path $bundleDir $primaryName
$primary = Join-Path $dropDir $primaryName
if ((Test-Path -LiteralPath $primarySrc -PathType Leaf) -and ($primarySrc -ne $primary)) {
  Copy-Item -LiteralPath $primarySrc -Destination $primary -Force
}
foreach ($file in @('enum.ps1','enum.js')) {
  $source = Join-Path $PSScriptRoot $file
  if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination (Join-Path $dropDir $file) -Force }
}

$argsToRun = if ($Arguments) { $Arguments } else { @('--profile','balanced','enum') }
$env:STEALTHY_MANIFEST_ROE_REF = if ($env:STEALTHY_ROE_REF) { $env:STEALTHY_ROE_REF } else { $cfg.roe_ref }
$env:STEALTHY_EXECUTION_PATH = 'binary'
$env:STEALTHY_PRIMARY_LAUNCH = 'ok'
$isJson = ($argsToRun -contains '--json') -or (($argsToRun -contains '--format') -and ($argsToRun -contains 'json'))
$approvedFallbacks = if ($cfg.windows_fallbacks) { $cfg.windows_fallbacks.Split(',') | ForEach-Object { $_.Trim() } } else { @('powershell') }

function Invoke-PowerShellFallback {
  if ($approvedFallbacks -notcontains 'powershell') { throw 'dispatcher: PowerShell fallback is not approved by the manifest' }
  $env:STEALTHY_EXECUTION_PATH = 'powershell-fallback'
  $env:STEALTHY_PRIMARY_LAUNCH = 'blocked'
  $env:STEALTHY_MANIFEST_ROE_REF = if ($env:STEALTHY_ROE_REF) { $env:STEALTHY_ROE_REF } else { $cfg.roe_ref }
  Write-Error 'dispatcher: primary executable blocked; using approved PowerShell fallback'
  $script = Join-Path $dropDir 'enum.ps1'
  if (-not (Test-Path -LiteralPath $script)) { throw 'dispatcher: PowerShell fallback script is missing' }
  if ($isJson) { & powershell.exe -NoProfile -File $script -Json } else { & powershell.exe -NoProfile -File $script }
  exit $LASTEXITCODE
}

if (Test-Path -LiteralPath $primary -PathType Leaf) {
  try {
    & $primary @argsToRun
    $status = $LASTEXITCODE
    if ($status -notin @(126,127)) { exit $status }
  } catch {
    Invoke-PowerShellFallback
  }
} else {
  Invoke-PowerShellFallback
}

Invoke-PowerShellFallback

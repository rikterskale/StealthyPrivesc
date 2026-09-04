param([switch]$DryRun)
$ErrorActionPreference = 'Stop'
$repo = if ($env:STEALTHY_REPO) { $env:STEALTHY_REPO } else { 'rikterskale/StealthyPrivesc' }
$tag = if ($env:STEALTHY_VERSION) { $env:STEALTHY_VERSION } else { (Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest").tag_name }
$architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
if ($architecture -ne 'X64') { throw "Unsupported Windows architecture: $architecture" }

$asset = 'stealthy-windows-x86_64.zip'
$tmp = Join-Path $env:TEMP ('stealthy-' + [guid]::NewGuid())
$extractDir = Join-Path $tmp 'kit'
$kitDir = if ($env:STEALTHY_KIT_DIR) { $env:STEALTHY_KIT_DIR } else { Join-Path $env:LOCALAPPDATA "StealthyPrivesc\$tag" }
$installDir = if ($env:STEALTHY_INSTALL_DIR) { $env:STEALTHY_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'StealthyPrivesc\bin' }
$base = "https://github.com/$repo/releases/download/$tag"

if ($DryRun) {
  Write-Output "Would install stealthy $tag from $repo"
  Write-Output "Binary destination: $(Join-Path $installDir 'stealthy.exe')"
  Write-Output "Kit destination: $kitDir"
  Write-Output 'Validation: SHA256SUMS plus GitHub artifact attestation'
  exit 0
}

try {
  New-Item -ItemType Directory -Force -Path $tmp, $extractDir | Out-Null
  $assetPath = Join-Path $tmp $asset
  Invoke-WebRequest "$base/$asset" -OutFile $assetPath
  $releaseSums = (Invoke-WebRequest "$base/SHA256SUMS").Content

  $checksumLines = @($releaseSums -split "`r?`n" | Where-Object {
    $parts = $_ -split '\s+', 2
    $parts.Count -eq 2 -and $parts[1] -eq $asset
  })
  if ($checksumLines.Count -ne 1) { throw "Release checksum for $asset is missing or ambiguous" }
  $expected = ($checksumLines[0] -split '\s+', 2)[0].ToLowerInvariant()
  if ($expected -notmatch '^[0-9a-f]{64}$') { throw 'Invalid release checksum' }
  $actual = (Get-FileHash $assetPath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($expected -ne $actual) { throw 'SHA256 checksum mismatch' }

  $gh = Get-Command gh -ErrorAction SilentlyContinue
  if (-not $gh) { throw 'GitHub CLI (gh) is required to verify release provenance' }
  & $gh.Source attestation verify $assetPath --repo $repo --signer-workflow "$repo/.github/workflows/release.yml"
  if ($LASTEXITCODE -ne 0) { throw 'GitHub artifact attestation verification failed' }

  Expand-Archive $assetPath -DestinationPath $extractDir -Force
  foreach ($required in @('stealthy.exe', 'RELEASE-MANIFEST.json', 'SHA256SUMS')) {
    if (-not (Test-Path -LiteralPath (Join-Path $extractDir $required) -PathType Leaf)) {
      throw "Release kit is missing $required"
    }
  }

  foreach ($line in Get-Content -LiteralPath (Join-Path $extractDir 'SHA256SUMS')) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $parts = $line -split '\s+', 2
    if ($parts.Count -ne 2 -or $parts[0] -notmatch '^[0-9a-fA-F]{64}$') { throw "Invalid internal checksum line: $line" }
    $relative = $parts[1].Replace('/', [IO.Path]::DirectorySeparatorChar)
    $path = Join-Path $extractDir $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Release kit file is missing: $relative" }
    $fileHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($fileHash -ne $parts[0].ToLowerInvariant()) { throw "Internal checksum mismatch: $relative" }
  }

  New-Item -ItemType Directory -Force -Path $kitDir, $installDir | Out-Null
  Copy-Item -Path (Join-Path $extractDir '*') -Destination $kitDir -Recurse -Force
  Copy-Item -LiteralPath (Join-Path $extractDir 'stealthy.exe') -Destination (Join-Path $installDir 'stealthy.exe') -Force
  Write-Output "Installed stealthy $tag binary to $(Join-Path $installDir 'stealthy.exe')"
  Write-Output "Installed verified delivery kit to $kitDir"
  Write-Output "Rollback: remove $(Join-Path $installDir 'stealthy.exe') and $kitDir after recording the installed version"
} finally {
  if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
}

$ErrorActionPreference = 'Stop'
$repo = if ($env:STEALTHY_REPO) { $env:STEALTHY_REPO } else { 'rikterskale/StealthyPrivesc' }
$tag = if ($env:STEALTHY_VERSION) { $env:STEALTHY_VERSION } else { (Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest").tag_name }
$asset = 'stealthy-windows-x86_64.zip'
$tmp = Join-Path $env:TEMP ('stealthy-' + [guid]::NewGuid())
$installDir = if ($env:STEALTHY_INSTALL_DIR) { $env:STEALTHY_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'StealthyPrivesc' }
New-Item -ItemType Directory -Force -Path $tmp, $installDir | Out-Null
$base = "https://github.com/$repo/releases/download/$tag"
Invoke-WebRequest "$base/$asset" -OutFile (Join-Path $tmp $asset)
$sums = (Invoke-WebRequest "$base/SHA256SUMS").Content
$expected = (($sums -split "`n") | Where-Object { $_ -match [regex]::Escape($asset) }).Split(' ')[0]
$actual = (Get-FileHash (Join-Path $tmp $asset) -Algorithm SHA256).Hash.ToLowerInvariant()
if ($expected -ne $actual) { throw 'SHA256 checksum mismatch' }
Expand-Archive (Join-Path $tmp $asset) -DestinationPath $installDir -Force
Write-Host "Installed stealthy $tag to $installDir\stealthy.exe"

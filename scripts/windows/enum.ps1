# StealthyPrivesc — PowerShell fallback (authorized assessments only)
# Prefer cmdlets/APIs over spawning cmd.exe. Enumeration only.

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
  Write-Host "FINDING: SeImpersonatePrivilege present — Potato-family may apply (manual only)"
}

Write-Host ""
Write-Host "Done. Enumeration only — no auto-exploit."

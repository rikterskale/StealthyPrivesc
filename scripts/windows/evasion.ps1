# StealthyPrivesc Windows evasion feature.
# Gated opt-in helper for amsi-bypass, etw-unhook, and av-edr-service.
# Requires authorization, allowlist membership, and --confirm-evasion.

[CmdletBinding(PositionalBinding = $false)]
param(
    [ValidateSet('amsi-bypass', 'etw-unhook', 'av-edr-service')]
    [string]$Technique,
    [switch]$Authorized,
    [switch]$ConfirmEvasion,
    [string]$AllowTechniques,
    [switch]$Json
)

function Test-EvasionAuthorization {
    param(
        [switch]$Authorized,
        [switch]$ConfirmEvasion,
        [string]$AllowTechniques
    )

    $auth = $Authorized -or ($env:STEALTHY_AUTHORIZED -eq "1")
    $confirm = $ConfirmEvasion -or $env:STEALTHY_EVASION_CONFIRMED -eq "1"

    if (-not $auth) {
        throw "Evasion techniques require --authorized or STEALTHY_AUTHORIZED=1"
    }

    if (-not $confirm) {
        throw "Evasion techniques require --confirm-evasion or STEALTHY_EVASION_CONFIRMED=1"
    }

    if ([string]::IsNullOrEmpty($AllowTechniques)) {
        throw "Evasion techniques require --allow-techniques <id>"
    }

    return $true
}

function Test-AllowedTechnique {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Technique,
        [Parameter(Mandatory=$true)]
        [string]$AllowTechniques
    )

    return @($AllowTechniques -split ',' | ForEach-Object { $_.Trim().ToLowerInvariant() }) -contains $Technique
}

function Invoke-EvasionTechnique {
    <#
    .SYNOPSIS
        Runs a gated Windows evasion technique after operator confirmation.

    .PARAMETER Technique
        Family to run: amsi-bypass, etw-unhook, or av-edr-service.

    .PARAMETER ConfirmEvasion
        Extra confirmation flag for evasion techniques

    .PARAMETER AllowTechniques
        Comma-separated list of allowed technique IDs

    .EXAMPLE
        Invoke-EvasionTechnique -Technique amsi-bypass -Authorized -ConfirmEvasion -AllowTechniques "amsi-bypass"
    #>

    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('amsi-bypass', 'etw-unhook', 'av-edr-service')]
        [string]$Technique,

        [switch]$Authorized,

        [switch]$ConfirmEvasion,

        [string]$AllowTechniques
    )

    Test-EvasionAuthorization -Authorized:$Authorized -ConfirmEvasion:$ConfirmEvasion -AllowTechniques $AllowTechniques | Out-Null
    if (-not (Test-AllowedTechnique -Technique $Technique -AllowTechniques $AllowTechniques)) {
        throw "$Technique not in allowlist"
    }

    $executed = $false
    $modifiesControls = $false
    $status = 'ready'
    $message = "Gated evasion technique '$Technique' is authorized for this invocation."
    $observedProducts = @()
    $nextSteps = $null

    switch ($Technique) {
        'amsi-bypass' {
            # Family-specific AMSI actions belong here when implemented.
        }
        'etw-unhook' {
            # Family-specific ETW actions belong here when implemented.
        }
        'av-edr-service' {
            # Read-only product observation only. Never stop/patch/unload sensors.
            $patterns = @(
                'Defender', 'CrowdStrike', 'Falcon', 'Sentinel', 'Carbon Black',
                'Cb Defense', 'Cortex', 'Cybereason', 'Sophos', 'Trend Micro',
                'McAfee', 'Trellix', 'Symantec', 'Norton', 'ESET', 'Bitdefender',
                'Kaspersky', 'Cylance', 'Elastic', 'Tanium', 'Malwarebytes'
            )
            $pattern = ($patterns | ForEach-Object { [regex]::Escape($_) }) -join '|'
            try {
                $services = @(Get-Service -ErrorAction SilentlyContinue |
                    Where-Object {
                        ($_.DisplayName -match $pattern -or $_.Name -match $pattern) -and
                        $_.Name -notin @('mpssvc', 'mpsdrv') -and
                        $_.DisplayName -notmatch 'Firewall'
                    } |
                    Select-Object -First 25 Name, DisplayName, Status)
                foreach ($svc in $services) {
                    $observedProducts += [pscustomobject]@{
                        source = 'service'
                        name = $svc.DisplayName
                        identity = $svc.Name
                        health = [string]$svc.Status
                    }
                }
            } catch {
                # Ignore service enumeration failures; playbook still applies.
            }
            try {
                $providers = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
                    Select-Object -First 25 displayName, productState)
                foreach ($provider in $providers) {
                    if (-not [string]::IsNullOrWhiteSpace($provider.displayName)) {
                        $observedProducts += [pscustomobject]@{
                            source = 'SecurityCenter2'
                            name = [string]$provider.displayName
                            identity = 'AntiVirusProduct'
                            health = [string]$provider.productState
                        }
                    }
                }
            } catch {
                # SecurityCenter2 may be unavailable under constrained hosts.
            }

            $status = if ($observedProducts.Count -gt 0) { 'observed' } else { 'ready' }
            $message = if ($observedProducts.Count -gt 0) {
                "Read-only AV/EDR observation matched $($observedProducts.Count) product signal(s). No controls were modified."
            } else {
                "Gated av-edr-service authorized. No catalogued product signals matched; continue with live-controls playbook."
            }
            $nextSteps = @(
                '1) Re-confirm ROE covers this host and AV/EDR interaction scope.',
                '2) stealthy --authorized live-controls --format json',
                '3) stealthy --authorized enum --plugins windows.endpoint_controls,windows.app_control --format json',
                '4) Correlate Defender/Operational, CodeIntegrity, PowerShell, Sysmon, and vendor-console telemetry with SOC.',
                '5) Prefer signed PE / non-TEMP staging / dispatcher fallbacks / endpoint-bypass + controls --execute.',
                '6) Route exclusions, quarantine restore, or sensor policy changes through approved change control - not this script.',
                '7) Hard stop if tamper protection / production scope / missing SOC owner blocks further work.'
            ) -join ' '
        }
    }

    $result = [ordered]@{
        schema_version = '1'
        feature = 'windows-evasion'
        technique = $Technique
        status = $status
        executed = $executed
        modifies_controls = $modifiesControls
        message = $message
    }
    if ($Technique -eq 'av-edr-service') {
        $result['observed_products'] = @($observedProducts)
        $result['operator_next_steps'] = $nextSteps
    }
    [pscustomobject]$result
}

if ([string]::IsNullOrWhiteSpace($Technique)) {
    throw 'Evasion technique requires -Technique'
}

$result = Invoke-EvasionTechnique `
    -Technique $Technique `
    -Authorized:$Authorized `
    -ConfirmEvasion:$ConfirmEvasion `
    -AllowTechniques $AllowTechniques
if ($Json) {
    $result | ConvertTo-Json -Depth 3 -Compress
} else {
    $result
}

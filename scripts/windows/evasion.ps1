# StealthyPrivesc Windows evasion scaffold feature.
# This shipped module records separately gated operator intent. It never patches
# process memory, changes logging, or starts/stops/suspends security services.

[CmdletBinding(PositionalBinding = $false)]
param(
    [ValidateSet('amsi-bypass', 'etw-unhook', 'av-edr-service')]
    [string]$Technique,
    [switch]$Authorized,
    [switch]$ConfirmEvasion,
    [string]$AllowTechniques,
    [switch]$Json
)

$EVASION_NOTICE = 'Scaffold only: no control-interference implementation is shipped or executed.'

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
        Records a separately gated evasion-family scaffold marker.
    
    .PARAMETER Technique
        Planned family to record: amsi-bypass, etw-unhook, or av-edr-service.
    
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

    [pscustomobject][ordered]@{
        schema_version = '1'
        feature = 'windows-evasion-scaffolds'
        technique = $Technique
        status = 'planned'
        executed = $false
        modifies_controls = $false
        message = $EVASION_NOTICE
    }
}

if ([string]::IsNullOrWhiteSpace($Technique)) {
    throw 'Evasion scaffold requires -Technique'
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

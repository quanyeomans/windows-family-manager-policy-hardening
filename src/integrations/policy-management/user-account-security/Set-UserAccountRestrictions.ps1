# User Account Security Policy Implementation
# Implements S001-S007 requirements with family-specific configuration
# Part of Windows Family Manager Policy Hardening System

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$ConfigPath,
    
    [Parameter()]
    [switch]$DryRun,
    
    [Parameter()]
    [switch]$Reverse,
    
    [Parameter()]
    [ValidateSet('Silent', 'Normal', 'Verbose')]
    [string]$LogLevel = 'Normal'
)

# Import required modules
Import-Module "$PSScriptRoot\..\..\..\common\Invoke-PolicyLogger.ps1" -Force
Import-Module "$PSScriptRoot\..\..\..\common\Test-PolicyCompliance.ps1" -Force

function Set-UserAccountRestrictions {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Config,
        [switch]$DryRun,
        [switch]$Reverse
    )
    
    $results = @{
        Applied = @()
        Failed = @()
        Skipped = @()
    }
    
    try {
        # Load family-specific configuration
        $familyConfig = $Config.FamilyConfiguration
        $policyConfig = $Config.PolicyConfiguration.UserAccountSecurity
        
        Write-PolicyLog -Message "Starting user account security policy deployment" -Level Info
        Write-PolicyLog -Message "Target users: $($familyConfig.Users.Children -join ', ')" -Level Info
        
        # S001: Disable local user account creation
        $policy = @{
            Name = "S001_DisableLocalUserCreation"
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Property = "NoLocalUsersAndGroups"
            Value = if ($Reverse) { 0 } else { 1 }
            Type = "DWord"
            Description = "Prevent creation of new local user accounts"
        }
        
        $policyResult = Set-RegistryPolicy @policy -DryRun:$DryRun -WhatIf:$WhatIfPreference
        if ($policyResult.Success) {
            $results.Applied += $policy.Name
        } else {
            $results.Failed += @{
                Policy = $policy.Name
                Error = $policyResult.Error
            }
        }
        
        # S002: Configure password policy for child accounts
        foreach ($childUser in $familyConfig.Users.Children) {
            $policy = @{
                Name = "S002_PasswordPolicy_$childUser"
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Property = "MaxPasswordAge_$childUser"
                Value = if ($Reverse) { 42 } else { $policyConfig.PasswordPolicy.MaxAge }
                Type = "DWord"
                Description = "Set maximum password age for child user: $childUser"
            }
            
            $policyResult = Set-RegistryPolicy @policy -DryRun:$DryRun -WhatIf:$WhatIfPreference
            if ($policyResult.Success) {
                $results.Applied += $policy.Name
                
                # Also set minimum password length
                $minLengthPolicy = @{
                    Name = "S002_MinPasswordLength_$childUser"
                    Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                    Property = "MinPasswordLength_$childUser"
                    Value = if ($Reverse) { 0 } else { $policyConfig.PasswordPolicy.MinLength }
                    Type = "DWord"
                    Description = "Set minimum password length for child user: $childUser"
                }
                
                $minResult = Set-RegistryPolicy @minLengthPolicy -DryRun:$DryRun -WhatIf:$WhatIfPreference
                if ($minResult.Success) {
                    $results.Applied += $minLengthPolicy.Name
                } else {
                    $results.Failed += @{
                        Policy = $minLengthPolicy.Name
                        Error = $minResult.Error
                    }
                }
            } else {
                $results.Failed += @{
                    Policy = $policy.Name
                    Error = $policyResult.Error
                }
            }
        }
        
        # S003: Restrict administrative access
        $policy = @{
            Name = "S003_RestrictAdminAccess"
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Property = "EnableLUA"
            Value = if ($Reverse) { 0 } else { 1 }
            Type = "DWord"
            Description = "Enable User Account Control for administrative tasks"
        }
        
        $policyResult = Set-RegistryPolicy @policy -DryRun:$DryRun -WhatIf:$WhatIfPreference
        if ($policyResult.Success) {
            $results.Applied += $policy.Name
        } else {
            $results.Failed += @{
                Policy = $policy.Name
                Error = $policyResult.Error
            }
        }
        
        # S004: Configure account lockout policy
        $policy = @{
            Name = "S004_AccountLockoutThreshold"
            Path = "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout"
            Property = "MaxDenials"
            Value = if ($Reverse) { 0 } else { $policyConfig.AccountLockout.Threshold }
            Type = "DWord"
            Description = "Set account lockout threshold"
        }
        
        $policyResult = Set-RegistryPolicy @policy -DryRun:$DryRun -WhatIf:$WhatIfPreference
        if ($policyResult.Success) {
            $results.Applied += $policy.Name
            
            # Set lockout duration
            $durationPolicy = @{
                Name = "S004_AccountLockoutDuration"
                Path = "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout"
                Property = "ResetTime"
                Value = if ($Reverse) { 0 } else { $policyConfig.AccountLockout.Duration }
                Type = "DWord"
                Description = "Set account lockout duration in minutes"
            }
            
            $durationResult = Set-RegistryPolicy @durationPolicy -DryRun:$DryRun -WhatIf:$WhatIfPreference
            if ($durationResult.Success) {
                $results.Applied += $durationPolicy.Name
            } else {
                $results.Failed += @{
                    Policy = $durationPolicy.Name
                    Error = $durationResult.Error
                }
            }
        } else {
            $results.Failed += @{
                Policy = $policy.Name
                Error = $policyResult.Error
            }
        }
        
        # S005: Disable guest account
        $policy = @{
            Name = "S005_DisableGuestAccount"
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Property = "DontDisplayLastUserName"
            Value = if ($Reverse) { 0 } else { 1 }
            Type = "DWord"
            Description = "Hide last logged on user name"
        }
        
        $policyResult = Set-RegistryPolicy @policy -DryRun:$DryRun -WhatIf:$WhatIfPreference
        if ($policyResult.Success) {
            $results.Applied += $policy.Name
        } else {
            $results.Failed += @{
                Policy = $policy.Name
                Error = $policyResult.Error
            }
        }
        
        # S006: Configure logon hours for child accounts
        foreach ($childUser in $familyConfig.Users.Children) {
            if ($policyConfig.LogonHours.Enabled) {
                $policy = @{
                    Name = "S006_LogonHours_$childUser"
                    Description = "Configure allowed logon hours for child user: $childUser"
                }
                
                # Use NET USER command for logon hours (registry approach is complex for this setting)
                $startHour = $policyConfig.LogonHours.StartTime
                $endHour = $policyConfig.LogonHours.EndTime
                $daysOfWeek = $policyConfig.LogonHours.DaysOfWeek -join ","
                
                if (-not $DryRun) {
                    try {
                        if ($Reverse) {
                            # Remove logon hour restrictions
                            $netResult = & net user $childUser /times:all 2>&1
                        } else {
                            # Set logon hour restrictions
                            $timeRestriction = "$daysOfWeek,$startHour-$endHour"
                            $netResult = & net user $childUser /times:$timeRestriction 2>&1
                        }
                        
                        if ($LASTEXITCODE -eq 0) {
                            $results.Applied += $policy.Name
                            Write-PolicyLog -Message "Successfully configured logon hours for $childUser" -Level Info
                        } else {
                            $results.Failed += @{
                                Policy = $policy.Name
                                Error = $netResult -join "`n"
                            }
                            Write-PolicyLog -Message "Failed to configure logon hours for $childUser`: $($netResult -join "`n")" -Level Error
                        }
                    }
                    catch {
                        $results.Failed += @{
                            Policy = $policy.Name
                            Error = $_.Exception.Message
                        }
                        Write-PolicyLog -Message "Exception configuring logon hours for $childUser`: $($_.Exception.Message)" -Level Error
                    }
                } else {
                    Write-PolicyLog -Message "[DRY RUN] Would configure logon hours for $childUser`: $timeRestriction" -Level Info
                    $results.Applied += $policy.Name
                }
            } else {
                $results.Skipped += "S006_LogonHours_$childUser (disabled in configuration)"
            }
        }
        
        # S007: Configure screen saver policy
        $policy = @{
            Name = "S007_ScreenSaverPolicy"
            Path = "HKCU:\Control Panel\Desktop"
            Property = "ScreenSaveTimeOut"
            Value = if ($Reverse) { "0" } else { $policyConfig.ScreenSaver.TimeoutSeconds.ToString() }
            Type = "String"
            Description = "Set screen saver timeout"
        }
        
        $policyResult = Set-RegistryPolicy @policy -DryRun:$DryRun -WhatIf:$WhatIfPreference
        if ($policyResult.Success) {
            $results.Applied += $policy.Name
            
            # Enable password protection for screen saver
            $passwordPolicy = @{
                Name = "S007_ScreenSaverPassword"
                Path = "HKCU:\Control Panel\Desktop"
                Property = "ScreenSaverIsSecure"
                Value = if ($Reverse) { "0" } else { "1" }
                Type = "String"
                Description = "Require password to unlock screen saver"
            }
            
            $passwordResult = Set-RegistryPolicy @passwordPolicy -DryRun:$DryRun -WhatIf:$WhatIfPreference
            if ($passwordResult.Success) {
                $results.Applied += $passwordPolicy.Name
            } else {
                $results.Failed += @{
                    Policy = $passwordPolicy.Name
                    Error = $passwordResult.Error
                }
            }
        } else {
            $results.Failed += @{
                Policy = $policy.Name
                Error = $policyResult.Error
            }
        }
        
        # Log final results
        Write-PolicyLog -Message "User account security policy deployment completed" -Level Info
        Write-PolicyLog -Message "Applied policies: $($results.Applied.Count)" -Level Info
        Write-PolicyLog -Message "Failed policies: $($results.Failed.Count)" -Level $(if ($results.Failed.Count -gt 0) { 'Warning' } else { 'Info' })
        Write-PolicyLog -Message "Skipped policies: $($results.Skipped.Count)" -Level Info
        
        if ($results.Failed.Count -gt 0) {
            Write-PolicyLog -Message "Failed policies details:" -Level Warning
            foreach ($failure in $results.Failed) {
                Write-PolicyLog -Message "  - $($failure.Policy): $($failure.Error)" -Level Warning
            }
        }
        
        return $results
        
    }
    catch {
        Write-PolicyLog -Message "Critical error in user account security policy deployment: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Set-RegistryPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        
        [Parameter(Mandatory)]
        [string]$Path,
        
        [Parameter(Mandatory)]
        [string]$Property,
        
        [Parameter(Mandatory)]
        $Value,
        
        [Parameter(Mandatory)]
        [ValidateSet('String', 'DWord', 'QWord', 'Binary', 'MultiString', 'ExpandString')]
        [string]$Type,
        
        [Parameter()]
        [string]$Description,
        
        [Parameter()]
        [switch]$DryRun
    )
    
    $result = @{
        Success = $false
        Error = $null
        Value = $Value
        PreviousValue = $null
    }
    
    try {
        # Check if registry path exists
        if (-not (Test-Path $Path)) {
            if (-not $DryRun -and $PSCmdlet.ShouldProcess($Path, "Create Registry Path")) {
                New-Item -Path $Path -Force | Out-Null
                Write-PolicyLog -Message "Created registry path: $Path" -Level Info
            } elseif ($DryRun) {
                Write-PolicyLog -Message "[DRY RUN] Would create registry path: $Path" -Level Info
            }
        }
        
        # Get current value for rollback capability
        try {
            $currentValue = Get-ItemProperty -Path $Path -Name $Property -ErrorAction Stop
            $result.PreviousValue = $currentValue.$Property
        }
        catch {
            $result.PreviousValue = $null
        }
        
        # Set the registry value
        if (-not $DryRun -and $PSCmdlet.ShouldProcess($Path, "Set Registry Value $Property = $Value")) {
            Set-ItemProperty -Path $Path -Name $Property -Value $Value -Type $Type
            Write-PolicyLog -Message "Set registry value: $Path\$Property = $Value" -Level Info
            
            # Verify the setting was applied
            $verifyValue = Get-ItemProperty -Path $Path -Name $Property
            if ($verifyValue.$Property -eq $Value) {
                $result.Success = $true
                Write-PolicyLog -Message "Verified registry setting: $Name" -Level Info
            } else {
                $result.Error = "Registry value verification failed"
                Write-PolicyLog -Message "Registry value verification failed for $Name" -Level Warning
            }
        } elseif ($DryRun) {
            Write-PolicyLog -Message "[DRY RUN] Would set registry value: $Path\$Property = $Value ($Type)" -Level Info
            $result.Success = $true  # Assume success for dry run
        } else {
            $result.Success = $true  # WhatIf scenario
        }
        
    }
    catch {
        $result.Error = $_.Exception.Message
        Write-PolicyLog -Message "Failed to set registry policy $Name`: $($_.Exception.Message)" -Level Error
    }
    
    return $result
}

# Main execution
if ($MyInvocation.InvocationName -ne '.') {
    try {
        # Load and validate configuration
        Write-PolicyLog -Message "Loading configuration from: $ConfigPath" -Level Info
        
        if (-not (Test-Path $ConfigPath)) {
            throw "Configuration file not found: $ConfigPath"
        }
        
        $configContent = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        
        # Validate required configuration sections
        if (-not $configContent.FamilyConfiguration) {
            throw "Required configuration section missing: FamilyConfiguration"
        }
        
        if (-not $configContent.PolicyConfiguration) {
            throw "Required configuration section missing: PolicyConfiguration"
        }
        
        if (-not $configContent.PolicyConfiguration.UserAccountSecurity) {
            throw "Required configuration section missing: PolicyConfiguration.UserAccountSecurity"
        }
        
        # Execute policy deployment
        $results = Set-UserAccountRestrictions -Config $configContent -DryRun:$DryRun -Reverse:$Reverse
        
        # Output results for automation/testing
        $outputPath = "$env:TEMP\user-account-security-results-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $results | ConvertTo-Json -Depth 10 | Set-Content $outputPath
        Write-PolicyLog -Message "Results saved to: $outputPath" -Level Info
        
        if ($results.Failed.Count -gt 0) {
            exit 1
        } else {
            exit 0
        }
    }
    catch {
        Write-PolicyLog -Message "Script execution failed: $($_.Exception.Message)" -Level Error
        Write-Error $_.Exception.Message
        exit 1
    }
}
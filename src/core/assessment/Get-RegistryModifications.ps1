# Registry Modification Audit - B001 Implementation
# Analyzes Windows Registry modifications for security risks and bypass detection

param(
    [Parameter()]
    [switch]$Verbose = $false
)

function Get-RegistryModifications {
    <#
    .SYNOPSIS
    Analyzes Windows Registry modifications for security vulnerabilities and bypass attempts.
    
    .DESCRIPTION
    Implements requirement B001 by auditing registry modifications that could indicate:
    - UAC bypass attempts
    - Security policy circumvention
    - Unauthorized system modifications
    - Time control bypass mechanisms
    
    .PARAMETER Verbose
    Enable verbose output for detailed analysis
    #>
    
    try {
        Write-Verbose "Starting registry modification analysis..."
        
        $findings = @()
        $securityScore = 100
        
        # Critical registry keys to monitor for modifications
        $criticalKeys = @(
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Name = "UAC and Security Policies"
                RiskLevel = "CRITICAL"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
                Name = "Windows Logon Settings"  
                RiskLevel = "HIGH"
            },
            @{
                Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Themes"
                Name = "Visual Themes Service"
                RiskLevel = "MEDIUM"
            },
            @{
                Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"
                Name = "User Policies"
                RiskLevel = "HIGH"
            },
            @{
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
                Name = "Windows Update Policies"
                RiskLevel = "HIGH"
            }
        )
        
        # High-risk registry modifications that indicate bypass attempts
        $bypassIndicators = @(
            @{ Key = "EnableLUA"; Value = 0; Description = "UAC completely disabled" },
            @{ Key = "ConsentPromptBehaviorAdmin"; Value = 0; Description = "Admin approval mode disabled" },
            @{ Key = "PromptOnSecureDesktop"; Value = 0; Description = "Secure desktop disabled" },
            @{ Key = "FilterAdministratorToken"; Value = 0; Description = "Built-in admin filtering disabled" },
            @{ Key = "DisableRegistryTools"; Value = 1; Description = "Registry editing disabled (control bypass)" },
            @{ Key = "DisableTaskMgr"; Value = 1; Description = "Task Manager disabled (monitoring bypass)" }
        )
        
        # Check each critical registry location
        foreach ($keyInfo in $criticalKeys) {
            Write-Verbose "Analyzing registry key: $($keyInfo.Path)"
            
            if (Test-Path $keyInfo.Path) {
                try {
                    $regKey = Get-ItemProperty -Path $keyInfo.Path -ErrorAction SilentlyContinue
                    
                    if ($regKey) {
                        # Check for bypass indicators in this key
                        foreach ($indicator in $bypassIndicators) {
                            $propertyValue = $regKey.PSObject.Properties[$indicator.Key]
                            
                            if ($propertyValue -and $propertyValue.Value -eq $indicator.Value) {
                                $finding = @{
                                    category = "B001_registry_modification"
                                    severity = switch ($keyInfo.RiskLevel) {
                                        "CRITICAL" { "CRITICAL" }
                                        "HIGH" { "HIGH" }
                                        "MEDIUM" { "MEDIUM" }
                                        default { "LOW" }
                                    }
                                    finding = "Registry bypass detected: $($indicator.Description)"
                                    details = @{
                                        registry_path = $keyInfo.Path
                                        property_name = $indicator.Key
                                        current_value = $propertyValue.Value
                                        risk_description = $indicator.Description
                                        key_category = $keyInfo.Name
                                    }
                                    remediation = "Restore registry key to secure default value"
                                    impact = "System security bypass capability"
                                }
                                
                                $findings += $finding
                                
                                # Reduce security score based on severity
                                $scoreReduction = switch ($keyInfo.RiskLevel) {
                                    "CRITICAL" { 25 }
                                    "HIGH" { 15 }
                                    "MEDIUM" { 10 }
                                    default { 5 }
                                }
                                $securityScore -= $scoreReduction
                                
                                Write-Warning "Registry bypass detected: $($indicator.Description) at $($keyInfo.Path)"
                            }
                        }
                        
                        # Check for unusual registry modifications (non-standard values)
                        $standardChecks = @(
                            @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Property = "EnableLUA"; Expected = 1 },
                            @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Property = "ConsentPromptBehaviorAdmin"; Expected = @(1,2,5) },
                            @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Property = "PromptOnSecureDesktop"; Expected = 1 }
                        )
                        
                        foreach ($check in $standardChecks) {
                            if ($keyInfo.Path -eq $check.Path) {
                                $actualValue = $regKey.PSObject.Properties[$check.Property]
                                if ($actualValue) {
                                    $isValid = if ($check.Expected -is [array]) {
                                        $actualValue.Value -in $check.Expected
                                    } else {
                                        $actualValue.Value -eq $check.Expected
                                    }
                                    
                                    if (-not $isValid) {
                                        $finding = @{
                                            category = "B001_registry_modification"
                                            severity = "MEDIUM"
                                            finding = "Non-standard registry value detected"
                                            details = @{
                                                registry_path = $check.Path
                                                property_name = $check.Property
                                                current_value = $actualValue.Value
                                                expected_value = $check.Expected
                                                risk_description = "Registry value deviates from security baseline"
                                            }
                                            remediation = "Review and correct registry value to meet security standards"
                                            impact = "Potential security policy weakening"
                                        }
                                        
                                        $findings += $finding
                                        $securityScore -= 8
                                        
                                        Write-Verbose "Non-standard registry value: $($check.Property) = $($actualValue.Value)"
                                    }
                                }
                            }
                        }
                    }
                } catch {
                    Write-Warning "Error accessing registry key $($keyInfo.Path): $($_.Exception.Message)"
                    
                    $finding = @{
                        category = "B001_registry_modification"
                        severity = "LOW"
                        finding = "Registry key access error"
                        details = @{
                            registry_path = $keyInfo.Path
                            error_message = $_.Exception.Message
                            risk_description = "Unable to verify registry security settings"
                        }
                        remediation = "Verify registry key permissions and accessibility"
                        impact = "Incomplete security assessment"
                    }
                    
                    $findings += $finding
                    $securityScore -= 3
                }
            } else {
                Write-Verbose "Registry key not found: $($keyInfo.Path)"
                
                # Missing critical registry keys can indicate system modification
                if ($keyInfo.RiskLevel -eq "CRITICAL") {
                    $finding = @{
                        category = "B001_registry_modification"
                        severity = "HIGH"
                        finding = "Critical registry key missing"
                        details = @{
                            registry_path = $keyInfo.Path
                            key_category = $keyInfo.Name
                            risk_description = "Critical system registry key not found"
                        }
                        remediation = "Investigate why critical registry key is missing and restore if necessary"
                        impact = "System security configuration incomplete"
                    }
                    
                    $findings += $finding
                    $securityScore -= 20
                }
            }
        }
        
        # Ensure minimum score
        $securityScore = [Math]::Max($securityScore, 0)
        
        Write-Verbose "Registry analysis complete. Security score: $securityScore"
        
        return @{
            security_score = $securityScore
            findings = $findings
            assessment_summary = @{
                total_keys_analyzed = $criticalKeys.Count
                bypass_indicators_found = ($findings | Where-Object { $_.details.risk_description -like "*bypass*" }).Count
                critical_findings = ($findings | Where-Object { $_.severity -eq "CRITICAL" }).Count
                high_findings = ($findings | Where-Object { $_.severity -eq "HIGH" }).Count
                medium_findings = ($findings | Where-Object { $_.severity -eq "MEDIUM" }).Count
                low_findings = ($findings | Where-Object { $_.severity -eq "LOW" }).Count
            }
        }
        
    } catch {
        Write-Error "Registry modification analysis failed: $($_.Exception.Message)"
        
        return @{
            security_score = 0
            findings = @(
                @{
                    category = "B001_registry_modification"
                    severity = "CRITICAL"
                    finding = "Registry analysis failed"
                    details = @{
                        error_message = $_.Exception.Message
                        risk_description = "Unable to complete registry security assessment"
                    }
                    remediation = "Investigate registry analysis failure and retry assessment"
                    impact = "System security status unknown"
                }
            )
            assessment_summary = @{
                total_keys_analyzed = 0
                bypass_indicators_found = 0
                critical_findings = 1
                high_findings = 0
                medium_findings = 0
                low_findings = 0
            }
        }
    }
}

# Execute if called directly
if ($MyInvocation.InvocationName -eq $MyInvocation.MyCommand.Name) {
    Get-RegistryModifications -Verbose:$Verbose | ConvertTo-Json -Depth 10
}
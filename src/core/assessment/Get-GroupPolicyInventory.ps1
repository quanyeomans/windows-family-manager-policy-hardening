# Group Policy Security Inventory - B003 Implementation
# Analyzes Windows Group Policy settings for security compliance and bypass detection

param(
    [Parameter()]
    [switch]$Verbose = $false
)

function Get-GroupPolicyInventory {
    <#
    .SYNOPSIS
    Inventories Windows Group Policy settings and analyzes security compliance.
    
    .DESCRIPTION
    Implements requirement B003 by analyzing Group Policy configurations for:
    - Security policy compliance
    - Policy bypass attempts
    - Missing critical security policies
    - Group Policy Object (GPO) integrity
    
    .PARAMETER Verbose
    Enable verbose output for detailed analysis
    #>
    
    try {
        Write-Verbose "Starting Group Policy security inventory..."
        
        $findings = @()
        $securityScore = 100
        
        # Critical Group Policy categories to assess
        $criticalPolicies = @(
            @{
                Category = "Account Policies"
                Path = "Computer Configuration\Windows Settings\Security Settings\Account Policies"
                RiskLevel = "HIGH"
            },
            @{
                Category = "Local Policies"
                Path = "Computer Configuration\Windows Settings\Security Settings\Local Policies"
                RiskLevel = "HIGH"
            },
            @{
                Category = "Windows Update"
                Path = "Computer Configuration\Administrative Templates\Windows Components\Windows Update"
                RiskLevel = "MEDIUM"
            },
            @{
                Category = "User Account Control"
                Path = "Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options"
                RiskLevel = "CRITICAL"
            },
            @{
                Category = "Audit Policies"
                Path = "Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy"
                RiskLevel = "MEDIUM"
            }
        )
        
        # Check if Group Policy tools are available
        $gpResult = $null
        try {
            # Try to get Group Policy results using gpresult
            $gpResultOutput = & gpresult /r /scope:computer 2>&1
            $gpResult = $gpResultOutput -join "`n"
            Write-Verbose "Group Policy results obtained via gpresult"
        } catch {
            Write-Verbose "gpresult not available or failed: $($_.Exception.Message)"
        }
        
        # Analyze security-related registry settings that reflect Group Policy
        $securityPolicyKeys = @(
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Policies = @(
                    @{ Name = "EnableLUA"; Expected = 1; Description = "User Account Control enabled" },
                    @{ Name = "ConsentPromptBehaviorAdmin"; Expected = @(1,2,5); Description = "Admin approval mode" },
                    @{ Name = "PromptOnSecureDesktop"; Expected = 1; Description = "Secure desktop for UAC prompts" }
                )
                Category = "User Account Control"
                RiskLevel = "CRITICAL"
            },
            @{
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
                Policies = @(
                    @{ Name = "DisableWindowsUpdateAccess"; Expected = 0; Description = "Windows Update access allowed" },
                    @{ Name = "SetDisableUXWUAccess"; Expected = 0; Description = "Windows Update UX access allowed" }
                )
                Category = "Windows Update"
                RiskLevel = "HIGH"
            },
            @{
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
                Policies = @(
                    @{ Name = "NoAutoUpdate"; Expected = 0; Description = "Automatic updates enabled" },
                    @{ Name = "AUOptions"; Expected = @(2,3,4); Description = "Automatic update configuration" }
                )
                Category = "Windows Update"
                RiskLevel = "HIGH"
            },
            @{
                Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
                Policies = @(
                    @{ Name = "ScreenSaveTimeOut"; Expected = @("600","900","1800"); Description = "Screen saver timeout" }
                )
                Category = "Desktop Security"
                RiskLevel = "LOW"
            }
        )
        
        # Check each security policy registry location
        foreach ($keyInfo in $securityPolicyKeys) {
            Write-Verbose "Analyzing Group Policy registry: $($keyInfo.Path)"
            
            if (Test-Path $keyInfo.Path) {
                try {
                    $regKey = Get-ItemProperty -Path $keyInfo.Path -ErrorAction SilentlyContinue
                    
                    if ($regKey) {
                        foreach ($policy in $keyInfo.Policies) {
                            $propertyValue = $regKey.PSObject.Properties[$policy.Name]
                            
                            if ($propertyValue) {
                                $actualValue = $propertyValue.Value
                                $isCompliant = if ($policy.Expected -is [array]) {
                                    $actualValue -in $policy.Expected -or $actualValue.ToString() -in $policy.Expected
                                } else {
                                    $actualValue -eq $policy.Expected -or $actualValue.ToString() -eq $policy.Expected.ToString()
                                }
                                
                                if (-not $isCompliant) {
                                    $severity = switch ($keyInfo.RiskLevel) {
                                        "CRITICAL" { "CRITICAL" }
                                        "HIGH" { "HIGH" }
                                        "MEDIUM" { "MEDIUM" }
                                        default { "LOW" }
                                    }
                                    
                                    $finding = @{
                                        category = "B003_group_policy_compliance"
                                        severity = $severity
                                        finding = "Group Policy non-compliance detected"
                                        details = @{
                                            policy_category = $keyInfo.Category
                                            policy_name = $policy.Name
                                            policy_description = $policy.Description
                                            registry_path = $keyInfo.Path
                                            current_value = $actualValue
                                            expected_value = $policy.Expected
                                            risk_description = "Group Policy setting does not meet security baseline"
                                        }
                                        remediation = "Configure Group Policy to meet security requirements: $($policy.Description)"
                                        impact = "Security policy enforcement weakened"
                                    }
                                    
                                    $findings += $finding
                                    
                                    $scoreReduction = switch ($severity) {
                                        "CRITICAL" { 15 }
                                        "HIGH" { 10 }
                                        "MEDIUM" { 7 }
                                        default { 3 }
                                    }
                                    $securityScore -= $scoreReduction
                                    
                                    Write-Warning "Group Policy non-compliance: $($policy.Description) = $actualValue (Expected: $($policy.Expected))"
                                } else {
                                    Write-Verbose "Group Policy compliant: $($policy.Description) = $actualValue"
                                }
                            } else {
                                # Policy not set - could indicate missing Group Policy
                                $finding = @{
                                    category = "B003_group_policy_compliance"
                                    severity = "MEDIUM"
                                    finding = "Group Policy setting not configured"
                                    details = @{
                                        policy_category = $keyInfo.Category
                                        policy_name = $policy.Name
                                        policy_description = $policy.Description
                                        registry_path = $keyInfo.Path
                                        risk_description = "Required security policy is not configured"
                                    }
                                    remediation = "Configure missing Group Policy setting: $($policy.Description)"
                                    impact = "Security policy not enforced"
                                }
                                
                                $findings += $finding
                                $securityScore -= 8
                                
                                Write-Verbose "Missing Group Policy setting: $($policy.Name)"
                            }
                        }
                    }
                } catch {
                    Write-Warning "Error accessing Group Policy registry $($keyInfo.Path): $($_.Exception.Message)"
                    
                    $finding = @{
                        category = "B003_group_policy_compliance"
                        severity = "LOW"
                        finding = "Group Policy registry access error"
                        details = @{
                            policy_category = $keyInfo.Category
                            registry_path = $keyInfo.Path
                            error_message = $_.Exception.Message
                            risk_description = "Unable to verify Group Policy settings"
                        }
                        remediation = "Investigate Group Policy registry access issues"
                        impact = "Incomplete Group Policy assessment"
                    }
                    
                    $findings += $finding
                    $securityScore -= 3
                }
            } else {
                # Missing Group Policy registry keys may indicate no policies applied
                if ($keyInfo.RiskLevel -in @("CRITICAL", "HIGH")) {
                    $finding = @{
                        category = "B003_group_policy_compliance"
                        severity = "MEDIUM"
                        finding = "Group Policy registry key missing"
                        details = @{
                            policy_category = $keyInfo.Category
                            registry_path = $keyInfo.Path
                            risk_description = "Group Policy registry key not found - policies may not be applied"
                        }
                        remediation = "Verify Group Policy application and domain membership"
                        impact = "Group Policy enforcement may be inactive"
                    }
                    
                    $findings += $finding
                    $securityScore -= 5
                    
                    Write-Verbose "Missing Group Policy registry key: $($keyInfo.Path)"
                }
            }
        }
        
        # Check for Group Policy bypass indicators
        $bypassIndicators = @(
            @{ 
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" 
                Key = "DisableGPO" 
                Value = 1 
                Description = "Group Policy processing disabled" 
            },
            @{ 
                Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\System" 
                Key = "DisableRegistryTools" 
                Value = 0 
                Description = "Registry tools restriction bypassed" 
            },
            @{ 
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" 
                Key = "DisableTaskMgr" 
                Value = 0 
                Description = "Task Manager restriction bypassed" 
            }
        )
        
        foreach ($indicator in $bypassIndicators) {
            if (Test-Path $indicator.Path) {
                try {
                    $regValue = Get-ItemProperty -Path $indicator.Path -Name $indicator.Key -ErrorAction SilentlyContinue
                    
                    if ($regValue -and $regValue.($indicator.Key) -eq $indicator.Value) {
                        $finding = @{
                            category = "B003_group_policy_compliance"
                            severity = "HIGH"
                            finding = "Group Policy bypass detected"
                            details = @{
                                registry_path = $indicator.Path
                                registry_key = $indicator.Key
                                current_value = $regValue.($indicator.Key)
                                bypass_description = $indicator.Description
                                risk_description = "Group Policy enforcement has been bypassed"
                            }
                            remediation = "Remove Group Policy bypass and restore proper enforcement"
                            impact = "Security policies can be circumvented"
                        }
                        
                        $findings += $finding
                        $securityScore -= 20
                        
                        Write-Warning "Group Policy bypass detected: $($indicator.Description)"
                    }
                } catch {
                    Write-Verbose "Error checking bypass indicator $($indicator.Key): $($_.Exception.Message)"
                }
            }
        }
        
        # Check for local Group Policy processing
        try {
            $gpProcessingKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            if (Test-Path $gpProcessingKey) {
                $gpProcessing = Get-ItemProperty -Path $gpProcessingKey -ErrorAction SilentlyContinue
                
                if ($gpProcessing) {
                    # Check if Group Policy caching is disabled (potential bypass)
                    if ($gpProcessing.DisableGPOQuickRefresh -eq 1) {
                        $finding = @{
                            category = "B003_group_policy_compliance"
                            severity = "MEDIUM"
                            finding = "Group Policy quick refresh disabled"
                            details = @{
                                registry_path = $gpProcessingKey
                                setting = "DisableGPOQuickRefresh"
                                current_value = 1
                                risk_description = "Group Policy quick refresh is disabled"
                            }
                            remediation = "Enable Group Policy quick refresh for timely policy updates"
                            impact = "Delayed security policy enforcement"
                        }
                        
                        $findings += $finding
                        $securityScore -= 5
                    }
                }
            }
        } catch {
            Write-Verbose "Error checking Group Policy processing settings: $($_.Exception.Message)"
        }
        
        # Ensure minimum score
        $securityScore = [Math]::Max($securityScore, 0)
        
        Write-Verbose "Group Policy analysis complete. Security score: $securityScore"
        
        return @{
            security_score = $securityScore
            findings = $findings
            assessment_summary = @{
                policy_categories_analyzed = $criticalPolicies.Count
                compliance_violations = ($findings | Where-Object { $_.finding -like "*non-compliance*" }).Count
                bypass_indicators_found = ($findings | Where-Object { $_.finding -like "*bypass*" }).Count
                missing_policies = ($findings | Where-Object { $_.finding -like "*not configured*" }).Count
                critical_findings = ($findings | Where-Object { $_.severity -eq "CRITICAL" }).Count
                high_findings = ($findings | Where-Object { $_.severity -eq "HIGH" }).Count
                medium_findings = ($findings | Where-Object { $_.severity -eq "MEDIUM" }).Count
                low_findings = ($findings | Where-Object { $_.severity -eq "LOW" }).Count
            }
        }
        
    } catch {
        Write-Error "Group Policy inventory failed: $($_.Exception.Message)"
        
        return @{
            security_score = 0
            findings = @(
                @{
                    category = "B003_group_policy_compliance"
                    severity = "CRITICAL"
                    finding = "Group Policy analysis failed"
                    details = @{
                        error_message = $_.Exception.Message
                        risk_description = "Unable to complete Group Policy security assessment"
                    }
                    remediation = "Investigate Group Policy analysis failure and retry assessment"
                    impact = "Group Policy security status unknown"
                }
            )
            assessment_summary = @{
                policy_categories_analyzed = 0
                compliance_violations = 0
                bypass_indicators_found = 0
                missing_policies = 0
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
    Get-GroupPolicyInventory -Verbose:$Verbose | ConvertTo-Json -Depth 10
}
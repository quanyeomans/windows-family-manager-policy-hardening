# User Account Security Inventory - B002 Implementation
# Analyzes Windows user accounts for security risks and privilege escalation vectors

param(
    [Parameter()]
    [switch]$Verbose = $false
)

function Get-UserAccountInventory {
    <#
    .SYNOPSIS
    Inventories Windows user accounts and analyzes security risks.
    
    .DESCRIPTION
    Implements requirement B002 by analyzing user accounts for:
    - Excessive administrative privileges
    - Weak password policies
    - Account security misconfigurations
    - Unauthorized accounts and privilege escalation risks
    
    .PARAMETER Verbose
    Enable verbose output for detailed analysis
    #>
    
    try {
        Write-Verbose "Starting user account security inventory..."
        
        $findings = @()
        $securityScore = 100
        
        # Get all local user accounts
        $localUsers = Get-LocalUser -ErrorAction SilentlyContinue
        
        if (-not $localUsers) {
            Write-Warning "Unable to retrieve local user accounts. Using Get-WmiObject fallback."
            $localUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue
        }
        
        # Get local administrators group members
        $adminGroupMembers = @()
        try {
            $adminGroup = Get-LocalGroup -Name "Administrators" -ErrorAction SilentlyContinue
            if ($adminGroup) {
                $adminGroupMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | 
                                   Where-Object { $_.ObjectClass -eq "User" } |
                                   ForEach-Object { $_.Name -replace ".*\\", "" }
            }
        } catch {
            Write-Verbose "Error accessing Administrators group: $($_.Exception.Message)"
        }
        
        Write-Verbose "Found $($localUsers.Count) local user accounts"
        Write-Verbose "Found $($adminGroupMembers.Count) users in Administrators group"
        
        # Analyze each user account
        foreach ($user in $localUsers) {
            $userName = if ($user.Name) { $user.Name } else { $user.Caption -replace ".*\\", "" }
            $userSID = if ($user.SID) { $user.SID.Value } else { $user.SID }
            
            Write-Verbose "Analyzing user account: $userName"
            
            # Check if user is administrator
            $isAdmin = $userName -in $adminGroupMembers
            
            # Well-known administrative accounts that should be monitored
            $wellKnownAdminAccounts = @("Administrator", "DefaultAccount", "Guest")
            $isWellKnownAccount = $userName -in $wellKnownAdminAccounts
            
            # Account status analysis
            $accountEnabled = if ($user.Enabled -ne $null) { $user.Enabled } else { -not $user.Disabled }
            $passwordRequired = if ($user.PasswordRequired -ne $null) { $user.PasswordRequired } else { $true }
            $passwordExpires = if ($user.PasswordExpires -ne $null) { $user.PasswordExpires } else { $true }
            
            # High-risk account configurations
            if ($isAdmin -and $accountEnabled) {
                # Administrative account that is enabled
                $riskLevel = if ($isWellKnownAccount) { "CRITICAL" } else { "HIGH" }
                
                $finding = @{
                    category = "B002_user_account_security"
                    severity = $riskLevel
                    finding = "Administrative account analysis"
                    details = @{
                        username = $userName
                        user_sid = $userSID
                        account_enabled = $accountEnabled
                        is_administrator = $isAdmin
                        is_well_known = $isWellKnownAccount
                        password_required = $passwordRequired
                        password_expires = $passwordExpires
                        risk_description = if ($isWellKnownAccount) { 
                            "Well-known administrative account is enabled and active"
                        } else { 
                            "Local administrative account with potential security risks" 
                        }
                    }
                    remediation = if ($isWellKnownAccount) {
                        "Consider disabling well-known administrative accounts and using named admin accounts"
                    } else {
                        "Review administrative privileges and ensure account follows security best practices"
                    }
                    impact = "Potential privilege escalation vector"
                }
                
                $findings += $finding
                
                $scoreReduction = if ($riskLevel -eq "CRITICAL") { 20 } else { 10 }
                $securityScore -= $scoreReduction
                
                Write-Verbose "Administrative account found: $userName (Risk: $riskLevel)"
            }
            
            # Password security analysis
            if ($accountEnabled -and -not $passwordRequired) {
                $finding = @{
                    category = "B002_user_account_security"
                    severity = "HIGH"
                    finding = "Account with no password requirement"
                    details = @{
                        username = $userName
                        user_sid = $userSID
                        password_required = $passwordRequired
                        is_administrator = $isAdmin
                        risk_description = "Account does not require a password"
                    }
                    remediation = "Enable password requirement for all user accounts"
                    impact = "Unauthorized access without authentication"
                }
                
                $findings += $finding
                $securityScore -= 15
                
                Write-Warning "Account without password requirement: $userName"
            }
            
            if ($accountEnabled -and -not $passwordExpires -and -not $isWellKnownAccount) {
                $finding = @{
                    category = "B002_user_account_security"
                    severity = "MEDIUM"
                    finding = "Account with non-expiring password"
                    details = @{
                        username = $userName
                        user_sid = $userSID
                        password_expires = $passwordExpires
                        is_administrator = $isAdmin
                        risk_description = "Account password set to never expire"
                    }
                    remediation = "Configure password expiration policy for user accounts"
                    impact = "Long-term password exposure risk"
                }
                
                $findings += $finding
                $securityScore -= 5
                
                Write-Verbose "Non-expiring password: $userName"
            }
            
            # Guest account analysis
            if ($userName -eq "Guest" -and $accountEnabled) {
                $finding = @{
                    category = "B002_user_account_security"
                    severity = "CRITICAL"
                    finding = "Guest account is enabled"
                    details = @{
                        username = $userName
                        user_sid = $userSID
                        account_enabled = $accountEnabled
                        risk_description = "Built-in Guest account is enabled"
                    }
                    remediation = "Disable the Guest account immediately"
                    impact = "Unauthorized anonymous access to system"
                }
                
                $findings += $finding
                $securityScore -= 25
                
                Write-Warning "Guest account is enabled - critical security risk"
            }
        }
        
        # Analyze administrator group membership
        $adminCount = $adminGroupMembers.Count
        if ($adminCount -gt 2) {
            $finding = @{
                category = "B002_user_account_security"
                severity = "MEDIUM"
                finding = "Excessive administrative accounts"
                details = @{
                    admin_account_count = $adminCount
                    admin_accounts = $adminGroupMembers
                    risk_description = "Too many accounts have administrative privileges"
                }
                remediation = "Review and reduce the number of administrative accounts"
                impact = "Increased attack surface and privilege escalation risk"
            }
            
            $findings += $finding
            $securityScore -= 10
            
            Write-Verbose "Excessive admin accounts detected: $adminCount accounts"
        }
        
        # Check for accounts with suspicious characteristics
        $suspiciousAccounts = $localUsers | Where-Object { 
            $accountName = if ($_.Name) { $_.Name } else { $_.Caption -replace ".*\\", "" }
            # Look for accounts with unusual naming patterns or characteristics
            $accountName -match "^\$" -or  # Accounts starting with $
            $accountName -match "^[0-9]+$" -or  # Numeric-only account names
            $accountName.Length -eq 1  # Single character account names
        }
        
        foreach ($suspiciousAccount in $suspiciousAccounts) {
            $accountName = if ($suspiciousAccount.Name) { $suspiciousAccount.Name } else { $suspiciousAccount.Caption -replace ".*\\", "" }
            
            $finding = @{
                category = "B002_user_account_security"
                severity = "LOW"
                finding = "Suspicious account naming pattern"
                details = @{
                    username = $accountName
                    user_sid = if ($suspiciousAccount.SID) { $suspiciousAccount.SID.Value } else { $suspiciousAccount.SID }
                    risk_description = "Account has unusual naming pattern that may indicate system modification"
                }
                remediation = "Investigate the purpose and origin of this account"
                impact = "Potential unauthorized account creation"
            }
            
            $findings += $finding
            $securityScore -= 3
        }
        
        # Ensure minimum score
        $securityScore = [Math]::Max($securityScore, 0)
        
        Write-Verbose "User account analysis complete. Security score: $securityScore"
        
        return @{
            security_score = $securityScore
            findings = $findings
            assessment_summary = @{
                total_accounts = $localUsers.Count
                admin_accounts = $adminGroupMembers.Count
                enabled_accounts = ($localUsers | Where-Object { 
                    $enabled = if ($_.Enabled -ne $null) { $_.Enabled } else { -not $_.Disabled }
                    $enabled 
                }).Count
                guest_account_enabled = ($localUsers | Where-Object { 
                    $name = if ($_.Name) { $_.Name } else { $_.Caption -replace ".*\\", "" }
                    $enabled = if ($_.Enabled -ne $null) { $_.Enabled } else { -not $_.Disabled }
                    $name -eq "Guest" -and $enabled 
                }) -ne $null
                critical_findings = ($findings | Where-Object { $_.severity -eq "CRITICAL" }).Count
                high_findings = ($findings | Where-Object { $_.severity -eq "HIGH" }).Count
                medium_findings = ($findings | Where-Object { $_.severity -eq "MEDIUM" }).Count
                low_findings = ($findings | Where-Object { $_.severity -eq "LOW" }).Count
            }
        }
        
    } catch {
        Write-Error "User account inventory failed: $($_.Exception.Message)"
        
        return @{
            security_score = 0
            findings = @(
                @{
                    category = "B002_user_account_security"
                    severity = "CRITICAL"
                    finding = "User account analysis failed"
                    details = @{
                        error_message = $_.Exception.Message
                        risk_description = "Unable to complete user account security assessment"
                    }
                    remediation = "Investigate user account analysis failure and retry assessment"
                    impact = "User account security status unknown"
                }
            )
            assessment_summary = @{
                total_accounts = 0
                admin_accounts = 0
                enabled_accounts = 0
                guest_account_enabled = $false
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
    Get-UserAccountInventory -Verbose:$Verbose | ConvertTo-Json -Depth 10
}
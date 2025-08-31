# System Assessment Orchestrator - B001-B006 Implementation
# Implements comprehensive security assessment requirements

param(
    [Parameter()]
    [string]$OutputFormat = "JSON",
    
    [Parameter()]
    [string]$ConfigPath = "",
    
    [Parameter()]
    [switch]$Verbose = $false
)

# Set strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-SystemAssessment {
    <#
    .SYNOPSIS
    Orchestrates comprehensive system security assessment per B001-B006 requirements.
    
    .DESCRIPTION
    Performs complete security assessment including registry modifications, user accounts,
    group policies, system integrity, network configuration, and time control bypasses.
    
    .PARAMETER OutputFormat
    Output format: JSON, XML, or Object
    
    .PARAMETER ConfigPath
    Path to assessment configuration file
    
    .PARAMETER Verbose
    Enable verbose logging
    #>
    
    try {
        Write-Host "=== SYSTEM SECURITY ASSESSMENT ===" -ForegroundColor Cyan
        Write-Host "Starting comprehensive security assessment..." -ForegroundColor Yellow
        
        # Initialize assessment results
        $assessmentResults = @{
            assessment_metadata = @{
                timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                system_info = "$env:COMPUTERNAME - $((Get-WmiObject Win32_OperatingSystem).Caption)"
                assessment_version = "1.0"
                duration_seconds = 0
            }
            security_scorecard = @{
                overall_score = 0
                essential8_compliance = @{}
                component_scores = @{}
            }
            findings_summary = @{
                critical = 0
                high = 0
                medium = 0
                low = 0
                total_findings = 0
            }
            detailed_findings = @()
            remediation_approach = @{
                recommended_strategy = "assessment_required"
                rationale = "Initial assessment in progress"
                data_preservation_required = $true
            }
        }
        
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        
        # B001: Registry Modification Audit
        Write-Host "`n[1/6] Analyzing registry modifications (B001)..." -ForegroundColor Blue
        $registryResults = Get-RegistryModifications -Verbose:$Verbose
        $assessmentResults.security_scorecard.component_scores["registry_security"] = $registryResults.security_score
        $assessmentResults.detailed_findings += $registryResults.findings
        Update-FindingsSummary -Findings $registryResults.findings -Summary $assessmentResults.findings_summary
        
        # B002: User Account Inventory
        Write-Host "[2/6] Inventorying user accounts (B002)..." -ForegroundColor Blue
        $userAccountResults = Get-UserAccountInventory -Verbose:$Verbose
        $assessmentResults.security_scorecard.component_scores["user_account_security"] = $userAccountResults.security_score
        $assessmentResults.detailed_findings += $userAccountResults.findings
        Update-FindingsSummary -Findings $userAccountResults.findings -Summary $assessmentResults.findings_summary
        
        # B003: Group Policy Inventory
        Write-Host "[3/6] Documenting Group Policy settings (B003)..." -ForegroundColor Blue
        $groupPolicyResults = Get-GroupPolicyInventory -Verbose:$Verbose
        $assessmentResults.security_scorecard.component_scores["group_policy_compliance"] = $groupPolicyResults.security_score
        $assessmentResults.detailed_findings += $groupPolicyResults.findings
        Update-FindingsSummary -Findings $groupPolicyResults.findings -Summary $assessmentResults.findings_summary
        
        # B004: System Integrity Check
        Write-Host "[4/6] Checking system integrity (B004)..." -ForegroundColor Blue
        $integrityResults = Test-SystemIntegrity -Verbose:$Verbose
        $assessmentResults.security_scorecard.component_scores["system_integrity"] = $integrityResults.security_score
        $assessmentResults.detailed_findings += $integrityResults.findings
        Update-FindingsSummary -Findings $integrityResults.findings -Summary $assessmentResults.findings_summary
        
        # B005: Network Configuration Assessment
        Write-Host "[5/6] Assessing network configuration (B005)..." -ForegroundColor Blue
        $networkResults = Get-NetworkConfiguration -Verbose:$Verbose
        $assessmentResults.security_scorecard.component_scores["network_security"] = $networkResults.security_score
        $assessmentResults.detailed_findings += $networkResults.findings
        Update-FindingsSummary -Findings $networkResults.findings -Summary $assessmentResults.findings_summary
        
        # B006: Time Control Bypass Detection
        Write-Host "[6/6] Detecting time control bypasses (B006)..." -ForegroundColor Blue
        $timeControlResults = Test-TimeControlBypasses -Verbose:$Verbose
        $assessmentResults.security_scorecard.component_scores["time_control_security"] = $timeControlResults.security_score
        $assessmentResults.detailed_findings += $timeControlResults.findings
        Update-FindingsSummary -Findings $timeControlResults.findings -Summary $assessmentResults.findings_summary
        
        $stopwatch.Stop()
        $assessmentResults.assessment_metadata.duration_seconds = [math]::Round($stopwatch.Elapsed.TotalSeconds, 2)
        
        # Calculate overall security score
        $componentScores = $assessmentResults.security_scorecard.component_scores
        $overallScore = Calculate-OverallSecurityScore -ComponentScores $componentScores
        $assessmentResults.security_scorecard.overall_score = $overallScore
        
        # Determine remediation approach
        $remediationStrategy = Get-RemediationStrategy -SecurityScore $overallScore -FindingsSummary $assessmentResults.findings_summary
        $assessmentResults.remediation_approach = $remediationStrategy
        
        # Generate Essential 8 compliance assessment
        $essential8Compliance = Get-Essential8ComplianceStatus -AssessmentResults $assessmentResults
        $assessmentResults.security_scorecard.essential8_compliance = $essential8Compliance
        
        Write-Host "`n=== ASSESSMENT COMPLETE ===" -ForegroundColor Green
        Write-Host "Overall Security Score: $($overallScore)/100" -ForegroundColor $(if ($overallScore -ge 80) { "Green" } elseif ($overallScore -ge 60) { "Yellow" } else { "Red" })
        Write-Host "Total Findings: $($assessmentResults.findings_summary.total_findings)" -ForegroundColor Gray
        Write-Host "Assessment Duration: $($assessmentResults.assessment_metadata.duration_seconds) seconds" -ForegroundColor Gray
        
        # Output results in requested format
        switch ($OutputFormat.ToUpper()) {
            "JSON" {
                return ($assessmentResults | ConvertTo-Json -Depth 10)
            }
            "XML" {
                return ($assessmentResults | ConvertTo-Xml -NoTypeInformation).OuterXml
            }
            "OBJECT" {
                return $assessmentResults
            }
            default {
                return ($assessmentResults | ConvertTo-Json -Depth 10)
            }
        }
        
    } catch {
        Write-Error "System assessment failed: $($_.Exception.Message)"
        
        # Return error result in consistent format
        $errorResult = @{
            assessment_metadata = @{
                timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                system_info = "$env:COMPUTERNAME - Assessment Failed"
                assessment_version = "1.0"
                error = $_.Exception.Message
            }
            security_scorecard = @{
                overall_score = 0
                error = "Assessment failed to complete"
            }
            findings_summary = @{
                critical = 0; high = 0; medium = 0; low = 0; total_findings = 0
            }
            detailed_findings = @()
            remediation_approach = @{
                recommended_strategy = "assessment_retry_required"
                rationale = "Assessment failed to complete successfully"
                data_preservation_required = $true
            }
        }
        
        return ($errorResult | ConvertTo-Json -Depth 10)
    }
}

function Update-FindingsSummary {
    param(
        [Parameter(Mandatory)]
        [array]$Findings,
        
        [Parameter(Mandatory)]
        [hashtable]$Summary
    )
    
    foreach ($finding in $Findings) {
        $severity = $finding.severity.ToUpper()
        switch ($severity) {
            "CRITICAL" { $Summary.critical++ }
            "HIGH" { $Summary.high++ }
            "MEDIUM" { $Summary.medium++ }
            "LOW" { $Summary.low++ }
        }
        $Summary.total_findings++
    }
}

function Calculate-OverallSecurityScore {
    param(
        [Parameter(Mandatory)]
        [hashtable]$ComponentScores
    )
    
    # Component weights (must sum to 1.0)
    $weights = @{
        "registry_security" = 0.20
        "user_account_security" = 0.20
        "group_policy_compliance" = 0.15
        "system_integrity" = 0.20
        "network_security" = 0.15
        "time_control_security" = 0.10
    }
    
    $weightedScore = 0
    foreach ($component in $ComponentScores.Keys) {
        if ($weights.ContainsKey($component)) {
            $weightedScore += $ComponentScores[$component] * $weights[$component]
        }
    }
    
    return [math]::Round($weightedScore, 1)
}

function Get-RemediationStrategy {
    param(
        [Parameter(Mandatory)]
        [double]$SecurityScore,
        
        [Parameter(Mandatory)]
        [hashtable]$FindingsSummary
    )
    
    $strategy = @{
        recommended_strategy = "assessment_required"
        rationale = "Determining optimal remediation approach"
        data_preservation_required = $true
        estimated_effort_hours = 0
        risk_level = "UNKNOWN"
    }
    
    # Determine strategy based on security score and findings
    if ($SecurityScore -ge 80) {
        $strategy.recommended_strategy = "selective_hardening"
        $strategy.rationale = "System is in good condition, selective improvements recommended"
        $strategy.estimated_effort_hours = 2
        $strategy.risk_level = "LOW"
    }
    elseif ($SecurityScore -ge 60) {
        $strategy.recommended_strategy = "in_place_remediation" 
        $strategy.rationale = "System shows manageable security gaps, in-place remediation feasible"
        $strategy.estimated_effort_hours = 4
        $strategy.risk_level = "MEDIUM"
    }
    elseif ($FindingsSummary.critical -ge 3 -or $SecurityScore -lt 40) {
        $strategy.recommended_strategy = "baseline_reset"
        $strategy.rationale = "Multiple critical findings require comprehensive baseline reset"
        $strategy.estimated_effort_hours = 8
        $strategy.risk_level = "HIGH"
    }
    else {
        $strategy.recommended_strategy = "in_place_remediation"
        $strategy.rationale = "Moderate security issues can be addressed through targeted remediation"
        $strategy.estimated_effort_hours = 6
        $strategy.risk_level = "MEDIUM"
    }
    
    return $strategy
}

function Get-Essential8ComplianceStatus {
    param(
        [Parameter(Mandatory)]
        [hashtable]$AssessmentResults
    )
    
    # Essential 8 Level 1 Controls Assessment
    $essential8Controls = @{
        "B020_passwords" = @{ status = "UNKNOWN"; score = 0; details = "Password policy assessment pending" }
        "B021_admin_rights" = @{ status = "UNKNOWN"; score = 0; details = "Admin rights assessment pending" }
        "B022_os_updates" = @{ status = "UNKNOWN"; score = 0; details = "OS update status pending" }
        "B023_app_updates" = @{ status = "UNKNOWN"; score = 0; details = "Application update status pending" }
        "B024_macro_security" = @{ status = "UNKNOWN"; score = 0; details = "Macro security assessment pending" }
        "B025_browser_security" = @{ status = "UNKNOWN"; score = 0; details = "Browser security assessment pending" }
        "B026_mfa" = @{ status = "UNKNOWN"; score = 0; details = "MFA assessment pending" }
        "B027_backups" = @{ status = "UNKNOWN"; score = 0; details = "Backup assessment pending" }
        "B028_antivirus" = @{ status = "UNKNOWN"; score = 0; details = "Antivirus assessment pending" }
    }
    
    # Analyze findings for Essential 8 compliance indicators
    foreach ($finding in $AssessmentResults.detailed_findings) {
        switch ($finding.category) {
            "B020_passwords" {
                $essential8Controls["B020_passwords"].status = if ($finding.severity -eq "PASS") { "PASS" } else { "FAIL" }
                $essential8Controls["B020_passwords"].score = if ($finding.severity -eq "PASS") { 10 } else { 0 }
                $essential8Controls["B020_passwords"].details = $finding.finding
            }
            "B021_admin_rights" {
                $essential8Controls["B021_admin_rights"].status = if ($finding.severity -in @("CRITICAL", "HIGH")) { "FAIL" } else { "PASS" }
                $essential8Controls["B021_admin_rights"].score = if ($finding.severity -in @("CRITICAL", "HIGH")) { 0 } else { 10 }
                $essential8Controls["B021_admin_rights"].details = $finding.finding
            }
        }
    }
    
    return $essential8Controls
}

# Import required assessment modules
. "$PSScriptRoot\Get-RegistryModifications.ps1"
. "$PSScriptRoot\Get-UserAccountInventory.ps1" 
. "$PSScriptRoot\Get-GroupPolicyInventory.ps1"
. "$PSScriptRoot\Test-SystemIntegrity.ps1"
. "$PSScriptRoot\Get-NetworkConfiguration.ps1"
. "$PSScriptRoot\Test-TimeControlBypasses.ps1"

# Execute assessment if script is run directly
if ($MyInvocation.InvocationName -eq $MyInvocation.MyCommand.Name) {
    Invoke-SystemAssessment -OutputFormat $OutputFormat -ConfigPath $ConfigPath -Verbose:$Verbose
}
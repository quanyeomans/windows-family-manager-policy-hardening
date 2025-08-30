# Family Control Baseline Deployment Script
# Orchestrates the complete Phase 0 deployment following our implementation guidelines
# Integrates: System Assessment + Security Baseline + Testing Framework

[CmdletBinding()]
param(
    [ValidateSet('Assessment', 'Deploy', 'Validate', 'Complete')]
    [string]$Phase = 'Complete',
    
    [ValidateSet('Personal', 'Enterprise', 'Custom')]
    [string]$SecurityLevel = 'Personal',
    
    [switch]$GamingOptimized = $true,
    
    [switch]$DryRun,
    
    [switch]$Force
)

function Deploy-FamilyControlBaseline {
    [CmdletBinding()]
    param(
        [string]$Phase,
        [string]$SecurityLevel, 
        [switch]$GamingOptimized,
        [switch]$DryRun,
        [switch]$Force
    )
    
    Write-Host "=================================================" -ForegroundColor Cyan
    Write-Host "FAMILY CONTROL SYSTEM - BASELINE DEPLOYMENT" -ForegroundColor Cyan
    Write-Host "Phase: $Phase | Security Level: $SecurityLevel | Gaming Optimized: $GamingOptimized" -ForegroundColor Gray
    Write-Host "=================================================" -ForegroundColor Cyan
    Write-Host ""
    
    $deploymentResult = @{
        Timestamp = Get-Date
        Phase = $Phase
        SecurityLevel = $SecurityLevel
        GamingOptimized = $GamingOptimized
        DryRun = $DryRun
        Success = $false
        Phases = @{}
        Issues = @()
        Recommendations = @()
    }
    
    try {
        # Phase 1: System Assessment (Always Required)
        if ($Phase -in @('Assessment', 'Complete')) {
            Write-Host "=== PHASE 1: SYSTEM ASSESSMENT ===" -ForegroundColor Yellow
            $assessmentResult = Invoke-PhaseAssessment -Force:$Force
            $deploymentResult.Phases.Assessment = $assessmentResult
            
            if (-not $assessmentResult.Success) {
                $deploymentResult.Issues += "System assessment failed - review critical issues before proceeding"
                if (-not $Force) {
                    throw "System not ready for deployment. Use -Force to override or address assessment issues first."
                }
            }
        }
        
        # Phase 2: Security Baseline Deployment
        if ($Phase -in @('Deploy', 'Complete')) {
            Write-Host "=== PHASE 2: SECURITY BASELINE DEPLOYMENT ===" -ForegroundColor Yellow
            $baselineResult = Invoke-PhaseSecurityBaseline -SecurityLevel $SecurityLevel -GamingOptimized:$GamingOptimized -DryRun:$DryRun
            $deploymentResult.Phases.SecurityBaseline = $baselineResult
            
            if (-not $baselineResult.Success) {
                $deploymentResult.Issues += "Security baseline deployment encountered issues"
            }
        }
        
        # Phase 3: Validation and Testing
        if ($Phase -in @('Validate', 'Complete')) {
            Write-Host "=== PHASE 3: VALIDATION AND TESTING ===" -ForegroundColor Yellow
            $validationResult = Invoke-PhaseValidation -DryRun:$DryRun
            $deploymentResult.Phases.Validation = $validationResult
            
            if (-not $validationResult.Success) {
                $deploymentResult.Issues += "Validation phase failed - security contracts not satisfied"
            }
        }
        
        # Overall Success Determination
        $deploymentResult.Success = $deploymentResult.Issues.Count -eq 0
        
        # Generate Final Report
        $reportPath = Save-DeploymentReport -Result $deploymentResult
        
        # Display Summary
        Show-DeploymentSummary -Result $deploymentResult -ReportPath $reportPath
        
        return $deploymentResult
        
    }
    catch {
        $deploymentResult.Issues += "Deployment failed: $($_.Exception.Message)"
        $deploymentResult.Success = $false
        Write-Error "Deployment failed: $($_.Exception.Message)"
        return $deploymentResult
    }
}

function Invoke-PhaseAssessment {
    [CmdletBinding()]
    param([switch]$Force)
    
    $phaseResult = @{
        Success = $false
        StartTime = Get-Date
        Results = @{}
        Issues = @()
    }
    
    try {
        # Execute system assessment
        Write-Host "  Running comprehensive system assessment..." -ForegroundColor Gray
        $assessmentScript = "src\integrations\system-discovery\Invoke-SystemAssessment.ps1"
        
        if (Test-Path $assessmentScript) {
            $assessment = & $assessmentScript -IncludeCHAPS -DetailedReport
            $phaseResult.Results.SystemAssessment = $assessment
            
            # Evaluate assessment results
            if ($assessment.ExecutiveSummary.ReadyForDeployment) {
                Write-Host "  ✅ System assessment: READY FOR DEPLOYMENT" -ForegroundColor Green
                $phaseResult.Success = $true
            } else {
                Write-Host "  ⚠️  System assessment: NOT READY" -ForegroundColor Yellow
                $phaseResult.Issues += "System not ready: $($assessment.ExecutiveSummary.OverallStatus)"
                $phaseResult.Issues += $assessment.ExecutiveSummary.RecommendedActions
            }
        } else {
            Write-Warning "  System assessment script not found - using minimal validation"
            $minimalAssessment = Test-MinimalSystemRequirements
            $phaseResult.Results.MinimalAssessment = $minimalAssessment
            $phaseResult.Success = $minimalAssessment.Success
            $phaseResult.Issues += $minimalAssessment.Issues
        }
        
        $phaseResult.EndTime = Get-Date
        $phaseResult.Duration = $phaseResult.EndTime - $phaseResult.StartTime
        
    }
    catch {
        $phaseResult.Issues += "Assessment phase error: $($_.Exception.Message)"
        $phaseResult.Success = $false
    }
    
    return $phaseResult
}

function Test-MinimalSystemRequirements {
    $requirements = @{
        Success = $true
        Issues = @()
        CheckedItems = @()
    }
    
    # Check Windows version
    $osVersion = Get-CimInstance Win32_OperatingSystem
    if ($osVersion.BuildNumber -lt 10240) {
        $requirements.Issues += "Windows 10 or higher required (current: $($osVersion.Caption))"
        $requirements.Success = $false
    }
    $requirements.CheckedItems += "Windows version: $($osVersion.Caption)"
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        $requirements.Issues += "PowerShell 5.0 or higher required (current: $($PSVersionTable.PSVersion))"
        $requirements.Success = $false
    }
    $requirements.CheckedItems += "PowerShell version: $($PSVersionTable.PSVersion)"
    
    # Check admin privileges
    if (-not (Test-IsElevated)) {
        $requirements.Issues += "Must run as Administrator for baseline deployment"
        $requirements.Success = $false
    }
    $requirements.CheckedItems += "Administrator privileges: $(if (Test-IsElevated) { 'Yes' } else { 'No' })"
    
    return $requirements
}

function Invoke-PhaseSecurityBaseline {
    [CmdletBinding()]
    param(
        [string]$SecurityLevel,
        [switch]$GamingOptimized,
        [switch]$DryRun
    )
    
    $phaseResult = @{
        Success = $false
        StartTime = Get-Date
        Results = @{}
        Issues = @()
    }
    
    try {
        # Execute security baseline deployment
        Write-Host "  Deploying security baseline..." -ForegroundColor Gray
        $baselineScript = "src\integrations\harden-windows\Invoke-SecurityBaseline.ps1"
        
        if (Test-Path $baselineScript) {
            $baseline = & $baselineScript -SecurityLevel $SecurityLevel -GamingOptimized:$GamingOptimized -DryRun:$DryRun
            $phaseResult.Results.SecurityBaseline = $baseline
            
            # Evaluate baseline deployment results
            if ($baseline.ValidationResult.Success) {
                Write-Host "  ✅ Security baseline deployment: SUCCESS" -ForegroundColor Green
                $phaseResult.Success = $true
            } else {
                Write-Host "  ⚠️  Security baseline deployment: PARTIAL SUCCESS" -ForegroundColor Yellow
                $phaseResult.Issues += "Baseline validation issues found"
                $phaseResult.Issues += $baseline.ValidationResult.Issues
                $phaseResult.Success = $baseline.HotCakeXResult.Status -eq "Success" -or $baseline.FamilyExtensionsResult.Status -eq "Success"
            }
        } else {
            Write-Warning "  Security baseline script not found - skipping baseline deployment"
            $phaseResult.Issues += "Security baseline script not available"
        }
        
        $phaseResult.EndTime = Get-Date
        $phaseResult.Duration = $phaseResult.EndTime - $phaseResult.StartTime
        
    }
    catch {
        $phaseResult.Issues += "Security baseline deployment error: $($_.Exception.Message)"
        $phaseResult.Success = $false
    }
    
    return $phaseResult
}

function Invoke-PhaseValidation {
    [CmdletBinding()]
    param([switch]$DryRun)
    
    $phaseResult = @{
        Success = $false
        StartTime = Get-Date
        Results = @{}
        Issues = @()
    }
    
    try {
        # Security Contract Tests (CRITICAL)
        Write-Host "  Running security contract tests..." -ForegroundColor Gray
        $contractTests = Test-SecurityContracts -DryRun:$DryRun
        $phaseResult.Results.SecurityContracts = $contractTests
        
        if (-not $contractTests.Success) {
            $phaseResult.Issues += "Security contract tests failed - CRITICAL"
            $phaseResult.Issues += $contractTests.FailedTests
        }
        
        # Gaming Performance Validation (if not dry run)
        if (-not $DryRun) {
            Write-Host "  Running gaming performance validation..." -ForegroundColor Gray
            $gamingTests = Test-GamingPerformanceValidation
            $phaseResult.Results.GamingPerformance = $gamingTests
            
            if (-not $gamingTests.Success) {
                $phaseResult.Issues += "Gaming performance validation failed"
                $phaseResult.Issues += $gamingTests.Issues
            }
        } else {
            Write-Host "  Skipping gaming performance validation (dry run)" -ForegroundColor Gray
        }
        
        # Overall validation success
        $phaseResult.Success = $contractTests.Success -and (($DryRun) -or $gamingTests.Success)
        
        $phaseResult.EndTime = Get-Date
        $phaseResult.Duration = $phaseResult.EndTime - $phaseResult.StartTime
        
    }
    catch {
        $phaseResult.Issues += "Validation phase error: $($_.Exception.Message)"
        $phaseResult.Success = $false
    }
    
    return $phaseResult
}

function Test-SecurityContracts {
    [CmdletBinding()]
    param([switch]$DryRun)
    
    $contractResult = @{
        Success = $false
        FailedTests = @()
        TestResults = @{}
    }
    
    try {
        # Run Pester security contract tests
        $contractTestScript = "tests\security-contracts\SecurityBoundary.Tests.ps1"
        
        if (Test-Path $contractTestScript) {
            if ($DryRun) {
                Write-Host "    Dry run - would execute security contract tests" -ForegroundColor Gray
                $contractResult.Success = $true
                $contractResult.TestResults = @{ Status = "DryRun"; Message = "Would execute security boundary tests" }
            } else {
                # Execute Pester tests
                $pesterResults = Invoke-Pester -Path $contractTestScript -PassThru -Quiet
                
                $contractResult.Success = $pesterResults.FailedCount -eq 0
                $contractResult.TestResults = @{
                    TotalTests = $pesterResults.TotalCount
                    PassedTests = $pesterResults.PassedCount
                    FailedTests = $pesterResults.FailedCount
                    Duration = $pesterResults.Time
                }
                
                if ($pesterResults.FailedCount -gt 0) {
                    $contractResult.FailedTests = $pesterResults.TestResult | Where-Object { $_.Result -eq "Failed" } | ForEach-Object { $_.Describe + ": " + $_.Name }
                }
            }
        } else {
            Write-Warning "    Security contract tests not found - using basic validation"
            $contractResult = Test-BasicSecurityValidation
        }
    }
    catch {
        $contractResult.FailedTests += "Security contract test execution failed: $($_.Exception.Message)"
        $contractResult.Success = $false
    }
    
    return $contractResult
}

function Test-BasicSecurityValidation {
    $basicValidation = @{
        Success = $true
        FailedTests = @()
        TestResults = @{ Type = "Basic" }
    }
    
    # Basic Windows Defender check
    try {
        $defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
        if (-not $defenderService -or $defenderService.Status -ne "Running") {
            $basicValidation.FailedTests += "Windows Defender service not running"
            $basicValidation.Success = $false
        }
    }
    catch {
        $basicValidation.FailedTests += "Could not check Windows Defender status"
        $basicValidation.Success = $false
    }
    
    # Basic UAC check
    try {
        $uacEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
        if (-not $uacEnabled -or $uacEnabled.EnableLUA -ne 1) {
            $basicValidation.FailedTests += "UAC not properly enabled"
            $basicValidation.Success = $false
        }
    }
    catch {
        $basicValidation.FailedTests += "Could not check UAC status"
        $basicValidation.Success = $false
    }
    
    return $basicValidation
}

function Test-GamingPerformanceValidation {
    try {
        $gamingScript = "src\custom\gaming-validation\Test-GamingPerformance.ps1"
        
        if (Test-Path $gamingScript) {
            # Run gaming performance validation
            $gamingResult = & $gamingScript -DurationSeconds 60 -ValidatePerformance
            
            return @{
                Success = $gamingResult.Success
                Issues = if ($gamingResult.Issues) { $gamingResult.Issues } else { @() }
                PerformanceDegradation = $gamingResult.Degradation.Overall
            }
        } else {
            return @{
                Success = $true
                Issues = @("Gaming performance script not found - skipping validation")
                PerformanceDegradation = 0
            }
        }
    }
    catch {
        return @{
            Success = $false
            Issues = @("Gaming performance validation failed: $($_.Exception.Message)")
            PerformanceDegradation = $null
        }
    }
}

function Save-DeploymentReport {
    [CmdletBinding()]
    param($Result)
    
    $reportPath = "logs\family-control-deployment-$(Get-Date -Format 'yyyy-MM-dd-HHmm').json"
    $Result | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath -Encoding UTF8
    
    return $reportPath
}

function Show-DeploymentSummary {
    [CmdletBinding()]
    param($Result, $ReportPath)
    
    Write-Host ""
    Write-Host "=================================================" -ForegroundColor Cyan
    Write-Host "DEPLOYMENT SUMMARY" -ForegroundColor Cyan
    Write-Host "=================================================" -ForegroundColor Cyan
    
    Write-Host "Overall Status: " -NoNewline
    $statusColor = if ($Result.Success) { "Green" } else { "Red" }
    $statusText = if ($Result.Success) { "✅ SUCCESS" } else { "❌ FAILED" }
    Write-Host $statusText -ForegroundColor $statusColor
    
    Write-Host "Phase: $($Result.Phase)" -ForegroundColor Gray
    Write-Host "Security Level: $($Result.SecurityLevel)" -ForegroundColor Gray
    Write-Host "Gaming Optimized: $($Result.GamingOptimized)" -ForegroundColor Gray
    Write-Host "Dry Run: $($Result.DryRun)" -ForegroundColor Gray
    Write-Host ""
    
    # Phase Results
    foreach ($phase in $Result.Phases.GetEnumerator()) {
        $phaseStatus = if ($phase.Value.Success) { "✅" } else { "❌" }
        Write-Host "$phaseStatus $($phase.Key): " -NoNewline
        Write-Host $phase.Value.Success -ForegroundColor $(if ($phase.Value.Success) { "Green" } else { "Red" })
        
        if ($phase.Value.Duration) {
            Write-Host "   Duration: $($phase.Value.Duration.TotalSeconds) seconds" -ForegroundColor Gray
        }
    }
    
    # Issues and Recommendations
    if ($Result.Issues.Count -gt 0) {
        Write-Host ""
        Write-Host "ISSUES:" -ForegroundColor Red
        foreach ($issue in $Result.Issues) {
            Write-Host "  ⚠️  $issue" -ForegroundColor Red
        }
    }
    
    if ($Result.Recommendations.Count -gt 0) {
        Write-Host ""
        Write-Host "RECOMMENDATIONS:" -ForegroundColor Yellow
        foreach ($rec in $Result.Recommendations) {
            Write-Host "  💡 $rec" -ForegroundColor Yellow
        }
    }
    
    # Next Steps
    Write-Host ""
    Write-Host "NEXT STEPS:" -ForegroundColor Cyan
    if ($Result.Success) {
        Write-Host "  → System baseline deployment completed successfully" -ForegroundColor Green
        Write-Host "  → Ready to proceed with Phase 1: Feature Implementation" -ForegroundColor Green
        Write-Host "  → Run security contract tests regularly to maintain compliance" -ForegroundColor Cyan
    } else {
        Write-Host "  → Address critical issues before proceeding" -ForegroundColor Red
        Write-Host "  → Review deployment report for detailed information" -ForegroundColor Yellow
        Write-Host "  → Use -Force flag to override warnings (not recommended)" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "Report saved to: $ReportPath" -ForegroundColor Gray
    Write-Host "=================================================" -ForegroundColor Cyan
}

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal] $identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Execute if script is run directly
if ($MyInvocation.InvocationName -ne '.') {
    Deploy-FamilyControlBaseline -Phase $Phase -SecurityLevel $SecurityLevel -GamingOptimized:$GamingOptimized -DryRun:$DryRun -Force:$Force
}
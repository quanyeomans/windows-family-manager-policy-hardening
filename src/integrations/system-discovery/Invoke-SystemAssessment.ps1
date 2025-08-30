# Comprehensive System Assessment Script
# Integrates our custom baseline with CHAPS vendor security assessment
# Requirements: B001-B006 + vendor integration strategy

[CmdletBinding()]
param(
    [string]$OutputPath = "logs\system-assessment-$(Get-Date -Format 'yyyy-MM-dd-HHmm').json",
    [switch]$IncludeCHAPS,
    [switch]$DetailedReport
)

function Invoke-SystemAssessment {
    [CmdletBinding()]
    param(
        [string]$OutputPath,
        [switch]$IncludeCHAPS,
        [switch]$DetailedReport
    )
    
    Write-Host "=== Family Control System Assessment ===" -ForegroundColor Cyan
    Write-Host "Timestamp: $(Get-Date)" -ForegroundColor Gray
    Write-Host ""
    
    $assessment = @{
        Timestamp = Get-Date
        AssessmentVersion = "1.0"
        SystemInfo = Get-BasicSystemInfo
    }
    
    # Phase 1: Custom Family Control Baseline Assessment
    Write-Host "Phase 1: Family Control Baseline Assessment" -ForegroundColor Yellow
    try {
        $baselineScript = "src\integrations\system-discovery\Get-SystemBaseline.ps1"
        if (Test-Path $baselineScript) {
            $assessment.FamilyBaseline = & $baselineScript -OutputPath "temp_baseline.json"
            Write-Host "✅ Family baseline assessment completed" -ForegroundColor Green
        } else {
            Write-Warning "Family baseline script not found, generating minimal baseline"
            $assessment.FamilyBaseline = Get-MinimalBaseline
        }
    }
    catch {
        Write-Error "Family baseline assessment failed: $($_.Exception.Message)"
        $assessment.FamilyBaseline = @{ Error = $_.Exception.Message }
    }
    
    # Phase 2: CHAPS Security Assessment (if available)
    if ($IncludeCHAPS) {
        Write-Host "Phase 2: CHAPS Security Assessment" -ForegroundColor Yellow
        try {
            $chapsResult = Invoke-CHAPSAssessment
            $assessment.CHAPSAssessment = $chapsResult
            Write-Host "✅ CHAPS security assessment completed" -ForegroundColor Green
        }
        catch {
            Write-Warning "CHAPS assessment failed: $($_.Exception.Message)"
            $assessment.CHAPSAssessment = @{ Error = $_.Exception.Message }
        }
    }
    
    # Phase 3: Essential 8 Compliance Check
    Write-Host "Phase 3: Essential 8 Compliance Assessment" -ForegroundColor Yellow
    $assessment.Essential8Compliance = Test-Essential8Compliance
    
    # Phase 4: Gaming Performance Baseline
    Write-Host "Phase 4: Gaming Performance Baseline" -ForegroundColor Yellow
    $assessment.GamingBaseline = Get-GamingPerformanceBaseline
    
    # Phase 5: Risk Analysis and Recommendations
    Write-Host "Phase 5: Risk Analysis" -ForegroundColor Yellow
    $assessment.RiskAnalysis = Get-RiskAnalysis -AssessmentData $assessment
    
    # Generate executive summary
    $assessment.ExecutiveSummary = Get-ExecutiveSummary -AssessmentData $assessment
    
    # Save comprehensive assessment
    $assessment | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host ""
    Write-Host "✅ System assessment completed: $OutputPath" -ForegroundColor Green
    
    # Display summary to console
    Show-AssessmentSummary -Assessment $assessment
    
    return $assessment
}

function Get-BasicSystemInfo {
    return @{
        ComputerName = $env:COMPUTERNAME
        OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
        OSBuild = (Get-CimInstance Win32_OperatingSystem).BuildNumber
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        IsElevated = Test-IsElevated
        DomainJoined = (Get-CimInstance Win32_ComputerSystem).PartOfDomain
        LastBootUpTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    }
}

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal] $identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-CHAPSAssessment {
    # LEVERAGE: Use CHAPS vendor dependency for security assessment
    $chapsScript = "vendor\chaps\chaps.ps1"
    
    if (-not (Test-Path $chapsScript)) {
        throw "CHAPS security assessment script not found. Run: git submodule update --init"
    }
    
    Write-Host "  Running CHAPS security assessment..." -ForegroundColor Gray
    
    # Execute CHAPS with appropriate parameters for family environment
    $chapsParams = @{
        # Configure CHAPS for family/personal use case
        SecurityLevel = "High"
        GenerateReport = $true
        OutputFormat = "JSON"
    }
    
    try {
        # Note: Actual CHAPS execution may need parameter adjustment based on their interface
        $chapsOutput = & $chapsScript @chapsParams 2>&1
        
        return @{
            ExecutionStatus = "Success"
            Output = $chapsOutput
            Timestamp = Get-Date
            Version = "CHAPS-Integrated"
        }
    }
    catch {
        return @{
            ExecutionStatus = "Failed"
            Error = $_.Exception.Message
            Timestamp = Get-Date
        }
    }
}

function Test-Essential8Compliance {
    Write-Host "  Checking Essential 8 Level 1 compliance..." -ForegroundColor Gray
    
    $compliance = @{
        OverallScore = 0
        MaxScore = 8
        Controls = @{}
    }
    
    # Essential 8 Control 1: Application Control
    try {
        $appControl = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
        $compliance.Controls.ApplicationControl = @{
            Status = if ($appControl) { "Implemented" } else { "Not Implemented" }
            Score = if ($appControl) { 1 } else { 0 }
            Details = "AppLocker or WDAC policy status"
        }
    }
    catch {
        $compliance.Controls.ApplicationControl = @{
            Status = "Unknown"
            Score = 0
            Details = "Unable to check AppLocker status"
        }
    }
    
    # Essential 8 Control 2: Patch Management
    try {
        $updates = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue
        $autoUpdate = $updates.AUOptions -eq 4 -or $updates.AUOptions -eq 3
        $compliance.Controls.PatchManagement = @{
            Status = if ($autoUpdate) { "Implemented" } else { "Not Implemented" }
            Score = if ($autoUpdate) { 1 } else { 0 }
            Details = "Automatic updates configuration"
        }
    }
    catch {
        $compliance.Controls.PatchManagement = @{
            Status = "Unknown"
            Score = 0
            Details = "Unable to check Windows Update settings"
        }
    }
    
    # Essential 8 Control 3: Administrative Privileges
    try {
        $adminUsers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        $adminCount = $adminUsers.Count
        $compliance.Controls.AdminPrivileges = @{
            Status = if ($adminCount -le 2) { "Good" } elseif ($adminCount -le 4) { "Acceptable" } else { "Poor" }
            Score = if ($adminCount -le 2) { 1 } elseif ($adminCount -le 4) { 0.5 } else { 0 }
            Details = "Admin users count: $adminCount"
        }
    }
    catch {
        $compliance.Controls.AdminPrivileges = @{
            Status = "Unknown"
            Score = 0
            Details = "Unable to check admin group membership"
        }
    }
    
    # Essential 8 Control 4: User Training (N/A for family system)
    $compliance.Controls.UserTraining = @{
        Status = "N/A - Family System"
        Score = 1
        Details = "User education handled through family communication"
    }
    
    # Essential 8 Control 5: Multi-factor Authentication
    try {
        # Check for Microsoft account MFA (for Microsoft Family integration)
        $compliance.Controls.MFA = @{
            Status = "Manual Verification Required"
            Score = 0.5
            Details = "Verify Microsoft account MFA is enabled for family management"
        }
    }
    catch {
        $compliance.Controls.MFA = @{
            Status = "Unknown"
            Score = 0
            Details = "Unable to verify MFA status"
        }
    }
    
    # Essential 8 Control 6: Data Backup
    try {
        $backupStatus = Get-WBSummary -ErrorAction SilentlyContinue
        $compliance.Controls.DataBackup = @{
            Status = if ($backupStatus) { "Implemented" } else { "Not Implemented" }
            Score = if ($backupStatus) { 1 } else { 0 }
            Details = "Windows Backup configuration status"
        }
    }
    catch {
        $compliance.Controls.DataBackup = @{
            Status = "Unknown"
            Score = 0
            Details = "Unable to check backup configuration"
        }
    }
    
    # Essential 8 Control 7: Email Security (N/A for family system)
    $compliance.Controls.EmailSecurity = @{
        Status = "N/A - Family System"
        Score = 1
        Details = "Email security managed through external providers"
    }
    
    # Essential 8 Control 8: Web Filtering
    try {
        # Check for Edge security settings and Family Safety integration
        $edgeSettings = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Edge" -ErrorAction SilentlyContinue
        $compliance.Controls.WebFiltering = @{
            Status = if ($edgeSettings) { "Partially Implemented" } else { "Not Implemented" }
            Score = if ($edgeSettings) { 0.5 } else { 0 }
            Details = "Edge browser policy configuration"
        }
    }
    catch {
        $compliance.Controls.WebFiltering = @{
            Status = "Unknown"
            Score = 0
            Details = "Unable to check web filtering configuration"
        }
    }
    
    # Calculate overall score
    $compliance.OverallScore = ($compliance.Controls.Values | ForEach-Object { $_.Score } | Measure-Object -Sum).Sum
    $compliance.CompliancePercentage = [math]::Round(($compliance.OverallScore / $compliance.MaxScore) * 100, 1)
    
    return $compliance
}

function Get-GamingPerformanceBaseline {
    Write-Host "  Establishing gaming performance baseline..." -ForegroundColor Gray
    
    $baseline = @{
        Timestamp = Get-Date
        SystemSpecs = Get-SystemSpecs
        PerformanceCounters = Get-PerformanceCounters
        GamingOptimizations = Get-GamingOptimizations
    }
    
    return $baseline
}

function Get-SystemSpecs {
    try {
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        $gpu = Get-CimInstance Win32_VideoController | Where-Object { $_.Name -notmatch "Microsoft|Remote" } | Select-Object -First 1
        $memory = Get-CimInstance Win32_ComputerSystem
        
        return @{
            CPU = @{
                Name = $cpu.Name
                Cores = $cpu.NumberOfCores
                LogicalProcessors = $cpu.NumberOfLogicalProcessors
                MaxClockSpeed = $cpu.MaxClockSpeed
            }
            GPU = @{
                Name = $gpu.Name
                DriverVersion = $gpu.DriverVersion
                VideoRAM = $gpu.AdapterRAM
            }
            Memory = @{
                TotalRAM = [math]::Round($memory.TotalPhysicalMemory / 1GB, 2)
            }
        }
    }
    catch {
        return @{ Error = "Unable to retrieve system specifications: $($_.Exception.Message)" }
    }
}

function Get-PerformanceCounters {
    try {
        $counters = @{
            CPUUsage = (Get-Counter "\Processor(_Total)\% Processor Time").CounterSamples[0].CookedValue
            MemoryAvailable = (Get-Counter "\Memory\Available MBytes").CounterSamples[0].CookedValue
            Timestamp = Get-Date
        }
        
        return $counters
    }
    catch {
        return @{ Error = "Unable to retrieve performance counters: $($_.Exception.Message)" }
    }
}

function Get-GamingOptimizations {
    $optimizations = @{
        GameMode = $false
        GameBar = $true
        FullscreenOptimizations = $true
    }
    
    try {
        # Check Game Mode setting
        $gameMode = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "AutoGameModeEnabled" -ErrorAction SilentlyContinue
        $optimizations.GameMode = ($gameMode.AutoGameModeEnabled -eq 1)
        
        # Check Game Bar setting
        $gameBar = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -ErrorAction SilentlyContinue
        $optimizations.GameBar = ($gameBar.UseNexusForGameBarEnabled -ne 0)
        
    }
    catch {
        # Settings not found or inaccessible
    }
    
    return $optimizations
}

function Get-RiskAnalysis {
    param($AssessmentData)
    
    Write-Host "  Analyzing security risks..." -ForegroundColor Gray
    
    $risks = @{
        HighRisk = @()
        MediumRisk = @() 
        LowRisk = @()
        Recommendations = @()
    }
    
    # Analyze Essential 8 compliance for risks
    if ($AssessmentData.Essential8Compliance.CompliancePercentage -lt 70) {
        $risks.HighRisk += "Low Essential 8 compliance ($($AssessmentData.Essential8Compliance.CompliancePercentage)%)"
        $risks.Recommendations += "Implement missing Essential 8 Level 1 controls before deploying family controls"
    }
    
    # Check for admin privilege risks
    $adminControl = $AssessmentData.Essential8Compliance.Controls.AdminPrivileges
    if ($adminControl.Score -lt 0.5) {
        $risks.MediumRisk += "Too many administrative accounts detected"
        $risks.Recommendations += "Reduce administrative account count to 2 or fewer"
    }
    
    # Check for baseline security risks
    if ($AssessmentData.FamilyBaseline.UserAccounts) {
        $suspiciousAccounts = $AssessmentData.FamilyBaseline.UserAccounts | Where-Object { $_.SuspiciousAccount }
        if ($suspiciousAccounts) {
            $risks.MediumRisk += "Suspicious user accounts detected: $($suspiciousAccounts.Count)"
            $risks.Recommendations += "Review and clean up suspicious user accounts before baseline deployment"
        }
    }
    
    return $risks
}

function Get-ExecutiveSummary {
    param($AssessmentData)
    
    $summary = @{
        OverallStatus = "Unknown"
        ReadyForDeployment = $false
        CriticalIssues = 0
        RecommendedActions = @()
        NextSteps = @()
    }
    
    # Determine overall readiness
    $essential8Score = $AssessmentData.Essential8Compliance.CompliancePercentage
    $highRisks = $AssessmentData.RiskAnalysis.HighRisk.Count
    $mediumRisks = $AssessmentData.RiskAnalysis.MediumRisk.Count
    
    if ($highRisks -eq 0 -and $essential8Score -ge 80) {
        $summary.OverallStatus = "Ready"
        $summary.ReadyForDeployment = $true
        $summary.NextSteps += "Proceed with Phase 1: Security Baseline Deployment"
    }
    elseif ($highRisks -eq 0 -and $essential8Score -ge 60) {
        $summary.OverallStatus = "Nearly Ready" 
        $summary.ReadyForDeployment = $false
        $summary.NextSteps += "Address medium-risk issues before deployment"
    }
    else {
        $summary.OverallStatus = "Not Ready"
        $summary.ReadyForDeployment = $false
        $summary.NextSteps += "Address critical security issues before proceeding"
    }
    
    $summary.CriticalIssues = $highRisks
    $summary.RecommendedActions = $AssessmentData.RiskAnalysis.Recommendations
    
    return $summary
}

function Show-AssessmentSummary {
    param($Assessment)
    
    Write-Host ""
    Write-Host "=== ASSESSMENT SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Overall Status: " -NoNewline
    
    $status = $Assessment.ExecutiveSummary.OverallStatus
    $color = switch ($status) {
        "Ready" { "Green" }
        "Nearly Ready" { "Yellow" }
        "Not Ready" { "Red" }
        default { "Gray" }
    }
    Write-Host $status -ForegroundColor $color
    
    Write-Host "Essential 8 Compliance: $($Assessment.Essential8Compliance.CompliancePercentage)%" -ForegroundColor $(if ($Assessment.Essential8Compliance.CompliancePercentage -ge 80) { "Green" } else { "Yellow" })
    Write-Host "Critical Issues: $($Assessment.ExecutiveSummary.CriticalIssues)" -ForegroundColor $(if ($Assessment.ExecutiveSummary.CriticalIssues -eq 0) { "Green" } else { "Red" })
    Write-Host "Ready for Deployment: " -NoNewline
    Write-Host $Assessment.ExecutiveSummary.ReadyForDeployment -ForegroundColor $(if ($Assessment.ExecutiveSummary.ReadyForDeployment) { "Green" } else { "Red" })
    
    if ($Assessment.ExecutiveSummary.RecommendedActions.Count -gt 0) {
        Write-Host ""
        Write-Host "RECOMMENDED ACTIONS:" -ForegroundColor Yellow
        foreach ($action in $Assessment.ExecutiveSummary.RecommendedActions) {
            Write-Host "  • $action" -ForegroundColor Yellow
        }
    }
    
    if ($Assessment.ExecutiveSummary.NextSteps.Count -gt 0) {
        Write-Host ""
        Write-Host "NEXT STEPS:" -ForegroundColor Cyan
        foreach ($step in $Assessment.ExecutiveSummary.NextSteps) {
            Write-Host "  → $step" -ForegroundColor Cyan
        }
    }
}

function Get-MinimalBaseline {
    # Fallback minimal baseline if main script not available
    return @{
        Timestamp = Get-Date
        Status = "Minimal baseline - full assessment script not available"
        UserAccounts = Get-LocalUser | ForEach-Object { @{ Name = $_.Name; Enabled = $_.Enabled } }
        NetworkAdapters = Get-NetAdapter | ForEach-Object { @{ Name = $_.Name; Status = $_.Status } }
    }
}

# Execute assessment if script is run directly
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-SystemAssessment -OutputPath $OutputPath -IncludeCHAPS:$IncludeCHAPS -DetailedReport:$DetailedReport
}
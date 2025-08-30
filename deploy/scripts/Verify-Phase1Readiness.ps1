# Phase 1 Readiness Verification Script
# Validates system setup and vendor integration before starting feature development

[CmdletBinding()]
param(
    [switch]$Detailed,
    [switch]$FixIssues
)

function Test-Phase1Readiness {
    [CmdletBinding()]
    param(
        [switch]$Detailed,
        [switch]$FixIssues
    )
    
    Write-Host "=== PHASE 1 READINESS VERIFICATION ===" -ForegroundColor Cyan
    Write-Host "Validating system setup for E2E thin slice development" -ForegroundColor Gray
    Write-Host ""
    
    $verification = @{
        Timestamp = Get-Date
        OverallReady = $false
        Components = @{}
        Issues = @()
        Recommendations = @()
    }
    
    # 1. Vendor Integration Validation
    Write-Host "1. Vendor Integration Status" -ForegroundColor Yellow
    $verification.Components.VendorIntegration = Test-VendorIntegration -FixIssues:$FixIssues
    
    # 2. Security Baseline Status  
    Write-Host "2. Security Baseline Status" -ForegroundColor Yellow
    $verification.Components.SecurityBaseline = Test-SecurityBaselineStatus
    
    # 3. Development Environment
    Write-Host "3. Development Environment" -ForegroundColor Yellow
    $verification.Components.DevEnvironment = Test-DevelopmentEnvironment -FixIssues:$FixIssues
    
    # 4. System Requirements
    Write-Host "4. System Requirements" -ForegroundColor Yellow
    $verification.Components.SystemRequirements = Test-SystemRequirements
    
    # 5. Project Structure Validation
    Write-Host "5. Project Structure" -ForegroundColor Yellow
    $verification.Components.ProjectStructure = Test-ProjectStructure
    
    # Overall readiness determination
    $allComponentsReady = $verification.Components.Values | ForEach-Object { $_.Ready } | Where-Object { $_ -eq $false }
    $verification.OverallReady = $allComponentsReady.Count -eq 0
    
    # Collect issues and recommendations
    foreach ($component in $verification.Components.Values) {
        $verification.Issues += $component.Issues
        $verification.Recommendations += $component.Recommendations
    }
    
    # Display results
    Show-ReadinessResults -Verification $verification -Detailed:$Detailed
    
    return $verification
}

function Test-VendorIntegration {
    [CmdletBinding()]
    param([switch]$FixIssues)
    
    $result = @{
        Ready = $false
        Issues = @()
        Recommendations = @()
        Details = @{}
    }
    
    Write-Host "  Testing HotCakeX integration..." -ForegroundColor Gray
    
    # Test HotCakeX submodule
    $hotcakeScript = "vendor\hotcakex\Harden-Windows-Security.ps1"
    if (Test-Path $hotcakeScript) {
        Write-Host "    ✅ HotCakeX submodule available" -ForegroundColor Green
        $result.Details.HotCakeX = "Available at vendor/hotcakex/"
        
        # Test script accessibility
        try {
            $scriptInfo = Get-Command $hotcakeScript -ErrorAction Stop
            $result.Details.HotCakeXScript = "Executable and accessible"
        }
        catch {
            $result.Issues += "HotCakeX script not executable"
            $result.Recommendations += "Check PowerShell execution policy"
        }
    } else {
        $result.Issues += "HotCakeX submodule not found - run 'git submodule update --init'"
        
        if ($FixIssues) {
            Write-Host "    🔧 Attempting to initialize HotCakeX submodule..." -ForegroundColor Yellow
            try {
                & git submodule update --init vendor/hotcakex
                if (Test-Path $hotcakeScript) {
                    Write-Host "    ✅ HotCakeX submodule initialized successfully" -ForegroundColor Green
                    $result.Details.HotCakeX = "Initialized automatically"
                } else {
                    $result.Issues += "HotCakeX submodule initialization failed"
                }
            }
            catch {
                $result.Issues += "Failed to initialize HotCakeX submodule: $($_.Exception.Message)"
            }
        }
    }
    
    # Test CHAPS integration
    Write-Host "  Testing CHAPS integration..." -ForegroundColor Gray
    $chapsScript = "vendor\chaps\chaps.ps1"
    if (Test-Path $chapsScript) {
        Write-Host "    ✅ CHAPS submodule available" -ForegroundColor Green
        $result.Details.CHAPS = "Available at vendor/chaps/"
    } else {
        $result.Issues += "CHAPS submodule not found"
        $result.Recommendations += "Run 'git submodule update --init'"
    }
    
    $result.Ready = $result.Issues.Count -eq 0
    return $result
}

function Test-SecurityBaselineStatus {
    $result = @{
        Ready = $false
        Issues = @()
        Recommendations = @()
        Details = @{}
    }
    
    Write-Host "  Checking security baseline status..." -ForegroundColor Gray
    
    # Test if baseline assessment has been run
    $assessmentFiles = Get-ChildItem -Path "logs" -Filter "system-assessment-*.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
    
    if ($assessmentFiles) {
        $latestAssessment = $assessmentFiles[0]
        $assessmentData = Get-Content $latestAssessment.FullName | ConvertFrom-Json
        
        Write-Host "    ✅ System assessment available ($($latestAssessment.Name))" -ForegroundColor Green
        $result.Details.LastAssessment = $latestAssessment.LastWriteTime
        $result.Details.Essential8Compliance = "$($assessmentData.Essential8Compliance.CompliancePercentage)%"
        $result.Details.ReadyForDeployment = $assessmentData.ExecutiveSummary.ReadyForDeployment
        
        if ($assessmentData.Essential8Compliance.CompliancePercentage -lt 60) {
            $result.Issues += "Essential 8 compliance low (" + $assessmentData.Essential8Compliance.CompliancePercentage + " percent)"
            $result.Recommendations += "Run security baseline deployment to improve compliance"
        }
        
        if ($assessmentData.ExecutiveSummary.ReadyForDeployment) {
            Write-Host "    ✅ System ready for deployment" -ForegroundColor Green
        } else {
            Write-Host "    ⚠️  System not ready for deployment" -ForegroundColor Yellow
            $result.Recommendations += "Address assessment recommendations before Phase 1"
        }
    } else {
        $result.Issues += "No system assessment found"
        $result.Recommendations += "Run 'deploy/scripts/Deploy-FamilyControlBaseline.ps1 -Phase Assessment' first"
    }
    
    # Check for security contract tests
    $securityTests = "tests\security-contracts\SecurityBoundary.Tests.ps1"
    if (Test-Path $securityTests) {
        Write-Host "    ✅ Security contract tests available" -ForegroundColor Green
        $result.Details.SecurityTests = "Available"
    } else {
        $result.Issues += "Security contract tests not found"
    }
    
    $result.Ready = $result.Issues.Count -eq 0
    return $result
}

function Test-DevelopmentEnvironment {
    [CmdletBinding()]
    param([switch]$FixIssues)
    
    $result = @{
        Ready = $false
        Issues = @()
        Recommendations = @()
        Details = @{}
    }
    
    Write-Host "  Checking development environment..." -ForegroundColor Gray
    
    # PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    $result.Details.PowerShellVersion = $psVersion.ToString()
    if ($psVersion.Major -ge 5) {
        Write-Host "    ✅ PowerShell $psVersion (compatible)" -ForegroundColor Green
    } else {
        $result.Issues += "PowerShell 5.0+ required (current: $psVersion)"
    }
    
    # Required PowerShell modules
    $requiredModules = @("Pester")  # Start with essential modules
    $availableModules = @()
    
    foreach ($module in $requiredModules) {
        try {
            $moduleInfo = Get-Module -ListAvailable -Name $module -ErrorAction Stop
            Write-Host "    ✅ Module $module available (v$($moduleInfo[0].Version))" -ForegroundColor Green
            $availableModules += $module
        }
        catch {
            Write-Host "    ❌ Module $module not available" -ForegroundColor Red
            $result.Issues += "PowerShell module $module not installed"
            
            if ($FixIssues) {
                Write-Host "    🔧 Attempting to install $module..." -ForegroundColor Yellow
                try {
                    Install-Module -Name $module -Scope CurrentUser -Force
                    Write-Host "    ✅ Module $module installed successfully" -ForegroundColor Green
                    $availableModules += $module
                }
                catch {
                    $result.Issues += "Failed to install module $module`: $($_.Exception.Message)"
                }
            } else {
                $result.Recommendations += "Install PowerShell module: Install-Module -Name $module"
            }
        }
    }
    
    $result.Details.AvailableModules = $availableModules
    
    # Git repository status
    try {
        $gitStatus = & git status --porcelain 2>$null
        Write-Host "    ✅ Git repository operational" -ForegroundColor Green
        $result.Details.GitStatus = "Clean working directory"
    }
    catch {
        $result.Issues += "Git repository not properly initialized"
        $result.Recommendations += "Ensure Git is installed and repository is initialized"
    }
    
    $result.Ready = $result.Issues.Count -eq 0
    return $result
}

function Test-SystemRequirements {
    $result = @{
        Ready = $false
        Issues = @()
        Recommendations = @()
        Details = @{}
    }
    
    Write-Host "  Checking system requirements..." -ForegroundColor Gray
    
    # Windows version
    $osVersion = Get-CimInstance Win32_OperatingSystem
    $result.Details.OSVersion = $osVersion.Caption
    $result.Details.BuildNumber = $osVersion.BuildNumber
    
    if ($osVersion.BuildNumber -ge 10240) {  # Windows 10+
        Write-Host "    ✅ Windows version: $($osVersion.Caption)" -ForegroundColor Green
    } else {
        $result.Issues += "Windows 10 or higher required"
    }
    
    # Administrator privileges check
    $isElevated = Test-IsElevated
    $result.Details.IsElevated = $isElevated
    
    if ($isElevated) {
        Write-Host "    ✅ Running as Administrator" -ForegroundColor Green
    } else {
        Write-Host "    ⚠️  Not running as Administrator" -ForegroundColor Yellow
        $result.Recommendations += "Some features require Administrator privileges"
    }
    
    # Disk space check
    $systemDrive = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $env:SystemDrive }
    $freeSpaceGB = [math]::Round($systemDrive.FreeSpace / 1GB, 2)
    $result.Details.FreeSpace = "$freeSpaceGB GB"
    
    if ($freeSpaceGB -gt 2) {
        Write-Host "    ✅ Disk space: $freeSpaceGB GB available" -ForegroundColor Green
    } else {
        $result.Issues += "Low disk space: $freeSpaceGB GB (minimum 2GB recommended)"
    }
    
    $result.Ready = $result.Issues.Count -eq 0 -or ($result.Issues.Count -eq 1 -and -not $isElevated)
    return $result
}

function Test-ProjectStructure {
    $result = @{
        Ready = $false
        Issues = @()
        Recommendations = @()
        Details = @{}
    }
    
    Write-Host "  Validating project structure..." -ForegroundColor Gray
    
    # Required directories
    $requiredDirs = @(
        "src\integrations\harden-windows",
        "src\integrations\family-safety", 
        "src\custom\transparency",
        "src\custom\gaming-validation",
        "tests\security-contracts",
        "config",
        "deploy\scripts"
    )
    
    $missingDirs = @()
    foreach ($dir in $requiredDirs) {
        if (Test-Path $dir) {
            $result.Details[$dir] = "Present"
        } else {
            $missingDirs += $dir
            $result.Issues += "Missing directory: $dir"
        }
    }
    
    if ($missingDirs.Count -eq 0) {
        Write-Host "    ✅ Project structure complete" -ForegroundColor Green
        $result.Ready = $true
    } else {
        Write-Host "    ❌ Missing directories: $($missingDirs.Count)" -ForegroundColor Red
        $result.Recommendations += "Create missing directories or reinitialize project structure"
    }
    
    return $result
}

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal] $identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-ReadinessResults {
    [CmdletBinding()]
    param($Verification, [switch]$Detailed)
    
    Write-Host ""
    Write-Host "=== PHASE 1 READINESS RESULTS ===" -ForegroundColor Cyan
    
    # Overall status
    Write-Host "Overall Readiness: " -NoNewline
    $statusColor = if ($Verification.OverallReady) { "Green" } else { "Red" }
    $statusText = if ($Verification.OverallReady) { "✅ READY" } else { "❌ NOT READY" }
    Write-Host $statusText -ForegroundColor $statusColor
    
    Write-Host ""
    
    # Component status
    foreach ($component in $Verification.Components.GetEnumerator()) {
        $componentStatus = if ($component.Value.Ready) { "✅" } else { "❌" }
        Write-Host "$componentStatus $($component.Key): " -NoNewline
        Write-Host $component.Value.Ready -ForegroundColor $(if ($component.Value.Ready) { "Green" } else { "Red" })
        
        if ($Detailed -and $component.Value.Details.Count -gt 0) {
            foreach ($detail in $component.Value.Details.GetEnumerator()) {
                Write-Host "    $($detail.Key): $($detail.Value)" -ForegroundColor Gray
            }
        }
    }
    
    # Issues
    if ($Verification.Issues.Count -gt 0) {
        Write-Host ""
        Write-Host "ISSUES TO ADDRESS:" -ForegroundColor Red
        foreach ($issue in $Verification.Issues | Select-Object -Unique) {
            Write-Host "  ⚠️  $issue" -ForegroundColor Red
        }
    }
    
    # Recommendations  
    if ($Verification.Recommendations.Count -gt 0) {
        Write-Host ""
        Write-Host "RECOMMENDATIONS:" -ForegroundColor Yellow
        foreach ($rec in $Verification.Recommendations | Select-Object -Unique) {
            Write-Host "  💡 $rec" -ForegroundColor Yellow
        }
    }
    
    # Next steps
    Write-Host ""
    Write-Host "NEXT STEPS:" -ForegroundColor Cyan
    if ($Verification.OverallReady) {
        Write-Host "  🚀 Ready to start Phase 1 - Iteration 1: Basic Time Awareness" -ForegroundColor Green
        Write-Host "  📝 Begin implementation following docs/iterations/ITERATION1_BASIC_TIME_AWARENESS.md" -ForegroundColor Green
        Write-Host "  🧪 Run daily security contract tests during development" -ForegroundColor Cyan
    } else {
        Write-Host "  🔧 Address issues listed above" -ForegroundColor Red
        Write-Host "  🔄 Re-run this verification with -FixIssues to auto-resolve some issues" -ForegroundColor Yellow
        Write-Host "  📋 Review deployment documentation for manual setup steps" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "Verification completed at: $(Get-Date)" -ForegroundColor Gray
}

# Execute if script is run directly
if ($MyInvocation.InvocationName -ne '.') {
    Test-Phase1Readiness -Detailed:$Detailed -FixIssues:$FixIssues
}
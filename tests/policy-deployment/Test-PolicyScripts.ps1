# Policy Script Testing Framework
# Validates policy deployment scripts work correctly
# Part of Windows Family Manager Policy Hardening System

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$Detailed,
    
    [Parameter()]
    [string]$TestConfigPath = "$PSScriptRoot\test-config.json"
)

function Test-PolicyScriptExecution {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ScriptPath,
        
        [Parameter(Mandatory)]
        [string]$ConfigPath,
        
        [Parameter(Mandatory)]
        [string]$TestName
    )
    
    $result = @{
        TestName = $TestName
        Success = $false
        PoliciesApplied = 0
        PoliciesFailed = 0
        ExecutionTime = 0
        ErrorMessage = $null
    }
    
    try {
        Write-Host "Testing: $TestName" -ForegroundColor Yellow
        
        if (-not (Test-Path $ScriptPath)) {
            throw "Script not found: $ScriptPath"
        }
        
        if (-not (Test-Path $ConfigPath)) {
            throw "Config not found: $ConfigPath"
        }
        
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        
        # Execute script in dry-run mode
        $output = & powershell -ExecutionPolicy Bypass -File $ScriptPath -ConfigPath $ConfigPath -DryRun 2>&1
        $exitCode = $LASTEXITCODE
        
        $stopwatch.Stop()
        $result.ExecutionTime = $stopwatch.ElapsedMilliseconds
        
        if ($exitCode -eq 0) {
            # Parse output for policy counts
            $appliedMatches = $output | Select-String "Applied policies: (\d+)"
            $failedMatches = $output | Select-String "Failed policies: (\d+)"
            
            if ($appliedMatches) {
                $result.PoliciesApplied = [int]$appliedMatches.Matches[0].Groups[1].Value
            }
            
            if ($failedMatches) {
                $result.PoliciesFailed = [int]$failedMatches.Matches[0].Groups[1].Value
            }
            
            $result.Success = ($result.PoliciesFailed -eq 0 -and $result.PoliciesApplied -gt 0)
            
            if ($result.Success) {
                Write-Host "  ✅ SUCCESS: $($result.PoliciesApplied) policies applied" -ForegroundColor Green
            } else {
                Write-Host "  ❌ FAILED: $($result.PoliciesFailed) failures, $($result.PoliciesApplied) applied" -ForegroundColor Red
            }
        } else {
            $result.ErrorMessage = $output -join "`n"
            Write-Host "  ❌ SCRIPT FAILED: Exit code $exitCode" -ForegroundColor Red
        }
        
        Write-Host "  ⏱️  Execution time: $($result.ExecutionTime)ms" -ForegroundColor Gray
        
    } catch {
        $result.ErrorMessage = $_.Exception.Message
        Write-Host "  ❌ TEST ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $result
}

# Main test execution
Write-Host "=== POLICY SCRIPT VALIDATION TESTS ===" -ForegroundColor Cyan
Write-Host "Testing policy deployment scripts in dry-run mode" -ForegroundColor Gray
Write-Host ""

$testResults = @()

# Test 1: User Account Security
$testResults += Test-PolicyScriptExecution -ScriptPath "$PSScriptRoot\..\..\src\integrations\policy-management\user-account-security\Set-UserAccountRestrictions.ps1" -ConfigPath $TestConfigPath -TestName "User Account Security"

Write-Host ""

# Test 2: Network Security  
$testResults += Test-PolicyScriptExecution -ScriptPath "$PSScriptRoot\..\..\src\integrations\policy-management\network-security\Set-NetworkSecurityPolicies.ps1" -ConfigPath $TestConfigPath -TestName "Network Security"

Write-Host ""

# Test 3: Application Control
$testResults += Test-PolicyScriptExecution -ScriptPath "$PSScriptRoot\..\..\src\integrations\policy-management\application-control\Set-ApplicationControlPolicies.ps1" -ConfigPath $TestConfigPath -TestName "Application Control"

Write-Host ""

# Results Summary
Write-Host "=== TEST RESULTS SUMMARY ===" -ForegroundColor Cyan

$totalTests = $testResults.Count
$passedTests = ($testResults | Where-Object { $_.Success }).Count
$failedTests = $totalTests - $passedTests
$totalPolicies = ($testResults | ForEach-Object { $_.PoliciesApplied } | Measure-Object -Sum).Sum
$avgExecutionTime = if ($testResults.Count -gt 0) { ($testResults | ForEach-Object { $_.ExecutionTime } | Measure-Object -Average).Average } else { 0 }

Write-Host "Tests Run: $totalTests" -ForegroundColor White
Write-Host "Passed: $passedTests" -ForegroundColor $(if ($passedTests -eq $totalTests) { "Green" } else { "Yellow" })
Write-Host "Failed: $failedTests" -ForegroundColor $(if ($failedTests -eq 0) { "Green" } else { "Red" })
Write-Host "Total Policies Tested: $totalPolicies" -ForegroundColor White
Write-Host "Average Execution Time: $([math]::Round($avgExecutionTime, 0))ms" -ForegroundColor Gray

if ($Detailed) {
    Write-Host "`n=== DETAILED RESULTS ===" -ForegroundColor Cyan
    foreach ($result in $testResults) {
        Write-Host "`n$($result.TestName):" -ForegroundColor Yellow
        Write-Host "  Status: $(if ($result.Success) { '✅ PASSED' } else { '❌ FAILED' })" -ForegroundColor $(if ($result.Success) { "Green" } else { "Red" })
        Write-Host "  Policies Applied: $($result.PoliciesApplied)" -ForegroundColor White
        Write-Host "  Policies Failed: $($result.PoliciesFailed)" -ForegroundColor White
        Write-Host "  Execution Time: $($result.ExecutionTime)ms" -ForegroundColor Gray
        
        if ($result.ErrorMessage) {
            Write-Host "  Error Details:" -ForegroundColor Red
            Write-Host "    $($result.ErrorMessage)" -ForegroundColor Red
        }
    }
}

# Exit with appropriate code
if ($failedTests -eq 0) {
    Write-Host "`n🎯 ALL TESTS PASSED" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n🚨 $failedTests TESTS FAILED" -ForegroundColor Red
    exit 1
}
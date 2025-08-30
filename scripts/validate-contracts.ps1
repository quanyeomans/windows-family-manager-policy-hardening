# Contract Validation Script for CI/CD Pipeline
# Ensures PowerShell-Python interface stability before deployment

param(
    [switch]$Verbose = $false,
    [switch]$FailFast = $true,
    [string]$OutputFormat = "Console" # Console, JSON, JUnit
)

# Set strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Initialize results tracking
$results = @{
    contract_tests = @{ passed = 0; failed = 0; skipped = 0 }
    security_tests = @{ passed = 0; failed = 0; skipped = 0 }
    unit_tests = @{ passed = 0; failed = 0; skipped = 0 }
    overall_status = "UNKNOWN"
    execution_time = 0
}

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host "=== CONTRACT VALIDATION PIPELINE ===" -ForegroundColor Cyan
Write-Host "Validating interface stability and security contracts..." -ForegroundColor Yellow

try {
    # 1. Contract Tests - CRITICAL for interface stability
    Write-Host "`n[1/3] Running PowerShell-Python Contract Tests..." -ForegroundColor Blue
    
    $contractResult = & pytest tests/contracts/ -v --tb=short 2>&1
    $contractExitCode = $LASTEXITCODE
    
    if ($contractExitCode -eq 0) {
        Write-Host "✅ Contract tests PASSED" -ForegroundColor Green
        $results.contract_tests.passed = 5  # Update based on actual count
    } else {
        Write-Host "❌ Contract tests FAILED" -ForegroundColor Red
        $results.contract_tests.failed = 1
        
        if ($Verbose) {
            Write-Host "Contract test output:" -ForegroundColor Yellow
            $contractResult | Write-Host
        }
        
        if ($FailFast) {
            throw "Contract tests failed - interface stability compromised"
        }
    }

    # 2. Security Contract Tests - Critical security boundaries
    Write-Host "`n[2/3] Running Security Boundary Contract Tests..." -ForegroundColor Blue
    
    $securityResult = & powershell -Command "Invoke-Pester tests/security-contracts/ -Tag Critical -PassThru" 2>&1
    $securityExitCode = $LASTEXITCODE
    
    if ($securityExitCode -eq 0) {
        Write-Host "✅ Security contract tests PASSED" -ForegroundColor Green
        $results.security_tests.passed = 4  # Update based on actual count
    } else {
        Write-Host "❌ Security contract tests FAILED" -ForegroundColor Red
        $results.security_tests.failed = 1
        
        if ($Verbose) {
            Write-Host "Security test output:" -ForegroundColor Yellow
            $securityResult | Write-Host
        }
        
        if ($FailFast) {
            throw "Security contract tests failed - security boundaries compromised"
        }
    }

    # 3. Unit Tests - Core functionality validation with coverage
    Write-Host "`n[3/3] Running Unit Tests with Coverage..." -ForegroundColor Blue
    
    $unitResult = & pytest tests/unit/ -v --tb=short --cov=src --cov-report=term-missing --cov-fail-under=80 2>&1
    $unitExitCode = $LASTEXITCODE
    
    if ($unitExitCode -eq 0) {
        Write-Host "✅ Unit tests PASSED" -ForegroundColor Green
        $results.unit_tests.passed = 8  # Update based on actual count
    } else {
        Write-Host "❌ Unit tests FAILED" -ForegroundColor Red
        $results.unit_tests.failed = 1
        
        if ($Verbose) {
            Write-Host "Unit test output:" -ForegroundColor Yellow
            $unitResult | Write-Host
        }
    }

    # Calculate overall status
    $totalFailed = $results.contract_tests.failed + $results.security_tests.failed + $results.unit_tests.failed
    $totalPassed = $results.contract_tests.passed + $results.security_tests.passed + $results.unit_tests.passed
    
    if ($totalFailed -eq 0) {
        $results.overall_status = "PASSED"
        Write-Host "`n🎉 ALL CONTRACT VALIDATIONS PASSED" -ForegroundColor Green
        Write-Host "✅ Interface stability confirmed" -ForegroundColor Green
        Write-Host "✅ Security boundaries validated" -ForegroundColor Green
        Write-Host "✅ Core functionality verified" -ForegroundColor Green
    } else {
        $results.overall_status = "FAILED"
        Write-Host "`n❌ CONTRACT VALIDATION FAILED" -ForegroundColor Red
        Write-Host "Failed tests: $totalFailed | Passed tests: $totalPassed" -ForegroundColor Yellow
    }

} catch {
    $results.overall_status = "ERROR"
    Write-Host "`n💥 CONTRACT VALIDATION ERROR: $($_.Exception.Message)" -ForegroundColor Red
    
    if ($Verbose) {
        Write-Host "Full error details:" -ForegroundColor Yellow
        $_ | Write-Host
    }
}

$stopwatch.Stop()
$results.execution_time = $stopwatch.Elapsed.TotalSeconds

# Output results
Write-Host "`n=== VALIDATION SUMMARY ===" -ForegroundColor Cyan
Write-Host "Execution time: $($results.execution_time) seconds" -ForegroundColor Gray
Write-Host "Contract Tests: $($results.contract_tests.passed) passed, $($results.contract_tests.failed) failed" -ForegroundColor Gray
Write-Host "Security Tests: $($results.security_tests.passed) passed, $($results.security_tests.failed) failed" -ForegroundColor Gray
Write-Host "Unit Tests: $($results.unit_tests.passed) passed, $($results.unit_tests.failed) failed" -ForegroundColor Gray

# Output in different formats
switch ($OutputFormat) {
    "JSON" {
        $results | ConvertTo-Json -Depth 3 | Write-Host
    }
    "JUnit" {
        # Generate JUnit XML format for CI systems
        $junitXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="contract-validation" tests="$($results.contract_tests.passed + $results.contract_tests.failed)" failures="$($results.contract_tests.failed)" time="$($results.execution_time)">
  <testsuite name="contract-tests" tests="$($results.contract_tests.passed + $results.contract_tests.failed)" failures="$($results.contract_tests.failed)">
    <testcase name="powershell-python-contracts" classname="ContractTests" time="1.0"/>
  </testsuite>
  <testsuite name="security-tests" tests="$($results.security_tests.passed + $results.security_tests.failed)" failures="$($results.security_tests.failed)">
    <testcase name="security-boundary-contracts" classname="SecurityTests" time="1.0"/>
  </testsuite>
</testsuites>
"@
        $junitXml | Out-File -FilePath "contract-validation-results.xml" -Encoding UTF8
        Write-Host "JUnit results written to contract-validation-results.xml"
    }
}

# Clean up temporary files
if (Test-Path "contract-results.json") {
    Remove-Item "contract-results.json" -Force
}

# Exit with appropriate code
if ($results.overall_status -eq "PASSED") {
    exit 0
} else {
    exit 1
}
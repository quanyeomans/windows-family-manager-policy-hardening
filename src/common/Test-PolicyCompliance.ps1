# Policy Compliance Testing Module
# Provides validation functions for policy deployment

function Test-PolicyCompliance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$PolicyResults,
        
        [Parameter()]
        [string[]]$RequiredPolicies = @()
    )
    
    $compliance = @{
        OverallCompliant = $false
        AppliedPolicies = $PolicyResults.Applied.Count
        FailedPolicies = $PolicyResults.Failed.Count
        CompliancePercentage = 0
        MissingPolicies = @()
        Details = $PolicyResults
    }
    
    try {
        $totalPolicies = $PolicyResults.Applied.Count + $PolicyResults.Failed.Count
        
        if ($totalPolicies -gt 0) {
            $compliance.CompliancePercentage = [math]::Round(($PolicyResults.Applied.Count / $totalPolicies) * 100, 2)
        }
        
        # Check for required policies
        if ($RequiredPolicies.Count -gt 0) {
            foreach ($required in $RequiredPolicies) {
                if ($required -notin $PolicyResults.Applied) {
                    $compliance.MissingPolicies += $required
                }
            }
        }
        
        # Overall compliance determination
        $compliance.OverallCompliant = ($PolicyResults.Failed.Count -eq 0) -and ($compliance.MissingPolicies.Count -eq 0)
        
        return $compliance
    }
    catch {
        Write-Warning "Error testing policy compliance: $($_.Exception.Message)"
        return $compliance
    }
}

function Test-RegistryPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        
        [Parameter(Mandatory)]
        [string]$Property,
        
        [Parameter(Mandatory)]
        $ExpectedValue
    )
    
    try {
        if (-not (Test-Path $Path)) {
            return @{ Compliant = $false; Reason = "Registry path does not exist: $Path" }
        }
        
        $actualValue = Get-ItemProperty -Path $Path -Name $Property -ErrorAction Stop
        
        if ($actualValue.$Property -eq $ExpectedValue) {
            return @{ Compliant = $true; ActualValue = $actualValue.$Property }
        } else {
            return @{ Compliant = $false; Reason = "Value mismatch. Expected: $ExpectedValue, Actual: $($actualValue.$Property)" }
        }
    }
    catch {
        return @{ Compliant = $false; Reason = "Error reading registry: $($_.Exception.Message)" }
    }
}

# Export-ModuleMember -Function Test-PolicyCompliance, Test-RegistryPolicy
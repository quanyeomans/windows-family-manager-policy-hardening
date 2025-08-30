# Policy Logging Module
# Provides centralized logging for policy deployment operations

function Write-PolicyLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Info',
        
        [Parameter()]
        [string]$LogPath = "$env:TEMP\FamilyControlSystem-$(Get-Date -Format 'yyyyMMdd').log"
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to console with appropriate color
    $color = switch ($Level) {
        'Info' { 'White' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        'Debug' { 'Cyan' }
        default { 'White' }
    }
    
    Write-Host $logEntry -ForegroundColor $color
    
    # Also write to log file
    try {
        $logDir = Split-Path $LogPath -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
        Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Could not write to log file: $($_.Exception.Message)"
    }
}

# Export-ModuleMember -Function Write-PolicyLog
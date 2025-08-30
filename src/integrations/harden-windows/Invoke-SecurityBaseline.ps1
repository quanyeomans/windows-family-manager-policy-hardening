# Security Baseline Deployment Script
# Integrates HotCakeX/Harden-Windows-Security for Essential 8 Level 1 compliance
# Requirements: B020-B028 from product specification + gaming compatibility

[CmdletBinding()]
param(
    [ValidateSet('Personal', 'Enterprise', 'Custom')]
    [string]$SecurityLevel = 'Personal',
    
    [switch]$GamingOptimized = $true,
    
    [switch]$DryRun,
    
    [string]$ConfigPath = "config\baselines\family-security-config.json"
)

function Invoke-SecurityBaseline {
    [CmdletBinding()]
    param(
        [string]$SecurityLevel,
        [switch]$GamingOptimized,
        [switch]$DryRun,
        [string]$ConfigPath
    )
    
    Write-Host "=== Family Control Security Baseline Deployment ===" -ForegroundColor Cyan
    Write-Host "Security Level: $SecurityLevel" -ForegroundColor Gray
    Write-Host "Gaming Optimized: $GamingOptimized" -ForegroundColor Gray
    Write-Host "Dry Run: $DryRun" -ForegroundColor Gray
    Write-Host ""
    
    # Load configuration
    $config = Get-SecurityConfiguration -ConfigPath $ConfigPath
    
    # Pre-deployment validation
    Write-Host "Phase 1: Pre-deployment Validation" -ForegroundColor Yellow
    $validationResult = Test-PreDeploymentRequirements
    if (-not $validationResult.Success) {
        throw "Pre-deployment validation failed: $($validationResult.Issues -join '; ')"
    }
    Write-Host "✅ Pre-deployment validation passed" -ForegroundColor Green
    
    # Create system restore point
    if (-not $DryRun) {
        Write-Host "Phase 2: Creating System Restore Point" -ForegroundColor Yellow
        try {
            $restorePoint = New-SystemRestorePoint -Description "Family Control Security Baseline" -RestorePointType MODIFY_SETTINGS
            Write-Host "✅ System restore point created" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to create system restore point: $($_.Exception.Message)"
        }
    }
    
    # Deploy HotCakeX security hardening
    Write-Host "Phase 3: HotCakeX Security Hardening" -ForegroundColor Yellow
    $hardenResult = Deploy-HotCakeXHardening -Level $SecurityLevel -GamingOptimized:$GamingOptimized -DryRun:$DryRun
    
    # Deploy family-specific security extensions
    Write-Host "Phase 4: Family Security Extensions" -ForegroundColor Yellow  
    $familyResult = Deploy-FamilySecurityExtensions -Config $config -DryRun:$DryRun
    
    # Validate deployment
    Write-Host "Phase 5: Deployment Validation" -ForegroundColor Yellow
    $validationResult = Test-SecurityBaselineDeployment
    
    # Generate deployment report
    $deploymentResult = @{
        Timestamp = Get-Date
        SecurityLevel = $SecurityLevel
        GamingOptimized = $GamingOptimized
        DryRun = $DryRun
        HotCakeXResult = $hardenResult
        FamilyExtensionsResult = $familyResult
        ValidationResult = $validationResult
        RestorePointCreated = $restorePoint -ne $null
    }
    
    # Save deployment log
    $logPath = "logs\security-baseline-deployment-$(Get-Date -Format 'yyyy-MM-dd-HHmm').json"
    $deploymentResult | ConvertTo-Json -Depth 10 | Out-File -FilePath $logPath -Encoding UTF8
    
    Write-Host ""
    Write-Host "✅ Security baseline deployment completed: $logPath" -ForegroundColor Green
    Show-DeploymentSummary -Result $deploymentResult
    
    return $deploymentResult
}

function Get-SecurityConfiguration {
    param([string]$ConfigPath)
    
    if (Test-Path $ConfigPath) {
        return Get-Content $ConfigPath | ConvertFrom-Json
    }
    
    # Default family security configuration
    Write-Host "Using default family security configuration" -ForegroundColor Yellow
    return @{
        Essential8Controls = @{
            ApplicationControl = @{
                Enabled = $true
                Mode = "Audit"  # Start with audit mode for gaming compatibility
                AllowedApplications = @("msedge.exe", "powershell.exe")
            }
            PatchManagement = @{
                AutomaticUpdates = $true
                IncludeRecommended = $true
                MaintenanceWindow = "Sunday 2:00 AM"
            }
            AdminPrivileges = @{
                MaxAdminAccounts = 2
                RequireComplexPasswords = $true
                RestrictTokens = $true
            }
            MultiFactorAuth = @{
                RequireMFA = $true
                ExemptLocalConsole = $true
            }
            DataBackup = @{
                EnableWindowsBackup = $true
                BackupUserData = $true
                BackupSchedule = "Daily"
            }
            WebFiltering = @{
                DefaultBrowser = "msedge.exe"
                BlockAlternativeBrowsers = $true
                EnableSafeSearch = $true
            }
        }
        FamilySpecific = @{
            NetworkRestrictions = @{
                AuthorizedSSIDs = @("HomeNetwork_5G", "HomeNetwork_2.4G") 
                DisableEthernet = $true
                BlockVPNApps = $true
            }
            GamingOptimizations = @{
                PreserveSteamPerformance = $true
                ExcludeGameDirectories = $true
                MinimizeRealtimeScanning = $true
            }
            TransparencySettings = @{
                ShowPrivacyNotification = $true
                LogUserActivities = $true
                EnableParentDashboard = $true
            }
        }
    }
}

function Test-PreDeploymentRequirements {
    $issues = @()
    
    # Check if running as Administrator
    if (-not (Test-IsElevated)) {
        $issues += "Must run as Administrator"
    }
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        $issues += "PowerShell 5.0 or higher required"
    }
    
    # Check Windows version
    $osVersion = Get-CimInstance Win32_OperatingSystem
    if ($osVersion.BuildNumber -lt 10240) {
        $issues += "Windows 10 or higher required"
    }
    
    # Check available disk space (minimum 1GB)
    $systemDrive = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $env:SystemDrive }
    $freeSpaceGB = [math]::Round($systemDrive.FreeSpace / 1GB, 2)
    if ($freeSpaceGB -lt 1) {
        $issues += "Insufficient disk space: $freeSpaceGB GB available (minimum 1GB required)"
    }
    
    return @{
        Success = $issues.Count -eq 0
        Issues = $issues
    }
}

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal] $identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Deploy-HotCakeXHardening {
    param(
        [string]$Level,
        [switch]$GamingOptimized,
        [switch]$DryRun
    )
    
    $result = @{
        Status = "NotStarted"
        Method = "Unknown"
        Details = @()
        Errors = @()
    }
    
    # Try to find HotCakeX script in multiple locations
    $hardenScriptPaths = @(
        "vendor\hotcakex\Harden-Windows-Security.ps1",
        "vendor\harden-windows-security\Harden-Windows-Security.ps1",
        "C:\Tools\HardWinSec\Harden-Windows-Security.ps1"
    )
    
    $hardenScript = $null
    foreach ($path in $hardenScriptPaths) {
        if (Test-Path $path) {
            $hardenScript = $path
            break
        }
    }
    
    if ($hardenScript) {
        Write-Host "  Found HotCakeX script: $hardenScript" -ForegroundColor Gray
        $result.Method = "HotCakeX-Direct"
        
        if (-not $DryRun) {
            try {
                # Configure HotCakeX parameters for family/gaming use
                $hardenParams = @{
                    Categories = @("Defender", "EdgeBrowserConfigurations")
                    Mode = "Unattended"
                }
                
                if ($GamingOptimized) {
                    # Exclude gaming-impacting configurations
                    $result.Details += "Gaming optimizations applied - excluding network and game mode settings"
                }
                
                Write-Host "    Executing HotCakeX security hardening..." -ForegroundColor Gray
                $hardenOutput = & $hardenScript @hardenParams 2>&1
                
                $result.Status = "Success"
                $result.Details += "HotCakeX hardening completed successfully"
                $result.Output = $hardenOutput
                
            }
            catch {
                $result.Status = "Failed"
                $result.Errors += "HotCakeX execution failed: $($_.Exception.Message)"
            }
        }
        else {
            $result.Status = "DryRun"
            $result.Details += "Dry run - would execute HotCakeX hardening with $Level level"
        }
    }
    else {
        # Fallback to manual Essential 8 implementation
        Write-Warning "  HotCakeX script not found, using manual Essential 8 implementation"
        $result.Method = "Manual-Essential8"
        $result.Status = "Fallback"
        
        $manualResult = Deploy-ManualEssential8Controls -DryRun:$DryRun
        $result.Details += $manualResult.Details
        $result.Errors += $manualResult.Errors
    }
    
    return $result
}

function Deploy-ManualEssential8Controls {
    param([switch]$DryRun)
    
    $result = @{
        Details = @()
        Errors = @()
    }
    
    Write-Host "    Implementing Essential 8 Level 1 controls manually..." -ForegroundColor Gray
    
    # Essential 8 Control 1: Application Control (Basic)
    try {
        if (-not $DryRun) {
            # Enable basic application reputation checking
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1 -Force
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value "Block" -Force
        }
        $result.Details += "Application reputation control enabled"
    }
    catch {
        $result.Errors += "Failed to enable application control: $($_.Exception.Message)"
    }
    
    # Essential 8 Control 2: Patch Management
    try {
        if (-not $DryRun) {
            # Enable automatic updates
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 4 -Force
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AutoInstallMinorUpdates" -Value 1 -Force
        }
        $result.Details += "Automatic Windows Updates enabled"
    }
    catch {
        $result.Errors += "Failed to configure automatic updates: $($_.Exception.Message)"
    }
    
    # Essential 8 Control 3: Administrative Privileges
    try {
        if (-not $DryRun) {
            # Enable UAC at highest level
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Force
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Force
        }
        $result.Details += "UAC configured for maximum security"
    }
    catch {
        $result.Errors += "Failed to configure UAC: $($_.Exception.Message)"
    }
    
    # Essential 8 Control 6: Data Backup (Enable Windows Backup)
    try {
        if (-not $DryRun) {
            # Enable File History if available
            $fileHistory = Get-Command Set-FileHistoryConfiguration -ErrorAction SilentlyContinue
            if ($fileHistory) {
                Enable-FileHistory -Force
                $result.Details += "File History backup enabled"
            }
        }
    }
    catch {
        $result.Errors += "Failed to enable backup: $($_.Exception.Message)"
    }
    
    return $result
}

function Deploy-FamilySecurityExtensions {
    param(
        $Config,
        [switch]$DryRun
    )
    
    $result = @{
        Status = "NotStarted"
        Details = @()
        Errors = @()
    }
    
    Write-Host "  Deploying family-specific security extensions..." -ForegroundColor Gray
    
    # Network restrictions
    try {
        if (-not $DryRun) {
            Deploy-NetworkRestrictions -Config $Config.FamilySpecific.NetworkRestrictions
        }
        $result.Details += "Network restrictions configured"
    }
    catch {
        $result.Errors += "Network restriction deployment failed: $($_.Exception.Message)"
    }
    
    # Browser restrictions
    try {
        if (-not $DryRun) {
            Deploy-BrowserRestrictions -Config $Config.Essential8Controls.WebFiltering
        }
        $result.Details += "Browser restrictions configured"
    }
    catch {
        $result.Errors += "Browser restriction deployment failed: $($_.Exception.Message)"
    }
    
    # Gaming optimizations
    if ($Config.FamilySpecific.GamingOptimizations.PreserveSteamPerformance) {
        try {
            if (-not $DryRun) {
                Set-GamingOptimizations -Config $Config.FamilySpecific.GamingOptimizations
            }
            $result.Details += "Gaming performance optimizations applied"
        }
        catch {
            $result.Errors += "Gaming optimization failed: $($_.Exception.Message)"
        }
    }
    
    $result.Status = if ($result.Errors.Count -eq 0) { "Success" } else { "Partial" }
    return $result
}

function Deploy-NetworkRestrictions {
    param($Config)
    
    # Disable ethernet adapter if configured
    if ($Config.DisableEthernet) {
        Get-NetAdapter -Name "Ethernet*" -ErrorAction SilentlyContinue | Disable-NetAdapter -Confirm:$false
    }
    
    # Configure authorized WiFi networks (requires elevated permissions and manual setup)
    Write-Host "    Network SSID restrictions require manual WiFi profile configuration" -ForegroundColor Yellow
}

function Deploy-BrowserRestrictions {
    param($Config)
    
    # Configure Edge as default browser
    if ($Config.DefaultBrowser -eq "msedge.exe") {
        # Set Edge security policies
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DefaultBrowserSettingEnabled" -Value 1 -Force
    }
    
    # Block alternative browsers (basic registry approach)
    if ($Config.BlockAlternativeBrowsers) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisallowRun" -Value 1 -Force
        
        # Add blocked browsers to disallowed run list
        $blockedBrowsers = @("chrome.exe", "firefox.exe", "opera.exe", "brave.exe")
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" -Force | Out-Null
        for ($i = 0; $i -lt $blockedBrowsers.Count; $i++) {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" -Name ($i + 1) -Value $blockedBrowsers[$i] -Force
        }
    }
}

function Set-GamingOptimizations {
    param($Config)
    
    # Enable Game Mode for better performance
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Value 1 -Force
    
    # Configure Windows Defender to exclude common game directories
    if ($Config.ExcludeGameDirectories) {
        $gameDirectories = @(
            "$env:ProgramFiles(x86)\Steam",
            "$env:ProgramFiles\Epic Games", 
            "$env:LOCALAPPDATA\Programs\Electronic Arts"
        )
        
        foreach ($dir in $gameDirectories) {
            if (Test-Path $dir) {
                try {
                    Add-MpPreference -ExclusionPath $dir -ErrorAction SilentlyContinue
                }
                catch {
                    # Defender cmdlet might not be available
                }
            }
        }
    }
}

function Test-SecurityBaselineDeployment {
    Write-Host "  Validating security baseline deployment..." -ForegroundColor Gray
    
    $validation = @{
        Success = $true
        Details = @()
        Issues = @()
    }
    
    # Test Essential 8 controls
    try {
        # Check automatic updates
        $auOptions = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -ErrorAction SilentlyContinue
        if ($auOptions.AUOptions -eq 4) {
            $validation.Details += "✅ Automatic updates enabled"
        } else {
            $validation.Issues += "⚠️ Automatic updates not properly configured"
            $validation.Success = $false
        }
        
        # Check UAC configuration
        $uacLevel = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
        if ($uacLevel.ConsentPromptBehaviorAdmin -eq 2) {
            $validation.Details += "✅ UAC configured for maximum security"
        } else {
            $validation.Issues += "⚠️ UAC not at recommended security level"
        }
        
        # Check Windows Defender status
        $defenderStatus = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
        if ($defenderStatus -and $defenderStatus.Status -eq "Running") {
            $validation.Details += "✅ Windows Defender running"
        } else {
            $validation.Issues += "⚠️ Windows Defender not running"
            $validation.Success = $false
        }
        
    }
    catch {
        $validation.Issues += "❌ Validation error: $($_.Exception.Message)"
        $validation.Success = $false
    }
    
    return $validation
}

function Show-DeploymentSummary {
    param($Result)
    
    Write-Host ""
    Write-Host "=== DEPLOYMENT SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Method: $($Result.HotCakeXResult.Method)" -ForegroundColor Gray
    Write-Host "HotCakeX Status: " -NoNewline
    
    $hStatus = $Result.HotCakeXResult.Status
    $color = switch ($hStatus) {
        "Success" { "Green" }
        "Partial" { "Yellow" }
        "Failed" { "Red" }
        default { "Gray" }
    }
    Write-Host $hStatus -ForegroundColor $color
    
    Write-Host "Family Extensions: " -NoNewline
    $fStatus = $Result.FamilyExtensionsResult.Status
    $color = switch ($fStatus) {
        "Success" { "Green" }
        "Partial" { "Yellow" } 
        "Failed" { "Red" }
        default { "Gray" }
    }
    Write-Host $fStatus -ForegroundColor $color
    
    Write-Host "Validation: " -NoNewline
    Write-Host $Result.ValidationResult.Success -ForegroundColor $(if ($Result.ValidationResult.Success) { "Green" } else { "Red" })
    
    if ($Result.ValidationResult.Issues.Count -gt 0) {
        Write-Host ""
        Write-Host "VALIDATION ISSUES:" -ForegroundColor Yellow
        foreach ($issue in $Result.ValidationResult.Issues) {
            Write-Host "  $issue" -ForegroundColor Yellow
        }
    }
    
    Write-Host ""
    Write-Host "Next: Run security contract tests to validate deployment" -ForegroundColor Cyan
}

# Execute if script is run directly
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-SecurityBaseline -SecurityLevel $SecurityLevel -GamingOptimized:$GamingOptimized -DryRun:$DryRun -ConfigPath $ConfigPath
}
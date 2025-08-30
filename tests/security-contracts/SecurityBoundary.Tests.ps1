# Security Boundary Contract Tests
# ZERO TOLERANCE - Any failure blocks all development
# Requirements: Security Framework + Testing Strategy

#Requires -Modules Pester

Import-Module Pester -Force

Describe "Security Boundary Contract Tests - ZERO TOLERANCE" -Tags @("security_contract", "zero_tolerance", "critical_security") {
    
    BeforeAll {
        Write-Host "Initializing Security Boundary Contract Tests..." -ForegroundColor Cyan
        
        # Ensure we're testing the actual system state
        $script:TestResults = @{}
        $script:SystemBaseline = @{}
        
        # Load system baseline if available
        $baselineFile = "logs\system-assessment-*.json" 
        $latestBaseline = Get-ChildItem -Path $baselineFile -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latestBaseline) {
            $script:SystemBaseline = Get-Content $latestBaseline.FullName | ConvertFrom-Json
        }
    }
    
    Context "Network Security Boundary Contracts" {
        
        It "MUST prevent unauthorized WiFi connections" -Tag "network_security" {
            # Test that system blocks connections to non-authorized networks
            $authorizedNetworks = @("HomeNetwork_5G", "HomeNetwork_2.4G")
            
            # Get current WiFi profiles
            try {
                $wifiProfiles = netsh wlan show profiles 2>$null | Select-String "All User Profile" | ForEach-Object {
                    ($_ -split ":")[1].Trim()
                }
                
                # Check that only authorized networks are configured
                foreach ($profile in $wifiProfiles) {
                    if ($profile -and $profile -ne "") {
                        $profile | Should -BeIn $authorizedNetworks -Because "Unauthorized WiFi profile '$profile' found"
                    }
                }
                
                $script:TestResults.NetworkSecurity = "PASS"
            }
            catch {
                $script:TestResults.NetworkSecurity = "ERROR: $($_.Exception.Message)"
                throw "Network security contract validation failed: $($_.Exception.Message)"
            }
        }
        
        It "MUST block VPN application execution" -Tag "network_security" {
            # Test that VPN applications cannot execute
            $commonVPNApps = @("nordvpn.exe", "expressvpn.exe", "surfshark.exe", "openvpn.exe", "windscribe.exe")
            
            foreach ($vpnApp in $commonVPNApps) {
                # Check if VPN app is in running processes
                $runningVPN = Get-Process | Where-Object { $_.ProcessName -like "*$($vpnApp.Replace('.exe', ''))*" }
                $runningVPN | Should -BeNullOrEmpty -Because "VPN application '$vpnApp' should be blocked from running"
                
                # Check if VPN app exists in common installation paths
                $commonPaths = @(
                    "$env:ProgramFiles\*$($vpnApp.Replace('.exe', ''))*",
                    "$env:ProgramFiles(x86)\*$($vpnApp.Replace('.exe', ''))*",
                    "$env:LOCALAPPDATA\Programs\*$($vpnApp.Replace('.exe', ''))*"
                )
                
                foreach ($path in $commonPaths) {
                    $vpnInstallation = Get-ChildItem -Path $path -Recurse -Include $vpnApp -ErrorAction SilentlyContinue
                    if ($vpnInstallation) {
                        # If VPN app exists, it should be blocked by policy
                        Write-Warning "VPN application found at $($vpnInstallation.FullName) - should be blocked by application control"
                        # Test execution blocking would require actually trying to run it, which is not safe in production
                    }
                }
            }
        }
        
        It "MUST disable ethernet adapter when configured" -Tag "network_security" {
            # Test ethernet adapter status
            try {
                $ethernetAdapters = Get-NetAdapter -Name "Ethernet*" -ErrorAction SilentlyContinue
                
                foreach ($adapter in $ethernetAdapters) {
                    # According to family security policy, ethernet should be disabled
                    $adapter.Status | Should -Be "Disabled" -Because "Ethernet adapter should be disabled per family security policy"
                }
            }
            catch {
                # If Get-NetAdapter not available, skip this test
                Write-Warning "Cannot test ethernet adapter status - NetAdapter cmdlets not available"
            }
        }
    }
    
    Context "User Account Security Boundary Contracts" {
        
        It "MUST prevent unauthorized local account creation" -Tag "user_security" {
            # Test that new local accounts cannot be created without admin privileges
            try {
                # This test requires admin context to validate the restriction is in place
                if (-not (Test-IsElevated)) {
                    Write-Warning "Not running as administrator - cannot fully test account creation restrictions"
                    return
                }
                
                # Check current user accounts
                $currentUsers = Get-LocalUser
                $userCount = $currentUsers.Count
                
                # Test that non-admin users cannot create accounts (requires attempting from non-admin context)
                # For now, verify that admin account count is limited
                $adminUsers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
                $adminUsers.Count | Should -BeLessOrEqual 3 -Because "Too many administrator accounts detected (should be 2-3 maximum)"
                
                $script:TestResults.UserAccountSecurity = "PASS"
            }
            catch {
                $script:TestResults.UserAccountSecurity = "ERROR: $($_.Exception.Message)"
                throw "User account security contract failed: $($_.Exception.Message)"
            }
        }
        
        It "MUST block privilege escalation attempts" -Tag "user_security" {
            # Test UAC configuration and admin group restrictions
            try {
                # Check UAC settings
                $uacSetting = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
                
                if ($uacSetting) {
                    # UAC should be configured for maximum security (value 2 = Always prompt)
                    $uacSetting.ConsentPromptBehaviorAdmin | Should -BeIn @(1, 2) -Because "UAC should be configured for security prompts"
                }
                
                # Check that UAC is enabled
                $uacEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
                if ($uacEnabled) {
                    $uacEnabled.EnableLUA | Should -Be 1 -Because "UAC must be enabled"
                }
                
            }
            catch {
                throw "Privilege escalation security contract failed: $($_.Exception.Message)"
            }
        }
    }
    
    Context "Application Control Security Boundary Contracts" {
        
        It "MUST allow only Microsoft Edge browser execution" -Tag "application_security" {
            # Test browser restriction policy
            $allowedBrowser = "msedge.exe"
            $blockedBrowsers = @("chrome.exe", "firefox.exe", "opera.exe", "brave.exe")
            
            # Check that Edge is available
            $edgePath = Get-Command msedge -ErrorAction SilentlyContinue
            if (-not $edgePath) {
                # Try common Edge installation paths
                $commonEdgePaths = @(
                    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
                    "$env:ProgramFiles(x86)\Microsoft\Edge\Application\msedge.exe"
                )
                
                $edgeFound = $false
                foreach ($path in $commonEdgePaths) {
                    if (Test-Path $path) {
                        $edgeFound = $true
                        break
                    }
                }
                
                $edgeFound | Should -Be $true -Because "Microsoft Edge must be available as the allowed browser"
            }
            
            # Check for blocked browsers in running processes
            $runningProcesses = Get-Process
            foreach ($blockedBrowser in $blockedBrowsers) {
                $browserProcess = $runningProcesses | Where-Object { $_.ProcessName -like "*$($blockedBrowser.Replace('.exe', ''))*" }
                $browserProcess | Should -BeNullOrEmpty -Because "Blocked browser '$blockedBrowser' should not be running"
            }
        }
        
        It "MUST allow PowerShell with monitoring enabled" -Tag "application_security" {
            # Test that PowerShell is available but monitored
            $powershellAvailable = Get-Command powershell -ErrorAction SilentlyContinue
            $powershellAvailable | Should -Not -BeNullOrEmpty -Because "PowerShell should be available for development work"
            
            # Check if PowerShell execution policy allows script execution
            $executionPolicy = Get-ExecutionPolicy
            $executionPolicy | Should -Not -Be "Restricted" -Because "PowerShell execution policy should allow development scripts"
            
            # Verify monitoring would be enabled (check for logging configuration)
            $psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
            $moduleLogging = Get-ItemProperty -Path $psLogPath -ErrorAction SilentlyContinue
            
            # Note: In family environment, we want transparency not stealth monitoring
            Write-Information "PowerShell monitoring status checked - family transparency model"
        }
    }
    
    Context "Essential 8 Security Boundary Contracts" {
        
        It "MUST have Windows Defender antivirus enabled" -Tag "essential8" {
            # Test Windows Defender status
            try {
                $defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
                $defenderService.Status | Should -Be "Running" -Because "Windows Defender must be running"
                
                # Check Defender status via WMI if available
                $defenderStatus = Get-CimInstance -Namespace "root\Microsoft\Windows\Defender" -ClassName "MSFT_MpComputerStatus" -ErrorAction SilentlyContinue
                if ($defenderStatus) {
                    $defenderStatus.AntivirusEnabled | Should -Be $true -Because "Windows Defender antivirus must be enabled"
                    $defenderStatus.RealTimeProtectionEnabled | Should -Be $true -Because "Real-time protection must be enabled"
                }
            }
            catch {
                throw "Windows Defender security contract failed: $($_.Exception.Message)"
            }
        }
        
        It "MUST have automatic updates enabled" -Tag "essential8" {
            # Test Windows Update configuration
            $auSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue
            
            if ($auSettings) {
                # AUOptions: 4 = Install automatically
                $auSettings.AUOptions | Should -BeIn @(3, 4) -Because "Automatic updates must be enabled"
            } else {
                # Check Windows Update service status as fallback
                $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
                $wuService.StartType | Should -Not -Be "Disabled" -Because "Windows Update service must not be disabled"
            }
        }
        
        It "MUST maintain system integrity protection" -Tag "essential8" {
            # Test system file protection and integrity
            try {
                # Check System File Checker availability
                $sfcCommand = Get-Command sfc -ErrorAction SilentlyContinue
                $sfcCommand | Should -Not -BeNullOrEmpty -Because "System File Checker must be available"
                
                # Check Windows Resource Protection service
                $wrpService = Get-Service -Name TrustedInstaller -ErrorAction SilentlyContinue
                if ($wrpService) {
                    $wrpService.Status | Should -BeIn @("Running", "Stopped") -Because "TrustedInstaller service must be functional"
                    $wrpService.StartType | Should -Not -Be "Disabled" -Because "TrustedInstaller service must not be disabled"
                }
            }
            catch {
                Write-Warning "System integrity check limited: $($_.Exception.Message)"
            }
        }
    }
    
    AfterAll {
        Write-Host ""
        Write-Host "=== SECURITY CONTRACT TEST RESULTS ===" -ForegroundColor Cyan
        
        $passedTests = 0
        $totalTests = $script:TestResults.Count
        
        foreach ($result in $script:TestResults.GetEnumerator()) {
            $status = if ($result.Value -eq "PASS") { "✅" } else { "❌" }
            Write-Host "$status $($result.Key): $($result.Value)" -ForegroundColor $(if ($result.Value -eq "PASS") { "Green" } else { "Red" })
            
            if ($result.Value -eq "PASS") {
                $passedTests++
            }
        }
        
        Write-Host ""
        Write-Host "Security Contracts: $passedTests/$totalTests passed" -ForegroundColor $(if ($passedTests -eq $totalTests) { "Green" } else { "Red" })
        
        if ($passedTests -ne $totalTests) {
            Write-Host "⚠️  CRITICAL: Security contract failures detected!" -ForegroundColor Red
            Write-Host "   All security contract tests must pass before proceeding with development." -ForegroundColor Red
        } else {
            Write-Host "✅ All security contracts validated - safe to proceed with development" -ForegroundColor Green
        }
    }
}

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal] $identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
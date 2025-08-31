# Network Configuration Assessment - B005 Implementation
# Analyzes Windows network configuration for security risks and bypass indicators

param(
    [Parameter()]
    [switch]$Verbose = $false
)

function Get-NetworkConfiguration {
    <#
    .SYNOPSIS
    Analyzes Windows network configuration for security vulnerabilities.
    
    .DESCRIPTION
    Implements requirement B005 by assessing network configuration including:
    - WiFi security protocols and configurations
    - Network profile security settings
    - Firewall configuration analysis
    - Network adapter security settings
    
    .PARAMETER Verbose
    Enable verbose output for detailed analysis
    #>
    
    try {
        Write-Verbose "Starting network configuration security assessment..."
        
        $findings = @()
        $securityScore = 100
        
        # Check Windows Firewall status
        Write-Verbose "Analyzing Windows Firewall configuration..."
        try {
            $firewallProfiles = @("Domain", "Private", "Public")
            $firewallIssues = @()
            
            foreach ($profile in $firewallProfiles) {
                try {
                    $firewallStatus = & netsh advfirewall show $profile.ToLower()profile state 2>&1
                    $isEnabled = $firewallStatus -match "State\s+ON"
                    
                    if (-not $isEnabled) {
                        $firewallIssues += $profile
                        
                        $severity = switch ($profile) {
                            "Public" { "CRITICAL" }
                            "Private" { "HIGH" }
                            "Domain" { "MEDIUM" }
                            default { "MEDIUM" }
                        }
                        
                        $finding = @{
                            category = "B005_network_configuration"
                            severity = $severity
                            finding = "Windows Firewall disabled"
                            details = @{
                                firewall_profile = $profile
                                current_state = "OFF"
                                expected_state = "ON"
                                risk_description = "Windows Firewall is disabled for $profile profile"
                            }
                            remediation = "Enable Windows Firewall for $profile profile"
                            impact = "Network traffic not filtered, system exposed to network attacks"
                        }
                        
                        $findings += $finding
                        
                        $scoreReduction = switch ($severity) {
                            "CRITICAL" { 25 }
                            "HIGH" { 15 }
                            "MEDIUM" { 10 }
                            default { 5 }
                        }
                        $securityScore -= $scoreReduction
                        
                        Write-Warning "Windows Firewall disabled for $profile profile"
                    } else {
                        Write-Verbose "Windows Firewall enabled for $profile profile"
                    }
                } catch {
                    Write-Verbose "Error checking firewall profile $profile`: $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Verbose "Error accessing Windows Firewall: $($_.Exception.Message)"
            
            $finding = @{
                category = "B005_network_configuration"
                severity = "MEDIUM"
                finding = "Unable to verify Windows Firewall status"
                details = @{
                    error_message = $_.Exception.Message
                    risk_description = "Windows Firewall status could not be determined"
                }
                remediation = "Manually verify Windows Firewall configuration"
                impact = "Firewall security status unknown"
            }
            
            $findings += $finding
            $securityScore -= 8
        }
        
        # Check WiFi security configurations
        Write-Verbose "Analyzing WiFi security configurations..."
        try {
            $wifiProfiles = & netsh wlan show profiles 2>&1
            
            if ($wifiProfiles -and $wifiProfiles -notlike "*not supported*" -and $wifiProfiles -notlike "*not available*") {
                # Extract profile names
                $profileNames = $wifiProfiles | 
                               Where-Object { $_ -match "All User Profile\s+:\s+(.+)" } |
                               ForEach-Object { ($_ -split ":\s+")[1].Trim() }
                
                Write-Verbose "Found $($profileNames.Count) WiFi profiles"
                
                foreach ($profileName in $profileNames) {
                    try {
                        $profileDetails = & netsh wlan show profile name="$profileName" key=clear 2>&1
                        
                        if ($profileDetails) {
                            # Check security type
                            $authLine = $profileDetails | Where-Object { $_ -match "Authentication\s+:\s+(.+)" }
                            $encryptionLine = $profileDetails | Where-Object { $_ -match "Cipher\s+:\s+(.+)" }
                            
                            if ($authLine) {
                                $authType = ($authLine -split ":\s+")[1].Trim()
                                $encryptionType = if ($encryptionLine) { ($encryptionLine -split ":\s+")[1].Trim() } else { "Unknown" }
                                
                                # Check for weak security configurations
                                $isWeak = $false
                                $weaknessType = ""
                                
                                if ($authType -eq "Open") {
                                    $isWeak = $true
                                    $weaknessType = "Open network (no authentication)"
                                } elseif ($authType -eq "WEP") {
                                    $isWeak = $true
                                    $weaknessType = "WEP encryption (deprecated and insecure)"
                                } elseif ($encryptionType -eq "WEP") {
                                    $isWeak = $true
                                    $weaknessType = "WEP encryption (deprecated and insecure)"
                                } elseif ($authType -eq "WPA-Personal" -and $encryptionType -eq "TKIP") {
                                    $isWeak = $true
                                    $weaknessType = "WPA with TKIP (vulnerable to attacks)"
                                }
                                
                                if ($isWeak) {
                                    $severity = switch ($authType) {
                                        "Open" { "HIGH" }
                                        "WEP" { "HIGH" }
                                        default { "MEDIUM" }
                                    }
                                    
                                    $finding = @{
                                        category = "B005_network_configuration"
                                        severity = $severity
                                        finding = "Weak WiFi security configuration"
                                        details = @{
                                            wifi_profile = $profileName
                                            authentication_type = $authType
                                            encryption_type = $encryptionType
                                            weakness_description = $weaknessType
                                            risk_description = "WiFi profile uses weak or deprecated security"
                                        }
                                        remediation = "Reconfigure WiFi to use WPA2/WPA3 with AES encryption"
                                        impact = "Network communications vulnerable to interception"
                                    }
                                    
                                    $findings += $finding
                                    
                                    $scoreReduction = switch ($severity) {
                                        "HIGH" { 12 }
                                        "MEDIUM" { 8 }
                                        default { 4 }
                                    }
                                    $securityScore -= $scoreReduction
                                    
                                    Write-Warning "Weak WiFi security: $profileName ($weaknessType)"
                                } else {
                                    Write-Verbose "WiFi profile secure: $profileName ($authType / $encryptionType)"
                                }
                            }
                        }
                    } catch {
                        Write-Verbose "Error analyzing WiFi profile $profileName`: $($_.Exception.Message)"
                    }
                }
            } else {
                Write-Verbose "WiFi not available or supported on this system"
            }
        } catch {
            Write-Verbose "Error analyzing WiFi configurations: $($_.Exception.Message)"
        }
        
        # Check network adapters for security configurations
        Write-Verbose "Analyzing network adapter configurations..."
        try {
            $networkAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }
            
            foreach ($adapter in $networkAdapters) {
                Write-Verbose "Checking network adapter: $($adapter.Name)"
                
                # Check for promiscuous mode (potential security risk)
                try {
                    $adapterAdvanced = Get-NetAdapterAdvancedProperty -Name $adapter.Name -ErrorAction SilentlyContinue
                    $promiscuousMode = $adapterAdvanced | Where-Object { $_.DisplayName -like "*Promiscuous*" }
                    
                    if ($promiscuousMode -and $promiscuousMode.DisplayValue -eq "Enabled") {
                        $finding = @{
                            category = "B005_network_configuration"
                            severity = "MEDIUM"
                            finding = "Network adapter in promiscuous mode"
                            details = @{
                                adapter_name = $adapter.Name
                                adapter_description = $adapter.InterfaceDescription
                                promiscuous_mode = "Enabled"
                                risk_description = "Network adapter configured to capture all network traffic"
                            }
                            remediation = "Disable promiscuous mode unless required for network monitoring"
                            impact = "Potential network traffic interception capability"
                        }
                        
                        $findings += $finding
                        $securityScore -= 8
                        
                        Write-Warning "Promiscuous mode enabled on adapter: $($adapter.Name)"
                    }
                } catch {
                    Write-Verbose "Error checking advanced properties for adapter $($adapter.Name): $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Verbose "Error analyzing network adapters: $($_.Exception.Message)"
        }
        
        # Check for open/listening ports
        Write-Verbose "Checking for potentially risky open ports..."
        try {
            $listeningPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
            $riskyPorts = @()
            
            # Common risky ports to monitor
            $knownRiskyPorts = @(
                @{ Port = 21; Service = "FTP"; Risk = "HIGH" },
                @{ Port = 23; Service = "Telnet"; Risk = "CRITICAL" },
                @{ Port = 25; Service = "SMTP"; Risk = "MEDIUM" },
                @{ Port = 53; Service = "DNS"; Risk = "LOW" },
                @{ Port = 80; Service = "HTTP"; Risk = "LOW" },
                @{ Port = 110; Service = "POP3"; Risk = "MEDIUM" },
                @{ Port = 143; Service = "IMAP"; Risk = "MEDIUM" },
                @{ Port = 443; Service = "HTTPS"; Risk = "LOW" },
                @{ Port = 993; Service = "IMAPS"; Risk = "LOW" },
                @{ Port = 995; Service = "POP3S"; Risk = "LOW" },
                @{ Port = 1433; Service = "SQL Server"; Risk = "HIGH" },
                @{ Port = 3389; Service = "RDP"; Risk = "HIGH" },
                @{ Port = 5900; Service = "VNC"; Risk = "HIGH" },
                @{ Port = 5985; Service = "WinRM HTTP"; Risk = "MEDIUM" },
                @{ Port = 5986; Service = "WinRM HTTPS"; Risk = "MEDIUM" }
            )
            
            foreach ($connection in $listeningPorts) {
                $port = $connection.LocalPort
                $riskyPort = $knownRiskyPorts | Where-Object { $_.Port -eq $port }
                
                if ($riskyPort) {
                    $severity = switch ($riskyPort.Risk) {
                        "CRITICAL" { "CRITICAL" }
                        "HIGH" { "HIGH" }
                        "MEDIUM" { "MEDIUM" }
                        default { "LOW" }
                    }
                    
                    # Only report HIGH and CRITICAL risk ports as findings
                    if ($severity -in @("HIGH", "CRITICAL")) {
                        $finding = @{
                            category = "B005_network_configuration"
                            severity = $severity
                            finding = "Risky network service listening"
                            details = @{
                                port_number = $port
                                service_name = $riskyPort.Service
                                local_address = $connection.LocalAddress
                                process_id = $connection.OwningProcess
                                risk_level = $riskyPort.Risk
                                risk_description = "High-risk network service is accepting connections"
                            }
                            remediation = "Review necessity of $($riskyPort.Service) service and secure or disable if not needed"
                            impact = "Potential attack vector through network service"
                        }
                        
                        $findings += $finding
                        
                        $scoreReduction = switch ($severity) {
                            "CRITICAL" { 15 }
                            "HIGH" { 10 }
                            default { 5 }
                        }
                        $securityScore -= $scoreReduction
                        
                        Write-Warning "Risky service listening: $($riskyPort.Service) on port $port"
                    } else {
                        Write-Verbose "Network service listening: $($riskyPort.Service) on port $port (low risk)"
                    }
                }
            }
        } catch {
            Write-Verbose "Error checking network connections: $($_.Exception.Message)"
        }
        
        # Check network location profiles
        Write-Verbose "Checking network location profiles..."
        try {
            $networkProfiles = Get-NetConnectionProfile -ErrorAction SilentlyContinue
            
            foreach ($profile in $networkProfiles) {
                if ($profile.NetworkCategory -eq "Public") {
                    Write-Verbose "Network profile correctly set to Public: $($profile.Name)"
                } else {
                    # Private or Domain networks on unknown networks could be a risk
                    if ($profile.Name -notlike "*domain*" -and $profile.NetworkCategory -eq "Private") {
                        $finding = @{
                            category = "B005_network_configuration"
                            severity = "LOW"
                            finding = "Network location may be incorrectly classified"
                            details = @{
                                network_name = $profile.Name
                                network_category = $profile.NetworkCategory
                                interface_alias = $profile.InterfaceAlias
                                risk_description = "Network classified as Private but may be untrusted"
                            }
                            remediation = "Verify network location setting is appropriate for the network security level"
                            impact = "Firewall rules may be less restrictive than appropriate"
                        }
                        
                        $findings += $finding
                        $securityScore -= 3
                        
                        Write-Verbose "Potentially misconfigured network location: $($profile.Name) ($($profile.NetworkCategory))"
                    }
                }
            }
        } catch {
            Write-Verbose "Error checking network profiles: $($_.Exception.Message)"
        }
        
        # Ensure minimum score
        $securityScore = [Math]::Max($securityScore, 0)
        
        Write-Verbose "Network configuration assessment complete. Security score: $securityScore"
        
        return @{
            security_score = $securityScore
            findings = $findings
            assessment_summary = @{
                firewall_profiles_checked = 3
                wifi_profiles_analyzed = if ($profileNames) { $profileNames.Count } else { 0 }
                network_adapters_checked = if ($networkAdapters) { $networkAdapters.Count } else { 0 }
                listening_ports_scanned = if ($listeningPorts) { $listeningPorts.Count } else { 0 }
                risky_services_detected = ($findings | Where-Object { $_.finding -like "*service listening*" }).Count
                weak_wifi_configs = ($findings | Where-Object { $_.finding -like "*WiFi security*" }).Count
                firewall_issues = ($findings | Where-Object { $_.finding -like "*Firewall*" }).Count
                critical_findings = ($findings | Where-Object { $_.severity -eq "CRITICAL" }).Count
                high_findings = ($findings | Where-Object { $_.severity -eq "HIGH" }).Count
                medium_findings = ($findings | Where-Object { $_.severity -eq "MEDIUM" }).Count
                low_findings = ($findings | Where-Object { $_.severity -eq "LOW" }).Count
            }
        }
        
    } catch {
        Write-Error "Network configuration assessment failed: $($_.Exception.Message)"
        
        return @{
            security_score = 0
            findings = @(
                @{
                    category = "B005_network_configuration"
                    severity = "CRITICAL"
                    finding = "Network configuration assessment failed"
                    details = @{
                        error_message = $_.Exception.Message
                        risk_description = "Unable to complete network security assessment"
                    }
                    remediation = "Investigate network assessment failure and retry assessment"
                    impact = "Network security status unknown"
                }
            )
            assessment_summary = @{
                firewall_profiles_checked = 0
                wifi_profiles_analyzed = 0
                network_adapters_checked = 0
                listening_ports_scanned = 0
                risky_services_detected = 0
                weak_wifi_configs = 0
                firewall_issues = 0
                critical_findings = 1
                high_findings = 0
                medium_findings = 0
                low_findings = 0
            }
        }
    }
}

# Execute if called directly
if ($MyInvocation.InvocationName -eq $MyInvocation.MyCommand.Name) {
    Get-NetworkConfiguration -Verbose:$Verbose | ConvertTo-Json -Depth 10
}
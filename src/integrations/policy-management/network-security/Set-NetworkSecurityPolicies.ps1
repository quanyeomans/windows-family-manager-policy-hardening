# Network Security Policy Implementation
# Implements S008-S014 requirements with family-specific configuration
# Part of Windows Family Manager Policy Hardening System

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$ConfigPath,
    
    [Parameter()]
    [switch]$DryRun,
    
    [Parameter()]
    [switch]$Reverse,
    
    [Parameter()]
    [ValidateSet('Silent', 'Normal', 'Verbose')]
    [string]$LogLevel = 'Normal'
)

# Import required modules
Import-Module "$PSScriptRoot\..\..\..\common\Invoke-PolicyLogger.ps1" -Force
Import-Module "$PSScriptRoot\..\..\..\common\Test-PolicyCompliance.ps1" -Force

function Set-NetworkSecurityPolicies {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Config,
        [switch]$DryRun,
        [switch]$Reverse
    )
    
    $results = @{
        Applied = @()
        Failed = @()
        Skipped = @()
        FirewallRules = @()
    }
    
    try {
        # Load family-specific configuration
        $familyConfig = $Config.FamilyConfiguration
        $networkConfig = $Config.PolicyConfiguration.NetworkSecurity
        
        Write-PolicyLog -Message "Starting network security policy deployment" -Level Info
        Write-PolicyLog -Message "Allowed domains: $($networkConfig.AllowedDomains.Count) configured" -Level Info
        
        # S008: Configure Windows Firewall
        $firewallResult = Set-WindowsFirewallPolicies -Config $networkConfig.WindowsFirewall -DryRun:$DryRun -Reverse:$Reverse
        $results.Applied += $firewallResult.Applied
        $results.Failed += $firewallResult.Failed
        $results.FirewallRules += $firewallResult.Rules
        
        # S009: Block unauthorized network protocols
        $protocolResult = Set-NetworkProtocolRestrictions -Config $networkConfig.ProtocolRestrictions -DryRun:$DryRun -Reverse:$Reverse
        $results.Applied += $protocolResult.Applied
        $results.Failed += $protocolResult.Failed
        
        # S010: Configure DNS filtering
        $dnsResult = Set-DNSFiltering -Config $networkConfig.DNSFiltering -DryRun:$DryRun -Reverse:$Reverse
        $results.Applied += $dnsResult.Applied
        $results.Failed += $dnsResult.Failed
        
        # S011: Disable network discovery
        $discoveryResult = Set-NetworkDiscoverySettings -Config $networkConfig.NetworkDiscovery -DryRun:$DryRun -Reverse:$Reverse
        $results.Applied += $discoveryResult.Applied
        $results.Failed += $discoveryResult.Failed
        
        # S012: Configure proxy settings
        if ($networkConfig.ProxySettings.Enabled) {
            $proxyResult = Set-ProxyConfiguration -Config $networkConfig.ProxySettings -DryRun:$DryRun -Reverse:$Reverse
            $results.Applied += $proxyResult.Applied
            $results.Failed += $proxyResult.Failed
        } else {
            $results.Skipped += "S012_ProxyConfiguration (disabled in config)"
        }
        
        # S013: Restrict remote connections
        $remoteResult = Set-RemoteConnectionRestrictions -Config $networkConfig.RemoteAccess -DryRun:$DryRun -Reverse:$Reverse
        $results.Applied += $remoteResult.Applied
        $results.Failed += $remoteResult.Failed
        
        # S014: Configure network location awareness
        $locationResult = Set-NetworkLocationSettings -Config $networkConfig.NetworkLocation -DryRun:$DryRun -Reverse:$Reverse
        $results.Applied += $locationResult.Applied
        $results.Failed += $locationResult.Failed
        
        # Log final results
        Write-PolicyLog -Message "Network security policy deployment completed" -Level Info
        Write-PolicyLog -Message "Applied policies: $($results.Applied.Count)" -Level Info
        Write-PolicyLog -Message "Failed policies: $($results.Failed.Count)" -Level $(if ($results.Failed.Count -gt 0) { 'Warning' } else { 'Info' })
        Write-PolicyLog -Message "Firewall rules created: $($results.FirewallRules.Count)" -Level Info
        
        return $results
        
    }
    catch {
        Write-PolicyLog -Message "Critical error in network security policy deployment: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Set-WindowsFirewallPolicies {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Config,
        [switch]$DryRun,
        [switch]$Reverse
    )
    
    $result = @{
        Applied = @()
        Failed = @()
        Rules = @()
    }
    
    Write-PolicyLog -Message "Configuring Windows Firewall policies" -Level Info
    
    # S008.1: Enable Windows Firewall for all profiles
    $profiles = @('Domain', 'Private', 'Public')
    foreach ($profile in $profiles) {
        $policy = @{
            Name = "S008_EnableFirewall_$profile"
            Profile = $profile
            Action = if ($Reverse) { 'Disable' } else { 'Enable' }
        }
        
        try {
            if (-not $DryRun -and $PSCmdlet.ShouldProcess("Windows Firewall $profile Profile", $policy.Action)) {
                if ($Reverse) {
                    Set-NetFirewallProfile -Profile $profile -Enabled False
                } else {
                    Set-NetFirewallProfile -Profile $profile -Enabled True
                    # Set default actions
                    Set-NetFirewallProfile -Profile $profile -DefaultInboundAction Block -DefaultOutboundAction Allow
                }
                $result.Applied += $policy.Name
                Write-PolicyLog -Message "$($policy.Action)d Windows Firewall for $profile profile" -Level Info
            } elseif ($DryRun) {
                Write-PolicyLog -Message "[DRY RUN] Would $($policy.Action.ToLower()) Windows Firewall for $profile profile" -Level Info
                $result.Applied += $policy.Name
            }
        }
        catch {
            $result.Failed += @{
                Policy = $policy.Name
                Error = $_.Exception.Message
            }
            Write-PolicyLog -Message "Failed to configure firewall profile $profile`: $($_.Exception.Message)" -Level Error
        }
    }
    
    # S008.2: Create specific firewall rules for allowed applications
    if ($Config.AllowedApplications -and -not $Reverse) {
        foreach ($app in $Config.AllowedApplications) {
            $ruleName = "FamilyControl_Allow_$($app.Name)"
            $policy = @{
                Name = "S008_AllowApp_$($app.Name)"
                RuleName = $ruleName
                Program = $app.Path
                Action = 'Allow'
            }
            
            try {
                if (-not $DryRun -and $PSCmdlet.ShouldProcess($ruleName, "Create Firewall Rule")) {
                    # Remove existing rule if present
                    Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
                    
                    # Create new rule
                    New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Program $app.Path -Action Allow -Profile Any
                    $result.Applied += $policy.Name
                    $result.Rules += $ruleName
                    Write-PolicyLog -Message "Created firewall rule for $($app.Name): $($app.Path)" -Level Info
                } elseif ($DryRun) {
                    Write-PolicyLog -Message "[DRY RUN] Would create firewall rule for $($app.Name): $($app.Path)" -Level Info
                    $result.Applied += $policy.Name
                    $result.Rules += $ruleName
                }
            }
            catch {
                $result.Failed += @{
                    Policy = $policy.Name
                    Error = $_.Exception.Message
                }
                Write-PolicyLog -Message "Failed to create firewall rule for $($app.Name): $($_.Exception.Message)" -Level Error
            }
        }
    } elseif ($Config.AllowedApplications -and $Reverse) {
        # Remove family control firewall rules
        try {
            $familyRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "FamilyControl_*" }
            foreach ($rule in $familyRules) {
                if (-not $DryRun -and $PSCmdlet.ShouldProcess($rule.DisplayName, "Remove Firewall Rule")) {
                    Remove-NetFirewallRule -DisplayName $rule.DisplayName
                    Write-PolicyLog -Message "Removed firewall rule: $($rule.DisplayName)" -Level Info
                } elseif ($DryRun) {
                    Write-PolicyLog -Message "[DRY RUN] Would remove firewall rule: $($rule.DisplayName)" -Level Info
                }
            }
            $result.Applied += "S008_RemoveFamilyRules"
        }
        catch {
            $result.Failed += @{
                Policy = "S008_RemoveFamilyRules"
                Error = $_.Exception.Message
            }
        }
    }
    
    return $result
}

function Set-NetworkProtocolRestrictions {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Config,
        [switch]$DryRun,
        [switch]$Reverse
    )
    
    $result = @{
        Applied = @()
        Failed = @()
    }
    
    Write-PolicyLog -Message "Configuring network protocol restrictions" -Level Info
    
    # S009.1: Disable unused network protocols
    $protocolsToDisable = $Config.DisabledProtocols
    foreach ($protocol in $protocolsToDisable) {
        $policy = @{
            Name = "S009_DisableProtocol_$protocol"
            Protocol = $protocol
            Action = if ($Reverse) { 'Enable' } else { 'Disable' }
        }
        
        try {
            switch ($protocol.ToUpper()) {
                'NETBIOS' {
                    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
                    $regProperty = "NetbiosOptions"
                    $regValue = if ($Reverse) { 0 } else { 2 }  # 2 = Disable NetBIOS over TCP/IP
                }
                'LLMNR' {
                    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
                    $regProperty = "EnableMulticast"
                    $regValue = if ($Reverse) { 1 } else { 0 }  # 0 = Disable LLMNR
                }
                'WPAD' {
                    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
                    $regProperty = "WpadOverride"
                    $regValue = if ($Reverse) { 0 } else { 1 }  # 1 = Disable WPAD
                }
                default {
                    throw "Unsupported protocol: $protocol"
                }
            }
            
            if (-not $DryRun -and $PSCmdlet.ShouldProcess($regPath, "Set Registry Value $regProperty = $regValue")) {
                # Create registry path if it doesn't exist
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                
                Set-ItemProperty -Path $regPath -Name $regProperty -Value $regValue -Type DWord
                $result.Applied += $policy.Name
                Write-PolicyLog -Message "$($policy.Action)d protocol: $protocol" -Level Info
            } elseif ($DryRun) {
                Write-PolicyLog -Message "[DRY RUN] Would $($policy.Action.ToLower()) protocol: $protocol" -Level Info
                $result.Applied += $policy.Name
            }
        }
        catch {
            $result.Failed += @{
                Policy = $policy.Name
                Error = $_.Exception.Message
            }
            Write-PolicyLog -Message "Failed to configure protocol $protocol`: $($_.Exception.Message)" -Level Error
        }
    }
    
    return $result
}

function Set-DNSFiltering {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Config,
        [switch]$DryRun,
        [switch]$Reverse
    )
    
    $result = @{
        Applied = @()
        Failed = @()
    }
    
    Write-PolicyLog -Message "Configuring DNS filtering" -Level Info
    
    # S010.1: Set DNS servers to family-safe providers
    if ($Config.Enabled) {
        $dnsServers = if ($Reverse) { 
            # Reset to automatic DNS
            @()
        } else { 
            $Config.SafeDNSServers 
        }
        
        try {
            $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Virtual -eq $false }
            
            foreach ($adapter in $adapters) {
                $policy = @{
                    Name = "S010_DNSFiltering_$($adapter.Name)"
                    Adapter = $adapter.Name
                    DNSServers = $dnsServers
                }
                
                if (-not $DryRun -and $PSCmdlet.ShouldProcess($adapter.Name, "Set DNS Servers")) {
                    if ($dnsServers.Count -gt 0) {
                        Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $dnsServers
                        Write-PolicyLog -Message "Set DNS servers for $($adapter.Name): $($dnsServers -join ', ')" -Level Info
                    } else {
                        Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ResetServerAddresses
                        Write-PolicyLog -Message "Reset DNS servers for $($adapter.Name) to automatic" -Level Info
                    }
                    $result.Applied += $policy.Name
                } elseif ($DryRun) {
                    if ($dnsServers.Count -gt 0) {
                        Write-PolicyLog -Message "[DRY RUN] Would set DNS servers for $($adapter.Name): $($dnsServers -join ', ')" -Level Info
                    } else {
                        Write-PolicyLog -Message "[DRY RUN] Would reset DNS servers for $($adapter.Name) to automatic" -Level Info
                    }
                    $result.Applied += $policy.Name
                }
            }
        }
        catch {
            $result.Failed += @{
                Policy = "S010_DNSFiltering"
                Error = $_.Exception.Message
            }
            Write-PolicyLog -Message "Failed to configure DNS filtering: $($_.Exception.Message)" -Level Error
        }
    } else {
        $result.Applied += "S010_DNSFiltering (skipped - disabled in config)"
    }
    
    return $result
}

function Set-NetworkDiscoverySettings {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Config,
        [switch]$DryRun,
        [switch]$Reverse
    )
    
    $result = @{
        Applied = @()
        Failed = @()
    }
    
    Write-PolicyLog -Message "Configuring network discovery settings" -Level Info
    
    # S011.1: Disable network discovery
    $policy = @{
        Name = "S011_NetworkDiscovery"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff"
        Value = if ($Reverse) { 0 } else { 1 }
    }
    
    try {
        if (-not $DryRun -and $PSCmdlet.ShouldProcess($policy.Path, "Set Network Discovery")) {
            if (-not (Test-Path $policy.Path)) {
                New-Item -Path $policy.Path -Force | Out-Null
            }
            
            # Disable network discovery through registry
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" -Name "(Default)" -Value ""
            
            # Also disable file and printer sharing
            $services = @('fdPHost', 'FDResPub', 'SSDPSRV', 'upnphost')
            foreach ($service in $services) {
                if ($Reverse) {
                    Set-Service -Name $service -StartupType Manual -ErrorAction SilentlyContinue
                } else {
                    Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                }
            }
            
            $result.Applied += $policy.Name
            Write-PolicyLog -Message "Configured network discovery: $(if ($Reverse) { 'Enabled' } else { 'Disabled' })" -Level Info
        } elseif ($DryRun) {
            Write-PolicyLog -Message "[DRY RUN] Would configure network discovery: $(if ($Reverse) { 'Enabled' } else { 'Disabled' })" -Level Info
            $result.Applied += $policy.Name
        }
    }
    catch {
        $result.Failed += @{
            Policy = $policy.Name
            Error = $_.Exception.Message
        }
        Write-PolicyLog -Message "Failed to configure network discovery: $($_.Exception.Message)" -Level Error
    }
    
    return $result
}

function Set-ProxyConfiguration {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Config,
        [switch]$DryRun,
        [switch]$Reverse
    )
    
    $result = @{
        Applied = @()
        Failed = @()
    }
    
    Write-PolicyLog -Message "Configuring proxy settings" -Level Info
    
    # S012.1: Configure system proxy
    $policy = @{
        Name = "S012_ProxyConfiguration"
        ProxyServer = $Config.ProxyServer
        ProxyPort = $Config.ProxyPort
        BypassList = $Config.BypassList
    }
    
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        
        if (-not $DryRun -and $PSCmdlet.ShouldProcess($regPath, "Configure Proxy Settings")) {
            if ($Reverse) {
                # Disable proxy
                Set-ItemProperty -Path $regPath -Name "ProxyEnable" -Value 0 -Type DWord
                Remove-ItemProperty -Path $regPath -Name "ProxyServer" -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $regPath -Name "ProxyOverride" -ErrorAction SilentlyContinue
                Write-PolicyLog -Message "Disabled proxy configuration" -Level Info
            } else {
                # Enable proxy
                Set-ItemProperty -Path $regPath -Name "ProxyEnable" -Value 1 -Type DWord
                Set-ItemProperty -Path $regPath -Name "ProxyServer" -Value "$($Config.ProxyServer):$($Config.ProxyPort)" -Type String
                
                if ($Config.BypassList) {
                    Set-ItemProperty -Path $regPath -Name "ProxyOverride" -Value ($Config.BypassList -join ";") -Type String
                }
                
                Write-PolicyLog -Message "Enabled proxy configuration: $($Config.ProxyServer):$($Config.ProxyPort)" -Level Info
            }
            $result.Applied += $policy.Name
        } elseif ($DryRun) {
            if ($Reverse) {
                Write-PolicyLog -Message "[DRY RUN] Would disable proxy configuration" -Level Info
            } else {
                Write-PolicyLog -Message "[DRY RUN] Would enable proxy: $($Config.ProxyServer):$($Config.ProxyPort)" -Level Info
            }
            $result.Applied += $policy.Name
        }
    }
    catch {
        $result.Failed += @{
            Policy = $policy.Name
            Error = $_.Exception.Message
        }
        Write-PolicyLog -Message "Failed to configure proxy settings: $($_.Exception.Message)" -Level Error
    }
    
    return $result
}

function Set-RemoteConnectionRestrictions {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Config,
        [switch]$DryRun,
        [switch]$Reverse
    )
    
    $result = @{
        Applied = @()
        Failed = @()
    }
    
    Write-PolicyLog -Message "Configuring remote connection restrictions" -Level Info
    
    # S013.1: Disable Remote Desktop
    $rdpPolicy = @{
        Name = "S013_DisableRDP"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
        Property = "fDenyTSConnections"
        Value = if ($Reverse) { 0 } else { 1 }  # 1 = Disable RDP
    }
    
    try {
        if (-not $DryRun -and $PSCmdlet.ShouldProcess($rdpPolicy.Path, "Configure Remote Desktop")) {
            Set-ItemProperty -Path $rdpPolicy.Path -Name $rdpPolicy.Property -Value $rdpPolicy.Value -Type DWord
            $result.Applied += $rdpPolicy.Name
            Write-PolicyLog -Message "Remote Desktop: $(if ($Reverse) { 'Enabled' } else { 'Disabled' })" -Level Info
        } elseif ($DryRun) {
            Write-PolicyLog -Message "[DRY RUN] Would configure Remote Desktop: $(if ($Reverse) { 'Enabled' } else { 'Disabled' })" -Level Info
            $result.Applied += $rdpPolicy.Name
        }
    }
    catch {
        $result.Failed += @{
            Policy = $rdpPolicy.Name
            Error = $_.Exception.Message
        }
        Write-PolicyLog -Message "Failed to configure Remote Desktop: $($_.Exception.Message)" -Level Error
    }
    
    # S013.2: Disable WinRM if not needed
    if (-not $Config.AllowWinRM) {
        $winrmPolicy = @{
            Name = "S013_DisableWinRM"
            Service = "WinRM"
        }
        
        try {
            if (-not $DryRun -and $PSCmdlet.ShouldProcess("WinRM Service", "Configure Startup Type")) {
                if ($Reverse) {
                    Set-Service -Name "WinRM" -StartupType Manual
                } else {
                    Set-Service -Name "WinRM" -StartupType Disabled
                    Stop-Service -Name "WinRM" -Force -ErrorAction SilentlyContinue
                }
                $result.Applied += $winrmPolicy.Name
                Write-PolicyLog -Message "WinRM Service: $(if ($Reverse) { 'Enabled' } else { 'Disabled' })" -Level Info
            } elseif ($DryRun) {
                Write-PolicyLog -Message "[DRY RUN] Would configure WinRM Service: $(if ($Reverse) { 'Enabled' } else { 'Disabled' })" -Level Info
                $result.Applied += $winrmPolicy.Name
            }
        }
        catch {
            $result.Failed += @{
                Policy = $winrmPolicy.Name
                Error = $_.Exception.Message
            }
            Write-PolicyLog -Message "Failed to configure WinRM service: $($_.Exception.Message)" -Level Error
        }
    }
    
    return $result
}

function Set-NetworkLocationSettings {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Config,
        [switch]$DryRun,
        [switch]$Reverse
    )
    
    $result = @{
        Applied = @()
        Failed = @()
    }
    
    Write-PolicyLog -Message "Configuring network location settings" -Level Info
    
    # S014.1: Set network category to Public for enhanced security
    $policy = @{
        Name = "S014_NetworkCategory"
        Category = if ($Reverse) { "Private" } else { "Public" }
    }
    
    try {
        if (-not $DryRun -and $PSCmdlet.ShouldProcess("Network Connections", "Set Network Category")) {
            $connections = Get-NetConnectionProfile
            foreach ($connection in $connections) {
                Set-NetConnectionProfile -InterfaceAlias $connection.InterfaceAlias -NetworkCategory $policy.Category
            }
            $result.Applied += $policy.Name
            Write-PolicyLog -Message "Set network category to: $($policy.Category)" -Level Info
        } elseif ($DryRun) {
            Write-PolicyLog -Message "[DRY RUN] Would set network category to: $($policy.Category)" -Level Info
            $result.Applied += $policy.Name
        }
    }
    catch {
        $result.Failed += @{
            Policy = $policy.Name
            Error = $_.Exception.Message
        }
        Write-PolicyLog -Message "Failed to configure network category: $($_.Exception.Message)" -Level Error
    }
    
    return $result
}

# Main execution
if ($MyInvocation.InvocationName -ne '.') {
    try {
        # Load and validate configuration
        Write-PolicyLog -Message "Loading configuration from: $ConfigPath" -Level Info
        
        if (-not (Test-Path $ConfigPath)) {
            throw "Configuration file not found: $ConfigPath"
        }
        
        $configContent = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        
        # Validate required configuration sections
        if (-not $configContent.PolicyConfiguration.NetworkSecurity) {
            throw "Required configuration section missing: PolicyConfiguration.NetworkSecurity"
        }
        
        # Execute policy deployment
        $results = Set-NetworkSecurityPolicies -Config $configContent -DryRun:$DryRun -Reverse:$Reverse
        
        # Output results for automation/testing
        $outputPath = "$env:TEMP\network-security-results-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $results | ConvertTo-Json -Depth 10 | Set-Content $outputPath
        Write-PolicyLog -Message "Results saved to: $outputPath" -Level Info
        
        if ($results.Failed.Count -gt 0) {
            exit 1
        } else {
            exit 0
        }
    }
    catch {
        Write-PolicyLog -Message "Script execution failed: $($_.Exception.Message)" -Level Error
        Write-Error $_.Exception.Message
        exit 1
    }
}
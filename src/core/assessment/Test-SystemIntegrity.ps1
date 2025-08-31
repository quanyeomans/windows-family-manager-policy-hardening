# System Integrity Check - B004 Implementation
# Tests system integrity and detects bypass tools and unauthorized modifications

param(
    [Parameter()]
    [switch]$Verbose = $false
)

function Test-SystemIntegrity {
    <#
    .SYNOPSIS
    Tests Windows system integrity and detects bypass tools.
    
    .DESCRIPTION
    Implements requirement B004 by checking system integrity including:
    - System file integrity verification
    - Detection of bypass tools and utilities
    - Unauthorized system modifications
    - Critical system service status
    
    .PARAMETER Verbose
    Enable verbose output for detailed analysis
    #>
    
    try {
        Write-Verbose "Starting system integrity check..."
        
        $findings = @()
        $securityScore = 100
        
        # Known bypass tools and utilities signatures
        $bypassToolSignatures = @(
            @{ Name = "Ultimate Windows Tweaker"; Risk = "HIGH"; Category = "System Tweaker" },
            @{ Name = "O&O ShutUp10"; Risk = "HIGH"; Category = "Privacy Tool" },
            @{ Name = "Process Hacker"; Risk = "HIGH"; Category = "Process Monitor" },
            @{ Name = "Cheat Engine"; Risk = "CRITICAL"; Category = "Memory Editor" },
            @{ Name = "Registry Workshop"; Risk = "MEDIUM"; Category = "Registry Editor" },
            @{ Name = "CCleaner"; Risk = "MEDIUM"; Category = "System Cleaner" },
            @{ Name = "IObit Uninstaller"; Risk = "LOW"; Category = "Uninstaller" },
            @{ Name = "Revo Uninstaller"; Risk = "LOW"; Category = "Uninstaller" },
            @{ Name = "Wise Registry Cleaner"; Risk = "MEDIUM"; Category = "Registry Cleaner" },
            @{ Name = "Advanced SystemCare"; Risk = "MEDIUM"; Category = "System Optimizer" },
            @{ Name = "Windows 10 Manager"; Risk = "HIGH"; Category = "System Manager" },
            @{ Name = "Autoruns"; Risk = "LOW"; Category = "Startup Manager" },
            @{ Name = "ProcessExplorer"; Risk = "LOW"; Category = "Process Monitor" },
            @{ Name = "TCPView"; Risk = "LOW"; Category = "Network Monitor" },
            @{ Name = "Wireshark"; Risk = "MEDIUM"; Category = "Network Analyzer" }
        )
        
        # Get installed software from multiple sources
        Write-Verbose "Scanning installed software for bypass tools..."
        $installedSoftware = @()
        
        # Method 1: Registry-based software detection (32-bit and 64-bit)
        $registryPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        foreach ($path in $registryPaths) {
            try {
                $software = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                           Where-Object { $_.DisplayName } |
                           Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
                
                $installedSoftware += $software
            } catch {
                Write-Verbose "Error accessing registry path $path`: $($_.Exception.Message)"
            }
        }
        
        # Method 2: WMI-based software detection (backup method)
        try {
            $wmiSoftware = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue |
                          Select-Object Name, Version, Vendor, InstallDate
            
            foreach ($wmi in $wmiSoftware) {
                $installedSoftware += @{
                    DisplayName = $wmi.Name
                    DisplayVersion = $wmi.Version
                    Publisher = $wmi.Vendor
                    InstallDate = $wmi.InstallDate
                }
            }
        } catch {
            Write-Verbose "WMI software detection failed: $($_.Exception.Message)"
        }
        
        Write-Verbose "Found $($installedSoftware.Count) installed software entries"
        
        # Check for bypass tools in installed software
        $detectedTools = @()
        foreach ($software in $installedSoftware) {
            $softwareName = $software.DisplayName
            if ($softwareName) {
                foreach ($signature in $bypassToolSignatures) {
                    if ($softwareName -like "*$($signature.Name)*" -or 
                        $softwareName.ToLower() -like "*$($signature.Name.ToLower())*") {
                        
                        $detectedTools += @{
                            Name = $softwareName
                            Version = $software.DisplayVersion
                            Publisher = $software.Publisher
                            InstallDate = $software.InstallDate
                            Signature = $signature
                        }
                        
                        $severity = switch ($signature.Risk) {
                            "CRITICAL" { "CRITICAL" }
                            "HIGH" { "HIGH" }
                            "MEDIUM" { "MEDIUM" }
                            default { "LOW" }
                        }
                        
                        $finding = @{
                            category = "B004_system_integrity"
                            severity = $severity
                            finding = "Bypass tool detected"
                            details = @{
                                tool_name = $softwareName
                                tool_version = $software.DisplayVersion
                                tool_publisher = $software.Publisher
                                tool_category = $signature.Category
                                install_date = $software.InstallDate
                                risk_level = $signature.Risk
                                risk_description = "Detected software tool that can bypass system restrictions"
                            }
                            remediation = "Review and consider removing bypass tool: $softwareName"
                            impact = "Potential system security bypass capability"
                        }
                        
                        $findings += $finding
                        
                        $scoreReduction = switch ($severity) {
                            "CRITICAL" { 25 }
                            "HIGH" { 15 }
                            "MEDIUM" { 10 }
                            default { 5 }
                        }
                        $securityScore -= $scoreReduction
                        
                        Write-Warning "Bypass tool detected: $softwareName ($($signature.Risk) risk)"
                        break
                    }
                }
            }
        }
        
        # Check system file integrity using sfc (System File Checker)
        Write-Verbose "Checking system file integrity..."
        try {
            # Note: sfc /verifyonly requires administrative privileges
            $sfcOutput = & sfc /verifyonly 2>&1
            $sfcResult = $sfcOutput -join "`n"
            
            if ($sfcResult -like "*found integrity violations*" -or $sfcResult -like "*corrupt*") {
                $finding = @{
                    category = "B004_system_integrity"
                    severity = "HIGH"
                    finding = "System file integrity violations detected"
                    details = @{
                        sfc_output = $sfcResult
                        risk_description = "System File Checker found corrupted or modified system files"
                    }
                    remediation = "Run 'sfc /scannow' as administrator to repair system files"
                    impact = "System stability and security compromised"
                }
                
                $findings += $finding
                $securityScore -= 20
                
                Write-Warning "System file integrity violations detected"
            } elseif ($sfcResult -like "*did not find any integrity violations*") {
                Write-Verbose "System file integrity check passed"
            } else {
                Write-Verbose "System file integrity check result unclear: $sfcResult"
            }
        } catch {
            Write-Verbose "System File Checker not available or failed: $($_.Exception.Message)"
            
            $finding = @{
                category = "B004_system_integrity"
                severity = "LOW"
                finding = "Unable to verify system file integrity"
                details = @{
                    error_message = $_.Exception.Message
                    risk_description = "System File Checker could not be executed"
                }
                remediation = "Manually verify system file integrity using administrative privileges"
                impact = "System integrity status unknown"
            }
            
            $findings += $finding
            $securityScore -= 5
        }
        
        # Check critical system services
        Write-Verbose "Checking critical system services..."
        $criticalServices = @(
            @{ Name = "Windows Defender Antivirus Service"; ServiceName = "WinDefend"; Risk = "CRITICAL" },
            @{ Name = "Windows Update"; ServiceName = "wuauserv"; Risk = "HIGH" },
            @{ Name = "Windows Firewall"; ServiceName = "mpssvc"; Risk = "HIGH" },
            @{ Name = "Security Center"; ServiceName = "wscsvc"; Risk = "MEDIUM" },
            @{ Name = "Task Scheduler"; ServiceName = "Schedule"; Risk = "MEDIUM" },
            @{ Name = "User Account Control"; ServiceName = "Appinfo"; Risk = "HIGH" }
        )
        
        foreach ($serviceInfo in $criticalServices) {
            try {
                $service = Get-Service -Name $serviceInfo.ServiceName -ErrorAction SilentlyContinue
                
                if ($service) {
                    if ($service.Status -ne "Running") {
                        $severity = switch ($serviceInfo.Risk) {
                            "CRITICAL" { "CRITICAL" }
                            "HIGH" { "HIGH" }
                            "MEDIUM" { "MEDIUM" }
                            default { "LOW" }
                        }
                        
                        $finding = @{
                            category = "B004_system_integrity"
                            severity = $severity
                            finding = "Critical system service not running"
                            details = @{
                                service_name = $serviceInfo.Name
                                service_key = $serviceInfo.ServiceName
                                current_status = $service.Status.ToString()
                                expected_status = "Running"
                                risk_level = $serviceInfo.Risk
                                risk_description = "Critical system service is not active"
                            }
                            remediation = "Start and configure automatic startup for service: $($serviceInfo.Name)"
                            impact = "System security functionality compromised"
                        }
                        
                        $findings += $finding
                        
                        $scoreReduction = switch ($severity) {
                            "CRITICAL" { 20 }
                            "HIGH" { 12 }
                            "MEDIUM" { 8 }
                            default { 4 }
                        }
                        $securityScore -= $scoreReduction
                        
                        Write-Warning "Critical service not running: $($serviceInfo.Name) ($($service.Status))"
                    } else {
                        Write-Verbose "Critical service running: $($serviceInfo.Name)"
                    }
                } else {
                    # Service not found
                    $finding = @{
                        category = "B004_system_integrity"
                        severity = "HIGH"
                        finding = "Critical system service not found"
                        details = @{
                            service_name = $serviceInfo.Name
                            service_key = $serviceInfo.ServiceName
                            risk_description = "Required system service is not installed"
                        }
                        remediation = "Investigate missing system service: $($serviceInfo.Name)"
                        impact = "System security functionality missing"
                    }
                    
                    $findings += $finding
                    $securityScore -= 15
                    
                    Write-Warning "Critical service not found: $($serviceInfo.Name)"
                }
            } catch {
                Write-Verbose "Error checking service $($serviceInfo.ServiceName): $($_.Exception.Message)"
            }
        }
        
        # Check for suspicious processes (simple process name analysis)
        Write-Verbose "Checking for suspicious processes..."
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            $suspiciousProcesses = @()
            
            foreach ($process in $processes) {
                # Check if process matches bypass tool signatures
                foreach ($signature in $bypassToolSignatures | Where-Object { $_.Risk -in @("CRITICAL", "HIGH") }) {
                    if ($process.ProcessName -like "*$($signature.Name.Replace(' ', ''))*" -or
                        $process.Description -like "*$($signature.Name)*") {
                        
                        $suspiciousProcesses += @{
                            ProcessName = $process.ProcessName
                            ProcessId = $process.Id
                            Description = $process.Description
                            Signature = $signature
                        }
                    }
                }
            }
            
            foreach ($susProcess in $suspiciousProcesses) {
                $finding = @{
                    category = "B004_system_integrity"
                    severity = "MEDIUM"
                    finding = "Suspicious process detected"
                    details = @{
                        process_name = $susProcess.ProcessName
                        process_id = $susProcess.ProcessId
                        process_description = $susProcess.Description
                        risk_description = "Process associated with bypass tool is running"
                    }
                    remediation = "Review running process and terminate if unauthorized"
                    impact = "Active bypass capability present"
                }
                
                $findings += $finding
                $securityScore -= 8
                
                Write-Verbose "Suspicious process detected: $($susProcess.ProcessName)"
            }
            
        } catch {
            Write-Verbose "Error checking processes: $($_.Exception.Message)"
        }
        
        # Ensure minimum score
        $securityScore = [Math]::Max($securityScore, 0)
        
        Write-Verbose "System integrity check complete. Security score: $securityScore"
        
        return @{
            security_score = $securityScore
            findings = $findings
            assessment_summary = @{
                software_entries_scanned = $installedSoftware.Count
                bypass_tools_detected = $detectedTools.Count
                critical_services_checked = $criticalServices.Count
                system_file_integrity = if ($findings | Where-Object { $_.finding -like "*integrity violations*" }) { "FAILED" } else { "UNKNOWN" }
                critical_findings = ($findings | Where-Object { $_.severity -eq "CRITICAL" }).Count
                high_findings = ($findings | Where-Object { $_.severity -eq "HIGH" }).Count
                medium_findings = ($findings | Where-Object { $_.severity -eq "MEDIUM" }).Count
                low_findings = ($findings | Where-Object { $_.severity -eq "LOW" }).Count
            }
        }
        
    } catch {
        Write-Error "System integrity check failed: $($_.Exception.Message)"
        
        return @{
            security_score = 0
            findings = @(
                @{
                    category = "B004_system_integrity"
                    severity = "CRITICAL"
                    finding = "System integrity check failed"
                    details = @{
                        error_message = $_.Exception.Message
                        risk_description = "Unable to complete system integrity assessment"
                    }
                    remediation = "Investigate system integrity check failure and retry assessment"
                    impact = "System integrity status unknown"
                }
            )
            assessment_summary = @{
                software_entries_scanned = 0
                bypass_tools_detected = 0
                critical_services_checked = 0
                system_file_integrity = "UNKNOWN"
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
    Test-SystemIntegrity -Verbose:$Verbose | ConvertTo-Json -Depth 10
}
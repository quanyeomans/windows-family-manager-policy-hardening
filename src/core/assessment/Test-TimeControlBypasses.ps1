# Time Control Bypass Detection - B006 Implementation
# Detects attempts to bypass time-based controls and parental restrictions

param(
    [Parameter()]
    [switch]$Verbose = $false
)

function Test-TimeControlBypasses {
    <#
    .SYNOPSIS
    Detects attempts to bypass time-based controls and parental restrictions.
    
    .DESCRIPTION
    Implements requirement B006 by detecting various time control bypass methods including:
    - System time manipulation detection
    - Time zone modification tracking
    - Time service configuration analysis
    - Family safety bypass detection
    
    .PARAMETER Verbose
    Enable verbose output for detailed analysis
    #>
    
    try {
        Write-Verbose "Starting time control bypass detection..."
        
        $findings = @()
        $securityScore = 100
        
        # Check Windows Time service status and configuration
        Write-Verbose "Analyzing Windows Time service configuration..."
        try {
            $timeService = Get-Service -Name "w32time" -ErrorAction SilentlyContinue
            
            if ($timeService) {
                if ($timeService.Status -ne "Running") {
                    $finding = @{
                        category = "B006_time_control_bypass"
                        severity = "HIGH"
                        finding = "Windows Time service not running"
                        details = @{
                            service_name = "Windows Time (w32time)"
                            current_status = $timeService.Status.ToString()
                            expected_status = "Running"
                            risk_description = "System time synchronization service is not active"
                        }
                        remediation = "Start and configure Windows Time service for automatic startup"
                        impact = "System time can be manipulated without network synchronization"
                    }
                    
                    $findings += $finding
                    $securityScore -= 15
                    
                    Write-Warning "Windows Time service not running - time manipulation possible"
                } else {
                    Write-Verbose "Windows Time service is running"
                }
                
                # Check time synchronization configuration
                try {
                    $w32tmConfig = & w32tm /query /configuration 2>&1
                    
                    if ($w32tmConfig -and $w32tmConfig -notlike "*error*") {
                        $configText = $w32tmConfig -join "`n"
                        
                        # Check if NTP is enabled
                        $ntpEnabled = $configText -match "Enabled:\s*1"
                        
                        if (-not $ntpEnabled) {
                            $finding = @{
                                category = "B006_time_control_bypass"
                                severity = "MEDIUM"
                                finding = "NTP time synchronization disabled"
                                details = @{
                                    service_configuration = "NTP Disabled"
                                    risk_description = "Network Time Protocol synchronization is disabled"
                                }
                                remediation = "Enable NTP time synchronization to prevent time manipulation"
                                impact = "System clock can drift or be manually adjusted"
                            }
                            
                            $findings += $finding
                            $securityScore -= 10
                            
                            Write-Warning "NTP time synchronization is disabled"
                        } else {
                            Write-Verbose "NTP time synchronization is enabled"
                        }
                        
                        # Check time source
                        $timeSource = $configText | Where-Object { $_ -match "NtpServer:\s*(.+)" }
                        if ($timeSource) {
                            $sourceValue = ($timeSource -split "NtpServer:\s*")[1].Trim()
                            
                            # Check for localhost or suspicious time sources
                            if ($sourceValue -like "*127.0.0.1*" -or $sourceValue -like "*localhost*") {
                                $finding = @{
                                    category = "B006_time_control_bypass"
                                    severity = "HIGH"
                                    finding = "Suspicious time source configuration"
                                    details = @{
                                        time_source = $sourceValue
                                        risk_description = "Time source points to local system"
                                    }
                                    remediation = "Configure legitimate external NTP servers"
                                    impact = "Time synchronization may be compromised"
                                }
                                
                                $findings += $finding
                                $securityScore -= 18
                                
                                Write-Warning "Suspicious time source detected: $sourceValue"
                            }
                        }
                    }
                } catch {
                    Write-Verbose "Error checking w32tm configuration: $($_.Exception.Message)"
                }
                
            } else {
                $finding = @{
                    category = "B006_time_control_bypass"
                    severity = "CRITICAL"
                    finding = "Windows Time service not found"
                    details = @{
                        service_name = "w32time"
                        risk_description = "Windows Time service is not installed or available"
                    }
                    remediation = "Investigate missing Windows Time service"
                    impact = "No time synchronization capability available"
                }
                
                $findings += $finding
                $securityScore -= 25
                
                Write-Warning "Windows Time service not found"
            }
        } catch {
            Write-Verbose "Error checking Windows Time service: $($_.Exception.Message)"
        }
        
        # Check for recent time zone changes (potential bypass indicator)
        Write-Verbose "Checking for recent time zone modifications..."
        try {
            $currentTimeZone = (Get-TimeZone).Id
            Write-Verbose "Current time zone: $currentTimeZone"
            
            # Check Windows Event Log for time changes (Event ID 4616)
            $timeChangeEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4616} -MaxEvents 50 -ErrorAction SilentlyContinue
            
            if ($timeChangeEvents) {
                $recentTimeChanges = $timeChangeEvents | Where-Object { $_.TimeCreated -gt (Get-Date).AddDays(-7) }
                
                if ($recentTimeChanges.Count -gt 2) {
                    $finding = @{
                        category = "B006_time_control_bypass"
                        severity = "MEDIUM"
                        finding = "Frequent system time changes detected"
                        details = @{
                            time_change_count = $recentTimeChanges.Count
                            period_days = 7
                            most_recent_change = $recentTimeChanges[0].TimeCreated
                            risk_description = "Multiple system time changes in recent period"
                        }
                        remediation = "Investigate reason for frequent time changes and secure time settings"
                        impact = "Potential time-based control bypass attempts"
                    }
                    
                    $findings += $finding
                    $securityScore -= 8
                    
                    Write-Warning "Frequent time changes detected: $($recentTimeChanges.Count) changes in 7 days"
                } else {
                    Write-Verbose "Normal time change activity detected"
                }
            }
        } catch {
            Write-Verbose "Error checking time change events: $($_.Exception.Message)"
        }
        
        # Check for Family Safety / Microsoft Family settings
        Write-Verbose "Checking Family Safety configuration..."
        try {
            # Check for Family Safety registry keys
            $familySafetyKeys = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Parental Controls",
                "HKCU:\SOFTWARE\Microsoft\FamilySafety"
            )
            
            foreach ($keyPath in $familySafetyKeys) {
                if (Test-Path $keyPath) {
                    Write-Verbose "Family Safety registry key found: $keyPath"
                    
                    try {
                        $familySettings = Get-ChildItem -Path $keyPath -ErrorAction SilentlyContinue
                        
                        if ($familySettings) {
                            # Look for time restriction bypass indicators
                            foreach ($setting in $familySettings) {
                                $settingPath = Join-Path $keyPath $setting.PSChildName
                                $settingValues = Get-ItemProperty -Path $settingPath -ErrorAction SilentlyContinue
                                
                                if ($settingValues) {
                                    # Check for disabled time restrictions
                                    if ($settingValues.PSObject.Properties["TimeAllowances"] -and 
                                        $settingValues.TimeAllowances -eq 0) {
                                        
                                        $finding = @{
                                            category = "B006_time_control_bypass"
                                            severity = "MEDIUM"
                                            finding = "Family Safety time restrictions disabled"
                                            details = @{
                                                registry_path = $settingPath
                                                setting_name = "TimeAllowances"
                                                current_value = 0
                                                risk_description = "Family Safety time restrictions have been disabled"
                                            }
                                            remediation = "Re-enable Family Safety time restrictions if intended for this user"
                                            impact = "Time-based parental controls not enforced"
                                        }
                                        
                                        $findings += $finding
                                        $securityScore -= 5
                                        
                                        Write-Warning "Family Safety time restrictions disabled"
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-Verbose "Error analyzing Family Safety settings: $($_.Exception.Message)"
                    }
                }
            }
        } catch {
            Write-Verbose "Error checking Family Safety configuration: $($_.Exception.Message)"
        }
        
        # Check for dual-boot or alternative OS installations (time bypass method)
        Write-Verbose "Checking for potential dual-boot configurations..."
        try {
            # Check for multiple boot entries
            $bootEntries = & bcdedit /enum 2>&1
            
            if ($bootEntries -and $bootEntries -notlike "*not recognized*") {
                $bootText = $bootEntries -join "`n"
                $osLoaderCount = ($bootText -split "Windows Boot Loader").Count - 1
                
                if ($osLoaderCount -gt 1) {
                    $finding = @{
                        category = "B006_time_control_bypass"
                        severity = "LOW"
                        finding = "Multiple OS boot entries detected"
                        details = @{
                            boot_loader_count = $osLoaderCount
                            risk_description = "Multiple operating systems may allow time control bypass"
                        }
                        remediation = "Verify all OS installations have consistent time controls"
                        impact = "Alternative OS might not enforce time restrictions"
                    }
                    
                    $findings += $finding
                    $securityScore -= 3
                    
                    Write-Verbose "Multiple OS boot entries detected: $osLoaderCount loaders"
                }
            }
        } catch {
            Write-Verbose "Error checking boot configuration: $($_.Exception.Message)"
        }
        
        # Check for time-related bypass tools in running processes
        Write-Verbose "Scanning for time manipulation tools..."
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            $timeBypassTools = @(
                "RunAsDate", "TimeShift", "FakeTime", "ClockGen", "TimeWarp"
            )
            
            foreach ($process in $processes) {
                foreach ($tool in $timeBypassTools) {
                    if ($process.ProcessName -like "*$tool*" -or 
                        $process.Description -like "*$tool*") {
                        
                        $finding = @{
                            category = "B006_time_control_bypass"
                            severity = "HIGH"
                            finding = "Time manipulation tool detected"
                            details = @{
                                process_name = $process.ProcessName
                                process_id = $process.Id
                                tool_signature = $tool
                                risk_description = "Process associated with time manipulation tool is running"
                            }
                            remediation = "Terminate process and remove time manipulation tool"
                            impact = "Active time control bypass capability"
                        }
                        
                        $findings += $finding
                        $securityScore -= 20
                        
                        Write-Warning "Time manipulation tool detected: $($process.ProcessName)"
                        break
                    }
                }
            }
        } catch {
            Write-Verbose "Error scanning processes for time tools: $($_.Exception.Message)"
        }
        
        # Check system clock accuracy (large deviation may indicate manipulation)
        Write-Verbose "Checking system clock accuracy..."
        try {
            $timeQuery = & w32tm /query /status 2>&1
            
            if ($timeQuery -and $timeQuery -notlike "*error*") {
                $statusText = $timeQuery -join "`n"
                
                # Look for time offset information
                $offsetLine = $statusText | Where-Object { $_ -match "Last Successful Sync Time:\s*(.+)" }
                
                if ($offsetLine) {
                    # Check when last sync occurred
                    $lastSyncString = ($offsetLine -split "Last Successful Sync Time:\s*")[1].Trim()
                    
                    try {
                        $lastSync = [DateTime]::Parse($lastSyncString)
                        $timeSinceSync = (Get-Date) - $lastSync
                        
                        if ($timeSinceSync.TotalHours -gt 24) {
                            $finding = @{
                                category = "B006_time_control_bypass"
                                severity = "MEDIUM"
                                finding = "System time not recently synchronized"
                                details = @{
                                    last_sync_time = $lastSync
                                    hours_since_sync = [Math]::Round($timeSinceSync.TotalHours, 1)
                                    risk_description = "System clock has not been synchronized recently"
                                }
                                remediation = "Force time synchronization and check network connectivity"
                                impact = "System time may be inaccurate or manipulated"
                            }
                            
                            $findings += $finding
                            $securityScore -= 5
                            
                            Write-Warning "System time not synchronized for $([Math]::Round($timeSinceSync.TotalHours, 1)) hours"
                        } else {
                            Write-Verbose "System time recently synchronized: $lastSync"
                        }
                    } catch {
                        Write-Verbose "Error parsing last sync time: $($_.Exception.Message)"
                    }
                }
            }
        } catch {
            Write-Verbose "Error checking time sync status: $($_.Exception.Message)"
        }
        
        # Ensure minimum score
        $securityScore = [Math]::Max($securityScore, 0)
        
        Write-Verbose "Time control bypass detection complete. Security score: $securityScore"
        
        return @{
            security_score = $securityScore
            findings = $findings
            assessment_summary = @{
                time_service_status = if ($timeService) { $timeService.Status.ToString() } else { "Not Found" }
                ntp_synchronization = "Checked"
                time_change_events_analyzed = if ($timeChangeEvents) { $timeChangeEvents.Count } else { 0 }
                family_safety_keys_checked = 2
                boot_configuration_analyzed = $true
                bypass_tools_detected = ($findings | Where-Object { $_.finding -like "*manipulation tool*" }).Count
                time_sync_issues = ($findings | Where-Object { $_.finding -like "*synchronized*" }).Count
                critical_findings = ($findings | Where-Object { $_.severity -eq "CRITICAL" }).Count
                high_findings = ($findings | Where-Object { $_.severity -eq "HIGH" }).Count
                medium_findings = ($findings | Where-Object { $_.severity -eq "MEDIUM" }).Count
                low_findings = ($findings | Where-Object { $_.severity -eq "LOW" }).Count
            }
        }
        
    } catch {
        Write-Error "Time control bypass detection failed: $($_.Exception.Message)"
        
        return @{
            security_score = 0
            findings = @(
                @{
                    category = "B006_time_control_bypass"
                    severity = "CRITICAL"
                    finding = "Time control bypass detection failed"
                    details = @{
                        error_message = $_.Exception.Message
                        risk_description = "Unable to complete time control bypass assessment"
                    }
                    remediation = "Investigate time control analysis failure and retry assessment"
                    impact = "Time control security status unknown"
                }
            )
            assessment_summary = @{
                time_service_status = "Unknown"
                ntp_synchronization = "Unknown"
                time_change_events_analyzed = 0
                family_safety_keys_checked = 0
                boot_configuration_analyzed = $false
                bypass_tools_detected = 0
                time_sync_issues = 0
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
    Test-TimeControlBypasses -Verbose:$Verbose | ConvertTo-Json -Depth 10
}
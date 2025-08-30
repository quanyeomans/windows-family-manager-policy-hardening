# System Baseline Discovery Script
# Requirements: B001-B006 from product specification
# Purpose: Complete audit of current Windows state before implementing security controls

[CmdletBinding()]
param(
    [string]$OutputPath = "logs\system-baseline-$(Get-Date -Format 'yyyy-MM-dd-HHmm').json"
)

function Get-SystemBaseline {
    [CmdletBinding()]
    param([string]$OutputPath)
    
    Write-Host "Starting system baseline assessment..." -ForegroundColor Cyan
    
    $baseline = @{
        Timestamp = Get-Date
        ComputerName = $env:COMPUTERNAME
        OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
    
    # B001: Audit current Windows registry modifications
    Write-Host "Auditing registry modifications..." -ForegroundColor Yellow
    $baseline.RegistryModifications = Get-RegistryModifications
    
    # B002: Inventory existing user accounts and privilege levels  
    Write-Host "Inventorying user accounts..." -ForegroundColor Yellow
    $baseline.UserAccounts = Get-UserAccountInventory
    
    # B003: Document current Group Policy settings
    Write-Host "Documenting Group Policy settings..." -ForegroundColor Yellow
    $baseline.GroupPolicySettings = Get-GroupPolicyInventory
    
    # B004: Scan for unauthorized system utilities and bypass tools
    Write-Host "Scanning for bypass tools..." -ForegroundColor Yellow
    $baseline.UnauthorizedTools = Get-UnauthorizedToolsScan
    
    # B005: Identify network configuration and WiFi profiles
    Write-Host "Analyzing network configuration..." -ForegroundColor Yellow
    $baseline.NetworkConfiguration = Get-NetworkConfigurationInventory
    
    # B006: Detect existing time control bypasses
    Write-Host "Detecting time control bypasses..." -ForegroundColor Yellow  
    $baseline.TimeControlBypasses = Get-TimeControlBypassDetection
    
    # Save baseline to file
    $baseline | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "✅ System baseline saved to: $OutputPath" -ForegroundColor Green
    
    return $baseline
}

function Get-RegistryModifications {
    # B001: Detect non-standard registry configurations
    $modifications = @()
    
    # Check common bypass registry locations
    $suspiciousKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
        "HKLM:\SYSTEM\CurrentControlSet\Services\Themes"
    )
    
    foreach ($key in $suspiciousKeys) {
        try {
            if (Test-Path $key) {
                $properties = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                if ($properties) {
                    $modifications += @{
                        Key = $key
                        Properties = $properties | Select-Object * -ExcludeProperty PS*
                        Suspicious = Test-SuspiciousRegistryValues $properties
                    }
                }
            }
        }
        catch {
            # Key doesn't exist or access denied
        }
    }
    
    return $modifications
}

function Get-UserAccountInventory {
    # B002: Complete user account analysis
    $accounts = @()
    
    # Get local user accounts
    try {
        $localUsers = Get-LocalUser
        foreach ($user in $localUsers) {
            $groupMemberships = @()
            try {
                $groups = Get-LocalGroup | Where-Object { 
                    (Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue) -contains $user.Name 
                }
                $groupMemberships = $groups.Name
            }
            catch {}
            
            $accounts += @{
                Name = $user.Name
                Enabled = $user.Enabled
                LastLogon = $user.LastLogon
                PasswordRequired = $user.PasswordRequired
                Groups = $groupMemberships
                IsAdmin = $groupMemberships -contains "Administrators"
                SuspiciousAccount = Test-SuspiciousAccount $user $groupMemberships
            }
        }
    }
    catch {
        # Fallback to WMI if Get-LocalUser not available
        $wmiUsers = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True"
        foreach ($user in $wmiUsers) {
            $accounts += @{
                Name = $user.Name
                Enabled = -not $user.Disabled
                Description = $user.Description
                SuspiciousAccount = ($user.Name -match "admin|root|hack|temp")
            }
        }
    }
    
    return $accounts
}

function Get-GroupPolicyInventory {
    # B003: Document current Group Policy state
    $policies = @{
        LocalPoliciesExist = $false
        PolicyFiles = @()
        SuspiciousPolicies = @()
    }
    
    # Check for existing local Group Policy files
    $policyPaths = @(
        "C:\Windows\System32\GroupPolicy\Machine\registry.pol",
        "C:\Windows\System32\GroupPolicy\User\registry.pol"
    )
    
    foreach ($path in $policyPaths) {
        if (Test-Path $path) {
            $policies.LocalPoliciesExist = $true
            $policies.PolicyFiles += @{
                Path = $path
                Size = (Get-Item $path).Length
                LastModified = (Get-Item $path).LastWriteTime
            }
        }
    }
    
    # Check for suspicious policy settings via registry
    $suspiciousPolicyKeys = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System", 
        "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
    )
    
    foreach ($key in $suspiciousPolicyKeys) {
        if (Test-Path $key) {
            $properties = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            if ($properties) {
                $policies.SuspiciousPolicies += @{
                    Key = $key
                    Values = $properties | Select-Object * -ExcludeProperty PS*
                }
            }
        }
    }
    
    return $policies
}

function Get-UnauthorizedToolsScan {
    # B004: Scan for bypass tools and unauthorized utilities
    $tools = @{
        SuspiciousProcesses = @()
        SuspiciousFiles = @()
        SuspiciousServices = @()
    }
    
    # Check running processes for bypass tools
    $suspiciousProcesses = @("cmd", "powershell", "regedit", "msconfig", "taskmgr", "control")
    $runningProcesses = Get-Process | Where-Object { 
        $suspiciousProcesses -contains $_.ProcessName.ToLower() 
    }
    
    foreach ($process in $runningProcesses) {
        $tools.SuspiciousProcesses += @{
            Name = $process.ProcessName
            Id = $process.Id
            Path = $process.Path
            StartTime = $process.StartTime
        }
    }
    
    # Check for portable tools in common locations
    $portableToolsPaths = @(
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Downloads", 
        "$env:TEMP",
        "C:\temp"
    )
    
    $suspiciousFilePatterns = @("*portable*", "*hack*", "*bypass*", "*crack*", "*admin*")
    
    foreach ($path in $portableToolsPaths) {
        if (Test-Path $path) {
            foreach ($pattern in $suspiciousFilePatterns) {
                $files = Get-ChildItem -Path $path -Filter $pattern -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    $tools.SuspiciousFiles += @{
                        Name = $file.Name
                        Path = $file.FullName
                        Size = $file.Length
                        LastModified = $file.LastWriteTime
                    }
                }
            }
        }
    }
    
    return $tools
}

function Get-NetworkConfigurationInventory {
    # B005: Network configuration and WiFi profile analysis
    $network = @{
        NetworkAdapters = @()
        WiFiProfiles = @()
        NetworkShares = @()
        SuspiciousConnections = @()
    }
    
    # Get network adapters
    try {
        $adapters = Get-NetAdapter -ErrorAction SilentlyContinue
        foreach ($adapter in $adapters) {
            $network.NetworkAdapters += @{
                Name = $adapter.Name
                InterfaceDescription = $adapter.InterfaceDescription
                Status = $adapter.Status
                LinkSpeed = $adapter.LinkSpeed
                MediaType = $adapter.MediaType
            }
        }
    }
    catch {
        # Fallback to WMI
        $adapters = Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.NetEnabled -eq $true }
        foreach ($adapter in $adapters) {
            $network.NetworkAdapters += @{
                Name = $adapter.Name
                Status = if ($adapter.NetEnabled) { "Up" } else { "Down" }
                MediaType = $adapter.AdapterType
            }
        }
    }
    
    # Get WiFi profiles (requires elevated permissions)
    try {
        $wifiOutput = netsh wlan show profiles 2>$null
        if ($wifiOutput) {
            $profiles = $wifiOutput | Select-String "All User Profile" | ForEach-Object { 
                ($_ -split ":")[1].Trim() 
            }
            $network.WiFiProfiles = $profiles
        }
    }
    catch {}
    
    return $network
}

function Get-TimeControlBypassDetection {
    # B006: Detect existing time control bypass methods
    $bypasses = @{
        TimeServiceModifications = @()
        ScheduledTasksModifications = @()
        RegistryTimeSettings = @()
        SuspiciousProcesses = @()
    }
    
    # Check Windows Time service
    try {
        $timeService = Get-Service -Name W32Time -ErrorAction SilentlyContinue
        if ($timeService) {
            $bypasses.TimeServiceModifications += @{
                Status = $timeService.Status
                StartType = $timeService.StartType
                Suspicious = ($timeService.Status -ne "Running")
            }
        }
    }
    catch {}
    
    # Check for time-related scheduled tasks
    try {
        $timeTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { 
            $_.TaskName -match "time|clock|sync" 
        }
        foreach ($task in $timeTasks) {
            $bypasses.ScheduledTasksModifications += @{
                Name = $task.TaskName
                State = $task.State
                LastRunTime = $task.LastRunTime
                Suspicious = ($task.State -ne "Ready")
            }
        }
    }
    catch {}
    
    return $bypasses
}

function Test-SuspiciousRegistryValues {
    param($Properties)
    
    # Check for common bypass registry modifications
    $suspiciousIndicators = @(
        "DisableRegistryTools",
        "DisableTaskMgr", 
        "DisableCMD",
        "NoControlPanel",
        "NoRun"
    )
    
    foreach ($prop in $Properties.PSObject.Properties) {
        if ($suspiciousIndicators -contains $prop.Name) {
            return $true
        }
    }
    
    return $false
}

function Test-SuspiciousAccount {
    param($User, $Groups)
    
    # Check for suspicious account characteristics
    $suspiciousNames = @("admin", "administrator", "root", "hack", "temp", "test")
    $suspiciousName = $suspiciousNames | Where-Object { $User.Name -match $_ }
    
    $hasAdminAccess = $Groups -contains "Administrators"
    $recentlyCreated = ($User.LastLogon -eq $null) -and $User.Enabled
    
    return ($suspiciousName -or ($hasAdminAccess -and $recentlyCreated))
}

# Execute system baseline if script is run directly
if ($MyInvocation.InvocationName -ne '.') {
    Get-SystemBaseline -OutputPath $OutputPath
}
# Gaming Performance Baseline and Validation Script
# Custom 20% - Gaming compatibility requirement unique to family system
# Requirements: P001-P012 from product specification

[CmdletBinding()]
param(
    [int]$DurationSeconds = 300,  # 5 minutes default
    [double]$MaxAcceptableDegradation = 2.0,  # 2% maximum performance loss
    [string]$BaselinePath = "tests\baselines\gaming-performance-baseline.json",
    [switch]$EstablishBaseline,
    [switch]$ValidatePerformance
)

function Test-GamingPerformance {
    [CmdletBinding()]
    param(
        [int]$DurationSeconds,
        [double]$MaxAcceptableDegradation,
        [string]$BaselinePath,
        [switch]$EstablishBaseline,
        [switch]$ValidatePerformance
    )
    
    Write-Host "=== Gaming Performance Validation ===" -ForegroundColor Cyan
    Write-Host "Duration: $DurationSeconds seconds" -ForegroundColor Gray
    Write-Host "Max Acceptable Degradation: $MaxAcceptableDegradation%" -ForegroundColor Gray
    Write-Host ""
    
    if ($EstablishBaseline) {
        Write-Host "Establishing Gaming Performance Baseline" -ForegroundColor Yellow
        $baseline = New-GamingPerformanceBaseline -DurationSeconds $DurationSeconds
        Save-GamingBaseline -Baseline $baseline -Path $BaselinePath
        return $baseline
    }
    
    if ($ValidatePerformance) {
        Write-Host "Validating Gaming Performance Against Baseline" -ForegroundColor Yellow
        $validation = Test-GamingPerformanceAgainstBaseline -DurationSeconds $DurationSeconds -BaselinePath $BaselinePath -MaxDegradation $MaxAcceptableDegradation
        return $validation
    }
    
    # Default: Establish baseline if none exists, otherwise validate
    if (-not (Test-Path $BaselinePath)) {
        Write-Host "No baseline found - establishing new baseline" -ForegroundColor Yellow
        $baseline = New-GamingPerformanceBaseline -DurationSeconds $DurationSeconds
        Save-GamingBaseline -Baseline $baseline -Path $BaselinePath
        return $baseline
    } else {
        Write-Host "Baseline exists - validating current performance" -ForegroundColor Yellow
        $validation = Test-GamingPerformanceAgainstBaseline -DurationSeconds $DurationSeconds -BaselinePath $BaselinePath -MaxDegradation $MaxAcceptableDegradation
        return $validation
    }
}

function New-GamingPerformanceBaseline {
    [CmdletBinding()]
    param([int]$DurationSeconds)
    
    Write-Host "  Collecting system performance baseline..." -ForegroundColor Gray
    
    $baseline = @{
        Timestamp = Get-Date
        DurationSeconds = $DurationSeconds
        SystemSpecs = Get-GamingSystemSpecs
        PerformanceMetrics = @{}
        GamingOptimizations = Get-GamingOptimizationStatus
        SecurityBaseline = Get-SecurityImpactBaseline
    }
    
    # Collect performance metrics over time
    Write-Host "  Measuring performance for $DurationSeconds seconds..." -ForegroundColor Gray
    $performanceData = Measure-SystemPerformance -DurationSeconds $DurationSeconds
    
    $baseline.PerformanceMetrics = @{
        AverageCPUUsage = $performanceData.AverageCPU
        AverageMemoryUsage = $performanceData.AverageMemory
        CPUVariance = $performanceData.CPUVariance
        MemoryVariance = $performanceData.MemoryVariance
        FrameTimeConsistency = $performanceData.FrameConsistency
        DiskIOLatency = $performanceData.DiskLatency
        NetworkLatency = $performanceData.NetworkLatency
    }
    
    Write-Host "  ✅ Performance baseline established" -ForegroundColor Green
    return $baseline
}

function Get-GamingSystemSpecs {
    try {
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        $gpu = Get-CimInstance Win32_VideoController | Where-Object { 
            $_.Name -notmatch "Microsoft|Remote|Basic" -and $_.AdapterRAM -gt 0 
        } | Select-Object -First 1
        $memory = Get-CimInstance Win32_ComputerSystem
        $storage = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 -and $_.DeviceID -eq $env:SystemDrive }
        
        return @{
            CPU = @{
                Name = $cpu.Name.Trim()
                Cores = $cpu.NumberOfCores
                LogicalProcessors = $cpu.NumberOfLogicalProcessors
                MaxClockSpeedMHz = $cpu.MaxClockSpeed
                Architecture = $cpu.Architecture
            }
            GPU = @{
                Name = if ($gpu) { $gpu.Name.Trim() } else { "Unknown" }
                DriverVersion = if ($gpu) { $gpu.DriverVersion } else { "Unknown" }
                VideoRAM = if ($gpu) { [math]::Round($gpu.AdapterRAM / 1GB, 2) } else { 0 }
            }
            Memory = @{
                TotalRAM_GB = [math]::Round($memory.TotalPhysicalMemory / 1GB, 2)
            }
            Storage = @{
                SystemDrive = $storage.DeviceID
                TotalSize_GB = [math]::Round($storage.Size / 1GB, 2)
                FreeSpace_GB = [math]::Round($storage.FreeSpace / 1GB, 2)
            }
            OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
        }
    }
    catch {
        return @{ Error = "Unable to retrieve system specifications: $($_.Exception.Message)" }
    }
}

function Get-GamingOptimizationStatus {
    $optimizations = @{
        GameMode = $null
        GameBar = $null
        FullscreenOptimizations = $null
        HighPerformancePowerPlan = $null
        WindowsDefenderExclusions = $null
    }
    
    try {
        # Check Game Mode
        $gameMode = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "AutoGameModeEnabled" -ErrorAction SilentlyContinue
        $optimizations.GameMode = if ($gameMode) { $gameMode.AutoGameModeEnabled -eq 1 } else { $false }
        
        # Check Game Bar
        $gameBar = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -ErrorAction SilentlyContinue
        $optimizations.GameBar = if ($gameBar) { $gameBar.UseNexusForGameBarEnabled -eq 1 } else { $true }
        
        # Check Power Plan
        $currentPowerPlan = powercfg /getactivescheme 2>$null
        $optimizations.HighPerformancePowerPlan = if ($currentPowerPlan) { 
            $currentPowerPlan -match "High performance|Ultimate Performance" 
        } else { $false }
        
        # Check for common gaming directory exclusions in Windows Defender
        $commonGameDirs = @(
            "$env:ProgramFiles(x86)\Steam",
            "$env:ProgramFiles\Epic Games",
            "$env:LOCALAPPDATA\Programs\Electronic Arts"
        )
        
        $exclusionCount = 0
        foreach ($dir in $commonGameDirs) {
            if (Test-Path $dir) {
                try {
                    # Note: Get-MpPreference might not be available in all environments
                    $exclusions = Get-MpPreference -ErrorAction SilentlyContinue
                    if ($exclusions -and $exclusions.ExclusionPath -contains $dir) {
                        $exclusionCount++
                    }
                }
                catch {
                    # Defender cmdlets not available
                }
            }
        }
        $optimizations.WindowsDefenderExclusions = $exclusionCount
        
    }
    catch {
        Write-Warning "Could not determine all gaming optimization settings: $($_.Exception.Message)"
    }
    
    return $optimizations
}

function Get-SecurityImpactBaseline {
    # Measure security software impact on performance
    $securityBaseline = @{
        WindowsDefender = @{
            Service = $null
            RealTimeProtection = $null
            ScanScheduled = $null
        }
        WindowsFirewall = @{
            Enabled = $null
        }
        UAC = @{
            Level = $null
        }
    }
    
    try {
        # Windows Defender status
        $defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
        $securityBaseline.WindowsDefender.Service = if ($defenderService) { $defenderService.Status } else { "Unknown" }
        
        # Defender settings
        try {
            $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($defenderStatus) {
                $securityBaseline.WindowsDefender.RealTimeProtection = $defenderStatus.RealTimeProtectionEnabled
            }
        }
        catch {
            # Defender cmdlets not available
        }
        
        # Windows Firewall
        $firewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        $securityBaseline.WindowsFirewall.Enabled = if ($firewallProfiles) { 
            ($firewallProfiles | Where-Object { $_.Enabled -eq $true }).Count -gt 0 
        } else { $null }
        
        # UAC Level
        $uacLevel = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
        $securityBaseline.UAC.Level = if ($uacLevel) { $uacLevel.ConsentPromptBehaviorAdmin } else { $null }
        
    }
    catch {
        Write-Warning "Could not determine security baseline: $($_.Exception.Message)"
    }
    
    return $securityBaseline
}

function Measure-SystemPerformance {
    [CmdletBinding()]
    param([int]$DurationSeconds)
    
    $measurements = @()
    $interval = 1  # 1 second intervals
    $totalMeasurements = $DurationSeconds / $interval
    
    Write-Host "    Collecting performance data..." -ForegroundColor Gray -NoNewline
    
    for ($i = 0; $i -lt $totalMeasurements; $i++) {
        try {
            $cpu = (Get-Counter "\Processor(_Total)\% Processor Time" -ErrorAction SilentlyContinue).CounterSamples[0].CookedValue
            $memory = (Get-Counter "\Memory\Available MBytes" -ErrorAction SilentlyContinue).CounterSamples[0].CookedValue
            $totalMemory = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB
            $memoryUsagePercent = [math]::Round((($totalMemory - $memory) / $totalMemory) * 100, 2)
            
            # Try to get disk and network metrics
            $diskLatency = 0
            $networkLatency = 0
            
            try {
                $diskLatency = (Get-Counter "\PhysicalDisk(_Total)\Avg. Disk sec/Read" -ErrorAction SilentlyContinue).CounterSamples[0].CookedValue * 1000
            }
            catch { }
            
            $measurements += @{
                Timestamp = Get-Date
                CPU = [math]::Round($cpu, 2)
                MemoryUsagePercent = $memoryUsagePercent
                DiskLatencyMs = [math]::Round($diskLatency, 2)
                NetworkLatencyMs = $networkLatency
            }
            
            # Progress indicator
            if ($i % 30 -eq 0) {
                Write-Host "." -ForegroundColor Gray -NoNewline
            }
            
            Start-Sleep $interval
        }
        catch {
            Write-Warning "Error collecting performance data: $($_.Exception.Message)"
        }
    }
    
    Write-Host " Done!" -ForegroundColor Gray
    
    # Calculate statistics
    $cpuValues = $measurements | ForEach-Object { $_.CPU }
    $memoryValues = $measurements | ForEach-Object { $_.MemoryUsagePercent }
    
    return @{
        AverageCPU = [math]::Round(($cpuValues | Measure-Object -Average).Average, 2)
        AverageMemory = [math]::Round(($memoryValues | Measure-Object -Average).Average, 2)
        CPUVariance = [math]::Round(($cpuValues | Measure-Object -StandardDeviation).StandardDeviation, 2)
        MemoryVariance = [math]::Round(($memoryValues | Measure-Object -StandardDeviation).StandardDeviation, 2)
        FrameConsistency = 95.0  # Placeholder - would need specialized tools for actual frame time measurement
        DiskLatency = [math]::Round(($measurements | ForEach-Object { $_.DiskLatencyMs } | Measure-Object -Average).Average, 2)
        NetworkLatency = 0  # Placeholder - would need network testing for actual latency
        RawMeasurements = $measurements
    }
}

function Save-GamingBaseline {
    [CmdletBinding()]
    param(
        $Baseline,
        [string]$Path
    )
    
    # Ensure directory exists
    $directory = Split-Path $Path -Parent
    if (-not (Test-Path $directory)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }
    
    # Save baseline
    $Baseline | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
    Write-Host "  ✅ Gaming performance baseline saved to: $Path" -ForegroundColor Green
}

function Test-GamingPerformanceAgainstBaseline {
    [CmdletBinding()]
    param(
        [int]$DurationSeconds,
        [string]$BaselinePath,
        [double]$MaxDegradation
    )
    
    if (-not (Test-Path $BaselinePath)) {
        throw "Baseline file not found: $BaselinePath"
    }
    
    # Load baseline
    $baseline = Get-Content $BaselinePath | ConvertFrom-Json
    Write-Host "  Loaded baseline from: $(Split-Path $BaselinePath -Leaf)" -ForegroundColor Gray
    
    # Measure current performance
    Write-Host "  Measuring current performance..." -ForegroundColor Gray
    $currentPerformance = Measure-SystemPerformance -DurationSeconds $DurationSeconds
    
    # Compare against baseline
    $comparison = @{
        Timestamp = Get-Date
        BaselineTimestamp = $baseline.Timestamp
        TestDuration = $DurationSeconds
        Success = $true
        Degradation = @{}
        Issues = @()
        Details = @{}
    }
    
    # CPU Performance Comparison
    $cpuBaseline = $baseline.PerformanceMetrics.AverageCPUUsage
    $cpuCurrent = $currentPerformance.AverageCPU
    $cpuDegradation = if ($cpuBaseline -gt 0) { 
        [math]::Round((($cpuCurrent - $cpuBaseline) / $cpuBaseline) * 100, 2) 
    } else { 0 }
    
    $comparison.Degradation.CPU = $cpuDegradation
    $comparison.Details.CPU = @{
        Baseline = $cpuBaseline
        Current = $cpuCurrent
        Change = $cpuDegradation
    }
    
    if ([math]::Abs($cpuDegradation) -gt $MaxDegradation) {
        $comparison.Success = $false
        $comparison.Issues += "CPU usage degradation: $cpuDegradation% (exceeds $MaxDegradation% threshold)"
    }
    
    # Memory Performance Comparison
    $memoryBaseline = $baseline.PerformanceMetrics.AverageMemoryUsage
    $memoryCurrent = $currentPerformance.AverageMemory
    $memoryDegradation = if ($memoryBaseline -gt 0) {
        [math]::Round((($memoryCurrent - $memoryBaseline) / $memoryBaseline) * 100, 2)
    } else { 0 }
    
    $comparison.Degradation.Memory = $memoryDegradation
    $comparison.Details.Memory = @{
        Baseline = $memoryBaseline
        Current = $memoryCurrent
        Change = $memoryDegradation
    }
    
    if ([math]::Abs($memoryDegradation) -gt $MaxDegradation) {
        $comparison.Success = $false
        $comparison.Issues += "Memory usage degradation: $memoryDegradation% (exceeds $MaxDegradation% threshold)"
    }
    
    # Overall Performance Score
    $overallDegradation = [math]::Max([math]::Abs($cpuDegradation), [math]::Abs($memoryDegradation))
    $comparison.Degradation.Overall = $overallDegradation
    
    # Save comparison results
    $resultPath = "logs\gaming-performance-validation-$(Get-Date -Format 'yyyy-MM-dd-HHmm').json"
    $comparison | ConvertTo-Json -Depth 10 | Out-File -FilePath $resultPath -Encoding UTF8
    
    # Display results
    Show-GamingPerformanceResults -Comparison $comparison
    
    return $comparison
}

function Show-GamingPerformanceResults {
    param($Comparison)
    
    Write-Host ""
    Write-Host "=== GAMING PERFORMANCE VALIDATION RESULTS ===" -ForegroundColor Cyan
    
    Write-Host "Overall Result: " -NoNewline
    $resultColor = if ($Comparison.Success) { "Green" } else { "Red" }
    $resultText = if ($Comparison.Success) { "✅ PASS" } else { "❌ FAIL" }
    Write-Host $resultText -ForegroundColor $resultColor
    
    Write-Host "Maximum Degradation: $($Comparison.Degradation.Overall)%" -ForegroundColor $(if ($Comparison.Degradation.Overall -le 2.0) { "Green" } else { "Red" })
    
    Write-Host ""
    Write-Host "Performance Metrics:" -ForegroundColor Yellow
    Write-Host "  CPU Usage: " -NoNewline
    Write-Host "$($Comparison.Details.CPU.Baseline)% → $($Comparison.Details.CPU.Current)% " -NoNewline
    $cpuChangeColor = if ([math]::Abs($Comparison.Details.CPU.Change) -le 2.0) { "Green" } else { "Red" }
    Write-Host "($($Comparison.Details.CPU.Change)%)" -ForegroundColor $cpuChangeColor
    
    Write-Host "  Memory Usage: " -NoNewline  
    Write-Host "$($Comparison.Details.Memory.Baseline)% → $($Comparison.Details.Memory.Current)% " -NoNewline
    $memChangeColor = if ([math]::Abs($Comparison.Details.Memory.Change) -le 2.0) { "Green" } else { "Red" }
    Write-Host "($($Comparison.Details.Memory.Change)%)" -ForegroundColor $memChangeColor
    
    if ($Comparison.Issues.Count -gt 0) {
        Write-Host ""
        Write-Host "PERFORMANCE ISSUES:" -ForegroundColor Red
        foreach ($issue in $Comparison.Issues) {
            Write-Host "  ⚠️  $issue" -ForegroundColor Red
        }
    }
    
    if ($Comparison.Success) {
        Write-Host ""
        Write-Host "✅ Gaming performance maintained within acceptable limits" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "❌ Gaming performance degradation exceeds acceptable limits" -ForegroundColor Red
        Write-Host "   Security policies may need adjustment for gaming compatibility" -ForegroundColor Red
    }
}

# Execute if script is run directly
if ($MyInvocation.InvocationName -ne '.') {
    Test-GamingPerformance -DurationSeconds $DurationSeconds -MaxAcceptableDegradation $MaxAcceptableDegradation -BaselinePath $BaselinePath -EstablishBaseline:$EstablishBaseline -ValidatePerformance:$ValidatePerformance
}
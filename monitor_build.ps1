# PowerShell monitoring script for Windows

# Function to write colored output
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    else {
        $input | Write-Output
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

# Function to get system resources
function Get-SystemResources {
    $cpu = Get-Counter '\Processor(_Total)\% Processor Time' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue
    $memory = Get-Counter '\Memory\% Committed Bytes In Use' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue
    $disk = Get-PSDrive C | Select-Object -ExpandProperty Used
    $diskTotal = Get-PSDrive C | Select-Object -ExpandProperty Free
    $diskUsage = [math]::Round(($disk / ($disk + $diskTotal)) * 100, 2)
    
    $dockerUsage = docker system df -v | Select-String "Total Space" | ForEach-Object { $_.ToString().Split(" ")[-1] }
    
    return "CPU: $cpu% | Memory: $memory% | Disk: $diskUsage% | Docker: $dockerUsage"
}

# Function to get build progress
function Get-BuildProgress {
    $currentStage = docker-compose logs --tail=50 | Select-String "Step" | Select-Object -Last 1
    $buildTime = Get-Process | Where-Object { $_.ProcessName -eq "docker-compose" } | Select-Object -ExpandProperty StartTime
    
    return "Current Stage: $currentStage | Build Time: $buildTime"
}

# Function to check for errors
function Check-Errors {
    $errors = docker-compose logs --tail=100 | Select-String -Pattern "error|fail|exception" -CaseSensitive:$false | Select-Object -Last 5
    
    if ($errors) {
        Write-ColorOutput Red "Recent Errors:"
        $errors | ForEach-Object { Write-Output $_.ToString() }
    }
}

# Create log file
$logFile = "build_monitor_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
"Build Monitor Log - Started at $(Get-Date)" | Out-File $logFile

Write-ColorOutput Blue "Starting build monitoring at $(Get-Date)"
Write-ColorOutput Yellow "Press Ctrl+C to stop monitoring"

try {
    while ($true) {
        Clear-Host
        
        # Display header
        Write-ColorOutput Blue "=== Build Process Monitor ==="
        Write-Output "Time: $(Get-Date)"
        Write-Output "Log File: $logFile"
        Write-Output ""
        
        # Get and display system resources
        Write-ColorOutput Yellow "System Resources:"
        $resources = Get-SystemResources
        Write-Output $resources
        "$(Get-Date) - Resources: $resources" | Add-Content $logFile
        
        # Get and display build progress
        Write-ColorOutput Yellow "`nBuild Progress:"
        $progress = Get-BuildProgress
        Write-Output $progress
        "$(Get-Date) - Progress: $progress" | Add-Content $logFile
        
        # Check for errors
        Write-ColorOutput Yellow "`nError Check:"
        Check-Errors | Add-Content $logFile
        
        # Display Docker container status
        Write-ColorOutput Yellow "`nDocker Status:"
        docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | Select-Object -Skip 1
        
        # Display disk space warning if needed
        $diskUsage = (Get-PSDrive C).Used / (Get-PSDrive C).Free * 100
        if ($diskUsage -gt 80) {
            Write-ColorOutput Red "`nWarning: Disk usage is above 80% ($diskUsage%)"
            "$(Get-Date) - Warning: High disk usage: $diskUsage%" | Add-Content $logFile
        }
        
        # Display memory warning if needed
        $memoryUsage = Get-Counter '\Memory\% Committed Bytes In Use' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue
        if ($memoryUsage -gt 80) {
            Write-ColorOutput Red "`nWarning: Memory usage is above 80% ($memoryUsage%)"
            "$(Get-Date) - Warning: High memory usage: $memoryUsage%" | Add-Content $logFile
        }
        
        # Wait for 5 seconds before next update
        Start-Sleep -Seconds 5
    }
}
finally {
    Write-ColorOutput Yellow "`nMonitoring stopped. Log file saved as: $logFile"
} 
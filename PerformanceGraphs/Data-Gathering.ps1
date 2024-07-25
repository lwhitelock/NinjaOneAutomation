# Author Luke Whitelock
# Date: 2024-07-25
# Version 1
# https://mspp.io
# https://docs.mspp.io/ninjaone/performance-graphs

# This script is designed to work with the graph and data aggregation script. This script should be setup first

# This script is designed to run every 5 minutes as a condition to log CPU, Memory and Disk Usage to a local JSON file.
# The companion script will then aggregate and generate graphs into custom fields.

# Instructions
# Create a script condition set to run every 5 minutes to run this script. It will not actually monitor anything and will only fail if there is an issue with it running.

# Path to store the JSON file
$jsonPath = "C:\ProgramData\NinjaRMMAgent\MachinePerformance.json"

# Function to collect system metrics
function Get-MachineMetrics {
    # CPU Usage
    $cpu = Get-Counter '\Processor(_Total)\% Processor Time' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue

    # Memory Usage in Percentage
    $totalMem = Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
    $availMem = Get-Counter '\Memory\Available MBytes' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue
    $usedMem = $totalMem.Sum / 1MB - $availMem
    $memPercentUsed = ($usedMem / ($totalMem.Sum / 1MB)) * 100

    # Disk Usage in Percentage per Drive
    $diskPercentUsed = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType = 3" | ForEach-Object {
        $usedSpace = ($_.Size - $_.FreeSpace) / $_.Size * 100
        return [PSCustomObject]@{
            Drive       = $_.DeviceID
            PercentUsed = [math]::Round($usedSpace, 2)
        }
    }

    return @{
        Timestamp = [System.DateTime]$(Get-Date).DateTime
        CPU = [math]::Round($cpu, 2)
        MemoryPercentUsed = [math]::Round($memPercentUsed, 2)
        DiskUsage = $diskPercentUsed
    }
}

# Read existing data from file
try {
    [System.Collections.Generic.List[PSCustomObject]]$data = Get-Content $jsonPath -ea stop | ConvertFrom-Json
} catch {
    [System.Collections.Generic.List[PSCustomObject]]$data = @() 
}

# Collect current metrics
$currentMetrics = Get-MachineMetrics

# Add to existing data
$data.add($currentMetrics)

# Write data back to JSON file, overwriting the existing data
$data | ConvertTo-Json -Depth 10 | Set-Content $jsonPath

Write-Host 'Data Gathering Complete'

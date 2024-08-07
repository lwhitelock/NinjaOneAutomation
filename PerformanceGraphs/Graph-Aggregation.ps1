# Author Luke Whitelock
# Date: 2024-07-25
# Version 1
# https://mspp.io
# https://docs.mspp.io/ninjaone/performance-graphs

# This script is designed to work with the data generated by the companion Data Gather script. Ensure you configure that script first

# This script will take the gathered performance data for a device and generate graphs of the data.
# The graphs are:
# The last 24 Hours
# 30 Days to 24 Hours
# 90 Days to 30 Days
# Each graph reduces the resolution of data points to allow to present larger time periods.
# The graphs do not overlap

# Instructions
# Create up to 3 WYSIWYG fields to store the different date ranges of Graph data.
# Ensure you set automation permissions to have at least Write access.
# Set a device definition scope for the fields.
# Optionally set them to auto expand in advanced settings.
# Configure the field names below to the ones you created. 
# If you do not want to generate one of the graphs set the name to $Null with no quotes
# Create a script condition or a scheduled task set to run once per hour which will aggregate the data and generate graphs.

# Settings
$24HoursField = '24HourPerformanceData'
$30DaysField = '30DayPerformanceData'
$90DaysField = '90DayPerformanceData'

$JsonPath = "C:\ProgramData\NinjaRMMAgent\MachinePerformance.json"

# Script Start

# Load existing data from file
if (Test-Path $JsonPath) {
        $InitialData = Get-Content $jsonPath | ConvertFrom-Json | Sort-Object Timestamp
} else {
        Write-Output "No data file found."
        exit 1
}

function Get-AggregateData($data, $startPeriod, $endPeriod, $intervalHours) {
        Write-Host "Aggregating data from $($startPeriod.ToString('o')) to $($endPeriod.ToString('o')) with interval $intervalHours hours."
        $groupedData = $data | Where-Object {
                $timestamp = [DateTime]$_.Timestamp
                $timestamp -ge $startPeriod -and $timestamp -lt $endPeriod
        } | Group-Object {
                [Math]::Floor(([DateTime]$_.Timestamp - $startPeriod).TotalHours / $intervalHours)
        }
    
        if ($groupedData.Count -eq 0) {
                Write-Host "No data found for aggregation in the given range."
        } else {
                Write-Host "Data found for aggregation: $($groupedData.Count) groups."
        }
    
        return $groupedData | ForEach-Object {
                $intervalIndex = $_.Name
                $hoursToAdd = [double]$intervalIndex * [double]$intervalHours
    
                try {
                        $intervalStart = $startPeriod.AddHours($hoursToAdd)
                } catch {
                        Write-Error "Failed to calculate interval start. Group Key: $intervalIndex, Interval Hours: $intervalHours, Hours to Add: $hoursToAdd"
                        continue
                }
    
                # Calculate averages
                $avgCPU = ($_.Group | Measure-Object -Property CPU -Average).Average
                $avgMem = ($_.Group | Measure-Object -Property MemoryPercentUsed -Average).Average
                $diskUsageGrouped = $_.Group | ForEach-Object { $_.DiskUsage } | Group-Object Drive | ForEach-Object {
                        $drive = $_.Name
                        $avgDiskUsage = ($_.Group | Measure-Object -Property PercentUsed -Average).Average
                        return [PSCustomObject]@{
                                Drive       = $drive
                                PercentUsed = [math]::Round($avgDiskUsage, 2)
                        }
                }
    
                # Return new object with aggregated data
                return [PSCustomObject]@{
                        Timestamp         = $intervalStart
                        CPU               = [math]::Round($avgCPU, 2)
                        MemoryPercentUsed = [math]::Round($avgMem, 2)
                        DiskUsage         = $diskUsageGrouped
                }
        }
}

function Get-NinjaOneColours ($NumColours) {
        # Step 1: Preset 10 colors
        [System.Collections.Generic.List[String]]$presetColors = @(
                '#007F8F',
                '#7949CE',
                '#5B1139',
                '#3733C8',
                '#567C19',
                '#042552',
                '#A13FA4',
                '#7A6D81',
                '#004858',
                '#895C07',
                '#0198AC',
                '#9969ED',
                '#862D5D',
                '#5753F2',
                '#729D2D',
                '#00357E',
                '#D552D9',
                '#9A8CA1',
                '#005E73',
                '#A9710A',
                '#A7CDD2',
                '#C8BAE2',
                '#D3B5C5',
                '#B5B3E2',
                '#BBCD9D',
                '#ADBED6',
                '#D5B1D6',
                '#C6C2C8',
                '#A2CAD3',
                '#D7C8AD'
        )

        # If the number of requested colors is less than or equal to the preset colors count
        if ($NumColours -le $presetColors.count) {
                return $presetColors[0..($NumColours - 1)]
        }

        # Step 2: Generate random colors
        $allColors = $presetColors
        for ($i = 0; $i -lt ($NumColours - $presetColors.count); $i++) {
                $R = Get-Random -Minimum 0 -Maximum 256
                $G = Get-Random -Minimum 0 -Maximum 256
                $B = Get-Random -Minimum 0 -Maximum 256
                $randomColor = "#{0:X2}{1:X2}{2:X2}" -f $R, $G, $B

                $allColors.add($randomColor)
        }

        # Step 3: Output the array of colors
        return $allColors
}


function Set-GraphData($DateStart, $DateEnd, $FieldName, $Title) {

        $Data = $RawData | Where-Object { $_.Timestamp -ge $DateStart -and $_.Timestamp -lt $DateEnd }

        if (($Data | Measure-Object).count -gt 2) {

                [System.Collections.Generic.List[String]]$HTML = @()

                $HTML.add(@"     
        <table
                    class="charts-css line multiple show-labels show-primary-axis show-10-secondary-axes show-heading" style="height: 500px;">
                    <caption> $Title </caption>
                    <tbody>
"@)

                $CPULast = $Data[0].CPU
                $MemLast = $Data[0].MemoryPercentUsed
                $DiskLast = $Data[0].DiskUsage | Sort-Object Drive

                $MaxDisks = ($Data | ForEach-Object { ($_.DiskUsage | Measure-Object).count } | Measure-Object -Max).Maximum
                $MaxItems = $MaxDisks + 2
                $Colours = Get-NinjaOneColours ($MaxItems)

                for ($i = 0; $i -lt $Data.Length; $i++) {

                        $CPUValue = $Data[$i].CPU
                        $MemValue = $Data[$i].MemoryPercentUsed
                        $DiskValue = $Data[$i].DiskUsage | Sort-Object Drive

                        $HTML.add('<tr><td style="--start: ' + ($CPULast / 100) + '; --end: ' + ($CPUValue / 100) + '; --color: ' + $Colours[0] + ';"></td>')
                        $HTML.add('<td style="--start: ' + ($MemLast / 100) + '; --end: ' + ($MemValue / 100) + '; --color: ' + $Colours[1] + ';">')
                        $ColCount = 2
                        foreach ($Disk in $DiskValue) {
                                $MatchedLast = $DiskLast | Where-Object { $_.Drive -eq $Disk.Drive }
                                $HTML.add('</td><td style="--start: ' + ($MatchedLast.PercentUsed / 100) + '; --end: ' + ($Disk.PercentUsed / 100) + '; --color: ' + $Colours[$ColCount] + ';">')
                                $ColCount++
                        }
                        $HTML.add('<span class="tooltip">' + $Data[$i].Timestamp + '<br>CPU: ' + $CPUValue + '%<br>Memory: ' + $MemValue + '%' + $(Foreach ($Disk in $DiskValue) { '<br>' + $Disk.Drive + ' ' + $Disk.PercentUsed + '%' }) + '</span></td>')
                        $HTML.add('</tr>')
                        $CPULast = $CPUValue
                        $MemLast = $MemValue
                        $DiskLast = $DiskValue
                }

                $HTML.add("</tbody></table>")
                $ColCount = 1

                $HTML.add(@"
<ul class="unstyled p-3" style="display: flex; justify-content: space-between;">
   <li><span class="chart-key" style="background-color: $($Colours[0]);"></span><span> CPU </span></li>
   <li><span class="chart-key" style="background-color: $($Colours[1]);"></span><span> Memory </span></li>
   $($Data.DiskUsage.Drive | Select-Object -unique | Sort-Object | ForEach-Object {$ColCount++; '<li><span class="chart-key" style="background-color: ' + $($Colours[$ColCount]) + ';"></span><span> ' + $_ + ' </span></li>';})
 </ul>
"@
                )
        } else {
                $HTML = '<h2>Not enough data to generate graph</h2>'
        }

        $HTML -Join '' | Ninja-Property-Set-Piped $FieldName

}


$currentDate = Get-Date
$oneDayAgo = $currentDate.AddDays(-1)
$thirtyDaysAgo = $currentDate.AddDays(-30)
$ninetyDaysAgo = $currentDate.AddDays(-90)

# Verify data ranges and aggregation thresholds
$newData = $InitialData | Where-Object { [DateTime]$_.Timestamp -gt $oneDayAgo }
$aggregate2_4Hours = Get-AggregateData $InitialData $thirtyDaysAgo $oneDayAgo 2.4
$aggregate7_2Hours = Get-AggregateData $InitialData $ninetyDaysAgo $thirtyDaysAgo 7.2

# Combine all data
$RawData = $newData + $aggregate2_4Hours + $aggregate7_2Hours

# Write data back to JSON file
$RawData | ConvertTo-Json -Depth 10 | Set-Content $jsonPath

if ($24HoursField) {
        Set-GraphData $oneDayAgo $currentDate $24HoursField 'Last 24 Hours Performance Data'
}

if ($30DaysField) {
        Set-GraphData $thirtyDaysAgo $oneDayAgo $30DaysField '30 Days to 24 Hours Performance Data'
}

if ($90DaysField) {
        Set-GraphData $ninetyDaysAgo $thirtyDaysAgo $90DaysField '90 Days to 30 Days Performance Data'
}

Write-Host "Script Complete"

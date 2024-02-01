
$Start = Get-Date

$NinjaOneInstance = Ninja-Property-Get ninjaoneInstance
$NinjaOneClientID = Ninja-Property-Get ninjaoneClientId
$NinjaOneClientSecret = Ninja-Property-Get ninjaoneClientSecret

$OverviewCompany = 'Global Overview'
$SummaryField = 'deviceAlertSummary'

try {

    if (!(Get-Module -Name "NinjaOneDocs")) {
        $Null = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        Install-Module -Name 'NinjaOneDocs' -Force -MinimumVersion 1.1.0
        Import-Module 'NinjaOneDocs'
    } else {
        Update-Module NinjaOneDocs -Force
        Import-Module 'NinjaOneDocs'
    }

    # Fix for PSCustomObjects being broken in 7.4.0
    $ExecutionContext.SessionState.LanguageMode = 'FullLanguage'


    function Get-AlertsTable ($Alerts, $MaxChars, $CountAlerts) {
        [System.Collections.Generic.List[string]]$ParsedTable = @()
      
        [System.Collections.Generic.List[PSCustomObject]]$WidgetData = @()
        $WidgetData.add([PSCustomObject]@{
                Value       = '<i class="fas fa-circle-xmark"></i>&nbsp;&nbsp;' + $(($CountAlerts | Where-Object { $_.Severity -eq 'CRITICAL' } | Measure-Object).count)
                Description = 'Critical'
                Colour      = '#D53948'
            })
        $WidgetData.add([PSCustomObject]@{
                Value       = '<i class="fas fa-triangle-exclamation"></i>&nbsp;&nbsp;' + $(($CountAlerts | Where-Object { $_.Severity -eq 'MAJOR' } | Measure-Object).count)
                Description = 'Major'
                Colour      = '#FAC905'
            })
        $WidgetData.add([PSCustomObject]@{
                Value       = '<i class="fas fa-circle-exclamation"></i>&nbsp;&nbsp;' + $(($CountAlerts | Where-Object { $_.Severity -eq 'MODERATE' } | Measure-Object).count)
                Description = 'Moderate'
                Colour      = '#337AB7'
            })
        $WidgetData.add([PSCustomObject]@{
                Value       = '<i class="fas fa-circle-exclamation"></i>&nbsp;&nbsp;' + $(($CountAlerts | Where-Object { $_.Severity -eq 'MINOR' } | Measure-Object).count)
                Description = 'Minor'
                Colour      = '#949597'
            })
        $WidgetData.add([PSCustomObject]@{
                Value       = '<i class="fas fa-circle-info"></i>&nbsp;&nbsp;' + $(($CountAlerts | Where-Object { $_.Severity -eq 'NONE' } | Measure-Object).count)
                Description = 'None'
                Colour      = '#949597'
            })
        

        $WidgetHTML = (Get-NinjaOneWidgetCard -Data $WidgetData -SmallCols 3 -MedCols 3 -LargeCols 5 -XLCols 5 -NoCard)
        $ParsedTable.add($WidgetHTML)
        $ParsedTable.add('<table>')
        $ParsedTable.add('<tr><th>Created</th><th></th><th>Device</th><th>Organization</th><th style="white-space: nowrap;">Severity</th><th style="white-space: nowrap;">Priority</th><th style="white-space: nowrap;">Last 30 Days</th><th>Message</th></tr>')

        foreach ($ParsedAlert in $Alerts) {
            $HTML = '<tr class="' + $ParsedAlert.RowClass + '">' +
            '<td style="white-space: nowrap;">' + ($ParsedAlert.Created).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") + '</td>' +
            '<td style="white-space: nowrap;"><i style="color: ' + $ParsedAlert.OnlineColour + ';" class="' + $ParsedAlert.OnlineIcon + '"></i></td>' +
            '<td style="white-space: nowrap;"><a href="https://' + $NinjaOneInstance + '/#/deviceDashboard/' + $ParsedAlert.DeviceID + '/overview">' + $ParsedAlert.Device + '</a></td>' +
            '<td style="white-space: nowrap;"><a href="https://' + $NinjaOneInstance + '/#/customerDashboard/' + $ParsedAlert.OrgID + '/overview">' + $ParsedAlert.OrgName + '</a></td>' +
            '<td style="white-space: nowrap;"><i style="color: ' + $ParsedAlert.SeverityColour + ';" class="' + $ParsedAlert.SeverityIcon + '"></i> ' + (Get-Culture).TextInfo.ToTitleCase($ParsedAlert.Severity.ToLower()) + '</td>' +
            '<td style="white-space: nowrap;"><i style="color: ' + $ParsedAlert.PriorityColour + ';" class="' + $ParsedAlert.PriorityIcon + '"></i> ' + (Get-Culture).TextInfo.ToTitleCase($ParsedAlert.Priority.ToLower()) + '</td>' +
            '<td style="white-space: nowrap;">' + $ParsedAlert.Last30Days + '</td>' +
            '<td>' + ($ParsedAlert.Message).Substring(0, [Math]::Min(($ParsedAlert.Message).Length, $MaxChars)) + '</td>' + '</tr>'

            $ParsedTable.add($HTML)
        }

        $ParsedTable.add('</table>')

        Return $ParsedTable
    }


    Connect-NinjaOne -NinjaOneInstance $NinjaOneInstance -NinjaOneClientID $NinjaOneClientID -NinjaOneClientSecret $NinjaOneClientSecret
    Write-Output "$(Get-Date): Fetching Core Data"
    $Alerts = Invoke-NinjaOneRequest -Method GET -Path 'alerts' -Paginate
    $Devices = Invoke-NinjaOneRequest -Method GET -Path 'devices' -Paginate
    $Organizations = Invoke-NinjaOneRequest -Method GET -Path 'organizations' -Paginate
    $Locations = Invoke-NinjaOneRequest -Method GET -Path 'locations' -Paginate


    Write-Output "$(Get-Date): Fetching Activities"

    $31DaysAgo = Get-NinjaOneTime -Date ((Get-Date).adddays(-31)) -Seconds
    [System.Collections.Generic.List[PSCustomObject]]$Activities = (Invoke-NinjaOneRequest -Method GET -Path 'activities' -QueryParams "status=TRIGGERED&pageSize=1000&after=$31DaysAgo").activities

    $Count = ($Activities.id | measure-object -Minimum).minimum

    $PageSize = 1000

    $Found = $False
 
    do {

        $Result = Invoke-NinjaOneRequest -Method GET -Path 'activities' -QueryParams "status=TRIGGERED&pageSize=$($PageSize)&olderThan=$($Count)&after=$31DaysAgo"

        if (($Result.Activities | Measure-Object).count -gt 0) {
            $Activities.AddRange([System.Collections.Generic.List[PSCustomObject]]$Result.Activities)
            $Count = ($Result.Activities.id | measure-object -Minimum).Minimum
            $Measurement = $($Result.Activities.id | measure-object -Minimum -Maximum)
            Write-Host "Min: $($Measurement.Minimum) Max: $($Measurement.Maximum)"
        } else {
            $Found = $True
        }

    } while ($Found -eq $False)

    [System.Collections.Generic.List[PSCustomObject]]$ParsedAlerts = @()

    Write-Output "$(Get-Date): Processing Organizations"
    foreach ($Org in $Organizations) {
        Write-Host "$(Get-Date): Processing $($Org.name)"
        $OrgDevices = $Devices | where-object { $_.organizationId -eq $Org.id }
        $OrgAlerts = $Alerts | Where-Object { $_.deviceId -in $OrgDevices.id }
        Foreach ($Alert in $OrgAlerts) {
            $CurrentActivity = $Activities | Where-Object { $_.seriesUid -eq $Alert.uid }
            if (($CurrentActivity | Measure-Object).count -ne 1) {
                $AssociatedTriggers = $Null
                $CurrentActivity = (Invoke-NinjaOneRequest -Method GET -Path 'activities' -QueryParams "status=TRIGGERED&seriesUid=$($Alert.uid)").Activities
            }

            $AssociatedTriggers = $Activities | Where-Object { $_.sourceConfigUid -eq $Alert.sourceConfigUid -and $_.deviceId -eq $Alert.deviceId }
            $AlertDevice = $Devices | Where-Object { $_.id -eq $Alert.deviceId }
            $AlertLocation = $Locations | Where-Object { $_.id -eq $AlertDevice.locationId }
            
            if ($AlertDevice.offline -eq $True) {
                $OnlineColour = '#949597'
                $OnlineIcon = 'fas fa-plug'
            } else {
                $OnlineColour = '#26a644'
                $OnlineIcon = 'fas fa-plug'
            }

            Switch ($CurrentActivity.severity) {
                'CRITICAL' { $SeverityIcon = 'fas fa-circle-xmark'; $SeverityColour = '#D53948'; $SeverityScore = 5; $RowClass = 'danger' }
                'MAJOR' { $SeverityIcon = 'fas fa-triangle-exclamation'; $SeverityColour = '#FAC905'; $SeverityScore = 4; $RowClass = 'warning' }
                'MODERATE' { $SeverityIcon = 'fas fa-circle-exclamation'; $SeverityColour = '#337AB7 '; $SeverityScore = 3; $RowClass = 'other' }
                'MINOR' { $SeverityIcon = 'fas fa-circle-exclamation'; $SeverityColour = '#949597'; $SeverityScore = 2; $RowClass = 'unknown' }
                'NONE' { $SeverityIcon = 'fas fa-circle-info'; $SeverityColour = '#949597'; $SeverityScore = 1; $RowClass = '' }
                default { $SeverityIcon = 'fas fa-circle-info'; $SeverityColour = '#949597'; $SeverityScore = 1; $RowClass = '' }
            }

            Switch ($CurrentActivity.priority) {
                'HIGH' { $PriorityIcon = 'fas fa-circle-arrow-up'; $PriorityColour = '#D53948'; $PriorityScore = 5 }
                'MEDIUM' { $PriorityIcon = 'fas fa-circle-arrow-right'; $PriorityColour = '#FAC905'; $PriorityScore = 4 }
                'LOW' { $PriorityIcon = 'fas fa-circle-arrow-down'; $PriorityColour = '#337AB7'; $PriorityScore = 3 }
                'NONE' { $PriorityIcon = 'fas fa-circle-info'; $PriorityColour = '#949597'; $PriorityScore = 2 }
                default { $PriorityIcon = 'fas fa-circle-info'; $PriorityColour = '#949597'; $PriorityScore = 2 }
            }


            
            $TotalCount = ($AssociatedTriggers | Measure-Object).count
            $Last30DaysAlerts = $AssociatedTriggers | Where-Object { $_.activityTime -gt (Get-NinjaOneTime -Date (Get-Date).AddDays(-30) -Seconds) } | Sort-Object activityTime
        
        
            # Get the current date
            $today = Get-Date

            # Initialize variables to track consecutive days and status
            $consecutiveDays = 0
            $previousStatus = $null
            $HTMLHistory = ''

            # Loop through the last 30 days
            for ($i = 0; $i -le 30; $i++) {
                # Calculate the date to check
                $dateToCheck = $today.AddDays(-$i)

                # Check if any alerts were created on this date
                $alertsOnThisDay = $Last30DaysAlerts | Where-Object { (Get-TimeFromNinjaOne -Date ($_.activityTime) -Seconds).Date -eq $dateToCheck.Date }
                $currentStatus = if ($alertsOnThisDay.Count -gt 0) { "#D53948" } else { "#cccccc" }

                # Check if the status changed or it's the last iteration
                if ($currentStatus -ne $previousStatus -or $i -eq 30) {
                    if ($consecutiveDays -gt 0) {
                        # Calculate width of the span
                        $width = $consecutiveDays * 3  # Example width calculation
                        $color = if ($previousStatus -eq "#D53948") { "#D53948" } else { "#cccccc" }
                        $HTMLHistory = "<div style='background-color: $color; width: ${width}px;'></div>" + $HTMLHistory
                    }

                    # Reset for the new status
                    $consecutiveDays = 0
                }

                # Increment the day count and update the previous status
                $consecutiveDays++
                $previousStatus = $currentStatus
            }

            # End of HTML output
            $HTMLHistory = '<div style="display: flex; height: 20px;">' + $HTMLHistory + '</div>'

            $ParsedAlerts.add([PSCustomObject]@{
                    Created        = Get-TimeFromNinjaOne -Date $Alert.createTime -seconds
                    Updated        = Get-TimeFromNinjaOne -Date $Alert.updateTime -seconds
                    Device         = $AlertDevice.systemName
                    DeviceID       = $AlertDevice.id
                    OnlineIcon     = $OnlineIcon
                    OnlineColour   = $OnlineColour
                    OrgName        = $Org.name
                    OrgID          = $Org.id
                    LocName        = $AlertLocation.name
                    LocID          = $AlertLocation.id
                    Message        = $Alert.message
                    Severity       = if ($CurrentActivity.severity) { $CurrentActivity.severity } else { 'None' }
                    Priority        = if ($CurrentActivity.priority) { $CurrentActivity.priority } else { 'None' }
                    SeverityIcon   = $SeverityIcon 
                    SeverityColour = $SeverityColour
                    SeverityScore  = $SeverityScore
                    PriorityIcon    = $PriorityIcon
                    PriorityColour  = $PriorityColour
                    PriorityScore   = $PriorityScore
                    RowClass       = $RowClass
                    TotalCount     = $TotalCount
                    Last30Days     = $HTMLHistory
                })


        }

        $OrgAlertsTable = ($ParsedAlerts | Where-object { $_.OrgID -eq $Org.id } | Sort-Object SeverityScore, PriorityScore, Created -Descending)
        $ParsedTable = Get-AlertsTable -Alerts $OrgAlertsTable -CountAlerts $OrgAlertsTable  -MaxChars 300
        
        $OrgUpdate = [PSCustomObject]@{
            "$SummaryField" = @{'html' = "$($ParsedTable -join '')" }
        }

        $Null = Invoke-NinjaOneRequest -Method PATCH -Path "organization/$($Org.id)/custom-fields" -InputObject $OrgUpdate

    }

    Write-Output "$(Get-Date): Generating Global View"
    # Set Global View
    $OverviewMatch = $Organizations | Where-Object { $_.name -eq $OverviewCompany }
    $ParsedTable = Get-AlertsTable -Alerts ($ParsedAlerts | Sort-Object SeverityScore, PriorityScore, Created -Descending | select-object -first 100) -MaxChars 100 -CountAlerts $ParsedAlerts
    $OrgUpdate = [PSCustomObject]@{
        "$SummaryField" = @{'html' = "$($ParsedTable -join '')" }
    }

    $Null = Invoke-NinjaOneRequest -Method PATCH -Path "organization/$($OverviewMatch.id)/custom-fields" -InputObject $OrgUpdate

    Write-Output "$(Get-Date): Processing Devices"
    # Set Each Device
    Foreach ($UpdateDevice in $Devices) {
        $DeviceAlerts = ($ParsedAlerts | Where-object { $_.DeviceID -eq $UpdateDevice.id } | Sort-Object SeverityScore, PriorityScore, Created -Descending)
        $ParsedTable = Get-AlertsTable -MaxChars 300 -Alerts $DeviceAlerts -CountAlerts $DeviceAlerts
        $DeviceUpdate = [PSCustomObject]@{
            "$SummaryField" = @{'html' = "$($ParsedTable -join '')" }
        }

        $Null = Invoke-NinjaOneRequest -Method PATCH -Path "device/$($UpdateDevice.id)/custom-fields" -InputObject $DeviceUpdate
    }

    Write-Output "$(Get-Date): Complete Total Runtime: $((New-TimeSpan -Start $Start -End (Get-Date)).TotalSeconds) seconds"

} catch {
    Write-Output "Failed to Generate Documentation: $_"
    exit 1
}


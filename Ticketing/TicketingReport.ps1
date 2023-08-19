# Ticketing Report Script
# Author: Luke Whitelock
# Date: 2023-08-19
# Please note this is not an official NinjaOne Script, please report any problems in GitHub
# https://github.com/lwhitelock/NinjaOneAutomation/issues

# Create a machine to machine API application with montitoring and management enabled and client_credentials enabled.
# Set the ID and Secret here: 
$Script:ClientID = Read-Host "Enter you NinjaOne Client Application ID"
$Script:Secret = Read-Host "Enter you NinjaOne Client Application Secret"

# Set the NinjaOne Instance you use eg eu.ninjarmm.com, app.ninjarmm.com, ca.ninjarmm.com, oc.ninjarmm.com
$Script:Instance = 'app.ninjarmm.com'

# Set the board ID to fetch tickets from. By default 2 is the All Tickets Board. 
# Please make sure the board you select has Ticket ID, Last Updated, and Tracked Time fields enabled.
$Script:BoardID = 2

# Set the location for the ticketing report to be saved. By default it will be saved to the folder where
# the script is run, with the current date appended.
$Date = Get-Date -Format "yyyy-MM-dd"
$Output_File = "$($Date)_Ticketing_Report.html"


###### Start of Functions ######

function Get-NinjaOneHTML {
    $Script:HTML = @"
    <html>

    <head>
        <link rel="stylesheet" href="https://rsms.me/inter/inter.css">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"
            integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw=="
            crossorigin="anonymous" referrerpolicy="no-referrer" />
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet"
            integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous">
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"
            integrity="sha384-kenU1KFdBIe4zVF0s0G1M5b4hcpxyD9F7jL+jjXkk+Q2h455rYXK/7HAuoJl+0I4" crossorigin="anonymous">
            </script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script src="https://kryogenix.org/code/browser/sorttable/sorttable.js"></script>
    </head>
    <title>Ticketing Report - $(Get-Date -Format 'yyyy-MM-dd')</title>
    
    <body>
    
        <div width="95%" class="p-3 m-3 shadow-lg">
    
            <div class="d-flex justify-content-center align-items-center text-center">
                <h2>Ticketing Report: $($Script:FromDate) - $($Script:ToDate) </h2>
            </div>
    
            <!-- Global Card -->
    
            <div class="card mb-3">
                <div class="card-body">
                    
                    <h5 class="card-title">Global Report</h5>
    
                    <p><strong>Technician Productivity Report</strong></p>
                    
                    <div class="row d-flex justify-content-center align-items-center mb-3">
                        <div class="col-md-5 m-1">
                            <canvas id="TechTimeChart"></canvas>
                        </div>
                        <div class="col-md-5 m-1">
                            <canvas id="TechCommentsChart"></canvas>
                        </div>
                    </div>
                    
                    $Script:TechTimeHTML  
    
                    <p><strong>Organization Productivity Report</strong></p>
    
                    <div class="row d-flex justify-content-center align-items-center mb-3">
                        <div class="col-md-5 m-1">
                            <canvas id="OrgTimeChart"></canvas>
                        </div>
                        <div class="col-md-5 m-1">
                            <canvas id="OrgCommentsChart"></canvas>
                        </div>
                    </div>
    
                    $Script:OrgTimeHTML  
    
                    <p><strong>Tags Productivity Report</strong></p>
    
                    <div class="row d-flex justify-content-center align-items-center mb-3">
                        <div class="col-md-5 m-1">
                            <canvas id="TagsTimeChart"></canvas>
                        </div>
                        <div class="col-md-5 m-1">
                            <canvas id="TagsCommentsChart"></canvas>
                        </div>
                    </div>
    
                    $Script:TagsTimeHTML
    
                </div>
    
            </div>
    
            <!-- Organization Cards -->
    
            $Script:OrgReportHTML

        </div>
    
    </body>
    
    </html>
    
    
    
    <script>
    
        document.addEventListener("DOMContentLoaded", function () {
            var tables = document.querySelectorAll(".table");
            tables.forEach(function (table) {
                sorttable.makeSortable(table);
            });
        });
    
        function getRandomColor() {
            var letters = '0123456789ABCDEF';
            var color = '#';
            for (var i = 0; i < 6; i++) {
                color += letters[Math.floor(Math.random() * 16)];
            }
            return color;
        }
    
        var colors = Array.from({ length: 100 }, getRandomColor);
    
        var chartData = $($Script:ChartData | ConvertTo-Json | Out-String);
    
        var canvases = document.querySelectorAll('canvas');
        canvases.forEach(function (canvas) {
            var id = canvas.id;
            if (chartData[id]) {
                new Chart(canvas, {
                    type: chartData[id].chartType,
                    data: {
                        labels: chartData[id].labels,
                        datasets: [{
                            label: chartData[id].label,
                            data: chartData[id].data,
                            backgroundColor: chartData[id].backgroundColor
                        }]
                    },
                    options: {
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
            }
        });
    
    
    </script>
    
    </body>
    
    </html>


"@   
    
    ($Script:HTML -replace '<table>', '<table class="table table-hover table-striped table-bordered">') | Out-File $Output_File
}

function Get-NinjaOneOrgCard ($OrgTickets, $OrgTechTime, $OrgTagsTime, $OrgID, $OrgName) {
    


    Set-NinjaOneChart -ChartName "Org-$OrgID-TopTicketChart" -Data ($OrgTickets | Select-Object -First 20) -DataColumn 'TotalTime' -Label 'Hours Tracked' -NameColumn 'TicketID'
    Set-NinjaOneChart -ChartName "Org-$OrgID-TopTechChartTime" -Data ($OrgTechTime | Sort-Object Name) -DataColumn 'Total Time Tracked' -Label 'Hours Tracked'
    Set-NinjaOneChart -ChartName "Org-$OrgID-TopTechChartComments" -Data ($OrgTechTime | Sort-Object Name) -DataColumn 'Total Comments Made' -Label 'Comments'
    Set-NinjaOneChart -ChartName "Org-$OrgID-TopTagChartTime" -Data ($OrgTagsTime | Sort-Object Name) -DataColumn 'Total Time Tracked' -Label 'Hours Tracked'
    Set-NinjaOneChart -ChartName "Org-$OrgID-TopTagChartComments" -Data ($OrgTagsTime | Sort-Object Name) -DataColumn 'Total Comments by Technicians' -Label 'Comments'

    $OrgHTML = @"
    <div class="card">
                <div class="card-body">
                    <h5 class="card-title">Organization Report - $OrgName</h5>
    
                    <p><strong>Top Tickets by Time</strong></p>
    
                    <div class="row d-flex justify-content-center align-items-center mb-3">
                        <div class="col-md-5 m-1">
                            <canvas id="Org-1-TopTicketChart"></canvas>
                        </div>
                    </div>
    
                    $($OrgTickets | Select-Object TicketID, Subject, Status, TotalTime -First 10 | ConvertTo-Html -As Table -Fragment)
    
                    <p><strong>Top 10 Technicians by Time</strong></p>
    
                    <div class="row d-flex justify-content-center align-items-center mb-3">
                        <div class="col-md-5 m-1">
                            <canvas id="Org-1-TopTechChartTime"></canvas>
                        </div>
                        <div class="col-md-5 m-1">
                            <canvas id="Org-1-TopTechChartComments"></canvas>
                        </div>
                    </div>
    
                    $($OrgTechTime | Sort-Object 'Total Time Tracked' -Descending | select-object -First 10 | ConvertTo-Html -As Table -Fragment)

                    <p><strong>Top 10 Tags by Time</strong></p>
    
                    <div class="row d-flex justify-content-center align-items-center mb-3">
                        <div class="col-md-5 m-1">
                            <canvas id="Org-1-TopTagChartTime"></canvas>
                        </div>
                        <div class="col-md-5 m-1">
                            <canvas id="Org-1-TopTagChartComments"></canvas>
                        </div>
                    </div>
    
                    $($OrgTagsTime | Sort-Object 'Total Time Tracked' -Descending | Select-object -First 10 | ConvertTo-Html -As Table -Fragment)
    
                </div>
            </div>
"@

    $Script:OrgReportHTML.add(($OrgHTML -replace '<table>', '<table class="table table-hover table-striped table-bordered">'))

}

function Connect-NinjaOne {
    $AuthBody = @{
        'grant_type'    = 'client_credentials'
        'client_id'     = $Script:ClientID
        'client_secret' = $Script:Secret
        'scope'         = 'monitoring management' 
    }
    
    $Result = Invoke-WebRequest -uri "https://$($Script:Instance)/ws/oauth/token" -Method POST -Body $AuthBody -ContentType 'application/x-www-form-urlencoded'
    
    $Script:AuthHeader = @{
        'Authorization' = "Bearer $(($Result.content | ConvertFrom-Json).access_token)"
    }
}



function Get-NinjaRequest($Path, $Method, $Body) {
    if ($Body) {
        Return (Invoke-WebRequest -uri "https://$($Instance)$($Path)" -Method $Method -Headers $Script:AuthHeader -ContentType 'application/json' -Body $Body).content | ConvertFrom-Json    
    }
    else {
        Return (Invoke-WebRequest -uri "https://$($Instance)$($Path)" -Method $Method -Headers $Script:AuthHeader -ContentType 'application/json').content | ConvertFrom-Json
    }
}



function Get-DateFromUnix ($UnixTime) {
    return $Script:epoch.AddSeconds($UnixTime)
}

function Get-UnixTimeFromDate($Date) {
    return (New-TimeSpan -Start $Script:epoch -End $Date).TotalSeconds
}


function Get-NinjaTickets ($LastCursor, $PageSize) {

    $Script:Ticketsearch = @"
{
    "sortBy": [
    {
    "field": "lastUpdated",
    "direction": "DESC"
    }
    ],
    "pageSize": $PageSize,
    "lastCursorId": $LastCursor
    }
"@

    $AllTickets = Get-NinjaRequest -Path "/v2/ticketing/trigger/board/$Script:BoardID/run" -Method POST -Body $Script:Ticketsearch

    Return $AllTickets

}

Function Get-NinjaOneTickets($FromUnix, $ToUnix) {
    $Found = $False
    $LastCursor = 0
    

    [System.Collections.Generic.List[PSCustomObject]]$Script:TicketsList = do {
        $FetchedTickets = Get-NinjaTickets -LastCursor $LastCursor -PageSize 1000
        if (($FetchedTickets.data[-1].lastUpdated -lt $FromUnix) -or (($FetchedTickets.data | Measure-Object).count -eq 0)) {
            $Found = $True
        }
        else {
            $LastCursor = $FetchedTickets.metadata.lastCursorId
        }
        $FetchedTickets.data
    
    } while ($Found -eq $False)
    
    $Script:TicketsListFiltered = $Script:TicketsList | Where-Object { $_.lastUpdated -ge $FromUnix -and $_.lastUpdated -le $ToUnix }
    
    $TotalFilteredTickets = ($Script:TicketsListFiltered | Measure-Object).count
    Write-Host "Total Tickets to Process: $TotalFilteredTickets"

    $ProcessedTicketCount = 0

    [System.Collections.Generic.List[PSCustomObject]]$Script:Tickets = foreach ($TicketItem in $Script:TicketsListFiltered) {
        $ProcessedTicketCount++
        $Ticket = Get-NinjaRequest -Path "/v2/ticketing/ticket/$($TicketItem.id)" -Method GET
        if ($TicketItem.totalTimeTracked -gt 0) {
            $TicketLogs = Get-NinjaRequest -Path "/v2/ticketing/ticket/$($TicketItem.id)/log-entry" -Method GET
        }
        else {
            $TicketLogs = $null
        }
    
        # Check if we only have 1 Time entry user try and map time entry UIDs to technicians. 
        $TimeEntryUsers = ($TicketLogs | Where-Object { $_.timeTracked -gt 0 } | Select-Object -unique appUserContactUid).appUserContactUid
        if (($TimeEntryUsers | measure-object).count -eq 1 ) {
            $TimeEntryUser = $TimeEntryUsers
        }
        else {
            $TimeEntryUser = $Null
        }
    
        [PSCustomObject]@{
            TicketID          = $Ticket.ID
            nodeID            = $Ticket.nodeID
            clientID          = $Ticket.clientID
            assignedAppUserID = $Ticket.assignedAppUserId
            requestorUid      = $Ticket.requesterUid
            Subject           = $Ticket.Subject
            Status            = $Ticket.Status.displayName
            Priority          = $Ticket.Priority
            Severity          = $Ticket.Severity
            Form              = $Ticket.ticketFormID
            source            = $Ticket.Source
            tag               = $Ticket.Tags
            createTime        = $Ticket.createTime
            Ticket            = $Ticket
            Logs              = $TicketLogs | Where-Object { $null -ne $_.appUserContactUid -and $_.type -in @('COMMENT', 'DESCRIPTION') -and $null -ne $_.timeTracked -and $_.createTime -ge $FromUnix -and $_.createTime -le $ToUnix } | Select-Object id, appUserContactUid, createTime, timeTracked, htmlBody, @{n = 'ticketID'; e = { $Ticket.ID } }
            TimeEntryUID      = $TimeEntryUser
            TotalTime         = [math]::Round((($TicketLogs | Where-Object { $_.timeTracked -gt 0 -and $_.createTime -ge $FromUnix -and $_.createTime -le $ToUnix }).timeTracked | Measure-Object -sum).sum / 60 / 60, 2)
        }

        Write-Progress -PercentComplete (($ProcessedTicketCount / $TotalFilteredTickets) * 100) -Status "Processing" -Activity "$ProcessedTicketCount / $TotalFilteredTickets Tickets Complete"
    }

    Write-Host "Processing Tickets Complete"
    
}

Function Invoke-NinjaOneUserMapping {
    # Try to figure out UIDs to User ID based on tickets where only one person has made time entries and then looking at the ticket assignee.
    $UserMappingData = $Script:Tickets | where-object { $Null -ne $_.TimeEntryUID -and $Null -ne $_.assignedAppUserID } | Select-Object assignedAppUserID, TimeEntryUID, @{n = 'Merged'; e = { "$($_.assignedAppUserID)|$($_.TimeEntryUID)" } } | Group-Object Merged | Sort-Object Count -Descending
    [System.Collections.Generic.List[PSCustomObject]]$Script:UserMap = Foreach ($AssignedUser in ($Script:Tickets.assignedAppUserID | Select-Object -unique)) {
        $UID = $UserMappingData | Where-Object { ($_.Name -split '\|')[0] -eq $AssignedUser -and $_.count -gt 1 }
        if (($UID | Measure-Object).count -eq 1) {
            $User = $Script:Users | Where-Object { $_.id -eq $AssignedUser }

            [PSCustomObject]@{
                ID    = $AssignedUser
                Name  = "$($User.firstName) $($User.lastName)"
                Email = $User.email
                UID   = ($UID.Name -split '\|')[1]
            }

        }
    }

    if ($Script:UserMapLoaded){
    $Script:UserMapFiltered = $Script:UserMap | Where-Object {$_.ID -notin $Script:UserMapLoaded.ID}
    $Script:UserMap = $Script:UserMapFiltered + $Script:UserMapLoaded
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



function Set-NinjaOneChart ($ChartName, $Data, $ChartType = 'bar', $DataColumn, $NameColumn = 'Name', $Label) {

    [PSCustomObject]$Chart = @{
        chartType       = $ChartType
        labels          = [System.Collections.Generic.List[String]]($Data."$NameColumn")
        data            = [System.Collections.Generic.List[Float]]($Data."$DataColumn")
        backgroundColor = [System.Collections.Generic.List[String]](Get-NinjaOneColours -NumColours ($Data | Measure-Object).count)
        label           = $Label
    }

    $Script:ChartData | Add-Member -NotePropertyName $ChartName -NotePropertyValue $Chart


}

Function Get-NinjaOneTechnicianReport {
    [System.Collections.Generic.List[PSCustomObject]]$Script:TechTime = Foreach ($Technician in $Script:UserMap) {
        [PSCustomObject]@{
            Name                             = $Technician.Name
            'Total Time Tracked'             = [math]::Round((($Script:Tickets.Logs | Where-Object { $_.appUserContactUid -eq $Technician.UID }).timeTracked | Measure-Object -Sum).sum / 60 / 60, 2)
            'Total Created Tickets Assigned' = ($Script:Tickets | Where-object { $_.assignedAppUserID -eq $Technician.id } | Measure-Object).count
            'Total Comments Made'            = ($Script:Tickets.Logs | where-object { $_.appUserContactUid -eq $Technician.UID } | measure-object).count
        }
        
    }

    Set-NinjaOneChart -ChartName 'TechTimeChart' -Data ($Script:TechTime | Sort-Object Name) -DataColumn 'Total Time Tracked' -Label 'Hours Tracked'
    Set-NinjaOneChart -ChartName 'TechCommentsChart' -Data ($Script:TechTime | Sort-Object Name) -DataColumn 'Total Comments Made' -Label 'Comments'

    $Script:TechTimeHTML = $TechTime | Sort-Object 'Total Time Tracked' -Descending | ConvertTo-HTML -AS Table -Fragment
}

Function Get-NinjaOneOrganizationReport {
    
    # Time Per Organization
    # Time By Techncian Report
    [System.Collections.Generic.List[PSCustomObject]]$Script:OrganizationTime = Foreach ($Org in $Script:Tickets.clientID | Select-Object -unique) {
        $MatchedOrg = $Script:Orgs | Where-Object { $_.id -eq $Org }

        [PSCustomObject]@{
            #Name                            = '<a href="#client-' + $Org + '">' + $MatchedOrg.Name + '</a>'
            Name                            = $MatchedOrg.Name
            'Total Time Tracked'            = [math]::Round((($Script:Tickets | Where-Object { $_.clientID -eq $Org }).logs.timetracked | Measure-Object -Sum).sum / 60 / 60 , 2)
            'Total Tickets Created'         = ($Script:Tickets | Where-object { $_.clientID -eq $Org } | Measure-Object).count
            'Total Comments by Technicians' = (($Script:Tickets | Where-object { $_.clientID -eq $Org }).Logs | Where-Object { $_.appUserContactUid -in $Script:UserMap.UID } | Measure-Object).count
        }

        $OrgTickets = ($Script:Tickets | Where-Object { $_.clientID -eq $Org }) | Sort-Object 'TotalTime' -Descending

        # Org Tech Time
        [System.Collections.Generic.List[PSCustomObject]]$Script:OrgTechTime = Foreach ($Technician in $Script:UserMap) {
            [PSCustomObject]@{
                Name                             = $Technician.Name
                'Total Time Tracked'             = [math]::Round(((($Script:Tickets | Where-object { $_.clientID -eq $Org }).Logs | Where-Object { $_.appUserContactUid -eq $Technician.UID }).timeTracked | Measure-Object -Sum).sum / 60 / 60, 2)
                'Total Created Tickets Assigned' = ($Script:Tickets | Where-object { $_.assignedAppUserID -eq $Technician.id -and $_.clientID -eq $Org } | Measure-Object).count
                'Total Comments Made'            = (($Script:Tickets | Where-Object { $_.clientID -eq $Org }).Logs | where-object { $_.appUserContactUid -eq $Technician.UID } | measure-object).count
            }
        
        }

        # Time Per Tag
        [System.Collections.Generic.List[PSCustomObject]]$Script:OrgTagsTime = Foreach ($Tag in $Script:Tickets.Tag | Select-Object -unique) {
            [PSCustomObject]@{
                Name                            = $Tag
                'Total Time Tracked'            = [math]::Round((($Script:Tickets | Where-Object { $Tag -in $_.tag -and $_.clientID -eq $Org }).logs.timetracked | Measure-Object -Sum).sum / 60 / 60 , 2)
                'Total Tickets Created'         = ($Script:Tickets | Where-object { $Tag -in $_.tag -and $_.clientID -eq $Org } | Measure-Object).count
                'Total Comments by Technicians' = (($Script:Tickets | Where-object { $Tag -in $_.tag -and $_.clientID -eq $Org }).Logs | Where-Object { $_.appUserContactUid -in $Script:UserMap.UID } | Measure-Object).count
            }
    
        }


        $OrgHTML = Get-NinjaOneOrgCard -OrgTickets $OrgTickets -OrgTechTime $OrgTechTime -OrgTagsTime $OrgTagsTime -OrgID $Org -OrgName $MatchedOrg.Name

        $Script:OrgReportHTML.add($OrgHTML)

    
    }

    Set-NinjaOneChart -ChartName 'OrgTimeChart' -Data ($Script:OrganizationTime | Sort-Object Name) -DataColumn 'Total Time Tracked' -Label 'Hours Tracked'
    Set-NinjaOneChart -ChartName 'OrgCommentsChart' -Data ($Script:OrganizationTime | Sort-Object Name) -DataColumn 'Total Comments by Technicians' -Label 'Comments'

    $Script:OrgTimeHTML = [System.Web.HttpUtility]::HtmlDecode(($OrganizationTime | Sort-Object 'Total Time Tracked' -Descending | ConvertTo-HTML -AS Table -Fragment))

}

Function Get-NinjaOneTagReport {
    # Time Per Tag
    [System.Collections.Generic.List[PSCustomObject]]$Script:TagsTime = Foreach ($Tag in $Script:Tickets.Tag | Select-Object -unique) {
        [PSCustomObject]@{
            Name                            = $Tag
            'Total Time Tracked'            = [math]::Round((($Script:Tickets | Where-Object { $Tag -in $_.tag }).logs.timetracked | Measure-Object -Sum).sum / 60 / 60 , 2)
            'Total Tickets Created'         = ($Script:Tickets | Where-object { $Tag -in $_.tag -and $_.createTime -ge $TargetUnix } | Measure-Object).count
            'Total Comments by Technicians' = (($Script:Tickets | Where-object { $Tag -in $_.tag }).Logs | Where-Object { $_.appUserContactUid -in $Script:UserMap.UID } | Measure-Object).count
        }
    
    }

    Set-NinjaOneChart -ChartName 'TagsTimeChart' -Data ($Script:TagsTime | Sort-Object Name) -DataColumn 'Total Time Tracked' -Label 'Hours Tracked'
    Set-NinjaOneChart -ChartName 'TagsCommentsChart' -Data ($Script:TagsTime | Sort-Object Name) -DataColumn 'Total Comments by Technicians' -Label 'Comments'

    $Script:TagsTimeHTML = $TagsTime | Sort-Object 'Total Time Tracked' -Descending | ConvertTo-HTML -AS Table -Fragment
}



Function Get-NinjaOneUserSelect {
    [System.Collections.Generic.List[PSCustomObject]]$Script:Contents = foreach ( $FoundTech in $Script:Tickets.Logs.appUserContactUid | Where-Object { $_ -notin $Script:UserMapLoaded.UID } | select-object -unique ) {
        $RecentComments = $Script:Tickets.Logs | Where-Object { $_.appUserContactUid -eq $FoundTech } | Sort-Object createTime -Descending | Select-Object -First 10
        $ParsedComments = $RecentComments | ForEach-Object {
            @"
                <p><strong>Ticket ID:</strong> $($_.TicketID) <strong>Time Created:</strong> $(Get-DateFromUnix -UnixTime $_.createTime) <strong>Time Tracked:</strong> $([math]::Round(($_.timeTracked / 60 / 60),2)) hours</p>
                $($_.htmlBody)
                <hr>
"@
        }

        [PSCustomObject]@{
            ID      = $FoundTech
            Content = $ParsedComments -join ''
        } 
    }

    [System.Collections.Generic.List[PSCustomObject]]$Script:TechnicianSelect = @()

    Foreach ($Tech in $Script:Users | Where-Object { $_.userType -eq 'TECHNICIAN' } | Sort-Object firstName) {
        $Script:TechnicianSelect.add([PSCustomObject]@{
                Name  = "$($Tech.firstName) $($Tech.lastName)"
                Value = $Tech.ID
            })

    }


}

function Set-NinjaUserMap ($ID, $UID) {
    $UpdateUserMap = $Script:UserMap | Where-Object { $_.UID -eq $UID }
    $UserDetails = $Script:Users | Where-Object { $_.ID -eq $ID }
    if (($UpdateUserMap | Measure-Object).count -eq 1) {
        $UpdateUserMap.ID = $UserDetails.id
        $UpdateUserMap.Name = "$($UserDetails.firstName) $($UserDetails.lastName)"
        $UpdateUserMap.Email = $UserDetails.email
    }
    else {
        $Script:UserMap.add(
            [PSCustomObject]@{
                ID    = $UserDetails.id
                Name  = "$($UserDetails.firstName) $($UserDetails.lastName)"
                Email = $UserDetails.email
                UID   = $UID
            }
        )
    }
}

function Get-NinjaBarChart ($Data) {
    $Colours = @('55ACBF', '9AB452', '3633B7', 'D8771F', '8063BF')
    $ColourCount = 0
    [System.Collections.Generic.List[String]]$BarHTML = @()
    $BarHTML.add('<table style="width: 33%; margin: 5px; border-radius: 5px; background-color: white; box-sizing: border-box; border-collapse: collapse;">')

    $Max = ($Data | Sort-Object Value -Descending | Select-Object -First 1).value
    
    foreach ($Item in $Data) {
        $ItemColour = $Colours[$ColourCount]
        $ColourCount++
        if ($ColourCount -eq $Colours.Length) {
            $ColourCount = 0
        }
        $BarHTML.add('<tr><td style="padding-right: 10px; vertical-align: middle;">' + $Item.Name + ' - ' + $Item.Value + '</td><td style="min-width:150px"><div style="width: ' + (($Item.Value / $Max) * 100) + '%; height: 20px; background-color: #' + $ItemColour + ';"></div></td></tr>')
    }

    $BarHtml.add('</table>')

    return $BarHTML -Join ''
}

# Function to load content into the WebBrowser
function Get-TechContent {
    $webBrowser.DocumentText = $Script:Contents[$script:currentContentIndex].Content
    $SelectedUser = $Script:Usermap | Where-Object { $_.UID -eq $Script:Contents[$script:currentContentIndex].ID }
    
    $desiredIndex = -1
    for ($i = 0; $i -lt $comboBox.Items.Count; $i++) {
        $item = $comboBox.Items[$i]
        if ($item.Value -eq $SelectedUser.ID) {
            $desiredIndex = $i
            break
        }
    }

    if ($desiredIndex -ne -1) {
        $comboBox.SelectedIndex = $desiredIndex
    }

}

function Get-SummaryContent {
    $comboBox.Visible = $false
    $htmlLabel.Visible = $false
    $selectLabel.Visible = $false
    $nextButton.Visible = $false
    $prevButton.Visible = $false
    $startButton.Visible = $true
    $saveButton.Visible = $true
            

    # Display the summary page
    $summaryHtml = @"
            <html>
            <head>
            <link href='https://fonts.googleapis.com/css?family=Open+Sans' rel='stylesheet'>
                <style>
                    body {
                        font-family: 'Open Sans', sans-serif;
                    }

        /* Basic styles for the Bootstrap table */
        table {
            width: 100%;
            margin-bottom: 1rem;
            background-color: transparent;
        }
        table th, table td {
            padding: 0.75rem;
            vertical-align: top;
            border-top: 1px solid #dee2e6;
        }
        thead th {
            vertical-align: bottom;
            border-bottom: 2px solid #dee2e6;
        }
        tbody + tbody {
            border-top: 2px solid #dee2e6;
        }
        table-striped tbody tr:nth-of-type(odd) {
            background-color: rgba(0, 0, 0, 0.05);
        }
        /* End of Bootstrap table styles */

                </style>
            </head>
            <h1>Summary</h1><hr>
"@
    $summaryHtml += '<table class="table table-striped table-bordered" border=1px style"width: 100%;"">'
    $summaryHtml += "<thead><tr><th>Technician</th><th>No. of Comments</th></tr></thead>"
    $summaryHtml += "<tbody>"



    $Script:UserMap | ForEach-Object {
        $UID = $_.UID
        $summaryHtml += "<tr><td>$($_.Name)</td><td>$(($Script:Tickets.Logs | Where-Object {$_.appUserContactUid -eq $UID} | Measure-Object).count)</td></tr>"
    }

    $summaryHtml += "</tbody></table>"
    $webBrowser.DocumentText = $summaryHtml

    # Optionally, hide the Next and Previous buttons
    $nextButton.Visible = $false
    $prevButton.Visible = $false
        
}

################################################################## Start of Script ##################################################################



$script:epoch = Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0 -Millisecond 0
[System.Collections.Generic.List[String]]$Script:OrgReportHTML = @()
[PSCustomObject]$Script:ChartData = @{}



Add-Type -AssemblyName System.Windows.Forms

[System.Windows.Forms.Application]::EnableVisualStyles()

# Sample HTML contents and their corresponding IDs
$Script:currentContentIndex = 0

$form = New-Object System.Windows.Forms.Form
$form.Text = "NinjaOne Ticketing - Report Generator"
$form.WindowState = [System.Windows.Forms.FormWindowState]::Maximized
$form.BackColor = [System.Drawing.Color]::FromArgb(235, 235, 235) # Light gray background
$form.Font = "Segoe UI, 10"

$screenWidth = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width

# Set the WebBrowser width to 2/3 of the screen's width
$webBrowserWidth = [int][math]::Round($screenWidth * (2 / 3))


$screenHeight = [int][System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height
$webBrowserHeight = [int]($screenHeight - 80)  # Deducting 80 for some margin and space for buttons


# Create the label for the Title
$topLabel = New-Object System.Windows.Forms.Label
$topLabel.Text = "Please map the comments to Technician who made them."
$topLabel.Font = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
$topLabel.Width = 500
$topLabel.Location = New-Object System.Drawing.Point((($screenWidth / 2) - 250 ), 20)
$form.Controls.Add($topLabel)

# Create the label for the HTML content
$htmlLabel = New-Object System.Windows.Forms.Label
$htmlLabel.Text = "Recent comments by techncian:"
$htmlLabel.Width = 200
$htmlLabel.Location = New-Object System.Drawing.Point(20, 40)
$form.Controls.Add($htmlLabel)



# Create the label for the select list
$selectLabel = New-Object System.Windows.Forms.Label
$selectLabel.Text = "Select the techncian:"
$selectLabel.Width = 200
$selectLabel.Location = New-Object System.Drawing.Point(($webBrowserWidth + 40), 70)
$form.Controls.Add($selectLabel)

$webBrowser = New-Object System.Windows.Forms.WebBrowser
$webBrowser.Location = New-Object System.Drawing.Point(20, ($htmlLabel.Bottom + 10))
$webBrowser.Width = $webBrowserWidth
$webBrowser.Height = $webBrowserHeight

# Now, we'll use the calculated width for the WebBrowser control for other components.
$comboBoxWidth = [int]($screenWidth - $webBrowserWidth - 60)

$comboBox = New-Object System.Windows.Forms.ComboBox
$comboBox.Location = New-Object System.Drawing.Point(($webBrowserWidth + 40), ($selectLabel.Bottom + 10))
$comboBox.Width = $comboBoxWidth
$comboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$comboBox.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat




# Adjust 'Next' Button position
$nextButton = New-Object System.Windows.Forms.Button
$nextButtonX = [int]($webBrowserWidth + 40)

$nextButton.Width = $comboBox.Width / 2 - 10
$nextButton.Height = 40
$nextButton.Text = "Next"
$nextButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$nextButton.BackColor = [System.Drawing.Color]::FromArgb(52, 152, 219)
$nextButton.ForeColor = [System.Drawing.Color]::White
$nextButton.Location = New-Object System.Drawing.Point(($webBrowserWidth + $nextButton.Width + 40), 20)

$startButton = New-Object System.Windows.Forms.Button
$startButton.Width = $comboBox.Width / 2 - 10
$startButton.Height = 40
$startButton.Text = "Generate Report"
$startButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$startButton.BackColor = [System.Drawing.Color]::FromArgb(52, 152, 219)
$startButton.ForeColor = [System.Drawing.Color]::White
$startButton.Location = New-Object System.Drawing.Point(($webBrowserWidth + $startButton.Width + 40), 20)

$saveButton = New-Object System.Windows.Forms.Button
$saveButton.Width = $comboBox.Width / 2 - 10
$saveButton.Height = 40
$saveButton.Text = "Save Mapping"
$saveButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$saveButton.BackColor = [System.Drawing.Color]::FromArgb(52, 152, 219)
$saveButton.ForeColor = [System.Drawing.Color]::White
$saveButton.Location = New-Object System.Drawing.Point(($webBrowserWidth + $startButton.Width + 40), 60)

$prevButton = New-Object System.Windows.Forms.Button
$prevButton.Width = [int]($comboBox.Width / 2 - 10)
$prevButton.Height = 40
$prevButton.Text = "Previous"
$prevButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$prevButton.BackColor = [System.Drawing.Color]::FromArgb(52, 152, 219)
$prevButton.ForeColor = [System.Drawing.Color]::White
$prevButton.Location = New-Object System.Drawing.Point($nextButtonX, 20)
$prevButton.Visible = $false


$form.Controls.Add($webBrowser)
$form.Controls.Add($loadButton)
$form.Controls.Add($comboBox)
$form.Controls.Add($nextButton)
$form.Controls.Add($startButton)
$form.Controls.Add($saveButton)
$form.Controls.Add($prevButton)
# ... Initialization and other variables ...

# Create the Login button
$loginButton = New-Object System.Windows.Forms.Button
$loginButton.Text = "Start"
$loginButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$loginButton.BackColor = [System.Drawing.Color]::FromArgb(52, 152, 219)
$loginButton.ForeColor = [System.Drawing.Color]::White
$loginButton.Font = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
$loginButton.Width = 150
$loginButton.Height = 40
$loginButton.Location = New-Object System.Drawing.Point((($form.Width - $loginButton.Width) / 2), (($form.Height - $loginButton.Height) / 2 - 30))
$form.Controls.Add($loginButton)

# Create the Login button
$loadButton = New-Object System.Windows.Forms.Button
$loadButton.Text = "Load Mapping Data"
$loadButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$loadButton.BackColor = [System.Drawing.Color]::FromArgb(52, 152, 219)
$loadButton.ForeColor = [System.Drawing.Color]::White
$loadButton.Font = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
$loadButton.Width = 200
$loadButton.Height = 40
$loadButton.Visible = $True
$form.Controls.Add($loadButton)

# Create a label for status messages
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Width = $form.Width
$statusLabel.Location = New-Object System.Drawing.Point(0, (($form.Height - $statusLabel.Height) / 2))
$statusLabel.Font = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Regular)
$statusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$statusLabel.Visible = $false
$form.Controls.Add($statusLabel)

# Create the From Date Label
$fromDateLabel = New-Object System.Windows.Forms.Label
$fromDateLabel.Text = "From Date:"
$fromDateLabel.AutoSize = $true

$form.Controls.Add($fromDateLabel)

# Create the From Date DateTimePicker
$fromDatePicker = New-Object System.Windows.Forms.DateTimePicker

$fromDatePicker.Format = [System.Windows.Forms.DateTimePickerFormat]::Short

$form.Controls.Add($fromDatePicker)

# Create the To Date Label
$toDateLabel = New-Object System.Windows.Forms.Label
$toDateLabel.Text = "To Date:"
$toDateLabel.AutoSize = $true

$form.Controls.Add($toDateLabel)

# Create the To Date DateTimePicker
$toDatePicker = New-Object System.Windows.Forms.DateTimePicker


$toDatePicker.Format = [System.Windows.Forms.DateTimePickerFormat]::Short

$form.Controls.Add($toDatePicker)


# Last 30 Days Button
$last30DaysButton = New-Object System.Windows.Forms.Button
$last30DaysButton.Text = "Last 30 Days"
$last30DaysButton.Width = 160
$last30DaysButton.Add_Click({
        $fromDatePicker.Value = (Get-Date).AddDays(-30)
        $toDatePicker.Value = Get-Date
    })
$form.Controls.Add($last30DaysButton)

# Last Calendar Month Button
$lastCalMonthButton = New-Object System.Windows.Forms.Button
$lastCalMonthButton.Text = "Last Calendar Month"
$lastCalMonthButton.Width = 160
$lastCalMonthButton.Add_Click({
        $fromDatePicker.Value = (Get-Date).AddMonths(-1).Date.AddDays( - (Get-Date).Day + 1)
        $toDatePicker.Value = (Get-Date).Date.AddDays( - (Get-Date).Day)
    })
$form.Controls.Add($lastCalMonthButton)

# Last 90 Days Button
$last90DaysButton = New-Object System.Windows.Forms.Button
$last90DaysButton.Text = "Last 90 Days"
$last90DaysButton.Width = 160
$last90DaysButton.Add_Click({
        $fromDatePicker.Value = (Get-Date).AddDays(-90)
        $toDatePicker.Value = Get-Date
    })
$form.Controls.Add($last90DaysButton)

# Last 3 Calendar Months Button
$last3CalMonthsButton = New-Object System.Windows.Forms.Button
$last3CalMonthsButton.Text = "Last 3 Calendar Months"
$last3CalMonthsButton.Width = 160
$last3CalMonthsButton.Add_Click({
        $fromDatePicker.Value = (Get-Date).AddMonths(-3).Date.AddDays( - (Get-Date).Day + 1)
        $toDatePicker.Value = (Get-Date).Date.AddDays( - (Get-Date).Day)
    })
$form.Controls.Add($last3CalMonthsButton)

# Create the title label
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "NinjaOne Ticketing - Report Generator"
$titleLabel.AutoSize = $false

$titleLabel.Height = 120

$titleLabel.Font = New-Object System.Drawing.Font("Arial", 24, [System.Drawing.FontStyle]::Bold)
$titleLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter

# Add the label to the form
$form.Controls.Add($titleLabel)

# Initially hide the HTML content and select list
$webBrowser.Visible = $false
$comboBox.Visible = $false
$htmlLabel.Visible = $false
$selectLabel.Visible = $false
$nextButton.Visible = $false
$prevButton.Visible = $false
$topLabel.Visible = $false
$startButton.Visible = $false
$saveButton.Visible = $false

$loginButton.Add_Click({
        

        # Adjust the status label location
        $statusLabel.Location = New-Object System.Drawing.Point(0, (($form.Height - $statusLabel.Height) / 2))
        $statusLabel.Width = $form.Width
        # Hide the Login button
        $loginButton.Visible = $false
        $fromDateLabel.Visible = $false
        $fromDatePicker.Visible = $false
        $toDateLabel.Visible = $false
        $toDatePicker.Visible = $false
        $last30DaysButton.Visible = $false
        $lastCalMonthButton.Visible = $false
        $last90DaysButton.Visible = $false
        $last3CalMonthsButton.Visible = $false
        $loadButton.Visible = $false

        $statusLabel.Visible = $true

        # Display "Logging in..." status
        $statusLabel.Text = "Logging in..."
        Connect-NinjaOne

        $Script:FromDate = Get-Date($fromDatePicker.Value) -Format 'yyyy-MM-dd'
        $Script:ToDate = Get-Date($toDatePicker.Value)  -Format 'yyyy-MM-dd'

        $Script:FromUnix = Get-UnixTimeFromDate -Date (Get-Date($fromDatePicker.Value)).Date
        $Script:ToUnix = Get-UnixTimeFromDate -Date (Get-Date($toDatePicker.Value)).Date.AddHours(23).AddMinutes(59).AddSeconds(59)

        $statusLabel.Text = "Fetching Contacts"
        $Script:Contacts = Get-NinjaRequest -Path "/v2/ticketing/contact/contacts" -Method GET
        
        $statusLabel.Text = "Fetching Users"
        $Script:Users = Get-NinjaRequest -Path "/v2/users" -Method GET

        $statusLabel.Text = "Fetching Organizations"
        $Script:Orgs = Get-NinjaRequest -Path "/v2/organizations" -Method GET

        $statusLabel.Text = "Fetching Tickets and Comments (Check PowerShell Console for Progress)"
        Get-NinjaOneTickets -FromUnix $Script:FromUnix -ToUnix $Script:ToUnix

        $statusLabel.Text = "Mapping Users"
        Invoke-NinjaOneUserMapping
        Get-NinjaOneUserSelect
        
        $comboBox.DisplayMember = "Name"
        $comboBox.ValueMember = "Value"
        $comboBox.Items.AddRange($Script:TechnicianSelect)
        
        
        # Hide the loading indicator and status label
        $statusLabel.Visible = $false
       
        $titleLabel.Visible = $false
 
        # Show the HTML content and select list
        $webBrowser.Visible = $true
        $comboBox.Visible = $true
        $htmlLabel.Visible = $true
        $selectLabel.Visible = $true
        $nextButton.Visible = $true
        $prevButton.Visible = $false
        $topLabel.Visible = $true
        
        $Script:ContentCount = ($Script:contents | Measure-Object).count

        if ($Script:ContentCount -ne 0 ) {
            Get-TechContent
        }
        else {
            Get-SummaryContent
        }
       
    })



$startButton.Add_Click({
        Write-Host 'Generating Report'
        Get-NinjaOneTechnicianReport
        Get-NinjaOneOrganizationReport
        Get-NinjaOneTagReport
        $Script:TechTimeChart = Get-NinjaBarChart -Data ($Script:TechTime | Select-Object name, @{n = 'Value'; e = { $_.'Total Time Tracked' } })
        Get-NinjaOneHTML
        Invoke-Item $Output_File
        $form.Close()
    })

$saveButton.Add_Click({
        # Create SaveFileDialog
        $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveFileDialog.FileName = "NinjaTicketingUserMapping.json"
        $saveFileDialog.Filter = "Json Files (*.json)|*.json"
        $result = $saveFileDialog.ShowDialog()

        # Check if user clicked 'OK'
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            $selectedPath = $saveFileDialog.FileName
            $Script:UserMap | ConvertTo-Json | Out-File $selectedPath
            $saveButton.Text = "Saved"
        }
    })

$loadButton.Add_Click({
        # Create OpenFileDialog
        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $openFileDialog.Filter = "Json Files (*.json)|*.json"
        $openFileDialog.Multiselect = $false

        # Show OpenFileDialog and get result
        $result = $openFileDialog.ShowDialog()

        # Check if user clicked 'OK'
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            $Script:selectedFilePath = $openFileDialog.FileName
            [System.Collections.Generic.List[PSCustomObject]]$Script:UserMapLoaded = Get-Content $selectedFilePath | ConvertFrom-Json
            $loadButton.Text = "Loaded"
        }
    })



$nextButton.Add_Click({
        if ($null -eq $comboBox.SelectedItem) {
            # Show a warning message if no option is selected
            [System.Windows.Forms.MessageBox]::Show("Please select a technician before proceeding.", "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }


        Set-NinjaUserMap -UID $Script:Contents[$script:currentContentIndex].ID -ID $comboBox.SelectedItem.value

        $script:currentContentIndex++
    
        # If there's another content set, load it, otherwise close the form
        if ($script:currentContentIndex -lt $Script:contents.Count) {
            Get-TechContent
        }
        else {
            Get-SummaryContent
        }

        if ($currentContentIndex -gt 0) {
            $prevButton.Visible = $true
        }
    })

$prevButton.Add_Click({

        Set-NinjaUserMap -UID $Script:Contents[$script:currentContentIndex].ID -ID $comboBox.SelectedItem.value

        if ($script:currentContentIndex -gt 0) {
            $script:currentContentIndex--
            Get-TechContent
        }
        if ($script:currentContentIndex -eq 0) {
            $prevButton.Visible = $false
        }
        $nextButton.Visible = $true
        # Show the HTML content and select list
        $webBrowser.Visible = $true
        
        $htmlLabel.Visible = $true
        $selectLabel.Visible = $true
        $comboBox.Visible = $true
        $topLabel.Visible = $true
        $startButton.Visible = $false
    })


$form.Add_Load({
        # Set the Location to center the button in the form

        $fromDatePicker.Location = New-Object System.Drawing.Point((($form.Width - $fromDatePicker.Width) / 2), (($form.Height / 2) - 80))
        $toDatePicker.Location = New-Object System.Drawing.Point((($form.Width - $toDatePicker.Width) / 2), (($form.Height / 2) - 50))
        $toDateLabel.Location = New-Object System.Drawing.Point((($form.Width - $toDateLabel.Width) / 2 - $toDatePicker.Width - 10), (($form.Height / 2) - 50))
        $fromDateLabel.Location = New-Object System.Drawing.Point((($form.Width - $fromDateLabel.Width) / 2 - $fromDatePicker.Width - 10), (($form.Height / 2) - 80))
        $loginButton.Location = New-Object System.Drawing.Point((($form.Width - $loginButton.Width) / 2), (($toDatePicker.bottom + 10)))
        $loadButton.Location = New-Object System.Drawing.Point((($form.Width - $loadButton.Width) / 2), (($loginButton.bottom + 10)))

        $DateButtonsWidth = ($form.Width - 175) / 2
        $last30DaysButton.Location = New-Object System.Drawing.Point(($DateButtonsWidth - 255), ($fromDatePicker.top - $last30DaysButton.Height - 10))
        $lastCalMonthButton.Location = New-Object System.Drawing.Point(($DateButtonsWidth - 85), ($fromDatePicker.top - $lastCalMonthButton.Height - 10))
        $last90DaysButton.Location = New-Object System.Drawing.Point(($DateButtonsWidth + 85), ($fromDatePicker.top - $last90DaysButton.Height - 10))
        $last3CalMonthsButton.Location = New-Object System.Drawing.Point(($DateButtonsWidth + 255), ($fromDatePicker.top - $last3CalMonthsButton.Height - 10))

        $titleLabel.Width = $form.Width
        $titleLabel.Location = New-Object System.Drawing.Point(0, 30)  # Adjust the Y-coordinate for your desired position
    })

# Initial load


$form.ShowDialog()


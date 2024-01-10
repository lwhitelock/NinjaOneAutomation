try {  

    $NinjaOneInstance = Ninja-Property-Get ninjaoneInstance
    $NinjaOneClientID = Ninja-Property-Get ninjaoneClientId
    $NinjaOneClientSecret = Ninja-Property-Get ninjaoneClientSecret

    ######  Configure mode #######
    # LASTDAYS - Will generate a report for the last x days 
    #$Mode = 'LASTDAYS'
    #$Lastdays = 360

    # LAST30 - Will generate reports for the last 30 days
    $Mode = 'LAST30'

    # LASTCALENDARMONTH - Will Generate a reports for the last calendar month
    # $Mode = 'LASTCALENDARMONTH'

    # LAST90DAYS - Will generate reports using the last 90 days.
    # $Mode = 'LAST90DAYS'

    # LAST3CALENDARMONTHS - Will generate reports for the last 3 calendar months.
    # $Mode = 'LAST3CALENDARMONTHS'

    # CUSTOM - Lets you specify a custom date range
    # $Mode = 'CUSTOM'
    # $StartDate = '2023-12-01'
    # $EndDate = '2023-12-21'

    ####### Settings #######

    # Set the board ID to fetch tickets from. By default 2 is the All Tickets Board. 
    # Please make sure the board you select has Ticket ID, Last Updated, and Tracked Time fields enabled.
    $Script:BoardID = 2

    # Set if you want reports to be generated to a custom field.
    $OutputToCustomField = $True
    $CustomFieldName = 'ticketingReports'

    # Set the name of the organization you would like global reports populated to.
    $GlobalReportOrg = 'Global Overview'

    # Set the location for the ticketing report to be saved. By default it will be saved to the folder where
    # the script is run, with the current date appended.
    $OutputToFile = $False
    $Date = Get-Date -Format "yyyy-MM-dd"
    $Output_File = "C:\Temp\$($Date)_Ticketing_Report.html"


    ####### End Settings #######
    $ScriptStart = Get-Date

    # Disable progress bars to increase speed.
    $ProgressPreference = 'SilentlyContinue'

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

        $AllTickets = Invoke-NinjaOneRequest -Path "ticketing/trigger/board/$Script:BoardID/run" -Method POST -Body $Script:Ticketsearch

        Return $AllTickets

    }

    Function Get-NinjaOneTickets($FromUnix, $ToUnix) {
        $Found = $False
        $LastCursor = 0
    

        [System.Collections.Generic.List[PSCustomObject]]$Script:TicketsList = do {
            $FetchedTickets = Get-NinjaTickets -LastCursor $LastCursor -PageSize 1000
            if (($FetchedTickets.data[-1].lastUpdated -lt $FromUnix) -or (($FetchedTickets.data | Measure-Object).count -eq 0)) {
                $Found = $True
            } else {
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
            $Ticket = Invoke-NinjaOneRequest -Path "ticketing/ticket/$($TicketItem.id)" -Method GET
            if ($TicketItem.totalTimeTracked -gt 0) {
                $TicketLogs = Invoke-NinjaOneRequest -Path "ticketing/ticket/$($TicketItem.id)/log-entry" -Method GET
            } else {
                $TicketLogs = $null
            }
    
            [PSCustomObject]@{
                TicketID          = '<a href="https://' + $NinjaOneInstance + '/#/ticketing/ticket/' + $Ticket.ID + '">' + $Ticket.ID + '</a>'
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
                Logs              = $TicketLogs | Where-Object { $null -ne $_.appUserContactUid -and $_.type -in @('COMMENT', 'DESCRIPTION') -and $null -ne $_.timeTracked -and $_.createTime -ge $FromUnix -and $_.createTime -le $ToUnix } | Select-Object * , @{n = 'ticketID'; e = { $Ticket.ID } }
                TotalTime         = [math]::Round((($TicketLogs | Where-Object { $_.timeTracked -gt 0 -and $_.createTime -ge $FromUnix -and $_.createTime -le $ToUnix }).timeTracked | Measure-Object -sum).sum / 60 / 60, 2)
            }

            #Write-Progress -PercentComplete (($ProcessedTicketCount / $TotalFilteredTickets) * 100) -Status "Processing" -Activity "$ProcessedTicketCount / $TotalFilteredTickets Tickets Complete"
        }

        Write-Host "Processing Tickets Complete"
    
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

    function Get-ChartData {
        param (
            $Data,
            $LabelColumn,
            $AmountColumn
        )

        [System.Collections.Generic.List[PSCustomObject]]$ReturnData = @()
        $Colours = Get-NinjaOneColours -NumColours ($Data | Measure-Object).count
        $Index = 0

        foreach ($Item in $Data) {
            $ReturnData.add([PSCustomObject]@{
                    Label  = $Item."$LabelColumn"
                    Amount = $Item."$AmountColumn"
                    Colour = $Colours[$Index]
                })

            $Index++
        }

        Return $ReturnData

    }

    Function Get-NinjaOneTechnicianReport {
        [System.Collections.Generic.List[PSCustomObject]]$Script:TechTime = $( Foreach ($Technician in ($Users | Where-Object { $_.userType -eq 'TECHNICIAN' })) {
                [PSCustomObject]@{
                    Name                             = "$($Technician.FirstName) $($Technician.LastName)"
                    'Total Time Tracked'             = [math]::Round((($Script:Tickets.Logs | Where-Object { $_.appUserContactID -eq $Technician.id -and $_.appUserContactType -eq 'TECHNICIAN' }).timeTracked | Measure-Object -Sum).sum / 60 / 60, 2)
                    'Total Created Tickets Assigned' = ($Script:Tickets | Where-object { $_.assignedAppUserID -eq $Technician.id } | Measure-Object).count
                    'Total Comments Made'            = ($Script:Tickets.Logs | where-object { $_.appUserContactId -eq $Technician.ID -and $_.appUserContactType -eq 'TECHNICIAN' } | measure-object).count
                }
        
            } ) | Where-Object { $_.'Total Time Tracked' -gt 0 -or $_.'Total Tickets Created' -gt 0 -or $_.'Total Comments by Technicians' }


        $TechTimeData = Get-ChartData -Data $Script:TechTime -LabelColumn 'Name' -AmountColumn 'Total Time Tracked'
        $TechCommentData = Get-ChartData -Data $Script:TechTime -LabelColumn 'Name' -AmountColumn 'Total Comments Made'
    
        $TechTimeChart = Get-NinjaBarGraph -Data $TechTimeData -Title 'Technician Time Tracked' -NoKey -Icon 'far fa-clock'
        $TechCommentChart = Get-NinjaBarGraph -Data $TechCommentData -Title 'Technician Total Comments' -NoKey 'far fa-comments'
        $TechTimeHTML = $TechTime | Sort-Object 'Total Time Tracked' -Descending | ConvertTo-HTML -AS Table -Fragment

        $TechnicianReportHTML = @"
    <div>$TechTimeChart</div>
    <div>$TechCommentChart</div>
    <div>$TechTimeHTML</div>
"@

        return $TechnicianReportHTML

    }

    Function Get-NinjaOneOrganizationReport {
    
        # Time Per Organization
        # Time By Techncian Report
        [System.Collections.Generic.List[PSCustomObject]]$Script:OrganizationTime = Foreach ($Org in $Script:Tickets.clientID | Select-Object -unique) {
            $MatchedOrg = $Script:Organizations | Where-Object { $_.id -eq $Org }

            [PSCustomObject]@{
                #Name                            = '<a href="#client-' + $Org + '">' + $MatchedOrg.Name + '</a>'
                Name                            = '<a href="https://' + $NinjaOneInstance + '/#/customerDashboard/' + $Org + '/customFields">' + $MatchedOrg.Name + '</a>'
                'Total Time Tracked'            = [math]::Round((($Script:Tickets | Where-Object { $_.clientID -eq $Org }).logs.timetracked | Measure-Object -Sum).sum / 60 / 60 , 2)
                'Total Tickets Created'         = ($Script:Tickets | Where-object { $_.clientID -eq $Org } | Measure-Object).count
                'Total Comments by Technicians' = (($Script:Tickets | Where-object { $_.clientID -eq $Org }).Logs | Where-Object { $_.appUserContactId -in $Users.ID -and $_.appUserContactType -eq 'TECHNICIAN' } | Measure-Object).count
            }

            $OrgTickets = ($Script:Tickets | Where-Object { $_.clientID -eq $Org }) | Sort-Object 'TotalTime' -Descending

            # Org Tech Time
            [System.Collections.Generic.List[PSCustomObject]]$Script:OrgTechTime = $(Foreach ($Technician in ($Users | Where-Object { $_.userType -eq 'TECHNICIAN' })) {
                    [PSCustomObject]@{
                        Name                             = "$($Technician.FirstName) $($Technician.LastName)"
                        'Total Time Tracked'             = [math]::Round(((($Script:Tickets | Where-object { $_.clientID -eq $Org }).Logs | Where-Object { $_.appUserContactId -eq $Technician.ID -and $_.appUserContactType -eq 'TECHNICIAN' }).timeTracked | Measure-Object -Sum).sum / 60 / 60, 2)
                        'Total Created Tickets Assigned' = ($Script:Tickets | Where-object { $_.assignedAppUserID -eq $Technician.id -and $_.clientID -eq $Org } | Measure-Object).count
                        'Total Comments Made'            = (($Script:Tickets | Where-Object { $_.clientID -eq $Org }).Logs | where-object { $_.appUserContactId -eq $Technician.ID -and $_.appUserContactType -eq 'TECHNICIAN' } | measure-object).count
                    }
        
                } ) | Where-Object { $_.'Total Time Tracked' -gt 0 -or $_.'Total Tickets Created' -gt 0 -or $_.'Total Comments by Technicians' }

            # Time Per Tag
            [System.Collections.Generic.List[PSCustomObject]]$Script:OrgTagsTime = $(Foreach ($Tag in $Script:Tickets.Tag | Select-Object -unique) {
                    [PSCustomObject]@{
                        Name                            = $Tag
                        'Total Time Tracked'            = [math]::Round((($Script:Tickets | Where-Object { $Tag -in $_.tag -and $_.clientID -eq $Org }).logs.timetracked | Measure-Object -Sum).sum / 60 / 60 , 2)
                        'Total Tickets Created'         = ($Script:Tickets | Where-object { $Tag -in $_.tag -and $_.clientID -eq $Org } | Measure-Object).count
                        'Total Comments by Technicians' = (($Script:Tickets | Where-object { $Tag -in $_.tag -and $_.clientID -eq $Org }).Logs | Where-Object { $_.appUserContactId -in $Users.ID -and $_.appUserContactType -eq 'TECHNICIAN' } | Measure-Object).count
                    }
    
                } ) | Where-Object { $_.'Total Time Tracked' -gt 0 -or $_.'Total Tickets Created' -gt 0 -or $_.'Total Comments by Technicians' }

            $TopTicketsData = Get-ChartData -Data ($OrgTickets | Select-Object -First 15) -AmountColumn 'TotalTime' -LabelColumn 'TicketID'
            $TopTechTimeData = Get-ChartData -Data ($OrgTechTime | Sort-Object Name) -AmountColumn 'Total Time Tracked' -LabelColumn 'Name'
            $TopTechCommentsData = Get-ChartData -Data ($OrgTechTime | Sort-Object Name) -AmountColumn 'Total Comments Made' -LabelColumn 'Name'
            $TopTagTimeData = Get-ChartData -Data ($OrgTagsTime | Sort-Object Name) -AmountColumn 'Total Time Tracked' -LabelColumn 'Name'
            $TopTagCommentData = Get-ChartData -Data ($OrgTagsTime | Sort-Object Name) -AmountColumn 'Total Comments by Technicians' -LabelColumn 'Name'

            $TopTicketsChart = Get-NinjaInLineBarGraph -Data $TopTicketsData -Title 'Top 15 Tickets by Time' -KeyInLine -Icon 'far fa-clock'
            $TopTechTimeChart = Get-NinjaBarGraph -Data $TopTechTimeData -Title 'Technician Time Tracked' -NoKey -Icon 'far fa-clock'
            $TopTechCommentsChart = Get-NinjaBarGraph -Data $TopTechCommentsData -Title 'Technician Comments Made' -NoKey -Icon 'far fa-comments'
            $TopTagTimeChart = Get-NinjaBarGraph -Data $TopTagTimeData -Title 'Tags Time Tracked' -NoKey -Icon 'far fa-clock'
            $TopTagCommentChart = Get-NinjaBarGraph -Data $TopTagCommentData -Title 'Tags Commments Made' -NoKey -Icon 'far fa-comments'

            $TopTicketsHTML = Get-NinjaOneCard -Title 'Top Tickets Summary' -Icon 'fas fa-ticket' -Body "<div>$TopTicketsChart</div><div>$($OrgTickets | Select-Object TicketID, Subject, Status, TotalTime -First 15 | ConvertTo-Html -As Table -Fragment)</div>" 
            $TechHTML = Get-NinjaOneCard -Title 'Technican Summary' -Icon 'fas fa-users' -Body "<div>$TopTechTimeChart</div><div>$TopTechCommentsChart</div><div>$($OrgTechTime | Sort-Object 'Total Time Tracked' -Descending | select-object -First 10 | ConvertTo-Html -As Table -Fragment)</div>" 
            $TagsHTML = Get-NinjaOneCard -Title 'Tag Summary' -Icon 'fas fa-tags' -Body "<div>$TopTagTimeChart</div><div>$TopTagCommentChart</div><div>$($OrgTagsTime | Sort-Object 'Total Time Tracked' -Descending | Select-object -First 10 | ConvertTo-Html -As Table -Fragment)</div>" 

            [System.Collections.Generic.List[PSCustomObject]]$WidgetData = @()
            $WidgetData.add([PSCustomObject]@{
                    Value       = ($OrgTickets | Measure-Object).count
                    Description = 'Total Tickets'
                    Colour      = '#337AB7'
                })

            $WidgetData.add([PSCustomObject]@{
                    Value       = [math]::Round((($OrgTickets).logs.timetracked | Measure-Object -Sum).sum / 60 / 60 , 2)
                    Description = 'Total Tech Hours'
                    Colour      = '#337AB7'
                })
            $WidgetData.add([PSCustomObject]@{
                    Value       = (($OrgTickets).Logs | where-object { $_.appUserContactType -eq 'TECHNICIAN' } | measure-object).count
                    Description = 'Total Tech Comments'
                    Colour      = '#337AB7'
                })

        

            $OrgTicketSummaryWidgetsHTML = (Get-NinjaOneWidgetCard -Data $WidgetData -SmallCols 2 -MedCols 2 -LargeCols 3 -XLCols 3 -NoCard)

            $OrgSummaryHTML = Get-NinjaOneCard -Title "Ticketing Report - $Start to $End" -Icon 'fas fa-ticket' -Body $OrgTicketSummaryWidgetsHTML 
        
            $OrgHTML = @"
        <div class="row g-3">
        <div class="col-12 d-flex">$OrgSummaryHTML</div>
        <div class="col-12 d-flex">$TopTicketsHTML</div>
        <div class="col-12 d-flex">$TechHTML</div>
        <div class="col-12 d-flex">$TagsHTML</div>
        </div>
"@

            if ($OutputToFile -eq $True) {
                $OrgCard = Get-NinjaOneCard -Title "$($MatchedOrg.Name) Report" -Icon 'fas fa-building' -Body $OrgHTML
                $Script:OrganizationHTML.add($OrgCard)
            }
        
            if ($OutputToCustomField -eq $True) {
                $UpdateBody = @{
                    "$CustomFieldName" = @{ 'html' = [System.Web.HttpUtility]::HtmlDecode($OrgHTML) }
                }
                $Null = Invoke-NinjaOneRequest -Method PATCH -Path "organization/$($Org)/custom-fields" -InputObject $UpdateBody
            }
    
        }

        $OrgTimeTrackedData = Get-ChartData -Data ($Script:OrganizationTime | Sort-Object Name) -AmountColumn 'Total Time Tracked' -LabelColumn 'Name'
        $OrgCommentsTrackedData = Get-ChartData -Data ($Script:OrganizationTime | Sort-Object Name) -AmountColumn 'Total Comments by Technicians' -LabelColumn 'Name'

        $OrgTimeTrackedChart = Get-NinjaInLineBarGraph -Data $OrgTimeTrackedData -Title 'Organizations by Time Tracked' -KeyInLine -Icon 'far fa-clock'
        $OrgCommentsTrackedChart = Get-NinjaInLineBarGraph -Data $OrgCommentsTrackedData -Title 'Organizations by Comments' -KeyInLine -Icon 'far fa-comments'
        $GlobalOrgTimeHTML = $OrganizationTime | Sort-Object 'Total Time Tracked' -Descending | ConvertTo-HTML -AS Table -Fragment

        $GlobalOrgHTML = @"
        <div>$OrgTimeTrackedChart</div>
        <div>$OrgCommentsTrackedChart</div>
        <div>$GlobalOrgTimeHTML</div>
"@

        return $GlobalOrgHTML

    }

    Function Get-NinjaOneTagReport {
        # Time Per Tag
        [System.Collections.Generic.List[PSCustomObject]]$Script:TagsTime = $(Foreach ($Tag in $Script:Tickets.Tag | Select-Object -unique) {
                [PSCustomObject]@{
                    Name                            = $Tag
                    'Total Time Tracked'            = [math]::Round((($Script:Tickets | Where-Object { $Tag -in $_.tag }).logs.timetracked | Measure-Object -Sum).sum / 60 / 60 , 2)
                    'Total Tickets Created'         = ($Script:Tickets | Where-object { $Tag -in $_.tag -and $_.createTime -ge $TargetUnix } | Measure-Object).count
                    'Total Comments by Technicians' = (($Script:Tickets | Where-object { $Tag -in $_.tag }).Logs | Where-Object { $_.appUserContactId -in $Users.ID -and $_.appUserContactType -eq 'TECHNICIAN' } | Measure-Object).count
                }
    
            }) | Where-Object { $_.'Total Time Tracked' -gt 0 -or $_.'Total Tickets Created' -gt 0 -or $_.'Total Comments by Technicians' }

        $TagTimeTrackedData = Get-ChartData -Data ($Script:TagsTime | Sort-Object Name) -AmountColumn 'Total Time Tracked' -LabelColumn 'Name'
        $TagCommentsTrackedData = Get-ChartData -Data ($Script:TagsTime | Sort-Object Name) -AmountColumn 'Total Comments by Technicians' -LabelColumn 'Name'

        $TagTimeTrackedChart = Get-NinjaBarGraph -Data $TagTimeTrackedData -Title 'Tags by Time Tracked' -NoKey -Icon 'far fa-clock'
        $TagCommentsTrackedChart = Get-NinjaBarGraph -Data $TagCommentsTrackedData -Title 'Tags by Comments' -NoKey -Icon 'far fa-comments'
        $TagsTimeHTML = $TagsTime | Sort-Object 'Total Time Tracked' -Descending | ConvertTo-HTML -AS Table -Fragment

        $TagsReportHTML = @"
    <div>$TagTimeTrackedChart</div>
    <div>$TagCommentsTrackedChart</div>
    <div>$TagsTimeHTML</div>
"@

        return $TagsReportHTML
        
    }

    if (!(Get-Module -Name "NinjaOneDocs")) {
        $Null = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        Install-Module -Name 'NinjaOneDocs' -Force -RequiredVersion 1.6.0 -Scope CurrentUser
        Import-Module 'NinjaOneDocs'
    } else {
        Update-Module NinjaOneDocs -RequiredVersion 1.6.0 -Force
        Import-Module 'NinjaOneDocs'
    }


    Switch ($Mode) {
        'LASTDAYS' {
            $StartUnix = Get-NinjaOneTime -Seconds -Date ((Get-Date).AddDays(-$Lastdays))
            $EndUnix = Get-NinjaOneTime -Seconds -Date (Get-Date)
        }
        'LAST30' {
            $StartUnix = Get-NinjaOneTime -Seconds -Date ((Get-Date).AddDays(-30))
            $EndUnix = Get-NinjaOneTime -Seconds -Date (Get-Date)
        }
        'LASTCALENDARMONTH' { 
            $StartUnix = Get-NinjaOneTime -Seconds -Date ((Get-Date).AddMonths(-1).Date.AddDays( - (Get-Date).Day + 1))
            $EndUnix = Get-NinjaOneTime -Seconds -Date ((Get-Date).Date.AddDays( - (Get-Date).Day))
        }
        'LAST90DAYS' { 
            $StartUnix = Get-NinjaOneTime -Seconds -Date ((Get-Date).AddDays(-90))
            $EndUnix = Get-NinjaOneTime -Seconds -Date (Get-Date)
        }
        'LAST3CALENDARMONTHS' {
            $StartUnix = Get-NinjaOneTime -Seconds -Date ((Get-Date).AddMonths(-3).Date.AddDays( - (Get-Date).Day + 1))
            $EndUnix = Get-NinjaOneTime -Seconds -Date ((Get-Date).Date.AddDays( - (Get-Date).Day))
        }
        'CUSTOM' {
            $StartUnix = Get-NinjaOneTime -Seconds -Date ((Get-Date($StartDate)))
            $EndUnix = Get-NinjaOneTime -Seconds -Date (Get-Date($EndDate))
        }
        default {
            Throw 'Unknown Mode'
        }
    }

    $Start = (Get-TimeFromNinjaOne -Date $StartUnix -Seconds).ToString("yyyy-MM-dd")
    $End = (Get-TimeFromNinjaOne -Date $EndUnix -Seconds).ToString("yyyy-MM-dd")

    Connect-NinjaOne -NinjaOneInstance $NinjaOneInstance -NinjaOneClientID $NinjaOneClientID -NinjaOneClientSecret $NinjaOneClientSecret

    $Users = Invoke-NinjaOneRequest -Path 'users' -Method GET -Paginate
    $Script:Organizations = Invoke-NinjaOneRequest -Path 'organizations' -Method GET -Paginate

    Get-NinjaOneTickets -FromUnix $StartUnix -ToUnix $EndUnix

    $TechReportHTML = Get-NinjaOneTechnicianReport
    $TechnicianHTML = Get-NinjaOneCard -Title 'Technician Summary' -Icon 'fas fa-users' -Body $TechReportHTML 

    [System.Collections.Generic.List[string]]$Script:OrganizationHTML = @()

    $GlobalOrgReportHTML = Get-NinjaOneOrganizationReport
    $GlobalOrgHTML = Get-NinjaOneCard -Title 'Organization Summary' -Icon 'fas fa-building' -Body $GlobalOrgReportHTML 

    $TagsReportHTML = Get-NinjaOneTagReport
    $TagsHTML = Get-NinjaOneCard -Title 'Tags Summary' -Icon 'fas fa-tags' -Body $TagsReportHTML 

    $GlobalOrg = $Script:Organizations | where-object { $_.name -eq $GlobalReportOrg }

    [System.Collections.Generic.List[PSCustomObject]]$WidgetData = @()
    $WidgetData.add([PSCustomObject]@{
            Value       = ($Tickets | Measure-Object).count
            Description = 'Total Tickets'
            Colour      = '#337AB7'
        })

    $WidgetData.add([PSCustomObject]@{
            Value       = [math]::Round((($Script:Tickets).logs.timetracked | Measure-Object -Sum).sum / 60 / 60 , 2)
            Description = 'Total Tech Hours'
            Colour      = '#337AB7'
        })
    $WidgetData.add([PSCustomObject]@{
            Value       = (($Script:Tickets).Logs | where-object { $_.appUserContactType -eq 'TECHNICIAN' } | measure-object).count
            Description = 'Total Tech Comments'
            Colour      = '#337AB7'
        })

    $TicketSummaryWidgetsHTML = (Get-NinjaOneWidgetCard -Data $WidgetData -SmallCols 2 -MedCols 2 -LargeCols 3 -XLCols 3 -NoCard)

    $SummaryHTML = Get-NinjaOneCard -Title "Ticketing Report - $Start to $End" -Icon 'fas fa-ticket' -Body $TicketSummaryWidgetsHTML 

    $OutputHTML = [System.Web.HttpUtility]::HtmlDecode('<div class="row g-3"><div class="col-12  d-flex">' + $SummaryHTML + '</div><div class="col-12  d-flex">' + $TechnicianHTML + '</div><div class="col-12 d-flex">' + $GlobalOrgHTML + '</div><div class="col-12 d-flex">' + $TagsHTML + '</div></div>')

    if ($OutputToCustomField -eq $True) {
        if (($GlobalOrg | Measure-Object).count -eq 1) {

            $UpdateBody = @{
                "$CustomFieldName" = @{ 'html' = $OutputHTML }
            }

            $Null = Invoke-NinjaOneRequest -Method PATCH -Path "organization/$($GlobalOrg.id)/custom-fields" -InputObject $UpdateBody
        } else {
            Write-Error "Could not match $($GlobalReportOrg) to a single organization"
        }

    }

    $FileHtml = @"
    <html>
    <head>
          <meta charset="utf-8">
          <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Inter">
          <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" integrity="sha512-DTOQO9RWCH3ppGqcWaEA1BIZOC6xxalwEsw9c2QQeAIftl+Vegovlnee1c9QX4TctnWMn13TZye+giMm8e2LwA==" crossorigin="anonymous" referrerpolicy="no-referrer" />
          <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.1/css/bootstrap-grid.min.css" integrity="sha512-2cWcZ9cbPMZFm2inlFOhwsBVbNMmNxKBtVXqL8OY9tXCZahhnIfXMxPCzpKqiHF2I2mOiNHNXEDUDglwd+4uYw==" crossorigin="anonymous" referrerpolicy="no-referrer" />
          <title>Ticketing Report</title>
        <style>
          
  body {
    margin: 0;
    background-color: transparent;
    word-break: break-word;
    font-family: inter, sans-serif;
  }

  *,
  ::after,
  ::before {
    box-sizing: border-box;
  }

  img {
    max-width: 100%;
    height: auto;
  }

  h1,
  h2 {
    margin-top: 10px;
  }

  blockquote {
    padding: 10px 20px;
    margin: 0 0 10px;
    border-left: 5px solid #EEEEEE;
    white-space: pre-wrap;
    overflow-wrap: break-word;
    word-break: break-word;
  }

  ol,
  ul {
    list-style-type: revert;
  }

  p,
  ul,
  li {
    color: #151617;
    font-size: 14px;
    font-weight: 400;
    word-wrap: break-word;
  }

  ul.unstyled {
    list-style-type: none;
    padding: 0;
    margin: 0;
  }

  h1 {
    color: #151617;
    font-size: 24px;
    font-weight: 600;
    word-wrap: break-word;
  }

  h2 {
    color: #151617;
    font-size: 20px;
    font-weight: 500;
    word-wrap: break-word;
  }

  h3 {
    color: #151617;
    font-size: 16px;
    font-weight: 500;
    word-wrap: break-word;
  }

  h4 {
    color: #5B666C;
    font-size: 14px;
    font-weight: 400;
    word-wrap: break-word;
  }

  h5 {
    color: #5B666C;
    font-size: 12px;
    font-weight: 400;
    word-wrap: break-word;
  }

  strong {
    color: #151617;
    font-size: 14px;
    font-weight: 600;
    word-wrap: break-word;
  }

  a {
    color: #337AB7;
    text-decoration: none;
  }

  a:hover {
    color: #23527c;
  }

  a:active {
    color: #23527c;
  }

  table {
    width: 100%;
    border-collapse: collapse;
  }

  th,
  td {
    text-align: left;
    padding: 8px;
    border-bottom: 0.5px solid #CAD0D6;
  }

  th {
    color: #151617;
    font-size: 14px;
    font-weight: 500;
    line-height: 21px;
    word-wrap: break-word;
  }

  td {
    color: #363B3E;
    font-size: 14px;
    font-weight: 400;
    line-height: 21px;
    word-wrap: break-word;
  }

  tbody tr:hover {
    background-color: #EFF1F3;
  }

  tr.danger {
    padding: 7px 8px;
    border-left: 6px #D53948 solid;
  }

  tr.warning {
    padding: 7px 8px;
    border-left: 6px #FAC905 solid;
  }

  tr.success {
    padding: 7px 8px;
    border-left: 6px #007644 solid;
  }

  tr.unknown {
    padding: 7px 8px;
    border-left: 6px #949597 solid;
  }

  tr.other {
    padding: 7px 8px;
    border-left: 6px #337AB7 solid;
  }

  .field-container {
    justify-content: center;
    align-items: center;
    max-width: 100%;
    gap: 10px;
    overflow: auto;
  }

  .card {
    padding: 24px;
    background: #FFFFFF;
    border-radius: 4px;
    border: 0.5px #CAD0D6 solid;
    flex-direction: column;
    justify-content: flex-start;
    align-items: flex-start;
    gap: 8px;
    display: inline-flex;
  }

  .card-title {
    color: #151617;
    font-size: 16px;
    font-weight: 500;
    line-height: 24px;
    word-wrap: break-word;
  }

  .card-title-box {
    align-self: stretch;
    justify-content: space-between;
    align-items: center;
    gap: 149px;
    display: inline-flex;
  }

  .card-link-box {
    border-radius: 4px;
    justify-content: center;
    align-items: center;
    gap: 8px;
    display: flex;
  }

  .card-link {
    color: #337AB7;
    font-size: 14px;
    font-weight: 500;
    line-height: 14px;
    word-wrap: break-word;
  }

  .card-body {
    color: #151617;
    font-size: 14px;
    font-weight: 400;
    line-height: 24px;
    word-wrap: break-word;
    width: 100%;
  }

  .stat-card {
    width: 100%;
    padding: 24px;
    border-radius: 4px;
    border: 0.5px #CAD0D6 solid;
    flex-direction: column;
    gap: 8px;
    display: inline-flex;
    justify-content: center;
    align-items: center;
    margin: 0px;
    padding-top: 36px;
    padding-bottom: 36px;
    text-align: Center;
    margin-bottom: 24px;
    height: 148px;
  }

  .stat-value {
    height: 50%;
    font-size: 40px;
    color: #cccccc;
    margin-bottom: 10px;
  }

  .stat-desc {
    height: 50%;
    white-space: nowrap;
  }

  .btn {
    padding: 12px;
    background: #337AB7;
    border-radius: 4px;
    justify-content: center;
    align-items: center;
    display: inline-flex;
    color: #FFFFFF;
    font-size: 14px;
    font-weight: 500;
    line-height: 14px;
    word-wrap: break-word;
    text-decoration: none;
    border: 1px solid transparent;
    transition: background-color 0.3s ease, border-color 0.3s ease;
    outline: none;
  }

  .btn:hover {
    background: #115D9F;
  }

  .btn:focus {
    border: 1px solid #337AB7;
  }

  .btn.secondary {
    background: #FFFFFF;
    color: #337AB7;
    padding: 12.5px;
    border: 0.5px solid #CAD0D6;
  }

  .btn.secondary:hover {
    background: #EFF1F3;
  }

  .btn.secondary:focus {
    border-color: 1px solid #337AB7;
  }

  .btn.danger {
    background: #C6313A;
    color: #FFFFFF;
    border: 0.5px solid transparent;
  }

  .btn.danger:hover {
    background: #A71C25;
  }

  .btn.danger:focus {
    border-color: 1px solid #337AB7;
  }

  .info-card {
    width: 100%;
    padding: 12px;
    background: #EBF2F8;
    border-radius: 4px;
    justify-content: flex-start;
    align-items: flex-start;
    gap: 8px;
    display: inline-flex;
    margin-bottom: 10px;
  }

  .info-icon {
    text-align: center;
    color: #337AB7;
    font-size: 14px;
    font-weight: 900;
    word-wrap: break-word;
  }

  .info-text {
    flex-direction: column;
    justify-content: flex-start;
    align-items: flex-start;
    gap: 8px;
    display: inline-flex;
  }

  .info-title {
    color: #151617;
    font-size: 14px;
    font-weight: 600;
    word-wrap: break-word;
  }

  .info-description {
    color: #151617;
    font-size: 14px;
    font-weight: 400;
    word-wrap: break-word;
  }

  .info-card.error {
    background-color: #FBEBED;
  }

  .info-card.error .info-icon {
    color: #C6313A;
  }

  .info-card.warning {
    background-color: #FBEBED;
  }

  .info-card.warning .info-icon {
    color: #FAC905;
  }

  .info-card.success {
    background-color: #E6F2E5;
  }

  .info-card.success .info-icon {
    color: #007644;
  }

  .tag {
    padding: 2px 8px;
    background: #018200;
    border-radius: 2px;
    justify-content: center;
    align-items: center;
    gap: 8px;
    display: inline-flex;
    color: #FFFFFF;
    font-size: 14px;
    font-weight: 400;
    word-wrap: break-word;
  }

  .tag.disabled {
    background: #E8E8EA;
    color: #6E6D7A;
  }

  .tag.expired {
    background: #E8E8EA;
    color: #211F33;
  }

  .close {
    position: absolute;
    top: 24px;
    right: 27px;
    color: #211F33;
    text-decoration: none;
    font-size: 24px;
    font-weight: 300;
  }

  .nowrap {
    white-space: nowrap;
  }

  .linechart {
    width: 100%;
    height: 50px;
    display: flex;
  }

  .chart-key {
    display: inline-block;
    width: 20px;
    height: 20px;
    margin-right: 10px;
  }

        </style></head>
        <body>
        $OutputHTML
        $($Script:OrganizationHTML)
        </body>
</html>
"@

    if ($OutputToFile -eq $True) {
        [System.Web.HttpUtility]::HtmlDecode($FileHTML) | Out-File $Output_File
    }

    Write-Output "$(Get-Date): Complete Total Runtime: $((New-TimeSpan -Start $ScriptStart -End (Get-Date)).TotalSeconds) seconds"

} catch {
    Write-Output "Failed to Generate Ticketing Reports. Linenumber: $($_.InvocationInfo.ScriptLineNumber) Error: $($_.Exception.message)"
    exit 1
}

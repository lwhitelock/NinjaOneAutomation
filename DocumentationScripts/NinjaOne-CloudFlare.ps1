
$Start = Get-Date

$NinjaOneInstance = Ninja-Property-Get ninjaoneInstance
$NinjaOneClientID = Ninja-Property-Get ninjaoneClientId
$NinjaOneClientSecret = Ninja-Property-Get ninjaoneClientSecret
$CloudFlareToken = Ninja-Property-Get cloudflareToken


try {

    if (!(Get-Module -Name "NinjaOneDocs")) {
        $Null = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        Install-Module -Name 'NinjaOneDocs' -Force -MinimumVersion 1.1.0
        Import-Module 'NinjaOneDocs'
    } else {
        Update-Module NinjaOneDocs -Force
        Import-Module 'NinjaOneDocs'
    }

    $BaseURL = 'https://api.cloudflare.com/client/v4'


    function Get-CloudFlarePage {
        param (
            [string]$Uri
        )
        $Page = 0
        [System.Collections.Generic.List[PSCustomObject]]$Array = @()
        do {
            $Page++
            $Result = (Invoke-WebRequest -URI "$($Uri)?per_page=50&page=$Page" -Method GET -Headers $Script:CloudFlareAuthHeaders -UseBasicParsing).content | convertfrom-json
            $Result.result | foreach-object {
                $Array.add($_)
            }
        } while ($Page -lt $Result.result_info.total_pages)
        Return $Array
    }

    function Compare-NestedObjects($obj1, $obj2) {
        $props1 = $obj1 | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name
        $props2 = $obj2 | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name
        $allProps = $props1 + $props2 | Select-Object -Unique

        foreach ($prop in $allProps) {
            $value1 = $obj1.$prop
            $value2 = $obj2.$prop

            if ($value1 -is [PSCustomObject] -and $value2 -is [PSCustomObject]) {
                # Recursive call for nested objects
                Compare-NestedObjects $value1 $value2
            } elseif ($value1 -ne $value2) {
                # Output the difference
                $ReturnItem = [PSCustomObject]@{
                    Property = $prop
                }
                if ($value1) {
                    $ReturnItem | Add-Member -NotePropertyName 'Original' -NotePropertyValue "$($value1 | Out-String)"
                }
                if ($value2) {
                    $ReturnItem | Add-Member -NotePropertyName 'New' -NotePropertyValue "$($value2 | Out-String)"
                }
                $ReturnItem

            }
        }
    }

    Connect-NinjaOne -NinjaOneInstance $NinjaOneInstance -NinjaOneClientID $NinjaOneClientID -NinjaOneClientSecret $NinjaOneClientSecret

    $CloudFlareTemplate = [PSCustomObject]@{
        name          = 'Cloudflare'
        allowMultiple = $true
        fields        = @([PSCustomObject]@{
                fieldLabel                = 'Link'
                fieldName                 = 'link'
                fieldType                 = 'WYSIWYG'
                fieldTechnicianPermission = 'READ_ONLY'
                fieldScriptPermission     = 'NONE'
                fieldApiPermission        = 'READ_WRITE'
                fieldContent              = @{
                    required         = $False
                    advancedSettings = @{
                        expandLargeValueOnRender = $True
                    }
                }
            },
            [PSCustomObject]@{
                fieldLabel                = 'Status'
                fieldName                 = 'status'
                fieldType                 = 'TEXT'
                fieldTechnicianPermission = 'READ_ONLY'
                fieldScriptPermission     = 'NONE'
                fieldApiPermission        = 'READ_WRITE'
            },
            [PSCustomObject]@{
                fieldLabel                = 'Name Servers'
                fieldName                 = 'nameServers'
                fieldType                 = 'TEXT'
                fieldTechnicianPermission = 'READ_ONLY'
                fieldScriptPermission     = 'NONE'
                fieldApiPermission        = 'READ_WRITE'
            },
            [PSCustomObject]@{
                fieldLabel                = 'Original Name Servers'
                fieldName                 = 'originalNameServers'
                fieldType                 = 'TEXT'
                fieldTechnicianPermission = 'READ_ONLY'
                fieldScriptPermission     = 'NONE'
                fieldApiPermission        = 'READ_WRITE'
            },
            [PSCustomObject]@{
                fieldLabel                = 'Original Registrar'
                fieldName                 = 'originalRegistrar'
                fieldType                 = 'TEXT'
                fieldTechnicianPermission = 'READ_ONLY'
                fieldScriptPermission     = 'NONE'
                fieldApiPermission        = 'READ_WRITE'
            },
            [PSCustomObject]@{
                fieldLabel                = 'Modified On'
                fieldName                 = 'modifiedOn'
                fieldType                 = 'DATE_TIME'
                fieldTechnicianPermission = 'READ_ONLY'
                fieldScriptPermission     = 'NONE'
                fieldApiPermission        = 'READ_WRITE'
            },
            [PSCustomObject]@{
                fieldLabel                = 'Account'
                fieldName                 = 'account'
                fieldType                 = 'TEXT'
                fieldTechnicianPermission = 'READ_ONLY'
                fieldScriptPermission     = 'NONE'
                fieldApiPermission        = 'READ_WRITE'
            },
            [PSCustomObject]@{
                fieldLabel                = 'Plan'
                fieldName                 = 'plan'
                fieldType                 = 'TEXT'
                fieldTechnicianPermission = 'READ_ONLY'
                fieldScriptPermission     = 'NONE'
                fieldApiPermission        = 'READ_WRITE'
            },
            [PSCustomObject]@{
                fieldLabel                = 'Plan Cost'
                fieldName                 = 'planCost'
                fieldType                 = 'TEXT'
                fieldTechnicianPermission = 'READ_ONLY'
                fieldScriptPermission     = 'NONE'
                fieldApiPermission        = 'READ_WRITE'
            },
            [PSCustomObject]@{
                fieldLabel                = 'DNSSEC Status'
                fieldName                 = 'dnssecStatus'
                fieldType                 = 'TEXT'
                fieldTechnicianPermission = 'READ_ONLY'
                fieldScriptPermission     = 'NONE'
                fieldApiPermission        = 'READ_WRITE'
            },
            [PSCustomObject]@{
                fieldLabel                = 'DNS Records'
                fieldName                 = 'dnsRecords'
                fieldType                 = 'WYSIWYG'
                fieldTechnicianPermission = 'READ_ONLY'
                fieldScriptPermission     = 'NONE'
                fieldApiPermission        = 'READ_WRITE'
                fieldContent              = @{
                    required         = $False
                    advancedSettings = @{
                        expandLargeValueOnRender = $True
                    }
                }
            },
            [PSCustomObject]@{
                fieldLabel                = 'Zone Settings'
                fieldName                 = 'zoneSettings'
                fieldType                 = 'WYSIWYG'
                fieldTechnicianPermission = 'READ_ONLY'
                fieldScriptPermission     = 'NONE'
                fieldApiPermission        = 'READ_WRITE'
                fieldContent              = @{
                    required         = $False
                    advancedSettings = @{
                        expandLargeValueOnRender = $False
                    }
                }
            },
            [PSCustomObject]@{
                fieldLabel                = 'BIND File'
                fieldName                 = 'bindFile'
                fieldType                 = 'WYSIWYG'
                fieldTechnicianPermission = 'READ_ONLY'
                fieldScriptPermission     = 'NONE'
                fieldApiPermission        = 'READ_WRITE'
                fieldContent              = @{
                    required         = $False
                    advancedSettings = @{
                        expandLargeValueOnRender = $False
                    }
                }
            },
            [PSCustomObject]@{
                fieldLabel                = 'Last 20 Audit Log Entries'
                fieldName                 = 'auditLog'
                fieldType                 = 'WYSIWYG'
                fieldTechnicianPermission = 'READ_ONLY'
                fieldScriptPermission     = 'NONE'
                fieldApiPermission        = 'READ_WRITE'
                fieldContent              = @{
                    required         = $False
                    advancedSettings = @{
                        expandLargeValueOnRender = $False
                    }
                }
            }
        )
    }

    $CFDocTemplate = Invoke-NinjaOneDocumentTemplate $CloudFlareTemplate
    $CloudFlareDocs = Invoke-NinjaOneRequest -Method GET -Path 'organization/documents' -QueryParams "templateIds=$($CFDocTemplate.id)"


    [System.Collections.Generic.List[PSCustomObject]]$NinjaDocUpdates = @()
    [System.Collections.Generic.List[PSCustomObject]]$NinjaDocCreation = @()

    $NinjaOneCloudMonitors = Invoke-NinjaOneRequest -Method GET -Path 'devices-detailed' -QueryParams "df=class=CLOUD_MONITOR_TARGET" -Paginate

    $Script:CloudFlareAuthHeaders = @{
        'Authorization' = "Bearer $CloudFlareToken"
    }

    $Zones = Get-CloudFlarePage -URI "$BaseURL/zones"

    [System.Collections.Generic.List[PSCustomObject]]$UnmatchedZones = @()


    foreach ($Zone in $Zones) {
        try {
            $MatchedDoc = $CloudFlareDocs | Where-Object { $_.documentName -eq $Zone.name }
            $MatchCount = ($MatchedDoc | measure-object).count
     
            # Match to a CloudMonitor
            if ($MatchCount -eq 0) {
                $NinjaMatch = ($NinjaOneCloudMonitors | where-object { $Zone.name -eq ((($_.target -replace 'https://', '') -replace 'www.', '') -split '/')[0] } | Select-Object organizationId -Unique).organizationId
                $MatchCFCount = ($NinjaMatch | measure-object).count
                if ($MatchCFCount -ne 1) {
                    $UnmatchedZones.add($Zone)
                    continue
                }
            
            } elseif ($MatchCount -gt 1) {
                Throw "Multiple NinjaOne Documents ($($MatchedDoc.documentId -join '')) matched to $($Zone.name)"
                continue
            
            } else {
                $NinjaMatch = $MatchedDoc.organizationId
            }

            $AuditLogs = ((Invoke-WebRequest -URI "$BaseURL/accounts/$($Zone.account.id)/audit_logs?zone.name=$($Zone.name)&direction=desc&per_page=20" -Method GET -Headers $Script:CloudFlareAuthHeaders -UseBasicParsing).Content | ConvertFrom-Json).result

            [System.Collections.Generic.List[string]]$LogTable = @()

            $LogTable.add('<div class="g-3">')

            foreach ($Log in $AuditLogs) {

                if ($Log.actor.type -eq 'System') {
                    $ActorName = 'System'
                    $ActorIP = 'N/A'
                } else {
                    $ActorName = $Log.actor.email
                    $ActorIP = $Log.actor.ip
                }

                if ($Log.oldValueJson -and $Log.newValueJson ) {
                    $Diff = Compare-NestedObjects $Log.oldValueJson $Log.newValueJson -ea Stop

                    $DiffParsed = foreach ($Change in $Diff) {
                        if ($Change.Original -ne $Change.New) {
                            $Change
                        }
                    }

                
                    $DiffTable = "$(($DiffParsed | ConvertTo-HTML -As Table -Fragment) -replace '<th>','<th style="white-space: nowrap;">')"
                } else {
                    $DiffTable = 'N/A'
                }

                $LogData = [PSCustomObject]@{
                    'Date / Time'   = $Log.when
                    'Action Type'   = $Log.action.type
                    'Action Info'   = $Log.action.info
                    'Changed By'    = $ActorName
                    'Changed By IP' = $ActorIP
                }

                $LogCard = Get-NinjaOneInfoCard -Title "Log Details" -Data $LogData
                $ChangeCard = Get-NinjaOneCard -Title 'Changed' -Body $DiffTable
                $LogRow = '<div class="row g-3 pb-3"><div class="col-xl-4 col-lg-4 col-md-12 col-sm-12 d-flex">' + $LogCard + '</div><div class="col-xl-8 col-lg-8 col-md-12 col-sm-12 d-flex">' + $ChangeCard + '</div></div>'

                $LogTable.add($LogRow)
            }

            $Logtable.add('</div>')



            $ZoneRecords = Get-CloudFlarePage -URI "$BaseURL/zones/$($Zone.ID)/dns_records"
            $ZoneHTML = $ZoneRecords | Select-Object @{N = 'Name'; E = { $_.name } }, @{N = 'Type'; E = { '<span style="white-space: nowrap;">' + "$($_.type)</span>" } }, @{N = 'Content'; E = { $_.content } }, @{N = 'Proxied'; E = { '<span style="white-space: nowrap;">' + "$($_.proxied)</span>" } }, @{N = 'TTL'; E = { '<span style="white-space: nowrap;">' + "$($_.ttl)</span>" } }, @{N = 'Modified'; E = { '<span style="white-space: nowrap;">' + "$($_.modified_on)</span>" } } | convertto-html -as Table -Fragment | out-String
            $ZoneHTML = [System.Web.HttpUtility]::HtmlDecode(($ZoneHTML -replace '<th>', '<th style="white-space: nowrap;">'))

            $ZoneSettings = Get-CloudFlarePage -URI "$BaseURL/zones/$($Zone.ID)/settings"
            $ZoneSettingsHTML = $ZoneSettings | Select-Object @{N = 'Setting'; E = { (Get-Culture).TextInfo.ToTitleCase(($_.id -replace '_', ' ').ToLower()) } }, @{N = 'Value'; E = { (Get-Culture).TextInfo.ToTitleCase(($_.value -replace '_', ' ').ToLower()) } }, @{N = 'Modified'; E = { $_.modified_on } } | convertto-html -as Table -Fragment | out-string
    
            $DNSSec = Get-CloudFlarePage -URI "$BaseURL/zones/$($Zone.ID)/dnssec"

            $FirewallRules = Get-CloudFlarePage -URI "$BaseURL/zones/$($Zone.ID)/firewall/rules" | convertto-html -as Table -Fragment | out-string
            $FirewallRules = [System.Web.HttpUtility]::HtmlDecode(($FirewallRules -replace '<th>', '<th style="white-space: nowrap;">'))

            $PageRules = Get-CloudFlarePage -URI "$BaseURL/zones/$($Zone.ID)/pagerules" | convertto-html -as Table -Fragment | out-string

            [System.Collections.Generic.List[PSCustomObject]]$WidgetData = @()
            $WidgetData.add([PSCustomObject]@{
                    Value       = ($ZoneRecords | Measure-Object).count
                    Description = 'DNS Records'
                    Colour      = '#337AB7'
                    Link        = "https://dash.cloudflare.com/$($Zone.account.id)/$($Zone.name)/dns/settings"
                })
            $WidgetData.add([PSCustomObject]@{
                    Value       = ($FirewallRules | Measure-Object).count
                    Description = 'Firewall Rules'
                    Colour      = '#337AB7'
                    Link        = "https://dash.cloudflare.com/$($Zone.account.id)/$($Zone.name)/security/waf/custom-rules"
                })

            $WidgetData.add([PSCustomObject]@{
                    Value       = ($PageRules | Measure-Object).count
                    Description = 'Page Rules'
                    Colour      = '#337AB7'
                    Link        = "https://dash.cloudflare.com/$($Zone.account.id)/$($Zone.name)/rules"
                })
            
            if ( $DNSSec.status -eq 'active') {
                $DNSSecStatus = '<i class="fas fa-circle-check"></i>'
                $DNSSecCol = '#337AB7'
            } else {
                $DNSSecStatus = '<i class="fas fa-circle-xmark"></i>'
                $DNSSecCol = '#D53948'
            }
            $WidgetData.add([PSCustomObject]@{
                    Value       = $DNSSecStatus
                    Description = 'DNSSEC'
                    Colour      = $DNSSecCol
                    Link        = "https://dash.cloudflare.com/$($Zone.account.id)/$($Zone.name)/dns/settings"
                })
            $WidgetData.add([PSCustomObject]@{
                    Value       = '<i class="fas fa-cloud"></i>'
                    Description = 'Open CloudFlare'
                    Colour      = '#337AB7'
                    Link        = "https://dash.cloudflare.com/$($Zone.account.id)/$($Zone.name)/rules"
                })
            $WidgetData.add([PSCustomObject]@{
                    Value       = '<i class="fas fas fa-globe"></i>'
                    Description = 'View Website'
                    Colour      = '#337AB7'
                    Link        = "https://dash.cloudflare.com/$($Zone.account.id)/$($Zone.name)/rules"
                })
        
            $SummaryDetailsCardHTML = Get-NinjaOneWidgetCard -Data $WidgetData -Icon 'fas fa-building' -SmallCols 2 -MedCols 3 -LargeCols 4 -XLCols 4 -NoCard

            $SummaryHTML = '<div style="row">' + $SummaryDetailsCardHTML + '</div>'

            $Response = Invoke-WebRequest -Headers $Script:CloudFlareAuthHeaders -Uri "$BaseURL/zones/$($Zone.ID)/dns_records/export" -Method GET -UseBasicParsing
            $BindFile = [System.Text.Encoding]::UTF8.GetString($response.Content)

            $DocFields = @{
                'link'                = @{'html' = $SummaryHTML }
                'status'              = $Zone.status
                'nameServers'         = $Zone.name_servers -join ', '
                'originalNameServers' = $Zone.original_name_servers -join ', '
                'originalRegistrar'   = $Zone.original_registrar
                'modifiedOn'          = Get-NinjaOneTime -Date (Get-Date($Zone.modified_on))
                'account'             = $Zone.account.name
                'plan'                = $Zone.plan.name
                'planCost'            = "$($Zone.plan.price) $($Zone.plan.currency)"
                'dnssecStatus'        = $DNSSec.status
                'dnsRecords'          = @{'html' = $ZoneHTML }
                'zoneSettings'        = @{'html' = $ZoneSettingsHTML }
                'bindFile'            = @{'html' = "<pre>$BindFile</pre>" }
                'auditLog'            = @{'html' = "$LogTable" }
            }

            if ($MatchedDoc) {
                $UpdateObject = [PSCustomObject]@{
                    documentId   = $MatchedDoc.documentId
                    documentName = $Zone.name
                    fields       = $DocFields
                }

                $NinjaDocUpdates.Add($UpdateObject)

            } else {
                $CreateObject = [PSCustomObject]@{
                    documentName       = $Zone.name
                    documentTemplateId = $CFDocTemplate.id
                    organizationId     = [int]$NinjaMatch
                    fields             = $DocFields
                }

                $NinjaDocCreation.Add($CreateObject)
            }

        } catch {
            Write-Error "Failed processing zone $($Zone.name).Linenumber: $($_.InvocationInfo.ScriptLineNumber) Error: $($_.Exception.message)"
        }
    }

    ## Perform the bulk updates of data

    try {
        # Create New Users
        if (($NinjaDocCreation | Measure-Object).count -ge 1) {
            Write-Host "Creating Documents"
            $CreatedDocs = Invoke-NinjaOneRequest -Path "organization/documents" -Method POST -InputObject $NinjaDocCreation -AsArray
            Write-Host "Created $(($CreatedDocs | Measure-Object).count) Documents"
        }
    } Catch {
        Write-Host "Bulk Creation Error, but may have been successful as only 1 record with an issue could have been the cause: $_"
    }

    try {
        # Update Users
        if (($NinjaDocUpdates | Measure-Object).count -ge 1) {
            Write-Host "Updating Documents"
            $UpdatedDocs = Invoke-NinjaOneRequest -Path "organization/documents" -Method PATCH -InputObject $NinjaDocUpdates -AsArray
            Write-Host "Updated $(($UpdatedDocs | Measure-Object).count) Documents"
        }
    } Catch {
        Write-Host "Bulk Update Errored, but may have been successful as only 1 record with an issue could have been the cause: $_"
    }


    Write-Host "The following domains were not matched to a CloudFlare Document or Cloud Monitor in NinjaOne. Please add a CloudFlare Apps and Services docment with a name matching the domain or Cloud Monitor under the correct Organization for them"
    $UnmatchedZones | Select-Object  name, account.name

    Write-Output "$(Get-Date): Complete Total Runtime: $((New-TimeSpan -Start $Start -End (Get-Date)).TotalSeconds) seconds"

} catch {
    Write-Output "Failed to Generate Documentation. Linenumber: $($_.InvocationInfo.ScriptLineNumber) Error: $($_.Exception.message)"
    exit 1
}

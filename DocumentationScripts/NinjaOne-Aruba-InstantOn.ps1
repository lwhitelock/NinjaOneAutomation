
$Start = Get-Date

$NinjaOneInstance = Ninja-Property-Get ninjaoneInstance
$NinjaOneClientID = Ninja-Property-Get ninjaoneClientId
$NinjaOneClientSecret = Ninja-Property-Get ninjaoneClientSecret
$ArubaInstantOnUser = Ninja-Property-Get arubaInstantOnUsername
$ArubaInstantOnPass = Ninja-Property-Get arubaInstantOnPassword

$NinjaTemplateNameSite = "Aruba Instant On - Site"
$NinjaTemplateNameDevice = "Aruba Instant On - Device"

function Get-ColorBasedOnStatus {
    param($status, $speed)
    switch ($status) {
        $True {
            switch ($speed) {
                '10Gbps' { return '#337AB7' }  # Blue for 10 Gbps
                '1Gbps' { return '#90EE90' }  # Light Green for 1 Gbps
                '100Mbps' { return '#008000' }  # Green for 100 Mbps
                '10Mbps' { return '#006400' }  # Dark Green for 10 Mbps
                default { return '#90EE90' }  # Assume > than 1GBps for unknown speed
            }
        }
        $False { return '#808080' }  # Grey for down
        default { return '#808080' }  # Grey for unknown status
    }
}

function Get-TextColorBasedOnBackground {
    param($backgroundColor)
    switch ($backgroundColor) {
        '#0000FF' { return '#FFFFFF' }
        '#006400' { return '#FFFFFF' }
        '#008000' { return '#FFFFFF' }
        '#FF0000' { return '#FFFFFF' }
        '#808080' { return '#FFFFFF' }
        default { return '#000000' }
    }
}

function Get-PortTable ($Ports) {
    [System.Collections.Generic.List[PSCustomObject]]$HTML = @()

    $html.add(@"
    <ul class="unstyled p-3" style="display: flex; justify-content: space-between;">
    <li><span class="chart-key" style="background-color: #337AB7;"></span><span > Up (10 Gbps)</span></li>
    <li><span class="chart-key" style="background-color: #90EE90;"></span><span > Up (1 Gbps)</span></li>
    <li><span class="chart-key" style="background-color: #008000;"></span><span > Up (100 Mbps)</span></li>
    <li><span class="chart-key" style="background-color: #006400;"></span><span > Up (10 Mbps)</span></li>
    <li><span class="chart-key" style="background-color: #808080;"></span><span > Down</span></li>
    <li><i class="fas fa-bolt" style="color:#FFA500;"></i> PoE Enabled</li>
    </ul>
    <table class="mb-3">
"@)

    $rowTemplate = '<tr>{0}</tr>'
    $cellTemplate = '<td width={0}% ><div class="p-1" style="height:50px; background-color: {1}; justify-content:center; text-align:center; color: {2};"><div class="col-12">{3}</div><div class="col-12"><i class="fas fa-ethernet"></i>{4}</div></div></td>'
    $lightningBolt = '&nbsp;<i class="fas fa-bolt" style="color:#FFA500;"></i>'

    $numberOfRows = if ($ports.Count -le 10) { 1 } else { 2 }
    $portsPerRow = [math]::Ceiling($ports.Count / $numberOfRows)

    for ($row = 0; $row -lt $numberOfRows; $row++) {
        $cells = ''
        $startIndex = $row * $portsPerRow
        $endIndex = [math]::Min($startIndex + $portsPerRow, $ports.Count) - 1
        $Width = 100 / $PortsPerRow

        for ($i = $startIndex; $i -le $endIndex; $i++) {
            $port = $ports[$i]
            $color = Get-ColorBasedOnStatus -status $port.Status -speed $port.Speed
            $FontColour = Get-TextColorBasedOnBackground -backgroundColor $color
            $poebolt = if ($port.PoE) { $lightningBolt } else { '' }
            $cells += $cellTemplate -f $Width, $color, $FontColour, $port.Port, $poebolt
        }

        $html.add(($rowTemplate -f $cells))
    }

    $html.add('</table>')

    return ($HTML -join '')
}

$ProgressPreference = 'SilentlyContinue'

try {

    [System.Collections.Generic.List[PSCustomObject]]$NinjaDocUpdates = @()
    [System.Collections.Generic.List[PSCustomObject]]$NinjaDocCreation = @()
    [System.Collections.Generic.List[PSCustomObject]]$NinjaRelationMap = @()

    if (!(Get-Module -Name "NinjaOneDocs")) {
        $Null = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        Install-Module -Name 'NinjaOneDocs' -Force -MaximumVersion 1.2.0
        Import-Module 'NinjaOneDocs'
    } else {
        Update-Module NinjaOneDocs -MaximumVersion 1.2.0 -Force
        Import-Module 'NinjaOneDocs'
    }



    function Get-URLEncode {
        param(
            [Byte[]]$Bytes
        )
        # Convert to Base 64
        $EncodedText = [Convert]::ToBase64String($Bytes)

        # Calculate Number of Padding Chars
        $Found = $false
        $EndPos = $EncodedText.Length
        do {
            if ($EncodedText[$EndPos] -ne '=') {
                $found = $true
            }    
            $EndPos = $EndPos - 1
        } while ($found -eq $false)

        # Trim the Padding Chars
        $Stripped = $EncodedText.Substring(0, $EndPos)
    
        # Add the number of padding chars to the end
        $PaddingNumber = "$Stripped$($EncodedText.Length - ($EndPos + 1))" 

        # Replace Characters
        $URLEncodedString = $PaddingNumber -replace [RegEx]::Escape("+"), '-' -replace [RegEx]::Escape("/"), '_'
    
        return $URLEncodedString

    }

    Connect-NinjaOne -NinjaOneInstance $NinjaOneInstance -NinjaOneClientID $NinjaOneClientID -NinjaOneClientSecret $NinjaOneClientSecret

    $NinjaOneOrgs = Invoke-NinjaOneRequest -Method GET -Path 'organizations' -Paginate

    $SiteLayoutFields = [PSCustomObject]@{
        name          = $NinjaTemplateNameSite
        allowMultiple = $true
        fields        = @(
            [PSCustomObject]@{
                fieldLabel                = 'Site Details'
                fieldName                 = 'siteDetails'
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
            }, [PSCustomObject]@{
                fieldLabel                = 'Admins'
                fieldName                 = 'admins'
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
            }, [PSCustomObject]@{
                fieldLabel                = 'Alerts'
                fieldName                 = 'alerts'
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
            }, [PSCustomObject]@{
                fieldLabel                = 'Wired Networks'
                fieldName                 = 'wiredNetworks'
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
            }, [PSCustomObject]@{
                fieldLabel                = 'Wireless Networks'
                fieldName                 = 'wirelessNetworks'
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
            }, [PSCustomObject]@{
                fieldLabel                = 'Application Usage'
                fieldName                 = 'applicationUsage'
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
            }, [PSCustomObject]@{
                fieldLabel                = 'Clients'
                fieldName                 = 'clients'
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
            }
        )
    }
    
    $SiteDocTemplate = Invoke-NinjaOneDocumentTemplate $SiteLayoutFields
    $SiteDocs = Invoke-NinjaOneRequest -Method GET -Path 'organization/documents' -QueryParams "templateIds=$($SiteDocTemplate.id)"
		

    $DeviceLayoutFields = [PSCustomObject]@{
        name          = $NinjaTemplateNameDevice
        allowMultiple = $true
        fields        = @(
            [PSCustomObject]@{
                fieldLabel                = 'Management URL'
                fieldName                 = 'managementUrl'
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
            }, [PSCustomObject]@{
                fieldLabel                = 'Type'
                fieldName                 = 'type'
                fieldType                 = 'TEXT'
                fieldTechnicianPermission = 'READ_ONLY'
                fieldScriptPermission     = 'NONE'
                fieldApiPermission        = 'READ_WRITE'
            }, [PSCustomObject]@{
                fieldLabel                = 'IP'
                fieldName                 = 'ip'
                fieldType                 = 'TEXT'
                fieldTechnicianPermission = 'READ_ONLY'
                fieldScriptPermission     = 'NONE'
                fieldApiPermission        = 'READ_WRITE'
            }, [PSCustomObject]@{
                fieldLabel                = 'MAC'
                fieldName                 = 'mac'
                fieldType                 = 'TEXT'
                fieldTechnicianPermission = 'READ_ONLY'
                fieldScriptPermission     = 'NONE'
                fieldApiPermission        = 'READ_WRITE'
            }, [PSCustomObject]@{
                fieldLabel                = 'Serial Number'
                fieldName                 = 'serialNumber'
                fieldType                 = 'TEXT'
                fieldTechnicianPermission = 'READ_ONLY'
                fieldScriptPermission     = 'NONE'
                fieldApiPermission        = 'READ_WRITE'
            }, [PSCustomObject]@{
                fieldLabel                = 'Model'
                fieldName                 = 'model'
                fieldType                 = 'TEXT'
                fieldTechnicianPermission = 'READ_ONLY'
                fieldScriptPermission     = 'NONE'
                fieldApiPermission        = 'READ_WRITE'
            }, [PSCustomObject]@{
                fieldLabel                = 'Uptime'
                fieldName                 = 'uptime'
                fieldType                 = 'TEXT'
                fieldTechnicianPermission = 'READ_ONLY'
                fieldScriptPermission     = 'NONE'
                fieldApiPermission        = 'READ_WRITE'
            }, [PSCustomObject]@{
                fieldLabel                = 'Radios'
                fieldName                 = 'radios'
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
            }, [PSCustomObject]@{
                fieldLabel                = 'Ethernet Ports'
                fieldName                 = 'ethernetPorts'
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
            }, [PSCustomObject]@{
                fieldLabel                = 'Alerts'
                fieldName                 = 'alerts'
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
            }, [PSCustomObject]@{
                fieldLabel                = 'Clients'
                fieldName                 = 'clients'
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
            }
        
        )
    }
	
    $DeviceDocTemplate = Invoke-NinjaOneDocumentTemplate $DeviceLayoutFields
    $DeviceDocs = Invoke-NinjaOneRequest -Method GET -Path 'organization/documents' -QueryParams "templateIds=$($DeviceDocTemplate.id)"


    # Generate the Code Verified and Code Challange used in OAUth
    $RandomNumberGenerator = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $Bytes = New-Object Byte[] 32
    $RandomNumberGenerator.GetBytes($Bytes)
    $CodeVerifier = (Get-URLEncode($Bytes)).Substring(0, 43)

    $StateRandomNumberGenerator = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $StateBytes = New-Object Byte[] 32
    $StateRandomNumberGenerator.GetBytes($StateBytes)
    $State = (Get-URLEncode($StateBytes)).Substring(0, 43)

    $hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
    $hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($CodeVerifier))
    $CodeChallenge = (Get-URLEncode($hash)).Substring(0, 43)

    #Create the form body for the initial login
    $LoginRequest = [ordered]@{
        username = $ArubaInstantOnUser
        password = $ArubaInstantOnPass
    }

    # Perform the initial authorisation
    $ContentType = 'application/x-www-form-urlencoded'
    $Token = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "https://sso.arubainstanton.com/aio/api/v1/mfa/validate/full" -body $LoginRequest -ContentType $ContentType).content | ConvertFrom-Json

    # Dowmload the global settings and get the Client ID incase this changes.
    $OAuthSettings = (Invoke-WebRequest -UseBasicParsing -Method Get -Uri "https://portal.arubainstanton.com/settings.json") | ConvertFrom-Json
    $ClientID = $OAuthSettings.ssoClientIdAuthZ

    # Use the initial token to perform the authorisation
    $URL = "https://sso.arubainstanton.com/as/authorization.oauth2?client_id=$ClientID&redirect_uri=https://portal.arubainstanton.com&response_type=code&scope=profile%20openid&state=$State&code_challenge_method=S256&code_challenge=$CodeChallenge&sessionToken=$($Token.access_token)"
    $AuthCode = Invoke-WebRequest -UseBasicParsing -Method GET -Uri $URL -MaximumRedirection 1

    # Extract the code returned in the redirect URL
    if ($null -ne $AuthCode.BaseResponse.ResponseUri) {
        # This is for Powershell 5
        $redirectUri = $AuthCode.BaseResponse.ResponseUri
    } elseif ($null -ne $AuthCode.BaseResponse.RequestMessage.RequestUri) {
        # This is for Powershell core
        $redirectUri = $AuthCode.BaseResponse.RequestMessage.RequestUri
    }

    $QueryParams = [System.Web.HttpUtility]::ParseQueryString($redirectUri.Query)
    $i = 0
    $ParsedQueryParams = foreach ($QueryStringObject in $QueryParams) {
        $queryObject = New-Object -TypeName psobject
        $queryObject | Add-Member -MemberType NoteProperty -Name Name -Value $QueryStringObject
        $queryObject | Add-Member -MemberType NoteProperty -Name Value -Value $QueryParams[$i]
        $queryObject
        $i++
    }

    $LoginCode = ($ParsedQueryParams | where-object { $_.name -eq 'code' }).value

    # Build the form data to request an actual token
    $TokenAuth = @{
        client_id     = $ClientID
        redirect_uri  = 'https://portal.arubainstanton.com'
        code          = $LoginCode
        code_verifier = $CodeVerifier
        grant_type    = 'authorization_code'

    }

    # Obtain the Bearer Token
    $Bearer = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "https://sso.arubainstanton.com/as/token.oauth2" -body $TokenAuth -ContentType $ContentType).content | ConvertFrom-Json


    # Get the headers ready for talking to the API. Note you get 500 errors if you don't include x-ion-api-version 7 for some endpoints and don't get full data on others
    $ContentType = 'application/json'
    $headers = @{
        Authorization       = "Bearer $($Bearer.access_token)"
        'x-ion-api-version' = 7
    }

    # Get all sites under account
    $Sites = (Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://nb.portal.arubainstanton.com/api/sites/" -ContentType $ContentType -Headers $headers).content | ConvertFrom-Json

    # Loop through each site and create documentation
    foreach ($site in $sites.Elements) {
        #First we will see if there is an Asset that matches the site name with this Asset Layout
        Write-Host "Attempting to map $($Site.name)"
        $MatchedSiteDoc = $SiteDocs | Where-Object { $_.documentName -eq $Site.name }
        if (!$MatchedSiteDoc) {
            #Check on Org name
            $Org = ($NinjaOneOrgs | Where-Object { $_.name -eq $Site.name }).id
            if (!$Org) {
                Write-Output "An Organization in NinjaOne could not be matched to the site. Please create a blank '$NinjaTemplateNameSite' asset, with a name of `"$($Site.name)`" under the Organization in NinjaOne you wish to map this site to."
                continue
            }
        } else {
            $Org = $MatchedSiteDoc.organizationId
        }
        Write-Host "Processing $($Site.name)"

        #Gather all Data
        #Site Details
        $LandingPage = (Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://nb.portal.arubainstanton.com/api/sites/$($Site.id)/landingPage" -ContentType $ContentType -Headers $headers).content | ConvertFrom-Json
        $administration = (Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://nb.portal.arubainstanton.com/api/sites/$($Site.id)/administration" -ContentType $ContentType -Headers $headers).content | ConvertFrom-Json
        $timezone = (Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://nb.portal.arubainstanton.com/api/sites/$($Site.id)/timezone" -ContentType $ContentType -Headers $headers).content | ConvertFrom-Json
        $maintenance = (Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://nb.portal.arubainstanton.com/api/sites/$($Site.id)/maintenance" -ContentType $ContentType -Headers $headers).content | ConvertFrom-Json
        $Alerts = (Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://nb.portal.arubainstanton.com/api/sites/$($Site.id)/alerts" -ContentType $ContentType -Headers $headers).content | ConvertFrom-Json
        $AlertsSummary = (Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://nb.portal.arubainstanton.com/api/sites/$($Site.id)/alertsSummary" -ContentType $ContentType -Headers $headers).content | ConvertFrom-Json
        $applicationCategoryUsage = (Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://nb.portal.arubainstanton.com/api/sites/$($Site.id)/applicationCategoryUsage" -ContentType $ContentType -Headers $headers) | ConvertFrom-Json  
       
        # Devices 
        $Inventory = (Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://nb.portal.arubainstanton.com/api/sites/$($Site.id)/inventory" -ContentType $ContentType -Headers $headers).content | ConvertFrom-Json
        $ClientSummary = (Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://nb.portal.arubainstanton.com/api/sites/$($Site.id)/clientSummary" -ContentType $ContentType -Headers $headers).content | ConvertFrom-Json
        $WiredClientSummary = (Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://nb.portal.arubainstanton.com/api/sites/$($Site.id)/wiredClientSummary" -ContentType $ContentType -Headers $headers).content | ConvertFrom-Json

        # Networks
        $WiredNetworks = (Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://nb.portal.arubainstanton.com/api/sites/$($Site.id)/wiredNetworks" -ContentType $ContentType -Headers $headers).content | ConvertFrom-Json
        $networksSummary = (Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://nb.portal.arubainstanton.com/api/sites/$($Site.id)/networksSummary" -ContentType $ContentType -Headers $headers).content | ConvertFrom-Json
    
        # Not Used in this example
        # $Summary = (Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://nb.portal.arubainstanton.com/api/sites/$($Site.id)" -ContentType $ContentType -Headers $headers).content | ConvertFrom-Json
        # $capabilities = (Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://nb.portal.arubainstanton.com/api/sites/$($Site.id)/capabilities" -ContentType $ContentType -Headers $headers).content | ConvertFrom-Json
        # $radiusNasSettings = (Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://nb.portal.arubainstanton.com/api/sites/$($Site.id)/radiusNasSettings" -ContentType $ContentType -Headers $headers).content | ConvertFrom-Json
        # $reservedIpSubnets = (Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://nb.portal.arubainstanton.com/api/sites/$($Site.id)/reservedIpSubnets" -ContentType $ContentType -Headers $headers).content | ConvertFrom-Json
        # $defaultWiredNetwork = (Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://nb.portal.arubainstanton.com/api/sites/$($Site.id)/defaultWiredNetwork" -ContentType $ContentType -Headers $headers).content | ConvertFrom-Json
        # $guestPortalSettings = (Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://nb.portal.arubainstanton.com/api/sites/$($Site.id)/guestPortalSettings" -ContentType $ContentType -Headers $headers).content | ConvertFrom-Json
        # $ClientBlacklist = (Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://nb.portal.arubainstanton.com/api/sites/$($Site.id)/clientBlacklist" -ContentType $ContentType -Headers $headers).content | ConvertFrom-Json 
        # $applicationCategoryUsageConfiguration = (Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://nb.portal.arubainstanton.com/api/sites/$($Site.id)/applicationCategoryUsageConfiguration" -ContentType $ContentType -Headers $headers).content | ConvertFrom-Json


        $AdminsHTML = ($administration.accounts | Select-Object @{n = 'Email'; e = { $_.email } }, @{n = 'Active'; e = { $_.isActivated } }, @{n = 'Primary Account'; e = { $_.isPrimaryAccount } } | ConvertTo-Html -fragment | Out-String)

        $AlertsHTML = ($alerts.elements | Select-Object @{n = 'Created'; e = { (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($_.raisedTime)) } }, @{n = 'Resolved'; e = { (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($_.clearedTime)) } }, @{n = 'Type'; e = { $_.type } }, @{n = 'Severity'; e = { $_.severity } } | ConvertTo-Html -fragment | Out-String) 
    
        $WiredNetworksHTML = ($WiredNetworks.elements | select-object @{n = 'Name'; e = { $_.wiredNetworkName } }, @{n = 'Management'; e = { $_.isManagement } }, @{n = 'Enabled'; e = { $_.isEnabled } }, @{n = 'Wireless Networks'; e = { $_.wirelessnetworks.networkname -join ', ' } } | ConvertTo-Html -fragment | Out-String)
    
        $WirelessNetworksHTML = ($networksSummary.elements | select-object @{n = 'Name'; e = { $_.networkName } }, @{n = 'Type'; e = { $_.type } }, @{n = 'Enabled'; e = { $_.isEnabled } }, @{n = 'SSID Hidden'; e = { $_.isSsidHidden } }, @{n = 'Authentication'; e = { $_.authentication } }, @{n = 'Security'; e = { $_.security } }, @{n = 'Captive Portal Enabled'; e = { $_.isCaptivePortalEnabled } } | ConvertTo-Html -fragment | Out-String)
    
        $ApplicationUsageHTML = ($applicationCategoryUsage.elements | where-object { $_.downstreamDataTransferredDuringLast24HoursInBytes -gt 0 -or $_.upstreamDataTransferredDuringLast24HoursInBytes -gt 0 } `
            | sort-object downstreamDataTransferredDuringLast24HoursInBytes -Descending `
            | Select-Object @{n = 'Name'; e = { $_.networkSsid } }, `
            @{n = 'Category'; e = { $_.applicationCategory } }, `
            @{n = 'Downloaded in last 24 hours (GBs)'; e = { [math]::Round(($_.downstreamDataTransferredDuringLast24HoursInBytes / 1024 / 1024 / 1024), 2) } }, `
            @{n = 'Uploaded in last 24 hours (GBs)'; e = { [math]::Round(($_.upstreamDataTransferredDuringLast24HoursInBytes / 1024 / 1024 / 1024), 2) } } `
            | ConvertTo-Html -fragment | Out-String)
    
        $WirelessClientsHTML = ($ClientSummary.elements | Select-Object @{n = 'Name'; e = { $_.name } }, @{n = 'Network'; e = { $_.NetworkSsid } }, @{n = 'IP Address'; e = { $_.ipAddress } }, @{n = 'AP'; e = { $_.apName } }, @{n = 'Protocol'; e = { $_.wirelessProtocol } }, @{n = 'Security'; e = { $_.wirelessSecurity } }, @{n = 'Connected (Hours)'; e = { [math]::Round(($_.connectionDurationInSeconds / 60 / 60), 2) } }, @{n = 'Signal Quality'; e = { $_.signalQuality } }, @{n = 'Signal'; e = { $_.signalInDbm } }, @{n = 'Noise'; e = { $_.noiseInDbm } }, @{n = 'SNR'; e = { $_.snrInDb } } | ConvertTo-Html -fragment | Out-String)

        $WiredClientsHTML = ($WiredClientSummary.elements | Select-Object @{n = 'Name'; e = { $_.name } }, @{n = 'MAC'; e = { $_.macAddress } }, @{n = 'Type'; e = { $_.clientType } }, @{n = 'Voice Device'; e = { $_.isVoiceDevice } }, @{n = 'IP Address'; e = { $_.ipAddress } } | ConvertTo-Html -fragment | Out-String)

        [System.Collections.Generic.List[PSCustomObject]]$WidgetData = @()
        $WidgetData.add([PSCustomObject]@{
                Value       = '<i class="fa-solid fa-network-wired fa-2xs"></i>' + " $($LandingPage.wiredClientsCount) | $($LandingPage.wirelessClientsCount) " + '<i class="fas fa-wifi fa-2xs"></i>'
                Description = 'Connected Clients'
                Colour      = '#337AB7'
                Link        = "https://portal.arubainstanton.com/#/site/$($Site.id)/home/view/clients"
            })
        $WidgetData.add([PSCustomObject]@{
                Value       = "$($LandingPage.currentlyActiveWiredNetworksCount) / $($LandingPage.configuredWiredNetworksCount)"
                Description = 'Active Wired Networks'
                Colour      = '#337AB7'
                Link        = "https://portal.arubainstanton.com/#/site/$($Site.id)/home/view/networks"
            })

        $WidgetData.add([PSCustomObject]@{
                Value       = "$($LandingPage.currentlyActiveWirelessNetworksCount) / $($LandingPage.configuredWirelessNetworksCount)"
                Description = 'Active Wireless Networks'
                Colour      = '#337AB7'
                Link        = "https://portal.arubainstanton.com/#/site/$($Site.id)/home/view/networks"
            })

        if ( $LandingPage.health -eq 'good') {
            $HealthStatus = '<i class="fas fa-circle-check"></i>'
            $HealthCol = '#337AB7'
        } else {
            $HealthStatus = '<i class="fas fa-circle-xmark"></i>'
            $HealthCol = '#D53948'
        }
        $WidgetData.add([PSCustomObject]@{
                Value       = $HealthStatus
                Description = 'Health'
                Colour      = $HealthCol
                Link        = "https://portal.arubainstanton.com/#/site/$($Site.id)/home/view/health"
            })
        $WidgetData.add([PSCustomObject]@{
                Value       = "$([math]::round(($LandingPage.totalDataTransferredDuringLast24HoursInBytes / 1024 / 1024 / 1024), 2)) GB"
                Description = 'Data Transfer (24 Hours)'
                Colour      = '#337AB7'
                Link        = "https://portal.arubainstanton.com/#/site/$($Site.id)/home/view/applications"
            })
        $WidgetData.add([PSCustomObject]@{
                Value       = '<i class="fas fas fa-globe"></i>'
                Description = 'View Portal'
                Colour      = '#337AB7'
                Link        = "https://portal.arubainstanton.com/#/site/$($Site.ID)/home/dashboard"
            })

        $SiteDetailsWidgetsHTML = Get-NinjaOneWidgetCard -Data $WidgetData -Icon 'fas fa-building' -SmallCols 2 -MedCols 3 -LargeCols 4 -XLCols 4 -NoCard

        $SiteDetailsHTML = '<div style="row">' + $SiteDetailsWidgetsHTML + '</div>'


        $SiteFields = @{
            'siteDetails'      = @{ 'html' = $SiteDetailsHTML }
            'admins'           = @{ 'html' = $AdminsHTML }
            'alerts'           = @{ 'html' = $AlertsHTML }
            'wiredNetworks'    = @{ 'html' = $WiredNetworksHTML }
            'wirelessNetworks' = @{ 'html' = $WirelessNetworksHTML }
            'applicationUsage' = @{ 'html' = $ApplicationUsageHTML }
            'clients'          = @{ 'html' = "<h3>Wireless Clients</h3>$($WirelessClientsHTML)<h3>Wired Clients</h3>$($WiredClientsHTML)" }
        }

        if ($MatchedSiteDoc) {
            $UpdateObject = [PSCustomObject]@{
                documentId   = $MatchedSiteDoc.documentId
                documentName = $site.name
                fields       = $SiteFields
            }

            $NinjaDocUpdates.Add($UpdateObject)

        } else {
            $CreateObject = [PSCustomObject]@{
                documentName       = $site.name
                documentTemplateId = $SiteDocTemplate.id
                organizationId     = [int]$Org
                fields             = $SiteFields
            }

            $NinjaDocCreation.Add($CreateObject)
        }

        if (($Inventory.elements | Measure-Object).count -ge 1) {
            $NinjaRelationMap.add(
                [PSCustomObject]@{
                    Org      = $Org
                    SiteName = $Site.Name
                    Devices  = $Inventory.elements.name
                }
            )
            foreach ($device in $Inventory.elements) {

            
                $RadiosHTML = ($device.radios | Select-Object @{n = 'MAC'; e = { $_.id } }, @{n = 'Band'; e = { $_.band } }, @{n = 'Channel'; e = { $_.channel } }, @{n = 'Clients'; e = { $_.wirelessClientsCount } }, @{n = 'Radio Power'; e = { $_.radioPower } }, @{n = 'Power Dbm'; e = { $_.txPowerEirpInDbm } }, @{n = 'In Use'; e = { $_.isRadioInUse } } | ConvertTo-Html -fragment | Out-String)

                # The port map status table is based off Kelvin Tegelaar's Unifi documentation script
                if (($Device.ethernetports | measure-object).count -gt 1) {
                    $Ports = foreach ($Port in $Device.ethernetports) {
                        $speed = switch ($port.speed) {
                            "mbps10000" { "10Gbps" }
                            "mbps1000" { "1Gbps" }
                            "mbps100" { "100Mbps" }
                            "mbps10" { "10Mbps" }
                            "mbps0" { "Port off" }
                        }

                        [PSCustomObject]@{
                            'Port'   = $Port.portNumber
                            'Status' = $Port.isLinkUp
                            'Speed'  = $Speed
                            'PoE'    = $Port.isProvidingPower
                        }
                    }

                    $PortTableHTML = Get-PortTable -Ports $Ports

                    $SwitchPortsDetailHTML = ($device.ethernetports | Select-Object @{n = 'Name'; e = { $_.name } }, `
                        @{n = 'No'; e = { $_.portNumber } }, `
                        @{n = 'PoE'; e = { if ($_.isProvidingPower -eq $True) { '<i class="fas fa-bolt" style="color:#FFA500;"></i>' } else { '<i class="fas fa-circle-minus" style="color:#808080;"></i>' } } }, `
                        @{n = 'Speed'; e = { $_.speed } }, `
                        @{n = 'Link Up'; e = { if ($_.isLinkUp -eq $True) { '<i class="fas fa-circle-check" style="color:#90EE90;"></i>' } else { '<i class="fas fa-circle-xmark" style="color:#808080;"></i>' } } }, `
                        @{n = 'Loop'; e = { $_.isLoopDetected } }, `
                        @{n = 'Direct Device'; e = { $_.directlyConnectedDeviceName } }, `
                        @{n = 'Uplink Device'; e = { $_.uplinkDeviceName } }, `
                        @{n = 'Downloaded GBs'; e = { [math]::Round(($_.downstreamDataTransferredInBytes / 1024 / 1024 / 1024), 2) } }, `
                        @{n = 'Uploaded GBs'; e = { [math]::Round(($_.upstreamDataTransferredInBytes / 1024 / 1024 / 1024), 2) } } `
                        | ConvertTo-Html -fragment | Out-String)

                    $SwitchPortHTML = [System.Web.HttpUtility]::HtmlDecode($PortTableHTML + $SwitchPortsDetailHTML)            

                } else {
                    $SwitchPortHTML = ''
                }

                $ActiveDeviceAlertsHTML = ($Device.ActiveAlerts | Select-Object @{n = 'Created'; e = { (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($_.raisedTime)) } }, @{n = 'Open for (hours)'; e = { [math]::round(($_.numberOfSecondsSinceRaised / 60 / 60), 2) } }, @{n = 'Type'; e = { $_.type } }, @{n = 'Severity'; e = { $_.severity } } | ConvertTo-Html -fragment | Out-String) 
    
                $DeviceClients = $ClientSummary.elements | Where-Object { $_.apName -eq $device.name }
                $DeviceClientsHTML = ($DeviceClients | Select-Object @{n = 'Name'; e = { $_.name } }, @{n = 'Network'; e = { $_.NetworkSsid } }, @{n = 'IP Address'; e = { $_.ipAddress } }, @{n = 'AP'; e = { $_.apName } }, @{n = 'Protocol'; e = { $_.wirelessProtocol } }, @{n = 'Security'; e = { $_.wirelessSecurity } }, @{n = 'Connected (Hours)'; e = { [math]::Round(($_.connectionDurationInSeconds / 60 / 60), 2) } }, @{n = 'Signal Quality'; e = { $_.signalQuality } }, @{n = 'Signal'; e = { $_.signalInDbm } }, @{n = 'Noise'; e = { $_.noiseInDbm } }, @{n = 'SNR'; e = { $_.snrInDb } } | ConvertTo-Html -fragment | Out-String)

                $ManagementLink =@"
 <ul class="row unstyled"><li class="col-sm-6 col-md-4 col-lg-4 col-xl-4"><a href="https://portal.arubainstanton.com/#/site/$($Site.ID)/home/view/inventory/devices" target="_blank" rel="nofollow noopener noreferrer"><span><i class="fas fa-globe"></i>&nbsp;&nbsp;</span><span style="text-align: center;">View in Portal</span></a></li></ul>
"@

                $DeviceFields = @{
                    'managementUrl' = @{ 'html' = $ManagementLink }
                    'type'          = $device.deviceType
                    'ip'            = $device.ipAddress
                    'mac'           = $device.macAddress
                    'serialNumber'  = $device.serialNumber
                    'model'         = $device.model
                    'uptime'        = "$([math]::Round(($device.uptimeInSeconds /60 / 60 / 24),2)) Days"
                    'radios'        = @{ 'html' = $RadiosHTML }
                    'ethernetPorts' = @{ 'html' = $SwitchPortHTML }
                    'alerts'        = @{ 'html' = $ActiveDeviceAlertsHTML }
                    'clients'       = @{ 'html' = $DeviceClientsHTML }
                }

                $MatchedDeviceDoc = $DeviceDocs | Where-Object { $_.documentName -eq $device.name }

                if ($MatchedDeviceDoc) {
                    $UpdateObject = [PSCustomObject]@{
                        documentId   = $MatchedDeviceDoc.documentId
                        documentName = $device.name
                        fields       = $DeviceFields
                    }
    
                    $NinjaDocUpdates.Add($UpdateObject)
    
                } else {
                    $CreateObject = [PSCustomObject]@{
                        documentName       = $device.name
                        documentTemplateId = $DeviceDocTemplate.id
                        organizationId     = [int]$Org
                        fields             = $DeviceFields
                    }
    
                    $NinjaDocCreation.Add($CreateObject)
                }

            }
        }
       
    }

    try {
        # Create New Documents
        if (($NinjaDocCreation | Measure-Object).count -ge 1) {
            Write-Host "Creating Documents"
            $CreatedDocs = Invoke-NinjaOneRequest -Path "organization/documents" -Method POST -InputObject $NinjaDocCreation -AsArray
            Write-Host "Created $(($CreatedDocs | Measure-Object).count) Documents"
        }
    } Catch {
        Write-Host "Bulk Creation Error, but may have been successful as only 1 record with an issue could have been the cause: $_"
    }

    try {
        # Update Documents
        if (($NinjaDocUpdates | Measure-Object).count -ge 1) {
            Write-Host "Updating Documents"
            $UpdatedDocs = Invoke-NinjaOneRequest -Path "organization/documents" -Method PATCH -InputObject $NinjaDocUpdates -AsArray
            Write-Host "Updated $(($UpdatedDocs | Measure-Object).count) Documents"
        }
    } Catch {
        Write-Host "Bulk Update Errored, but may have been successful as only 1 record with an issue could have been the cause: $_"
    }

    $AllDocs = $CreatedDocs + $UpdatedDocs

    Write-Host "Updating Relations"
    Foreach ($Relation in $NinjaRelationMap) {
        $SiteDoc = $AllDocs | Where-Object { $_.documentName -eq $Relation.SiteName -and $_.organizationId -eq $Relation.Org -and $_.documentTemplateId -eq $SiteDocTemplate.id }
        $DeviceDocs = $AllDocs | Where-Object { $_.documentName -in $Relation.Devices -and $_.organizationId -eq $Relation.Org -and $_.documentTemplateId -eq $DeviceDocTemplate.id }
        $RelatedItems = Invoke-NinjaOneRequest -Path "related-items/with-entity/DOCUMENT/$($SiteDoc.documentId)" -Method GET
        [System.Collections.Generic.List[PSCustomObject]]$Relations = @()
        foreach ($LinkDevice in $DeviceDocs) {
            $ExistingRelation = $RelatedItems | Where-Object { $_.relEntityType -eq 'DOCUMENT' -and $_.relEntityId -eq $LinkDevice.documentId }
            if (!$ExistingRelation) {
                $Relations.Add(
                    [PSCustomObject]@{
                        relEntityType = "DOCUMENT"
                        relEntityId   = $LinkDevice.documentId
                    }
                )
            }
        }

        try {
            # Update Relations
            if (($Relations | Measure-Object).count -ge 1) {
                if (($Relations | Measure-Object).count -gt 1) {
                    $JsonBody = $Relations | ConvertTo-Json -Depth 100
                } else {
                    $JsonBody = "[$($Relations | ConvertTo-Json -Depth 100)]"
                }
                $Null = Invoke-NinjaOneRequest -Path "related-items/entity/DOCUMENT/$($SiteDoc.documentId)/relations" -Method POST -Body $JsonBody -EA Stop
            }
        } Catch {
            Write-Host "Creating Relations Failed: $_"
        }

    }

    Write-Output "$(Get-Date): Complete Total Runtime: $((New-TimeSpan -Start $Start -End (Get-Date)).TotalSeconds) seconds"

} catch {
    Write-Output "Failed to Generate Documentation. Linenumber: $($_.InvocationInfo.ScriptLineNumber) Error: $($_.Exception.message)"
    Exit 1
}

# NinjaOne TD Synnex Sync
# This script will sync subscription data from TD Synnex to NinjaOne License Management

#### Settings ####

# Set if you would like to include the NinjaOne Organization in the license name or not
$IncludeOrganizationName = $True

# If your company names do not match in TD Synnex and NinjaOne you can specify the overriden names here. If they do match this can be left as $NameOverride = @()
$NameOverride = @(
    @{  
        TDSynnexName     = 'Company 1 Ltd'
        NinjaOneName = 'Company 1' 
    },
    @{  
        TDSynnexName     = 'Example Customer'
        NinjaOneName = 'Example Organization' 
    }
)

#### Credentials ####

# TDSynnax Settings
$Script:TDSAccountID = Ninja-Property-Get tdSynnaxAccountId
$TDSRefreshToken = Ninja-Property-Get tdSynnaxRefreshToken

# NinjaOne API Details
$ClientID = Ninja-Property-Get ninjaoneClientId
$Secret = Ninja-Property-Get ninjaoneClientSecret
$NinjaInstance = Ninja-Property-Get ninjaoneInstance


$ProgressPreference = 'SilentlyContinue'

function Connect-TDSynnex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RefreshToken
    )

    $TDSAuth = @{
        grant_type    = 'refresh_token'
        refresh_token = $RefreshToken
    }

   
    try {
        $Response = (Invoke-WebRequest -Method POST -Uri 'https://ion.tdsynnex.com/oauth/token' -ContentType 'application/x-www-form-urlencoded' -Body $TDSAuth -UseBasicParsing).content | ConvertFrom-Json
        $script:TDSynnexAccessToken = $Response.access_token
        $script:TDSynnexRefreshToken = $Response.refresh_token
        Ninja-Property-Set tdSynnaxRefreshToken $($script:TDSynnexRefreshToken)
    }
    catch {
        Write-Host $_ -ForegroundColor Red
        exit 1
    }
 

}

function Invoke-TDSynnexRequest {
    [CmdletBinding()]
    Param(
        [string]$Method,
        [string]$Resource,
        [string]$ResourceFilter,
        [string]$Body,
        [string]$PaginationMode = 'Token'
    )
	
    if (!$script:TDSynnexAccessToken) {
        Write-Host "Please run 'Connect-TDSynnex' first" -ForegroundColor Red
    }
    else {
	
        $headers = @{
            Authorization = "Bearer $($script:TDSynnexAccessToken)"
        }

        try {
            if (($Method -eq "put") -or ($Method -eq "post") -or ($Method -eq "delete")) {
                $Response = Invoke-WebRequest -UseBasicParsing -Method $method -Uri ("https://ion.tdsynnex.com/api/v3/accounts/$($Script:TDSAccountID)/" + $Resource) -ContentType 'application/json' -Body $Body -Headers $headers -ea stop
                $Result = $Response | ConvertFrom-Json
            }
            elseif ($PaginationMode -eq 'Token') {
                $Complete = $false
                $PageToken = $Null
                $Result = do {
                    $Response = Invoke-WebRequest -UseBasicParsing -Method $method -Uri ("https://ion.tdsynnex.com/api/v3/accounts/$($Script:TDSAccountID)/" + $Resource + "?pageSize=200&pageToken=$PageToken" + $ResourceFilter) -ContentType 'application/json' -Headers $headers -ea stop
                    $JSON = $Response.content | ConvertFrom-Json
                    if ($JSON.nextPageToken) {
                        $PageToken = $JSON.nextPageToken
                        $JSON
                    }
                    else {
                        $Complete = $true
                        $JSON
                    }
                } while ($Complete -eq $false)
            }
            elseif ($PaginationMode -eq 'Pagination') {
                $Complete = $false
                $PageSize = 200
                $Offset = 0
                $Result = do {
                    $Response = Invoke-WebRequest -UseBasicParsing -Method $method -Uri ("https://ion.tdsynnex.com/api/v3/accounts/$($Script:TDSAccountID)/" + $Resource + "?pagination.limit=$PageSize&pagination.offset=$Offset" + $ResourceFilter) -ContentType 'application/json' -Headers $headers -ea stop
                    $Script:RequestResult = $Response
                    $JSON = $Response.content | ConvertFrom-Json
                    $Offset = $Offset + $PageSize
                    if ($JSON.paginationResponse.totalSize -le $Offset) {
                        $Complete = $true   
                    }
                    $JSON
                } while ($Complete -eq $false)
            }
        }
        catch {
            if ($_.Response.StatusCode -eq 429) {
                Write-Warning "Rate limit exceeded. Waiting to try again."
                Start-Sleep 8
                $Result = Invoke-TDSynnexRequest -Method $Method -Resource $Resource -ResourceFilter $ResourceFilter -Body $Body
            }
            else {
                Write-Host "Error: An Error Occured $($_) "
            }
        }
		
        return $Result
		
    }	
}

function Get-NinjaOneTime {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $false)]
        [DateTime]$Date = (Get-Date), # Use current date by default
        [Switch]$Seconds
    )

    $unixEpoch = Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0 -Millisecond 0
    $timeSpan = $Date.ToUniversalTime() - $unixEpoch

    if ($Seconds) {
        return [int64]([math]::Round($timeSpan.TotalSeconds))
    }
    else {
        return [int64]([math]::Round($timeSpan.TotalMilliSeconds))
    }
}

# AI Generated function
function Get-TruncatedString {
    param (
        [string]$InputString,
        [int]$MaxLength = 249,
        [string]$Suffix = "..."
    )

    if ($null -eq $InputString) {
        return $null
    }

    if ($InputString.Length -gt $MaxLength) {
        $trimLength = $MaxLength - $Suffix.Length
        return $InputString.Substring(0, $trimLength) + $Suffix
    }

    return $InputString
}

# Connect to Pax 8 and fetch data
Connect-TDSynnex -RefreshToken $TDSRefreshToken

# Get All TD Synnex Products
$TDSynnexProducts = (Invoke-TDSynnexRequest -Method GET -Resource 'products').products

$TDSSubscriptions = (Invoke-TDSynnexRequest -Method GET -Resource 'subscriptions' -PaginationMode 'Pagination').items | Where-Object {$_.subscriptionStatus -eq 'active'}

#Connect to NinjaOne
$AuthBody = @{
    'grant_type'    = 'client_credentials'
    'client_id'     = $ClientID
    'client_secret' = $Secret
    'scope'         = 'monitoring management' 
}

$Result = Invoke-WebRequest -UseBasicParsing -uri "https://$($NinjaInstance)/ws/oauth/token" -Method POST -Body $AuthBody -ContentType 'application/x-www-form-urlencoded'

$NinjaAuthHeader = @{
    'Authorization' = "Bearer $(($Result.content | ConvertFrom-Json).access_token)"
}

$NinjaOneOrgs = (Invoke-WebRequest -UseBasicParsing -uri "https://$($NinjaInstance)/api/v2/organizations" -Method GET -Headers $NinjaAuthHeader -ContentType 'application/json' -ea stop).content | ConvertFrom-Json


Foreach ($OrgSubscriptions in $TDSSubscriptions | Group-Object customerName) {
    $Override = $NameOverride | Where-Object { $_.TDSynnexName -eq $OrgSubscriptions.name }
    if (($Override | Measure-Object).count -eq 1) {
        $OrganizationName = $Override.NinjaOneName
    }
    else {
        $OrganizationName = $OrgSubscriptions.name
    }

    if ($OrganizationName -notin $NinjaOneOrgs.name) {
        Write-Host "Error: '$($OrganizationName)' did not match an Organization in NinjaOne. Please create them in NinjaOne or update the Name Override settings in the script to map to the correct Organization"
        continue
    }

    foreach ($Subscription in $OrgSubscriptions.Group) {

        $Product = $TDSynnexProducts | Where-Object { $_.id -eq $Subscription.ccpProductId }
       
        if ($IncludeOrganizationName -eq $True) {
            $LicenseName = "$OrganizationName - $($Subscription.subscriptionName)"
        }
        else {
            $LicenseName = "$($Subscription.subscriptionName)"
        }

        $TermSettings = switch ($Subscription.subscriptionBillingTerm) {
            'P1M' { @{renewalUnit = 'MONTH'; value = 1; expirationDate = (Get-NinjaOneTime -Date $Subscription.subscriptionEndDate); autoRenewal = $True } }
            'P1Y' { @{renewalUnit = 'YEAR'; value = 1; expirationDate = (Get-NinjaOneTime -Date $Subscription.subscriptionEndDate); autoRenewal = $True } }
            'monthly' { @{renewalUnit = 'MONTH'; value = 1; expirationDate = (Get-NinjaOneTime -Date $Subscription.subscriptionEndDate); autoRenewal = $True } }
            'quarterly' { @{renewalUnit = 'MONTH'; value = 3; expirationDate = (Get-NinjaOneTime -Date $Subscription.subscriptionEndDate); autoRenewal = $True } }
            'annually' { @{renewalUnit = 'YEAR'; value = 1; expirationDate = (Get-NinjaOneTime -Date $Subscription.subscriptionEndDate); autoRenewal = $True } }
            default { $Null }
        }

        $CreateUpdateLicense = @{
            name          = $LicenseName
            description   = ''
            type          = 'CUSTOM'
            publisherName = $Product.attachedPrograms.displayName
            vendorName    = 'TD Synnex'
            scope         = @{
                organizationNames = @($OrganizationName)
            }
            quantity      = $Subscription.subscriptionTotalLicenses
            currentUsage  = $Subscription.subscriptionTotalLicenses
            costMode      = 'PER_LICENSE'
            cost          = $Subscription.cost
            term          = $TermSettings
        } | ConvertTo-Json

        try {
            $NinjaOneLicense = (Invoke-WebRequest -UseBasicParsing -uri "https://$($NinjaInstance)/api/v2/software-license/upsert" -Method POST -Headers $NinjaAuthHeader -Body $CreateUpdateLicense -ContentType 'application/json' -ea stop).content | ConvertFrom-Json
            Write-Host "Created / updated license $($LicenseName) for $($OrganizationName)"
        }
        catch {
            Write-Host "Error: Failed to create / update license $($LicenseName) for $($OrganizationName): $($_)"
        }

        $NinjaOneLicense.term = $TermSettings
        try {
            $NinjaOneLicense = (Invoke-WebRequest -UseBasicParsing -uri "https://$($NinjaInstance)/api/v2/software-license/$($NinjaOneLicense.id)" -Method PUT -Headers $NinjaAuthHeader -Body ($NinjaOneLicense | ConvertTo-Json) -ContentType 'application/json' -ea stop).content | ConvertFrom-Json
            Write-Host "Term settings updated for $($LicenseName) for $($OrganizationName)"
        }
        catch {
            ($NinjaOneLicense | ConvertTo-Json)
            Write-Host "Error: Failed to set term for license $($LicenseName) for $($OrganizationName): $($_)"
        }
        

    }
        
}

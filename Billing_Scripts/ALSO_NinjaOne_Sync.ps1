# NinjaOne ALSO Sync
# This script will sync subscription data from ALSO to NinjaOne License Management

#### Settings ####

# Set if you would like to include the NinjaOne Organization in the license name or not
$IncludeOrganizationName = $True

# If your company names do not match in ALSO and NinjaOne you can specify the overriden names here. If they do match this can be left as $NameOverride = @()
$NameOverride = @(
    @{  
        ALSOName     = 'Company 1 Ltd'
        NinjaOneName = 'Company 1' 
    },
    @{  
        ALSOName     = 'Example Customer'
        NinjaOneName = 'Example Organization' 
    }
)

#### Credentials ####
# ALSO Settings
$ALSOInstance = Ninja-Property-Get alsoInstance
$ALSOAccountID = Ninja-Property-Get alsoAccountId
$ALSOUsername = Ninja-Property-Get alsoUsername
$ALSOPassword = Ninja-Property-Get alsoPassword

# NinjaOne API Details
$ClientID = Ninja-Property-Get ninjaoneClientId
$Secret = Ninja-Property-Get ninjaoneClientSecret
$NinjaInstance = Ninja-Property-Get ninjaoneInstance


$ProgressPreference = 'SilentlyContinue'

#### Functions ####

function Connect-ALSO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Instance,
        [Parameter(Mandatory = $true)]
        [string]$Username,
        [Parameter(Mandatory = $true)]
        [string]$Password

    )

    $ALSOAuthBody = @{
        username = $ALSOUsername
        password = $ALSOPassword
    } | ConvertTo-Json
    
    try {
        $Response = Invoke-WebRequest -UseBasicParsing -Method POST -Uri "https://$($Instance)/SimpleAPI/SimpleAPIService.svc/rest/GetSessionToken" -ContentType 'application/json' -Body $ALSOAuthBody
        $Script:ALSOToken = ($Response | ConvertFrom-Json)
        $Script:ALSOInstance = $Instance
    }
    catch {
        Write-Host $_ -ForegroundColor Red
    }
 
}

function Invoke-ALSORequest {
    [CmdletBinding()]
    Param(
        [string]$Resource,
        [string]$ResourceFilter,
        [string]$Body
    )
	
    if (!$script:ALSOToken) {
        Write-Host "Please run 'Connect-ALSO' first" -ForegroundColor Red
    }
    else {
	
        $headers = @{
            Authenticate = "CCPSessionId $($script:ALSOToken)"
        }

        try {
            if ($Null -ne $Body) {
                $Response = Invoke-WebRequest -UseBasicParsing -Method POST -Uri ("https://$($Script:ALSOInstance)/SimpleAPI/SimpleAPIService.svc/rest/" + $Resource) -ContentType 'application/json' -Body $Body -Headers $headers -ea stop
            }
            else {
                $Response = Invoke-WebRequest -UseBasicParsing -Method POST -Uri ("https://$($Script:ALSOInstance)/SimpleAPI/SimpleAPIService.svc/rest/" + $Resource + $ResourceFilter) -ContentType 'application/json' -Headers $headers -ea stop
            }
            $Result = $Response | ConvertFrom-Json

            return $Result
        }
        catch {
            if ($_.Response.StatusCode -eq 429) {
                Write-Warning "Rate limit exceeded. Waiting to try again."
                Start-Sleep 8
                $Result = Invoke-ALSORequest -Resource $Resource -ResourceFilter $ResourceFilter -Body $Body
            }
            else {
                Write-Host "Error: An Error Occured $($_.message) "
            }
        }    
		
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

#### Script ####

# Connect to ALSO and fetch data
Connect-ALSO -Instance $ALSOInstance -Username $ALSOUsername -Password $ALSOPassword

$ALSOBody = @{
    accountId = $ALSOAccountID
} | ConvertTo-Json

# Get All ALSO Companies
$ALSOCompanies = Invoke-ALSORequest -resource "GetCompanies" -body $ALSOBody

# Fetch product info
$ALSOMarketPlaces = Invoke-ALSORequest -resource "GetMarketplaces" -body '{}'

$AlsoMarketPlaceList = @{
    marketplaceId = $ALSOMarketPlaces[0].Id
} | ConvertTo-Json
$ALSOMarketplaceItems = Invoke-ALSORequest -resource "ListMarketplaceServices" -body $AlsoMarketPlaceList

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

# Fetch Orgs from NinjaOne
$NinjaOneOrgs = (Invoke-WebRequest -UseBasicParsing -uri "https://$($NinjaInstance)/api/v2/organizations" -Method GET -Headers $NinjaAuthHeader -ContentType 'application/json' -ea stop).content | ConvertFrom-Json

foreach ($Company in $ALSOCompanies) {
    # See if there is an overriden name for it
    $Override = $NameOverride | Where-Object { $_.ALSOName -eq $Company.CompanyName }
    if (($Override | Measure-Object).count -eq 1) {
        $OrganizationName = $Override.NinjaOneName
    }
    else {
        $OrganizationName = $Company.CompanyName
    }

    # Match the overriden name to Organizations in NinjaOne and skip if not matched.
    if ($OrganizationName -notin $NinjaOneOrgs.name) {
        Write-Host "Error: '$($OrganizationName)' did not match an Organization in NinjaOne. Please create them in NinjaOne or update the Name Override settings in the script to map to the correct Organization"
        continue
    }

    Write-Host "Processing $($OrganizationName)"

    $ALSOSubscriptionBody = @{
        parentAccountId = $Company.AccountId
        resellerContext = $ALSOAccountID
    } | ConvertTo-Json
    $CompanySubscriptions = Invoke-ALSORequest -resource "GetSubscriptions" -body $ALSOSubscriptionBody | Where-Object {$_.AccountState -eq 'Active'}
    

    foreach ($Subscription in $CompanySubscriptions) {

        if (!$Subscription.PriceableItems[0].CommitementPeriodInMonths) {
            Write-Host "Not a recurring subscription"
            continue
        }

        $Product = $ALSOMarketplaceItems | Where-Object { $_.ProductName -eq $Subscription.ServiceName }
        if (($Product | Measure-Object).count -ne 1) {
            Write-Host "Error: $($Subscription.ServiceName) was not matched to a product and will not be synced"
            continue
        }

        # Add the org name to the license name if enabled.
        if ($IncludeOrganizationName -eq $True) {
            $LicenseName = "$OrganizationName - $($Subscription.ServiceDisplayName)"
        }
        else {
            $LicenseName = "$($Subscription.ServiceDisplayName)"
        }

        # Check for renewal
        if ($Subscription.AdvancePeriodEndAction -eq 'Renew') {
            $Renew = $True
        }
        else {
            $Renew = $False
        }

        # Populate the term settings if ALSO returns a commitment
        $TermSettings = @{
            renewalUnit    = 'MONTH'
            value          = $Subscription.PriceableItems[0].CommitementPeriodInMonths;
            expirationDate = (Get-NinjaOneTime -Date $Subscription.ContractEndDate)
            autoRenewal    = $Renew
        }

        $Quantity = ($Subscription.fields | Where-Object { $_.Name -eq 'Quantity' }).value

        # Build the body for an upsert
        $CreateUpdateLicense = @{
            name          = $LicenseName
            description   = (Get-TruncatedString -InputString $Subscription.PriceableItems[0].PriceableItemDescription)
            type          = 'CUSTOM'
            publisherName = $Product.OwnerName
            vendorName    = 'ALSO'
            scope         = @{
                organizationNames = @($OrganizationName)
            }
            quantity      = $Quantity
            currentUsage  = $Quantity
            costMode      = 'PER_LICENSE'
            cost          = [math]::Round(($Subscription.PriceableItems[0].PurchasePrice), 2)
            term          = $TermSettings
        } | ConvertTo-Json

        # Perform the upsert
        try {
            $NinjaOneLicense = (Invoke-WebRequest -UseBasicParsing -uri "https://$($NinjaInstance)/api/v2/software-license/upsert" -Method POST -Headers $NinjaAuthHeader -Body $CreateUpdateLicense -ContentType 'application/json' -ea stop).content | ConvertFrom-Json
            Write-Host "Created / updated license $($LicenseName) for $($OrganizationName)"
        }
        catch {
            Write-Host "Error: Failed to create / update license $($LicenseName) for $($OrganizationName): $($_.message)"
        }


    }

}

# NinjaOne Pax8 Sync
# This script will syncronise subscription data from Pax8 into NinjaOne Software License Management.

#### Settings ####

# Set if you would like to include the NinjaOne Organization in the license name or not
$IncludeOrganizationName = $True


# If your company names do not match in Pax8 and NinjaOne you can specify the overriden names here. If they do match this can be left as $NameOverride = @()
$NameOverride = @(
    @{  
        Pax8Name     = 'Company 1 Ltd'
        NinjaOneName = 'Company 1' 
    },
    @{  
        Pax8Name     = 'Example Customer'
        NinjaOneName = 'Example Organization' 
    }
)

#### Credentials ####
# Pax 8 Settings
$Pax8ClientID = Ninja-Property-Get pax8ClientID
$Pax8ClientSecret = Ninja-Property-Get pax8ClientSecret

# NinjaOne API Details
$ClientID = Ninja-Property-Get ninjaoneClientId
$Secret = Ninja-Property-Get ninjaoneClientSecret
$NinjaInstance = Ninja-Property-Get ninjaoneInstance

$ProgressPreference = 'SilentlyContinue'

#### Functions ####

function Connect-Pax8 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientID,
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret

    )

    $auth = @{
        client_id     = $ClientID
        client_secret = $ClientSecret
        audience      = "api://p8p.client"
        grant_type    = "client_credentials"
    }
    
    $json = $auth | ConvertTo-json -Depth 2

    try {
        $Response = Invoke-WebRequest -UseBasicParsing -Method POST -Uri 'https://login.pax8.com/oauth/token' -ContentType 'application/json' -Body $json
        $script:Pax8Token = ($Response | ConvertFrom-Json).access_token
    }
    catch {
        Write-Host $_ -ForegroundColor Red
    }
 

}

function Invoke-Pax8Request {
    [CmdletBinding()]
    Param(
        [string]$Method,
        [string]$Resource,
        [string]$ResourceFilter,
        [string]$Body
    )
	
    if (!$script:Pax8Token) {
        Write-Host "Please run 'Connect-Pax8' first" -ForegroundColor Red
    }
    else {
	
        $headers = @{
            Authorization = "Bearer $($script:Pax8Token)"
        }



        try {
            if (($Method -eq "put") -or ($Method -eq "post") -or ($Method -eq "delete")) {
                $Response = Invoke-WebRequest -UseBasicParsing -Method $method -Uri ('https://api.pax8.com/v1/' + $Resource) -ContentType 'application/json' -Body $Body -Headers $headers -ea stop
                $Result = $Response | ConvertFrom-Json
            }
            else {
                $Complete = $false
                $PageNo = 0
                $Result = do {
                    $Response = Invoke-WebRequest -UseBasicParsing -Method $method -Uri ('https://api.pax8.com/v1/' + $Resource + "?page=$PageNo&size=200" + $ResourceFilter) -ContentType 'application/json' -Headers $headers -ea stop
                    $JSON = $Response.content | ConvertFrom-Json
                    if ($JSON.Page) {
                        if (($JSON.Page.totalPages - 1) -eq $PageNo -or $JSON.Page.totalPages -eq 0) {
                            $Complete = $true
                        }
                        $PageNo = $PageNo + 1
                        $JSON.content
                    }
                    else {
                        $Complete = $true
                        $JSON
                    }
                } while ($Complete -eq $false)
            }
        }
        catch {
            if ($_.Response.StatusCode -eq 429) {
                Write-Warning "Rate limit exceeded. Waiting to try again."
                Start-Sleep 8
                $Result = Invoke-Pax8Request -Method $Method -Resource $Resource -ResourceFilter $ResourceFilter -Body $Body
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

#### Script ####

# Connect to Pax 8 and fetch data
Connect-Pax8 -ClientID $Pax8ClientID -ClientSecret $Pax8ClientSecret

# Get All Pax 8 Companies
$Pax8Companies = Invoke-Pax8Request -method get -resource "companies"

# Get Pax 8 Products
[System.Collections.Generic.List[PSCustomObject]]$Pax8Products = Invoke-Pax8Request -method get -resource "products"

$Subscriptions = Invoke-Pax8Request -method get -resource "subscriptions" | where-object { $_.status -eq 'Active' }

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

# Loop through all subscriptions per customer and update in NinjaOne
Foreach ($OrgSubscriptions in $Subscriptions | Group-Object companyId) {

    # Find the company in Pax8
    $Pax8Company = ($Pax8Companies | Where-Object { $_.id -eq $OrgSubscriptions.Name }).name
    
    # See if there is an overriden name for it
    $Override = $NameOverride | Where-Object { $_.Pax8Name -eq $Pax8Company }
    if (($Override | Measure-Object).count -eq 1) {
        $OrganizationName = $Override.NinjaOneName
    }
    else {
        $OrganizationName = $Pax8Company
    }

    # Match the overriden name to Organizations in NinjaOne and skip if not matched.
    if ($OrganizationName -notin $NinjaOneOrgs.name) {
        Write-Host "Error: '$($OrganizationName)' did not match an Organization in NinjaOne. Please create them in NinjaOne or update the Name Override settings in the script to map to the correct Organization"
        continue
    }

    # Loop through each subscription for the Organization
    foreach ($Subscription in $OrgSubscriptions.Group) {
        $Product = $Pax8Products | Where-Object { $_.id -eq $Subscription.productId }
        if (($Product | measure-object).count -ne 1) {
            $FetchedProduct = Invoke-Pax8Request -method get -resource "products/$($Subscription.productId)"
            if (($FetchedProduct | measure-object).count -ne 1) {
                Write-Host "Error: Product $($Pax8Sub.productId) not found in Pax8"
                continue
            }
            $Pax8Products.add($FetchedProduct)
            $Product = $FetchedProduct
        }

        # Add the org name to the license name if enabled.
        if ($IncludeOrganizationName -eq $True) {
            $LicenseName = "$OrganizationName - $($Product.Name)"
        }
        else {
            $LicenseName = "$($Product.Name)"
        }

        # Populate the term settings if Pax8 returns a commitment
        if ($Subscription.commitment) {
            $TermSettings = switch ($Subscription.commitment.term) {
                'Monthly' { @{renewalUnit = 'MONTH'; value = 1; expirationDate = (Get-NinjaOneTime -Date $Subscription.commitment.endDate); autoRenewal = $True } }
                'Annual' { @{renewalUnit = 'YEAR'; value = 1; expirationDate = (Get-NinjaOneTime -Date $Subscription.commitment.endDate); autoRenewal = $True } }
                '1-Year' { @{renewalUnit = 'YEAR'; value = 1; expirationDate = (Get-NinjaOneTime -Date $Subscription.commitment.endDate); autoRenewal = $True } }
                '2-Year' { @{renewalUnit = 'YEAR'; value = 2; expirationDate = (Get-NinjaOneTime -Date $Subscription.commitment.endDate); autoRenewal = $True } }
                '3-Year' { @{renewalUnit = 'YEAR'; value = 3; expirationDate = (Get-NinjaOneTime -Date $Subscription.commitment.endDate); autoRenewal = $True } }
                'One-Time' { $Null }
                'Trial' { $Null }
                'Activation' { $Null }
            }
        }

        # Build the body for an upsert
        $CreateUpdateLicense = @{
            name          = $LicenseName
            description   = (Get-TruncatedString -InputString $Product.shortDescription)
            type          = 'CUSTOM'
            publisherName = $Product.vendorName
            vendorName    = 'Pax8'
            scope         = @{
                organizationNames = @($OrganizationName)
            }
            quantity      = $Subscription.quantity
            currentUsage  = $Subscription.quantity
            costMode      = 'PER_LICENSE'
            cost          = $Subscription.partnerCost
            term          = $TermSettings
        } | ConvertTo-Json

        # Perform the upsert
        try {
            $NinjaOneLicense = (Invoke-WebRequest -UseBasicParsing -uri "https://$($NinjaInstance)/api/v2/software-license/upsert" -Method POST -Headers $NinjaAuthHeader -Body $CreateUpdateLicense -ContentType 'application/json' -ea stop).content | ConvertFrom-Json
            Write-Host "Created / updated license $($LicenseName) for $($OrganizationName)"
        }
        catch {
            Write-Host "Error: Failed to create / update license $($LicenseName) for $($OrganizationName): $($_)"
        }

        # NinjaOne doesn't currently support the term through upsert so if we have a term it will need to be manually set. This can be removed when Ninja adds term support to upsert.
        if ($Subscription.commitment -and $Null -ne $TermSettings) {
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
        
}

# Author: Luke Whitelock
# Date: 2023-03-18
# Website: https://mspp.io

############ Settings ############

# Create a new API key in Ninja set to "API Services (machine-to-machine)"
# Enter a name
# Leave Redirect URIs blanks
# Tick all the scopes
# Select "Client Credentials" as the Allowed Grant Types

# Enter the API Key details here:
$NinjaURL = 'https://eu.ninjarmm.com'
$ClientID = 'ABCDEFGHIJKLMN-1234456677'
$Secret = 'asdasdasdsadasdasdas-asdasdsadsadsasadadasdsa'

# Specify the Organization you would like to copy the policy mapping from
$CopySettingsFromOrg = "Luke's Testing"

# Specify the location of the Import CSV
# It should have the following format:
# Organization_Name,Location_Name,Location_Address,Location_Description
# Testing 123,Location 123 1,"Testing Road 1, Testington, Test Street",Testing Loc 1
# Testing 123,Location 123 2,"Testing Road 2, Testington, Test Street",Testing Loc 2
# Testing 123,Location 123 3,"Testing Road 3, Testington, Test Street",Testing Loc 3
# Testing 456,Location 456 1,"Testing Road 4, Testington, Test Street",Testing Loc 4
# Testing 456,Location 456 2,"Testing Road 5, Testington, Test Street",Testing Loc 5
# Testing 789,Location 789 1,"Testing Road 6, Testington, Test Street",Testing Loc 6

$ImportFile = 'c:\temp\ImportNinjaOrgsLocs.csv'

# Node approval mode for your organizations (AUTOMATIC, MANUAL REJECT)
$NodeApproval = 'AUTOMATIC'



############ End of Settings ############

try {
    # Connect to Ninja
    $AuthBody = @{
        'grant_type'    = 'client_credentials'
        'client_id'     = $ClientID
        'client_secret' = $Secret
        'scope'         = 'monitoring management control'
    }

    $Result = Invoke-WebRequest -uri "$($NinjaURL)/ws/oauth/token" -Method POST -Body $AuthBody -ContentType 'application/x-www-form-urlencoded'

    $AuthHeader = @{
        'Authorization' = "Bearer $(($Result.content | ConvertFrom-Json).access_token)"
    }

    # Obtain current organizations
    $Orgs = (Invoke-WebRequest -uri "$($NinjaURL)/api/v2/organizations" -Method GET -Headers $AuthHeader -ContentType 'application/json').content | convertfrom-json

    # Locate the organization to be used to copy settings from.
    $SettingsOrg = $Orgs | Where-Object { $_.name -eq $CopySettingsFromOrg }

    if (($SettingsOrg | measure-object).count -ne 1) {
        throw "Organization to copy settings from was not found"
    }

    # Obtain the default settings
    $SettingOrgFull = (Invoke-WebRequest -uri "$($NinjaURL)/v2/organization/$($SettingsOrg.id)" -Method GET -Headers $AuthHeader -ContentType 'application/json').content | convertfrom-json

    # Load the import CSV
    $ItemsToImport = Import-Csv -Path $ImportFile

    # Find unique Orgs
    $ImportOrgs = ($ItemsToImport | select-object -unique Organization_Name).Organization_Name

    # Loop through and process each Org
    foreach ($Org in $ImportOrgs){
        # Check the Org doesn't already exist
        $LookupOrg = $Orgs | where-object {$_.name -eq $org}
        if (($LookupOrg | Measure-Object).count -ne 0){
            Write-Error "Organization $Org already exists"
            continue
        }
  
        # Process locations
        [System.Collections.Generic.List[PSCustomObject]]$Locations = $ItemsToImport | where-object {$_.Organization_Name -eq $Org} | Foreach-Object {
            [PSCustomObject]@{
            name = $_.Location_Name
            address = $_.Location_Address
            description = $_.Location_Description
            }
        }

        # Create the Organization creation body
        $OrgCreate = @{
            name = $Org
            nodeApprovalMode = $NodeApproval
            locations = $Locations
            policies = $SettingOrgFull.policies        
        } | ConvertTo-Json

        # Create the Organization
        $Result = Invoke-WebRequest -uri "$($NinjaURL)/api/v2/organizations" -Method POST -Headers $AuthHeader -ContentType 'application/json' -Body $OrgCreate
   
    }

}

catch {
    Write-Host "An Error Occurred $_"
}

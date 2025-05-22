######## API 301 Webinar ########
# Filtering Examples
# https://www.youtube.com/watch?v=dQRUpDJwio4
#
######## Client Credentials ########
# Securely fetch your credentials from a credential store. For example NinjaOne Secure Custom Fields
# See here for an example of how to do this in a secure way https://docs.mspp.io/ninjaone/getting-started

$ClientID = 'My Client ID'
$Secret = 'My Secret'

$AuthBody = @{
    'grant_type' = 'client_credentials'
    'client_id' = $ClientID
    'client_secret' = $Secret
    'scope' = 'monitoring management control' 
}

$Result = Invoke-WebRequest -uri "https://eu.ninjarmm.com/ws/oauth/token" -Method POST -Body $AuthBody -ContentType 'application/x-www-form-urlencoded'

$AuthHeader = @{
    'Authorization' = "Bearer $(($Result.content | ConvertFrom-Json).access_token)"
}


######## Filtering by Tags ########
$Tags = (Invoke-WebRequest -uri "https://eu.ninjarmm.com/api/v2/tag" -Method Get -Headers $AuthHeader -ContentType 'application/json').Content | ConvertFrom-Json

$Tags.tags

$Filter = 'tagId notin (1,2)'

$Encoded = [uri]::EscapeDataString($Filter)

$Devices = (Invoke-WebRequest -uri "https://eu.ninjarmm.com/api/v2/devices?df=$($Encoded)" -Method Get -Headers $AuthHeader -ContentType 'application/json').Content | ConvertFrom-Json

$Devices

######## Mutliple Filters ########
$Filter = 'tagId in (1,2) AND online'

$Encoded = [uri]::EscapeDataString($Filter)

$Devices = (Invoke-WebRequest -uri "https://eu.ninjarmm.com/api/v2/devices?df=$($Encoded)" -Method Get -Headers $AuthHeader -ContentType 'application/json').Content | ConvertFrom-Json

$Devices

######## Local Filtering ########
$CustomFields = (Invoke-WebRequest -uri "https://eu.ninjarmm.com/api/v2/queries/custom-fields-detailed?fields=textTest" -Method Get -Headers $AuthHeader -ContentType 'application/json').Content | ConvertFrom-Json
$CustomFields.results

$MatchedDevices = $CustomFields.results | ForEach-Object {
     $CurrentDevice = $_
    if ((($CurrentDevice.Fields | Where-Object {$_.name -eq 'textTest' -and $_.value -eq 'Testing'})| Measure-Object).count -eq 1){
        $CurrentDevice
    }
}

$MatchedDevices

$Filter = "id in ($($MatchedDevices.deviceId -join ','))"
$Encoded = [uri]::EscapeDataString($Filter)
$Devices = (Invoke-WebRequest -uri "https://eu.ninjarmm.com/api/v2/devices?df=$($Encoded)" -Method Get -Headers $AuthHeader -ContentType 'application/json').Content | ConvertFrom-Json
$Devices

######## Organization Custom Fields ########
$Filter = 'of=cf=textTest=Testing'

$Organizations = (Invoke-WebRequest -uri "https://eu.ninjarmm.com/api/v2/organizations?$($Filter)" -Method Get -Headers $AuthHeader -ContentType 'application/json').Content | ConvertFrom-Json

$Organizations



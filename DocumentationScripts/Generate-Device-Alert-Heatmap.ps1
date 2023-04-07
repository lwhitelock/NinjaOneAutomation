# Author: Luke Whitelock
# Date: 2023-04-07
# License: MIT
# Details: https://mspp.io/ninjaone-device-alert-heat-map/

$Secret = Get-AzKeyVaultSecret -vaultName $VaultName -name "NinjaOneSecret" -AsPlainText
$ClientID = Get-AzKeyVaultSecret -vaultName $VaultName -name "NinjaOneClientID" -AsPlainText
$NinjaURL = 'https://eu.ninjarmm.com'

$HeatMapField = 'alertHeatMap'


function Get-MapColour {
    param (
        $MapList,
        $Count
    )

    $Maximum = ($MapList | measure-object).count - 1
    $Index = [array]::indexof($MapList, "$count")
    $Sixth = $Maximum / 6

    if ($count -eq 0) {
        return ""
    }
    elseif ($Index -ge 0 -and $Index -le $Sixth * 4) {
        return "$Count"
    }
    elseif ($Index -gt $Sixth * 4 -and $Index -le $Sixth * 5) {
        return "<strong>$Count</strong>"
    }
    elseif ($Index -gt $Sixth * 5 -and $Index -lt $Maximum) {
        return "<h2>$Count</h2>"
    }
    else {
        return "<h1>$Count</h1>"
    }
    
}

function Get-HeatMap {
    param(
        $InputData,
        $XValues,
        $YValues
    )

    $BaseMap = [ordered]@{}
    foreach ($y in $YValues) {
        foreach ($x in $XValues) {
            $BaseMap.add("$($y)$($x)", 0)
        }
    }

    foreach ($DataToParse in $InputData) {
        $BaseMap["$($DataToParse)"] += 1
    }

    $MapValues = $BaseMap.values | Where-Object { $_ -ne 0 } | Group-Object
    $MapList = $MapValues.Name

    $TableHTML = '<table width="100%" style="border-collapse: collapse;"><tbody><tr><td style="padding: 5px;border-width: 1px;border-style: solid;border-color: #D1D0DA;word-break: break-word;box-sizing: border-box;text-align:left;"></td>'

    foreach ($x in $XValues) {
        $TableHTML = $TableHTML + '<td style="padding: 5px;border-width: 1px;border-style: solid;border-color: #D1D0DA;word-break: break-word;box-sizing: border-box;text-align:left;"><strong>' + $x + '</strong></td>'
    }
    
    $TableHTML = $TableHTML + '</tr>'

    
    foreach ($y in $YValues) {
        $RowHTML = ''
        foreach ($x in $XValues) {
            $RowHTML = $RowHTML + '<td style="padding: 5px;border-width: 1px;border-style: solid;border-color: #D1D0DA;word-break: break-word;box-sizing: border-box;text-align:left;">' + $(Get-MapColour -MapList $MapList -Count $($BaseMap."$($y)$($x)")) + '</td>'
        }
        
        $TableHTML = $TableHTML + '<tr><td style="padding: 5px;border-width: 1px;border-style: solid;border-color: #D1D0DA;word-break: break-word;box-sizing: border-box;text-align:left;">' + "$y</td>$RowHTML</tr>"
    }

    $TableHTML = $TableHTML + '</table>'

    return $TableHTML
}

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

[datetime]$origin = '1970-01-01 00:00:00'
$XValues = @("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23")
$YValues = @("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")

$Devices = (Invoke-WebRequest -uri "$($NinjaURL)/api/v2/devices" -Method GET -Headers $AuthHeader -ContentType 'application/json').content | convertfrom-json

foreach ($Device in $Devices) {

    $Activities = ((Invoke-WebRequest -uri "$($NinjaURL)/api/v2/device/$($Device.id)/activities?activityType=CONDITION&status=TRIGGERED" -Method GET -Headers $AuthHeader -ContentType 'application/json').content | convertfrom-json).activities

    $ParsedDates = foreach ($Activity in $Activities) {
        $ConditionDate = $origin.AddSeconds($Activity.activityTime)
        "$($ConditionDate.dayofweek)$($ConditionDate.hour)"
    }

    $HTMLHeatmapTable = Get-Heatmap -InputData $ParsedDates -XValues $XValues -YValues $YValues

    $HTML = @{
        'html' = $HTMLHeatmapTable
    } | ConvertTo-Json | Out-String
    
    $UpdateBody = @{
        "$HeatMapField" = $HTML
    } | ConvertTo-Json

    
    $Result = Invoke-WebRequest -uri "$($NinjaURL)/api/v2/device/$($Device.id)/custom-fields" -Method PATCH -Headers $AuthHeader -ContentType 'application/json' -Body $UpdateBody

}

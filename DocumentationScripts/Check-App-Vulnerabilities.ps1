# Author: Luke Whitelock
# Based on: https://github.com/vulmon/Vulmap/tree/master/Vulmap-Windows
# Date: 2023-06-20
# Website: https://mspp.io
# License: GPL-3.0
# Details: 
# This will look for any applications installed on a machine or in a user's profile 
# and then check their version against the vulmnon.com database. The results are 
# written to custom fields where conditions can be setup to create alerts.

# Create a Text custom field for the overall status:
$VulnStatusField = 'vulnerabilityStatus'

# Create a Multi-Line custom field for the detailed output.
$VulnDetails = 'vulnerabilityDetails'

# Create a directory to store logs.
$VulnLogDir = "$env:SystemDrive\RMM\Logs\VulnScans"

# Add any CVEs you wish to ignore here.
$ExcludeCVES = @('CVE-3000-123', 'CVE-3000-456')

$registry_paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
$vulMapScannerUri = 'https://vulmon.com/scannerapi_vv211'

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Collections.Generic.List[PSCustomObject]]$Inventory = @()

function Get-ProductList () {
  Write-Verbose 'Reading installed software from registry.'
  foreach ($registry_path in $registry_paths) {
    $subkeys = Get-ChildItem -Path $registry_path -ErrorAction SilentlyContinue

    if ($subkeys) {
      ForEach ($key in $subkeys) {
        $DisplayName = $key.getValue('DisplayName')

        if ($null -ne $DisplayName) {
          $DisplayVersion = $key.GetValue('DisplayVersion')

          $Inventory.add([PSCustomObject]@{
              PSTypeName      = 'System.Software.Inventory'
              DisplayName     = $DisplayName.Trim()
              DisplayVersion  = $DisplayVersion
              NameVersionPair = $DisplayName.Trim() + $DisplayVersion
              Installed       = 'Machine Wide'
            })
        }
      }
    }
  }
}

function Get-UsersProductList () {
  Write-Verbose 'Reading installed software from registry.'

  # Define a Provider Drive to access HKEy_Users
  New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null

  # define the user keys to be skipped (system / service keys)
  $Skip_User_Keys = @('.default') 

  # open / connect to the registry / read the user subkeys
  $hkeyUsersSubkeys = $(  
    ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('USERS', $env:COMPUTERNAME)).GetSubKeyNames() | 
    # skip any undesirable keys
    ForEach-Object { if ($_ -notin $Skip_User_Keys) { $_ } } |
    ForEach-Object { if ($_.indexof('_Classes') -LT 0) { $_ } }
  ) 

  # Loop through the users
  $hkeyUsersSubkeys | ForEach-Object {

    $UserSIDPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$_"
    $Username = (Get-ItemProperty -Path $UserSIDPath).ProfileImagePath.Split('\')[-1]
        
    $UsersKeys = "REGISTRY::HKEY_USERS\$_\Software\Microsoft\Windows\CurrentVersion\Uninstall", "REGISTRY::HKEY_USERS\$_\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

    foreach ($registry_path in $UsersKeys) {
      $subkeys = Get-ChildItem -Path $registry_path -ErrorAction SilentlyContinue
    
      if ($subkeys) {
        ForEach ($key in $subkeys) {
          $DisplayName = $key.getValue('DisplayName')
    
          if ($null -ne $DisplayName) {
            $DisplayVersion = $key.GetValue('DisplayVersion')
            Write-Host "Adding $($DisplayName.Trim())"
            $Inventory.add([PSCustomObject]@{
                PSTypeName      = 'System.Software.Inventory'
                DisplayName     = $DisplayName.Trim()
                DisplayVersion  = $DisplayVersion
                NameVersionPair = $DisplayName.Trim() + $DisplayVersion
                Installed       = $Username
              })
          }
        }
      }
    }
  }   
}

function Get-JsonRequestBatches ($inventory) {
  $numberOfBatches = [math]::Ceiling(@($inventory).count / 100)

  for ($i = 0; $i -lt $numberOfBatches; $i++) {
    Write-Verbose "Submitting software to vulmon.com api, batch '$i' of '$numberOfBatches'."
    $productList = $inventory |
    Select-Object -First 100 |
    ForEach-Object {
      [pscustomobject]@{
        product = $_.DisplayName
        version = if ($_.DisplayVersion) { $_.DisplayVersion } else { '' }
      }
    }

    $inventory = $inventory | Select-Object -Skip 100

    $json_request_data = [ordered]@{
      os           = (Get-CimInstance Win32_OperatingSystem -Verbose:$false).Caption
      product_list = @($productList)
    } | ConvertTo-Json

    $webRequestSplat = @{
      Uri             = $vulMapScannerUri
      Method          = 'POST'
      Body            = @{ querydata = $json_request_data }
      UseBasicParsing = $True
    }

    if ($Proxy) { $webRequestSplat.Proxy = $Proxy }
        (Invoke-WebRequest @webRequestSplat).Content | ConvertFrom-Json
  }
}

function Resolve-RequestResponses ($responses) {
  $count = 0
  foreach ($response in $responses) {
    foreach ($vuln in ($response | Select-Object -ExpandProperty results -ErrorAction SilentlyContinue)) {
      Write-Verbose 'Parsing results from vulmon.com api.'
      $interests = $vuln |
      Select-Object -Property query_string -ExpandProperty vulnerabilities | Where-Object { $_.cveid -notin $ExcludeCVES } |
      ForEach-Object {
        [PSCustomObject]@{
          Product                = $_.query_string
          'CVE ID'               = $_.cveid
          'Risk Score'           = $_.cvssv2_basescore
          'Vulnerability Detail' = $_.url
          'Name'                 = $vuln.user_provided_product
          'Version'              = $vuln.user_provided_version
          'Installed In'         = ($Inventory | Where-Object { $_.DisplayName -eq $vuln.user_provided_product -and $_.DisplayVersion -eq $vuln.user_provided_version }).Installed -join ', '
        }
      }

      $count += $interests.Count
      Write-Verbose "Found '$count' vulnerabilities so far."

      $interests
    }
  }
}

function Invoke-VulnerabilityScan ($Inventory) {
  Write-Host 'Vulnerability scanning started...'
  $responses = Get-JsonRequestBatches $inventory
  $vuln_list = Resolve-RequestResponses $responses
  Write-Host "Checked $(@($inventory).count) items" -ForegroundColor Green

  if ($null -like $vuln_list) {
    Write-Host "No vulnerabilities detected - Checked $(@($inventory).count) items"
    $null = Ninja-Property-Set $VulnStatusField "No Vulnerabilities Detected - $(Get-Date)"
    $null = Ninja-Property-Set $VulnDetails "$(@($inventory).count) items checked no vulnerabilities found."
  }
  else {
    $VulnText = ForEach ($Vul in $vuln_list) {
      if ($null -ne $Vul.'Risk Score') { $Risk = $Vul.'Risk Score' }
      else { $Risk = 'Unknown' }
      "------------------------------------`rProduct: $($Vul.Name) - $($Vul.Version)`rCVE ID: $($Vul.'CVE ID')`rRisk Score: $($Risk)`rInstalled For: $($Vul.'Installed In')`rDetail: $($Vul.'Vulnerability Detail')`r"
    } -join ''
    
    Write-Host "$($vuln_list.Count) Vulnerabilities Found"
    $VulnStatus = "$($vuln_list.Count) Vulnerabilities Found - $(Get-Date)"
    $null = Ninja-Property-Set $VulnStatusField $VulnStatus
    $VulnLog = "$VulnLogDir\VulnScan-$(Get-Date -Format 'yyyyMMdd-HHmm').txt"
    $VulnLogData = $VulnStatus + "`r" + $VulnText
    $VulnLogData | Out-File (New-Item -Path $VulnLog -Force)
    if (($VulnText | Measure-Object -Character).Characters -lt 10000) { $null = Ninja-Property-Set $VulnDetails $VulnText }
    else { $null = Ninja-Property-Set $VulnDetails "Vulnerability details exceeded 10,000 character limit.`rSee log for details: $VulnLog" }
    Write-Host "Log saved to $VulnLog"
  }
}

Get-ProductList
Get-UsersProductList
Invoke-VulnerabilityScan -inventory ($inventory | Sort-Object NameVersionPair -Unique)

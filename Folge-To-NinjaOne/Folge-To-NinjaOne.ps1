# Folge -> NinjaOne Sync
# Create a single page API application in NinjaOne
# Give it Monitoring and Management Scope
# Set it to authorization code
# Enter the Redirect URL exactly as below
# Save the application and set the client ID below, a secret is not required.
# Configure your NinjaOne instance URL below.


# Import necessary assemblies
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

#### NinjaOne Connection Settings
$ClientID = 'Your Client ID'
$NinjaOneInstance = 'eu.ninjarmm.com'
$RedirectURL = 'http://localhost:9090/'
####


# Variables to store user selections (Declared at script scope)
$script:IsConnected = $false         # Flag to check if connected
$script:SelectedUploadType = "Checklist"  # Default value
$script:SelectedOption = "Template"       # Default value
$script:SelectedOrganizationName = ""
$script:SelectedOrganizationId = ""
$script:SelectedFolder = ""
$script:SelectedFolderId = ""
$script:SelectedFilePath = ""
$script:filePathBox = $null
$script:orgCombo = $null
$script:StepList = $null    # Declare StepList at script scope
$script:pages = @()         # Declare pages at script scope
$script:currentIndex = 0
$script:connectButton = $null     # Declare connectButton at script scope
$script:connectionMessage = $null # Declare connectionMessage at script scope
$script:NextButton = $null        # Ensure NextButton is at script scope
$script:treeView = $null          # Declare treeView at script scope
$script:uploading = $false        # Flag to indicate if uploading is in progress

# Variables to store page indices
$script:PageIndices = @{
    Confirmation   = 0
    Uploading      = 0
    UploadComplete = 0
}

# XAML for the GUI
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Folge to NinjaOne Importer" Height="500" Width="800" WindowStartupLocation="CenterScreen">
    <Grid>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="200"/> <!-- Sidebar -->
            <ColumnDefinition Width="*"/>   <!-- Main Content -->
        </Grid.ColumnDefinitions>

        <!-- Sidebar with Step Indicator -->
        <StackPanel Grid.Column="0" Background="#2D2D30">
            <TextBlock Text="Steps" Foreground="White" FontSize="18" Margin="10"/>
            <ListBox Name="StepList" Background="#2D2D30" BorderThickness="0" Foreground="White" FontSize="16">
                <ListBoxItem Content="1. Connect"/>
                <ListBoxItem Content="2. Select File"/>
                <ListBoxItem Content="3. Choose Upload Type"/>
                <ListBoxItem Content="4. Additional Options"/>
                <!-- We will conditionally add steps based on selection -->
                <ListBoxItem Content="5. Confirmation"/>
            </ListBox>
        </StackPanel>

        <!-- Main Content Area -->
        <Grid Grid.Column="1" Name="MainContent" Margin="20">
            <!-- Content will be loaded dynamically -->
        </Grid>
    </Grid>
</Window>
"@

# Load the XAML
[xml]$xamlXML = $xaml
$reader = (New-Object System.Xml.XmlNodeReader $xamlXML)
$Window = [Windows.Markup.XamlReader]::Load($reader)

# Accessing Controls
$MainContent = $Window.FindName("MainContent")
$script:StepList = $Window.FindName("StepList")  # Assign to $script:StepList

# Function to update the step indicator
Function UpdateStepIndicator($stepIndex) {
    $script:StepList.SelectedIndex = $stepIndex
}

Function Get-FolderTree($parentId, $parentItem) {
    $childFolders = $script:FolderData | Where-Object { $_.parentid -eq $parentId }
    foreach ($folder in $childFolders) {
        $treeViewItem = New-Object System.Windows.Controls.TreeViewItem
        $treeViewItem.Header = $folder.name
        $treeViewItem.Tag = $folder.id  # Store the id in the Tag property
        Get-FolderTree -parentId $folder.id -parentItem $treeViewItem
        $parentItem.Items.Add($treeViewItem) | Out-Null
    }
}

function Get-Folder ($FolderID, $OrganizationID) {
    
    $Folder = (Invoke-WebRequest -uri "https://$($NinjaOneInstance)/api/v2/knowledgebase/folder?folderId=$FolderID&organizationId=$OrganizationID" -Method GET -Headers $AuthHeader -ContentType 'application/json').content | ConvertFrom-Json -depth 100

    if ($Null -eq $Folder.parentFolderId) {
        if ($null -ne $OrganizationID) {
            $Folder.Name = 'Organization Knowledge Base Root Folder'
        } else {
            $Folder.Name = 'Global Knowledge Base Root Folder'  
        }
    }

    $script:FolderData.add(
        [PSCustomObject]@{
            Name     = $Folder.name
            ID       = $Folder.id
            ParentID = $Folder.parentFolderId
        }
    )

    foreach ($SubFolder in ($Folder.content | Where-Object { $_.isFolder -eq $True })) {
        Get-Folder -FolderID $SubFolder.id -OrganizationID $OrganizationID
    }
}

Function Get-FolderPath($FolderID, $CurrentString = $Null, $ItemCount = 0) {
    $FolderItem = $script:FolderData | Where-Object { $_.id -eq $FolderID }
    if ($Null -ne $FolderItem.ParentID) {
        if ($ItemCount -eq 0) {
            $CurrentString = $FolderItem.name
        } else {
            $CurrentString = $FolderItem.name + '|' + $CurrentString
        }
        $ItemCount++
        $CurrentString = Get-FolderPath -FolderID $FolderItem.ParentID -CurrentString $CurrentString -ItemCount $ItemCount
    }
    Return $CurrentString
}

function TestImage {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('PSPath')]
        [string] $Path
    )

    PROCESS {

        $knownHeaders = @{
            jpg = @( "FF", "D8" );
            bmp = @( "42", "4D" );
            gif = @( "47", "49", "46" );
            tif = @( "49", "49", "2A" );
            png = @( "89", "50", "4E", "47", "0D", "0A", "1A", "0A" );
            pdf = @( "25", "50", "44", "46" );
        }

        # coerce relative paths from the pipeline into full paths

        if ($_ -ne $null) {
            $Path = $_.FullName
        }

        # read in the first 8 bits
        $bytes = Get-Content -LiteralPath $Path -AsByteStream -ReadCount 1 -TotalCount 8 -ErrorAction Ignore
        $retval = 'NONIMAGE'
        
        foreach ($key in $knownHeaders.Keys) {
            # make the file header data the same length and format as the known header
            $fileHeader = $bytes |
            Select-Object -First $knownHeaders[$key].Length |
            ForEach-Object { $_.ToString("X2") }
            if ($fileHeader.Length -eq 0) {
                continue
            }
            # compare the two headers
            $diff = Compare-Object -ReferenceObject $knownHeaders[$key] -DifferenceObject $fileHeader
            if (($diff | Measure-Object).Count -eq 0) {
                $retval = $key
            }
        }
        return $retval
    }
}

function Invoke-UploadNinjaImages($Images, $ImagePath, $EntityType) {

    [System.Collections.Generic.List[PSCustomObject]]$UploadedImages = @()

    Foreach ($Image in $Images) {
        try {
            $imageFullPath = "$ImagePath/$Image"
            $imageType = TestImage($imageFullPath)
            if ($imageType -ne 'NONIMAGE') {
                Write-Host "Uploading Image"
                $ImageName = ($imageFullPath -split '/')[-1]
                $multipartContent = [System.Net.Http.MultipartFormDataContent]::new()
                $FileStream = [System.IO.FileStream]::new($imageFullPath, [System.IO.FileMode]::Open)
                $fileHeader = [System.Net.Http.Headers.ContentDispositionHeaderValue]::new("form-data")
                $fileHeader.Name = 'files'
                $fileHeader.FileName = "$ImageName.$imageType"
                $fileContent = [System.Net.Http.StreamContent]::new($FileStream)
                $fileContent.Headers.ContentDisposition = $fileHeader
                $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("image/$imageType")
                $multipartContent.Add($fileContent)
                if ($EntityType) {
                    $URI = "https://$($NinjaOneInstance)/ws/api/v2/attachments/temp/upload?entityType=$EntityType"
                } else {
                    $URI = "https://$($NinjaOneInstance)/ws/api/v2/attachments/temp/upload"
                }
                $Result = (Invoke-WebRequest -Uri $URI -Body $multipartContent -Method 'POST' -Headers $Script:AuthHeader).content | ConvertFrom-Json -Depth 100
                $FileStream.close()
                $UploadedImages.add(
                    [PSCustomObject]@{
                        name      = $Image
                        filename  = $ImageName
                        contentID = $result.contentId
                    }
                )
            } else {
                Write-Error 'Image Not Detected'
            }
        } catch {
            Write-Error "Failed to upload image: $_"
        }
    }

    return $UploadedImages
}

function Invoke-FolgeToNinjaKB ($FolgeDocument, $FolgeDocPath, $ImportMode, $OrganizationID, $FolderID) {
    try {
        $FolgeParentDirectory = Split-Path -Path $FolgeDocPath -Parent
        $ImageIDs = Invoke-UploadNinjaImages -Images $FolgeDocument.Steps.screenshotRelativePath -ImagePath $FolgeParentDirectory

        [System.Collections.Generic.List[String]]$PageHTML = @()
        $StepIndex = 1

        # Loop through steps building an HTML body
        Foreach ($Step in $FolgeDocument.Steps | Sort-Object index) {
            $PageHTML.add(@"
        <table>
        <tbody>
        <tr><td><h1>$($StepIndex)) $($Step.title)</h1></td></tr>
        <tr><td><img src="cid:$(($ImageIDs | Where-Object {$_.filename -eq $Step.screenshotFilename}).contentId)"></img></td></tr>
        $(if ($Step.Description){"<tr><td><p>$($Step.description)</p></td></tr>"})
        </tbody>
        </table>
        <br />
"@)
            $StepIndex++        
        }

        # Generate the JSON body depending on if it is a Global or Organization Document
        if ($ImportMode -eq 'Organization') {
            $KBArticleCreate = [PSCustomObject]@{
                name                = $FolgeDocument.guide.title
                organizationId      = $OrganizationID
                destinationFolderId = $FolderID
                content             = @{
                    html = $PageHTML -join ''
                }
            } | ConvertTo-Json
        } elseif ($ImportMode -eq 'Global') {
            $KBArticleCreate = [PSCustomObject]@{
                name                = $FolgeDocument.guide.title
                destinationFolderId = $FolderID
                content             = @{
                    html = $PageHTML -join ''
                }
            } | ConvertTo-Json
        } else {
            Throw "Import Mode not found: $ImportMode"
        }

        $CreatedDoc = (Invoke-WebRequest -Method POST -URI "https://$($NinjaOneInstance)/api/v2/knowledgebase/articles" -ContentType "application/json" -Body "[$KBArticleCreate]" -Headers $AuthHeader -ea Stop).content | ConvertFrom-Json

        if ($ImportMode -eq 'Organization') {
            Start-Process "https://$($NinjaOneInstance)/#/customerDashboard/$OrganizationID/documentation/knowledgeBase/$($CreatedDoc.id)/file"
        } else {
            Start-Process "https://$($NinjaOneInstance)/#/systemDashboard/knowledgeBase/$($CreatedDoc.id)/file"
        }

        Return "Document Created Successfully"

    } catch {
        Write-Error "An Error Occured: $_"
        Return "An Error Occured: $_"
    }
}

function Invoke-FolgeToNinjaChecklist ($FolgeDocument, $FolgeDocPath, $ImportMode, $OrganizationID) {

    try {
        $FolgeParentDirectory = Split-Path -Path $FolgeDocPath -Parent
        $ImageIDs = Invoke-UploadNinjaImages -Images $FolgeDocument.Steps.screenshotRelativePath -ImagePath $FolgeParentDirectory -EntityType CHECKLIST

        [System.Collections.Generic.List[PSCustomObject]]$Tasks = @()
        $StepIndex = 1

        # Loop through steps building an HTML body
        Foreach ($Step in $FolgeDocument.Steps | Sort-Object index) {
            $StepHTML = @"
        <table>
        <tbody>
        <tr><td><img src="cid:$(($ImageIDs | Where-Object {$_.filename -eq $Step.screenshotFilename}).contentId)"></img></td></tr>
        $(if ($Step.Description){"<tr><td><p>$($Step.description)</p></td></tr>"})
        </tbody>
        </table>
        <br />
"@
            $Task = [PSCustomObject]@{
                position    = $StepIndex
                name        = $Step.title
                description = @{
                    html = $StepHTML
                }
            }

            $Tasks.add($Task)

            $StepIndex++        
        }

        if ($ImportMode -eq 'Template') {

            $ChecklistBody = [pscustomobject]@{
                name  = $FolgeDocument.guide.title
                tasks = $Tasks
            }

            if ($FolgeDocument.guide.description) {
                $description = @{
                    html = $FolgeDocument.guide.description
                }
                
            } else {
                $description = @{
                    html = 'N/A'
                }
            }
            $ChecklistBody | Add-Member NoteProperty description -Value $description

            $ChecklistJson = $ChecklistBody | ConvertTo-Json -Depth 100

            Write-Host $ChecklistJson

            $CreatedTemplate = (Invoke-WebRequest -Method POST -URI "https://$($NinjaOneInstance)/api/v2/checklist/templates" -ContentType "application/json" -Body "[$ChecklistJson]" -Headers $AuthHeader -ea Stop).content | ConvertFrom-Json
            Write-Host "Template: $($CreatedTemplate | ConvertTo-Json)"

            Return "Checklist Template Created Successfully"

        } elseif ($Importmode -eq 'Organization') {

            $ChecklistBody = [pscustomobject]@{
                name           = $FolgeDocument.guide.title
                organizationId = $OrganizationID
                tasks          = $Tasks
            }

            if ($FolgeDocument.guide.description) {
                $description = @{
                    html = $FolgeDocument.guide.description
                }
                
            } else {
                $description = @{
                    html = 'N/A'
                }
            }
            $ChecklistBody | Add-Member NoteProperty description -Value $description

            $ChecklistJson = $ChecklistBody | ConvertTo-Json -Depth 100

            Write-Host $ChecklistJson

            $CreatedChecklist = (Invoke-WebRequest -Method POST -URI "https://$($NinjaOneInstance)/api/v2/organization/checklists" -ContentType "application/json" -Body "[$ChecklistJson]" -Headers $AuthHeader -ea Stop).content | ConvertFrom-Json
            Write-Host "Template: $($CreatedChecklist | ConvertTo-Json)"

            Start-Process "https://$($NinjaOneInstance)/#/customerDashboard/$OrganizationID/documentation/checklists/$($CreatedChecklist.id)"

            Return "Checklist Created Successfully"
        } else {
            Throw "Import Mode not Found: $ImportMode"
        }
                

    } catch {
        Write-Error "An Error Occured: $_"
        Return "An Error Occured: $_"
    }
}

Function New-PKCE {
    <#
    .SYNOPSIS
    Generate OAuth 2.0 Proof Key for Code Exchange (PKCE) 'code_challenge' and 'code_verifier' for use with an OAuth2 Authorization Code Grant flow 
    .DESCRIPTION
    Proof Key for Code Exchange (PKCE) is a mechanism, typically used together with an OAuth2 Authorization Code Grant flow to provide an enhanced level of security when authenticating to an Identity Provider (IDP) to get an access token.
    .PARAMETER codeVerifier
    (optional) ClientID and ClientSecret of the Azure AD registered application with the necessary permissions for MSUser v3.
    .PARAMETER length
    (optional) Length of the code verifier to generate
    .EXAMPLE
    New-PKCE
    .EXAMPLE 
    Generate the code challenge for a specific code verifier
    New-PKCE -codeVerifier 'yfQ3wNRAyimC2qFc0wXI04u6pb2vRWRfUGdbcILFYOxqC1iJ84dSU0uCsVsHoMuv4Mbu5kmQxd3sZspfnPotrIPx1A9DOVmY3ahcKTjJ5xoGz95A7J8zSw86HW5eZpE'
    .EXAMPLE
    Specify the length of the code verifier to generate
    New-PKCE -length 99
    .LINK
    http://darrenjrobinson.com/
    #>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [ValidatePattern('(?# Code Verifier can only contain alphanumeric characters and . ~ - _)^[a-zA-Z0-9-._~]+$')][string]$codeVerifier,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [int]$length = 128
    )


    if ($length -gt 128 -or $length -lt 43) {
        Write-Warning "Code Verifier length must be of 43 to 128 characters in length (inclusive)."
        exit 
    }

    if ($codeVerifier) {
        if ($codeVerifier.Length -gt 128 -or $codeVerifier.Length -lt 43) {
            Write-Warning "Code Verifier length must be of 43 to 128 characters in length (inclusive)."
            exit 
        }  
    }

    $pkceTemplate = [pscustomobject][ordered]@{  
        code_verifier  = $null  
        code_challenge = $null   
    }  
        
    if ($codeVerifier) {
        $hashAlgo = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
        $hash = $hashAlgo.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($codeVerifier))
        $b64Hash = [System.Convert]::ToBase64String($hash)
        $code_challenge = $b64Hash.Substring(0, 43)

        $code_challenge = $code_challenge.Replace("/", "_")
        $code_challenge = $code_challenge.Replace("+", "-")
        $code_challenge = $code_challenge.Replace("=", "")

        $pkceChallenges = $pkceTemplate.PsObject.Copy()
        $pkceChallenges.code_challenge = $code_challenge 
        $pkceChallenges.code_verifier = $codeVerifier 

        return $pkceChallenges 
    } else {
        # PKCE Code verifier. Random alphanumeric string used on the client side
        # From the ASCII Table in Decimal A-Z a-z 0-9
        $codeVerifier = -join (((48..57) * 4) + ((65..90) * 4) + ((97..122) * 4) | Get-Random -Count $length | ForEach-Object { [char]$_ })

        $hashAlgo = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
        $hash = $hashAlgo.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($codeVerifier))
        $b64Hash = [System.Convert]::ToBase64String($hash)
        $code_challenge = $b64Hash.Substring(0, 43)
        
        $code_challenge = $code_challenge.Replace("/", "_")
        $code_challenge = $code_challenge.Replace("+", "-")
        $code_challenge = $code_challenge.Replace("=", "")

        $pkceChallenges = $pkceTemplate.PsObject.Copy()
        $pkceChallenges.code_challenge = $code_challenge
        $pkceChallenges.code_verifier = $codeVerifier 

        return $pkceChallenges 
    }
}

function Get-OAuthCode {
    param (
        [System.UriBuilder]$AuthURL,
        [string]$RedirectURL
    )
    $HTTP = [System.Net.HttpListener]::new()
    $HTTP.Prefixes.Add($RedirectURL)
    $HTTP.Start()
    Start-Process $AuthURL.ToString()
    $Result = @{}
    while ($HTTP.IsListening) {
        $Context = $HTTP.GetContext()
        if ($Context.Request.QueryString -and $Context.Request.QueryString['Code']) {
            $Result.Code = $Context.Request.QueryString['Code']
            if ($null -ne $Result.Code) {
                $Result.GotAuthorisationCode = $True
            }
            [string]$HTML = @"
            <html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NinjaOne Authorization Code</title>
    <style>
        body {
            background-color: #f0f2f5;
            font-family: Arial, sans-serif;
            margin: 0;
        }
        .card {
            max-width: 500px;
            margin: 100px auto;
            background-color: #ffffff;
            padding: 40px 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        .card h1 {
            margin-bottom: 20px;
            font-size: 24px;
            color: #333333;
        }
        .card p {
            margin: 10px 0;
            font-size: 16px;
            color: #555555;
        }
        .checkmark {
            font-size: 60px;
            color: #28a745;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="checkmark">&#10004;</div>
        <h1>NinjaOne Login Successful</h1>
        <p>An authorization code has been received successfully.</p>
        <p>Please close this tab and return to the import tool Window.</p>
    </div>
</body>
</html>
"@
            $Response = [System.Text.Encoding]::UTF8.GetBytes($HTML)
            $Context.Response.ContentLength64 = $Response.Length
            $Context.Response.OutputStream.Write($Response, 0, $Response.Length)
            $Context.Response.OutputStream.Close()
            Start-Sleep -Seconds 1
            $HTTP.Stop()
        }
    }
    Return $Result
}

# Define the different pages
$script:pages = @()  # Initialize $script:pages

# Page 0: Connect to NinjaOne
$page0 = {
    $grid = New-Object System.Windows.Controls.Grid

    $stack = New-Object System.Windows.Controls.StackPanel
    $stack.HorizontalAlignment = 'Center'
    $stack.VerticalAlignment = 'Center'

    $text = New-Object System.Windows.Controls.TextBlock
    $text.Text = "Connect to NinjaOne"
    $text.FontSize = 18
    $text.Margin = "0,0,0,20"
    $text.HorizontalAlignment = 'Center'

    $script:connectButton = New-Object System.Windows.Controls.Button
    $script:connectButton.Content = "Connect"
    $script:connectButton.Width = 120
    $script:connectButton.Height = 40
    $script:connectButton.Background = [System.Windows.Media.Brushes]::Blue
    $script:connectButton.Foreground = [System.Windows.Media.Brushes]::White
    $script:connectButton.FontSize = 16
    $script:connectButton.HorizontalAlignment = 'Center'

    # Add a TextBlock for the success message
    $script:connectionMessage = New-Object System.Windows.Controls.TextBlock
    $script:connectionMessage.Text = ""
    $script:connectionMessage.FontSize = 14
    $script:connectionMessage.Margin = "0,10,0,0"
    $script:connectionMessage.HorizontalAlignment = 'Center'
    $script:connectionMessage.Foreground = [System.Windows.Media.Brushes]::Green

    $script:connectButton.Add_Click({
            # Simulate connection process
            $script:connectButton.Content = "Connecting"

            try {
                $PKCE = New-PKCE -length 43

                $AuthURL = "https://$NinjaOneInstance/ws/oauth/authorize?response_type=code&client_id=$ClientID&redirect_uri=$RedirectURL&scope=monitoring%20management&code_challenge=$($PKCE.code_challenge)&code_challenge_method=S256&state=FOLGELOGIN"

                $AuthResult = Get-OAuthCode -AuthURL $AuthURL -RedirectURL $RedirectURL

                $AuthBody = @{
                    'grant_type'    = 'authorization_code'
                    'client_id'     = $ClientID
                    'code'          = $AuthResult.code
                    'code_verifier' = $PKCE.code_verifier
                    'redirect_uri'  = $RedirectURL 
                }
           
                $Result = Invoke-WebRequest -uri "https://$($NinjaOneInstance)/ws/oauth/token" -Method POST -Body $AuthBody -ContentType 'application/x-www-form-urlencoded' -ea Stop

                $Script:AuthHeader = @{
                    'Authorization' = "Bearer $(($Result.content | ConvertFrom-Json).access_token)"
                }

                $script:IsConnected = $true
                $script:connectButton.Content = "Connected"
                $script:connectButton.IsEnabled = $false
                $script:NextButton.IsEnabled = $true
                $script:connectionMessage.Text = "Connected successfully please click Next"
            
            } catch {
                Write-Error "Error: $_"
                $script:connectionMessage.Foreground = [System.Windows.Media.Brushes]::Red
                $script:connectionMessage.Text = "Connection Failed: $_"
            }
        })

    $null = $stack.Children.Add($text)
    $null = $stack.Children.Add($script:connectButton)
    $null = $stack.Children.Add($script:connectionMessage)

    $grid.Children.Add($stack) | Out-Null
    $grid
}

# Page 1: Select File
$page1 = {
    $grid = New-Object System.Windows.Controls.Grid

    $text = New-Object System.Windows.Controls.TextBlock
    $text.Text = "Please export your Folge document as a .json file"
    $text.FontSize = 16
    $text.Margin = "0,0,0,20"

    $button = New-Object System.Windows.Controls.Button
    $button.Content = "Browse..."
    $button.Width = 100
    $button.Margin = "0,0,0,10"

    # Initialize $filePathBox at script scope
    $script:filePathBox = New-Object System.Windows.Controls.TextBox
    $script:filePathBox.Margin = "0,10,0,0"
    $script:filePathBox.IsReadOnly = $true
    $script:filePathBox.Height = 25

    $button.Add_Click({
            $dlg = New-Object Microsoft.Win32.OpenFileDialog
            $dlg.Filter = "JSON Files (*.json)|*.json"
            $result = $dlg.ShowDialog()
            if ($result -eq $true) {
                $script:SelectedFilePath = $dlg.FileName
                $script:filePathBox.Text = $script:SelectedFilePath
            }
        })

    $stack = New-Object System.Windows.Controls.StackPanel
    $null = $stack.Children.Add($text)
    $null = $stack.Children.Add($button)
    $null = $stack.Children.Add($script:filePathBox)

    $grid.Children.Add($stack) | Out-Null
    $grid
}

# Page 2: Choose Upload Type
$page2 = {
    $grid = New-Object System.Windows.Controls.Grid

    $text = New-Object System.Windows.Controls.TextBlock
    $text.Text = "How would you like to upload the file?"
    $text.FontSize = 16
    $text.Margin = "0,0,0,20"

    $options = New-Object System.Windows.Controls.StackPanel
    $options.Orientation = "Vertical"

    $radio1 = New-Object System.Windows.Controls.RadioButton
    $radio1.Content = "Upload as Checklist"
    $radio1.GroupName = "UploadType"
    $radio1.IsChecked = $true  # Default selection

    $radio2 = New-Object System.Windows.Controls.RadioButton
    $radio2.Content = "Upload as KB Article"
    $radio2.GroupName = "UploadType"

    # Correctly attach event handlers
    $radio1.Add_Checked({
            $script:SelectedUploadType = "Checklist"
        })
    $radio2.Add_Checked({
            $script:SelectedUploadType = "KB Article"
        })

    $null = $options.Children.Add($radio1)
    $null = $options.Children.Add($radio2)

    $stack = New-Object System.Windows.Controls.StackPanel
    $null = $stack.Children.Add($text)
    $null = $stack.Children.Add($options)

    $grid.Children.Add($stack) | Out-Null
    $grid
}

# Page 3: Additional Options
$page3 = {
    # Fetch NinjaOne Orgs
    $script:Organizations = (Invoke-WebRequest -uri "https://$($NinjaOneInstance)/api/v2/organizations" -Method GET -Headers $AuthHeader -ContentType 'application/json').content | ConvertFrom-Json -depth 100 | Sort-Object name

    $grid = New-Object System.Windows.Controls.Grid

    $text = New-Object System.Windows.Controls.TextBlock
    $text.FontSize = 16
    $text.Margin = "0,0,0,20"

    $options = New-Object System.Windows.Controls.StackPanel
    $options.Orientation = "Vertical"

    if ($script:SelectedUploadType -eq "Checklist") {
        $text.Text = "Additional options for Checklist:"

        $radio1 = New-Object System.Windows.Controls.RadioButton
        $radio1.Content = "Create as a Template"
        $radio1.GroupName = "ChecklistOption"
        $radio1.IsChecked = $true  # Default selection

        $radio2 = New-Object System.Windows.Controls.RadioButton
        $radio2.Content = "Upload to an Organization"
        $radio2.GroupName = "ChecklistOption"

        $radio1.Add_Checked({
                $script:SelectedOption = "Template"
                if ($script:orgCombo -ne $null) {
                    $script:orgCombo.Visibility = "Collapsed"
                }
            })
        $radio2.Add_Checked({
                $script:SelectedOption = "Organization"
                if ($script:orgCombo -ne $null) {
                    $script:orgCombo.Visibility = "Visible"
                }
            })

        $null = $options.Children.Add($radio1)
        $null = $options.Children.Add($radio2)

        $script:orgCombo = New-Object System.Windows.Controls.ComboBox
        $script:orgCombo.Margin = "0,10,0,0"
        $script:orgCombo.Width = 300
        $script:orgCombo.DisplayMemberPath = "Name"
        $script:orgCombo.SelectedValuePath = "ID"
        $script:orgCombo.ItemsSource = $script:Organizations
        $script:orgCombo.Visibility = "Collapsed"
        $script:orgCombo.Add_SelectionChanged({
                $script:SelectedOrganizationName = $script:orgCombo.SelectedItem.Name
                $script:SelectedOrganizationId = $script:orgCombo.SelectedValue
            })

        $null = $options.Children.Add($script:orgCombo)
    } else {
        $text.Text = "Additional options for KB Article:"

        $radio1 = New-Object System.Windows.Controls.RadioButton
        $radio1.Content = "Upload to Global Knowledge Base"
        $radio1.GroupName = "KBOption"
        $radio1.IsChecked = $true  # Default selection

        $radio2 = New-Object System.Windows.Controls.RadioButton
        $radio2.Content = "Upload to an Organization Knowledge Base"
        $radio2.GroupName = "KBOption"

        $radio1.Add_Checked({
                $script:SelectedOption = "Global"
                if ($script:orgCombo -ne $null) {
                    $script:orgCombo.Visibility = "Collapsed"
                }
            })
        $radio2.Add_Checked({
                $script:SelectedOption = "Organization"
                if ($script:orgCombo -ne $null) {
                    $script:orgCombo.Visibility = "Visible"
                }
            })

        $null = $options.Children.Add($radio1)
        $null = $options.Children.Add($radio2)

        $script:orgCombo = New-Object System.Windows.Controls.ComboBox
        $script:orgCombo.Margin = "0,10,0,0"
        $script:orgCombo.Width = 300
        $script:orgCombo.DisplayMemberPath = "Name"
        $script:orgCombo.SelectedValuePath = "ID"
        $script:orgCombo.ItemsSource = $script:Organizations
        $script:orgCombo.Visibility = "Collapsed"
        $script:orgCombo.Add_SelectionChanged({
                $script:SelectedOrganizationName = $script:orgCombo.SelectedItem.Name
                $script:SelectedOrganizationId = $script:orgCombo.SelectedValue
            })

        $null = $options.Children.Add($script:orgCombo)
    }

    $stack = New-Object System.Windows.Controls.StackPanel
    $null = $stack.Children.Add($text)
    $null = $stack.Children.Add($options)

    $grid.Children.Add($stack) | Out-Null
    $grid
}

# Page 4: Select Folder (Conditionally included)
$page4 = {
    
    # Fetch Folder Structure from NinjaOne
    [System.Collections.Generic.List[PSCustomObject]]$script:FolderData = @()

    if ($script:SelectedOption -eq "Organization") {
        $NinjaOrgID = $script:SelectedOrganizationId
    } else {
        $NinjaOrgID = $Null
    }
    
    Get-Folder -FolderID $Null -OrganizationID $NinjaOrgID

    $grid = New-Object System.Windows.Controls.Grid

    $text = New-Object System.Windows.Controls.TextBlock
    $text.Text = "Select the folder to upload to:"
    $text.FontSize = 16
    $text.Margin = "0,0,0,20"

    # TreeView for folder selection
    $script:treeView = New-Object System.Windows.Controls.TreeView
    $script:treeView.Add_SelectedItemChanged({
            if ($script:treeView.SelectedItem -is [System.Windows.Controls.TreeViewItem]) {
                $script:SelectedFolder = $script:treeView.SelectedItem.Header
                $script:SelectedFolderId = $script:treeView.SelectedItem.Tag
            }
        })

    

    # Build the folder tree from the data
    $rootItems = $script:FolderData | Where-Object { $_.parentid -eq $null }
    foreach ($folder in $rootItems) {
        $treeViewItem = New-Object System.Windows.Controls.TreeViewItem
        $treeViewItem.Header = $folder.name
        $treeViewItem.Tag = $folder.id  # Store the id in the Tag property
        Get-FolderTree -parentId $folder.id -parentItem $treeViewItem
        $script:treeView.Items.Add($treeViewItem) | Out-Null
    }

    $stack = New-Object System.Windows.Controls.StackPanel
    $null = $stack.Children.Add($text)
    $null = $stack.Children.Add($script:treeView)

    $grid.Children.Add($stack) | Out-Null
    $grid
}

# Page 5: Confirmation
$page5 = {
    $grid = New-Object System.Windows.Controls.Grid

    $text = New-Object System.Windows.Controls.TextBlock
    $text.Text = "Confirmation"
    $text.FontSize = 18
    $text.Margin = "0,0,0,20"

    $details = New-Object System.Windows.Controls.TextBlock
    $details.Text = "Please review your selections before proceeding.`n`n"
    $details.FontSize = 14

    $summary = New-Object System.Windows.Controls.TextBlock
    $summary.FontSize = 14
    $summary.Text = ""
    if ($script:IsConnected) {
        $summary.Text += "Connected to NinjaOne`n"
    } else {
        $summary.Text += "Not Connected`n"
    }
    $summary.Text += "File: $script:SelectedFilePath`n"
    $summary.Text += "Upload Type: $script:SelectedUploadType`n"
    $summary.Text += "Option: $script:SelectedOption`n"
    if ($script:SelectedOrganizationName -ne "") {
        $summary.Text += "Organization: $script:SelectedOrganizationName (ID: $script:SelectedOrganizationId)`n"
    }
    if ($script:SelectedUploadType -eq "KB Article" -and $script:SelectedFolder -ne "") {
        $summary.Text += "Folder: $script:SelectedFolder (ID: $script:SelectedFolderId)`n"
    }

    $stack = New-Object System.Windows.Controls.StackPanel
    $null = $stack.Children.Add($text)
    $null = $stack.Children.Add($details)
    $null = $stack.Children.Add($summary)

    $grid.Children.Add($stack) | Out-Null
    $grid
}

# Page 6: Uploading
$page6 = {
    $grid = New-Object System.Windows.Controls.Grid

    $stack = New-Object System.Windows.Controls.StackPanel
    $stack.HorizontalAlignment = 'Center'
    $stack.VerticalAlignment = 'Center'

    $text = New-Object System.Windows.Controls.TextBlock
    $text.Text = "Uploading..."
    $text.FontSize = 18
    $text.Margin = "0,0,0,20"
    $text.HorizontalAlignment = 'Center'

    $null = $stack.Children.Add($text)

    $grid.Children.Add($stack) | Out-Null
    $grid
}

# Page 7: Upload Complete
$page7 = {
    $grid = New-Object System.Windows.Controls.Grid

    $stack = New-Object System.Windows.Controls.StackPanel
    $stack.HorizontalAlignment = 'Center'
    $stack.VerticalAlignment = 'Center'

    $text = New-Object System.Windows.Controls.TextBlock
    $text.Text = "$Script:UploadResult"
    $text.FontSize = 18
    $text.Margin = "0,0,0,20"
    $text.HorizontalAlignment = 'Center'

    $uploadAnotherButton = New-Object System.Windows.Controls.Button
    $uploadAnotherButton.Content = "Upload Another"
    $uploadAnotherButton.Width = 150
    $uploadAnotherButton.Height = 40
    $uploadAnotherButton.FontSize = 16
    $uploadAnotherButton.HorizontalAlignment = 'Center'

    $uploadAnotherButton.Add_Click({
            # Reset settings
            $script:SelectedFilePath = ""
            $script:SelectedUploadType = "Checklist"
            $script:SelectedOption = "Template"
            $script:SelectedOrganizationName = ""
            $script:SelectedOrganizationId = ""
            $script:SelectedFolder = ""
            $script:SelectedFolderId = ""
            $script:filePathBox.Text = ""
            $script:NextButton.Content = "Next"
            if ($script:orgCombo -ne $null) {
                $script:orgCombo.SelectedIndex = -1
                $script:orgCombo.Visibility = "Collapsed"
            }
            $script:currentIndex = 1  # Go back to Select File page
            LoadPage $script:currentIndex
        })

    $null = $stack.Children.Add($text)
    $null = $stack.Children.Add($uploadAnotherButton)

    $grid.Children.Add($stack) | Out-Null
    $grid
}


# Initialize pages array
# We will adjust this based on user selections
$script:pages = @($page0, $page1, $page2, $page3, $page5, $page6, $page7)  # Exclude page4 initially

# Update PageIndices
$script:PageIndices.Confirmation = 4
$script:PageIndices.Uploading = 5
$script:PageIndices.UploadComplete = 6

# Navigation Buttons
$script:NextButton = New-Object System.Windows.Controls.Button
$script:NextButton.Content = "Next"
$script:NextButton.Width = 80
$script:NextButton.Margin = "5"
$script:NextButton.IsEnabled = $false  # Disabled until connected

$BackButton = New-Object System.Windows.Controls.Button
$BackButton.Content = "Back"
$BackButton.Width = 80
$BackButton.Margin = "5"
$BackButton.IsEnabled = $false

$NavStack = New-Object System.Windows.Controls.StackPanel
$NavStack.Orientation = "Horizontal"
$NavStack.HorizontalAlignment = "Right"
$NavStack.Margin = "0,10,0,0"
$NavStack.VerticalAlignment = "Bottom"

$null = $NavStack.Children.Add($BackButton)
$null = $NavStack.Children.Add($script:NextButton)

# Function to load page
Function LoadPage($index) {
    $MainContent.Children.Clear()
    $content = & $script:pages[$index]
    if ($content -ne $null) {
        $MainContent.Children.Add($content) | Out-Null
    }
    # Show navigation buttons only if not on Uploading or Upload Complete pages
    if ($index -le $script:PageIndices.Confirmation) {
        $MainContent.Children.Add($NavStack) | Out-Null
    }
    UpdateStepIndicator $index
    # Adjust BackButton and NextButton state
    if ($script:currentIndex -eq 0) {
        $BackButton.IsEnabled = $false
        if ($script:IsConnected) {
            $script:NextButton.IsEnabled = $true
        } else {
            $script:NextButton.IsEnabled = $false
        }
    } elseif ($script:currentIndex -ge $script:PageIndices.UploadComplete) {
        $BackButton.IsEnabled = $false
        $script:NextButton.IsEnabled = $false
    } else {
        $BackButton.IsEnabled = $true
        $script:NextButton.IsEnabled = $true
    }
}

# Event Handlers
$script:NextButton.Add_Click({
        if ($script:currentIndex -lt $script:PageIndices.Confirmation) {
            if ($script:currentIndex -eq 2) {
                # Update the pages array based on selection
                if ($script:SelectedUploadType -eq "KB Article") {
                    # Include folder selection step
                    $script:pages = @($page0, $page1, $page2, $page3, $page4, $page5, $page6, $page7)
                    # Update PageIndices
                    $script:PageIndices.Confirmation = 5
                    $script:PageIndices.Uploading = 6
                    $script:PageIndices.UploadComplete = 7
                    # Update the step list in the sidebar
                    $script:StepList.Items.Clear()
                    $null = $script:StepList.Items.Add((New-Object System.Windows.Controls.ListBoxItem -Property @{Content = "1. Connect" }))
                    $null = $script:StepList.Items.Add((New-Object System.Windows.Controls.ListBoxItem -Property @{Content = "2. Select File" }))
                    $null = $script:StepList.Items.Add((New-Object System.Windows.Controls.ListBoxItem -Property @{Content = "3. Choose Upload Type" }))
                    $null = $script:StepList.Items.Add((New-Object System.Windows.Controls.ListBoxItem -Property @{Content = "4. Additional Options" }))
                    $null = $script:StepList.Items.Add((New-Object System.Windows.Controls.ListBoxItem -Property @{Content = "5. Select Folder" }))
                    $null = $script:StepList.Items.Add((New-Object System.Windows.Controls.ListBoxItem -Property @{Content = "6. Confirmation" }))
                } else {
                    # Exclude folder selection step
                    $script:pages = @($page0, $page1, $page2, $page3, $page5, $page6, $page7)
                    # Update PageIndices
                    $script:PageIndices.Confirmation = 4
                    $script:PageIndices.Uploading = 5
                    $script:PageIndices.UploadComplete = 6
                    # Update the step list in the sidebar
                    $script:StepList.Items.Clear()
                    $null = $script:StepList.Items.Add((New-Object System.Windows.Controls.ListBoxItem -Property @{Content = "1. Connect" }))
                    $null = $script:StepList.Items.Add((New-Object System.Windows.Controls.ListBoxItem -Property @{Content = "2. Select File" }))
                    $null = $script:StepList.Items.Add((New-Object System.Windows.Controls.ListBoxItem -Property @{Content = "3. Choose Upload Type" }))
                    $null = $script:StepList.Items.Add((New-Object System.Windows.Controls.ListBoxItem -Property @{Content = "4. Additional Options" }))
                    $null = $script:StepList.Items.Add((New-Object System.Windows.Controls.ListBoxItem -Property @{Content = "5. Confirmation" }))
                }
                # Do not reset $script:currentIndex
            }
            $script:currentIndex++
            LoadPage $script:currentIndex
            if ($script:currentIndex -eq $script:PageIndices.Confirmation) {
                $script:NextButton.Content = "Upload"
            } else {
                $script:NextButton.Content = "Next"
            }
        } elseif ($script:currentIndex -eq $script:PageIndices.Confirmation) {
            # Show uploading page
            $script:currentIndex++
            LoadPage $script:currentIndex

            # Upload to NinjaOne
            ## Get the Folge Document
            Try {
                $Script:FolgeDocument = Get-Content $script:SelectedFilePath | ConvertFrom-Json
                if ($Null -eq $Script.FolgeDocument.guide.title) {
                    Throw "$script:SelectedFilePath is not a valid Folge Document"
                }
            } catch {
                $script:ResultMessage = $_
            }

            ## Process based on the selected options
            if ($script:SelectedUploadType -eq "KB Article") {
                if ($script:SelectedOption -eq "Organization") {
                    $Script:UploadResult = Invoke-FolgeToNinjaKB -FolgeDocument $Script:FolgeDocument -FolgeDocPath $script:SelectedFilePath -ImportMode 'Organization' -OrganizationID $script:SelectedOrganizationId -FolderID $script:SelectedFolderId
                } else {
                    $Script:UploadResult = Invoke-FolgeToNinjaKB -FolgeDocument $Script:FolgeDocument -FolgeDocPath $script:SelectedFilePath -ImportMode 'Global' -FolderID $script:SelectedFolderId
                }      
            } else {
                if ($script:SelectedOption -eq "Template") {
                    $Script:UploadResult = Invoke-FolgeToNinjaChecklist -FolgeDocument $Script:FolgeDocument -FolgeDocPath $script:SelectedFilePath -ImportMode 'Template'
                } else {
                    $Script:UploadResult = Invoke-FolgeToNinjaChecklist -FolgeDocument $Script:FolgeDocument -FolgeDocPath $script:SelectedFilePath -ImportMode 'Organization' -OrganizationID $script:SelectedOrganizationId
                }
                
            }


            # After upload, show upload complete page
            $script:currentIndex++
            LoadPage $script:currentIndex
        }
    })

$BackButton.Add_Click({
        if ($script:currentIndex -gt 0) {
            $script:currentIndex--
            LoadPage $script:currentIndex
            if ($script:currentIndex -eq $script:PageIndices.Confirmation - 1) {
                $script:NextButton.Content = "Finish"
            } else {
                $script:NextButton.Content = "Next"
            }
            if ($script:currentIndex -eq 0) {
                $BackButton.IsEnabled = $false
                if ($script:IsConnected) {
                    $script:NextButton.IsEnabled = $true
                } else {
                    $script:NextButton.IsEnabled = $false
                }
            }
        }
    })

# Initialize
LoadPage $script:currentIndex

# Show the window
$Window.ShowDialog() | Out-Null

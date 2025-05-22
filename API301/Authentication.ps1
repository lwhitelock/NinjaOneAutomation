######## API 301 Webinar ########
# Authentication Examples
# https://www.youtube.com/watch?v=dQRUpDJwio4
#
# Securely fetch your credentials from a credential store. For example NinjaOne Secure Custom Fields
# See here for an example of how to do this in a secure way https://docs.mspp.io/ninjaone/getting-started

######## Client Credentials ########
# Create an API Application in NinjaOne with a Type of API Services (machine-to-machine)

$ClientID = 'My Client ID'
$Secret = 'My Secret'

$AuthBody = @{
    'grant_type' = 'client_credentials'
    'client_id' = $ClientID
    'client_secret' = $Secret
    'scope' = 'monitoring management' 
}

$Result = Invoke-WebRequest -uri "https://eu.ninjarmm.com/ws/oauth/token" -Method POST -Body $AuthBody -ContentType 'application/x-www-form-urlencoded'

$AuthHeader = @{
    'Authorization' = "Bearer $(($Result.content | ConvertFrom-Json).access_token)"
}

$Orgs = (Invoke-WebRequest -uri "https://eu.ninjarmm.com/api/v2/organizations" -Method Get -Headers $AuthHeader -ContentType 'application/json').Content | ConvertFrom-Json

$Orgs

######## Authentication Flow ########
# Create an API Application in NinjaOne with a type of Web (PHP, Java, .Net Core, etc.)

$ClientID = 'My Client ID'
$Secret = 'My Secret'
$RedirectURL = 'http://localhost:9090/'

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
            [string]$HTML = '<h1>NinjaOne Authorization Code</h1><br /><p>An authorisation code has been received. The HTTP listener will stop in 5 seconds.</p><p>Please close this tab / window.</p>'
            $Response = [System.Text.Encoding]::UTF8.GetBytes($HTML)
            $Context.Response.ContentLength64 = $Response.Length
            $Context.Response.OutputStream.Write($Response, 0, $Response.Length)
            $Context.Response.OutputStream.Close()
            Start-Sleep -Seconds 5
            $HTTP.Stop()
        }
    }
    Return $Result
}

$AuthURL = "https://eu.ninjarmm.com/oauth/authorize?response_type=code&client_id=$ClientID&redirect_uri=$RedirectURL&scope=monitoring%20offline_access&state=STATE"

$Result = Get-OAuthCode -AuthURL $AuthURL -RedirectURL $RedirectURL

$AuthBody = @{
    'grant_type' = 'authorization_code'
    'client_id' = $ClientID
    'client_secret' = $Secret
    'code' = $Result.code
    'redirect_uri' = $RedirectURL 
}

$Result = Invoke-WebRequest -uri "https://eu.ninjarmm.com/ws/oauth/token" -Method POST -Body $AuthBody -ContentType 'application/x-www-form-urlencoded'

$AuthHeader = @{
    'Authorization' = "Bearer $(($Result.content | ConvertFrom-Json).access_token)"
}

$Devices = (Invoke-WebRequest -uri "https://eu.ninjarmm.com/api/v2/devices" -Method Get -Headers $AuthHeader -ContentType 'application/json').Content | ConvertFrom-Json

$Devices

######## Refresh Token ########
# Ensure your API Application has Refresh Token as an allowed Grant Type. 

$RefreshToken = ($Result.content | ConvertFrom-Json).refresh_token

$AuthBody = @{
    'grant_type'    = 'refresh_token'
    'client_id'     = $ClientID
    'client_secret' = $Secret
    'refresh_token' = $RefreshToken
}

$Result = Invoke-WebRequest -uri "https://eu.ninjarmm.com/ws/oauth/token" -Method POST -Body $AuthBody -ContentType 'application/x-www-form-urlencoded'

$AuthHeader = @{
    'Authorization' = "Bearer $(($Result.content | ConvertFrom-Json).access_token)"
}

$DevicesDetailed = (Invoke-WebRequest -uri "https://eu.ninjarmm.com/api/v2/devices-detailed" -Method Get -Headers $AuthHeader -ContentType 'application/json').Content | ConvertFrom-Json

$DevicesDetailed


######## PKCE ########
# Create an API Application in NinjaOne with a type of Single Page (Angular, React, Vue, etc.)
# Once created edit the API application and add the Refresh Token Grant Type.

$ClientID = 'My Client ID'
$RedirectURL = 'http://localhost:9090/'

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
            [string]$HTML = '<h1>NinjaOne</h1><br /><p>An authorisation code has been received. Please close this tab / window.</p>'
            $Response = [System.Text.Encoding]::UTF8.GetBytes($HTML)
            $Context.Response.ContentLength64 = $Response.Length
            $Context.Response.OutputStream.Write($Response, 0, $Response.Length)
            $Context.Response.OutputStream.Close()
            Start-Sleep -Seconds 5
            $HTTP.Stop()
        }
    }
    Return $Result
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

        $code_challenge = $code_challenge.Replace("/","_")
        $code_challenge = $code_challenge.Replace("+","-")
        $code_challenge = $code_challenge.Replace("=","")

        $pkceChallenges = $pkceTemplate.PsObject.Copy()
        $pkceChallenges.code_challenge = $code_challenge 
        $pkceChallenges.code_verifier = $codeVerifier 

        return $pkceChallenges 
    }
    else {
        # PKCE Code verifier. Random alphanumeric string used on the client side
        # From the ASCII Table in Decimal A-Z a-z 0-9
        $codeVerifier = -join (((48..57) * 4) + ((65..90) * 4) + ((97..122) * 4) | Get-Random -Count $length | ForEach-Object { [char]$_ })

        $hashAlgo = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
        $hash = $hashAlgo.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($codeVerifier))
        $b64Hash = [System.Convert]::ToBase64String($hash)
        $code_challenge = $b64Hash.Substring(0, 43)
        
        $code_challenge = $code_challenge.Replace("/","_")
        $code_challenge = $code_challenge.Replace("+","-")
        $code_challenge = $code_challenge.Replace("=","")

        $pkceChallenges = $pkceTemplate.PsObject.Copy()
        $pkceChallenges.code_challenge = $code_challenge
        $pkceChallenges.code_verifier = $codeVerifier 

        return $pkceChallenges 
    }
}

$PKCE = New-PKCE -length 43


$AuthURL = "https://eu.ninjarmm.com/ws/oauth/authorize?response_type=code&client_id=$ClientID&redirect_uri=$RedirectURL&scope=monitoring%20management%20offline_access&code_challenge=$($PKCE.code_challenge)&code_challenge_method=S256&state=STATE"

$AuthResult = Get-OAuthCode -AuthURL $AuthURL -RedirectURL $RedirectURL

$AuthBody = @{
    'grant_type' = 'authorization_code'
    'client_id' = $ClientID
    'code' = $AuthResult.code
    'code_verifier' = $PKCE.code_verifier
    'redirect_uri' = $RedirectURL 
}

$Result = Invoke-WebRequest -uri "https://eu.ninjarmm.com/ws/oauth/token" -Method POST -Body $AuthBody -ContentType 'application/x-www-form-urlencoded'

$RefreshToken = (($Result.content | ConvertFrom-Json).refresh_token)

$AuthBody = @{
    'grant_type' = 'refresh_token'
    'client_id' = $ClientID
    'refresh_token' = $RefreshToken
}

$AuthResult = Invoke-WebRequest -uri "https://eu.ninjarmm.com/ws/oauth/token" -Method POST -Body $AuthBody -ContentType 'application/x-www-form-urlencoded'

$AuthHeader = @{
    'Authorization' = "Bearer $(($AuthResult.content | ConvertFrom-Json).access_token)"
}

$TicketBoards = (Invoke-WebRequest -uri "https://eu.ninjarmm.com/api/v2/ticketing/trigger/boards" -Method GET -Headers $AuthHeader -ContentType 'application/json').content | convertfrom-json
$TicketBoards

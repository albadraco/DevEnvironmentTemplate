param(
[Parameter(Mandatory = $true, ParameterSetName="TCLatest")]
[Parameter(Mandatory = $true, ParameterSetName="TCNum")]
[Parameter(Mandatory = $true, ParameterSetName="Local")]
[Parameter(Mandatory = $true, ParameterSetName="TCID")]
[ValidateScript({If ($_ -match '^[a-z][a-z0-9-]{1,10}$') {
    $True
    } Else {
        Throw "Error: $_ Doesn't meet requirements for prefix! Must start with a letter, contain only letters/numbers/dashes (due to domain naming restrictions), and must not exceed 11 chars (due to Windows restrictions on computer names)."
}})]
[string]
$Prefix,

[Parameter(Mandatory = $false, ParameterSetName="TCLatest")]
[Parameter(Mandatory = $false, ParameterSetName="TCNum")]
[Parameter(Mandatory = $false, ParameterSetName="Local")]
[Parameter(Mandatory = $false, ParameterSetName="TCID")]
[switch]
$CreateVDA,

#[Parameter(Mandatory = $false, ParameterSetName="TCLatest")]
#[Parameter(Mandatory = $false, ParameterSetName="TCNum")]
#[Parameter(Mandatory = $false, ParameterSetName="Local")]
#[Parameter(Mandatory = $false, ParameterSetName="TCID")]
#[switch]
#$CreateNetScaler,

[Parameter(Mandatory = $false, ParameterSetName="TCLatest")]
[Parameter(Mandatory = $false, ParameterSetName="TCNum")]
[Parameter(Mandatory = $false, ParameterSetName="Local")]
[Parameter(Mandatory = $false, ParameterSetName="TCID")]
[System.Management.Automation.PSCredential]
$AdminCredential,

[Parameter(Mandatory = $true, ParameterSetName="TCLatest")]
[Parameter(Mandatory = $true, ParameterSetName="TCNum")]
[Parameter(Mandatory = $true, ParameterSetName="Local")]
[Parameter(Mandatory = $true, ParameterSetName="TCID")]
[ValidateSet("AzureCloud", "AzureChinaCloud", "AzureUSGovernment", "AzureGermanCloud")]
[string]
$AzureEnvironment,

[Parameter(Mandatory = $true, ParameterSetName="TCLatest")]
[Parameter(Mandatory = $true, ParameterSetName="TCNum")]
[Parameter(Mandatory = $true, ParameterSetName="Local")]
[Parameter(Mandatory = $true, ParameterSetName="TCID")]
[string]
$ResourceGroupName,

[Parameter(Mandatory = $false, ParameterSetName="TCLatest")]
[Parameter(Mandatory = $false, ParameterSetName="TCNum")]
[Parameter(Mandatory = $false, ParameterSetName="Local")]
[Parameter(Mandatory = $false, ParameterSetName="TCID")]
[string]
$DeploymentName = "$Prefix-Deployment",

[Parameter(Mandatory = $false, ParameterSetName="TCLatest")]
[Parameter(Mandatory = $false, ParameterSetName="TCNum")]
[Parameter(Mandatory = $false, ParameterSetName="Local")]
[Parameter(Mandatory = $false, ParameterSetName="TCID")]
[switch]
$UseLetsEncrypt = $false,

[Parameter(Mandatory = $false, ParameterSetName="TCLatest")]
[Parameter(Mandatory = $false, ParameterSetName="TCNum")]
[Parameter(Mandatory = $false, ParameterSetName="Local")]
[Parameter(Mandatory = $false, ParameterSetName="TCID")]
[string]
$DDCSize = "Standard_D2_v2",

[Parameter(Mandatory = $false, ParameterSetName="TCLatest")]
[Parameter(Mandatory = $false, ParameterSetName="TCNum")]
[Parameter(Mandatory = $false, ParameterSetName="Local")]
[Parameter(Mandatory = $false, ParameterSetName="TCID")]
[string]
$DCSize = "Standard_D2_v2",

[Parameter(Mandatory = $false, ParameterSetName="TCLatest")]
[Parameter(Mandatory = $false, ParameterSetName="TCNum")]
[Parameter(Mandatory = $false, ParameterSetName="Local")]
[Parameter(Mandatory = $false, ParameterSetName="TCID")]
[string]
$VDASize = "Standard_D2_v2",

[Parameter(Mandatory = $false, ParameterSetName="TCLatest")]
[Parameter(Mandatory = $false, ParameterSetName="TCNum")]
[Parameter(Mandatory = $false, ParameterSetName="Local")]
[Parameter(Mandatory = $false, ParameterSetName="TCID")]
[string]
$DomainName = "xenapp.local",

[Parameter(Mandatory = $true, ParameterSetName="TCID")]
[int]
$TCBuildId,

[Parameter(Mandatory = $true, ParameterSetName="TCNum")]
[int]
$TCBuildNumber,

[Parameter(Mandatory = $true, ParameterSetName="TCLatest")]
[switch]
$TCLatestBuild,

[Parameter(Mandatory = $false, ParameterSetName="TCLatest")]
[Parameter(Mandatory = $false, ParameterSetName="TCNum")]
[string]
$TCBuildType = "Main-FullBuild",


[Parameter(Mandatory = $false, ParameterSetName="TCLatest")]
[Parameter(Mandatory = $false, ParameterSetName="TCNum")]
[Parameter(Mandatory = $false, ParameterSetName="TCID")]
[System.Management.Automation.PSCredential]
$TCCredential,

[Parameter(Mandatory = $true, ParameterSetName="TCLatest")]
[Parameter(Mandatory = $true, ParameterSetName="TCNum")]
[Parameter(Mandatory = $true, ParameterSetName="Local")]
[Parameter(Mandatory = $true, ParameterSetName="TCID")]
[string]
$StorageAccountName,

[Parameter(Mandatory = $false, ParameterSetName="TCLatest")]
[Parameter(Mandatory = $false, ParameterSetName="TCNum")]
[Parameter(Mandatory = $false, ParameterSetName="Local")]
[Parameter(Mandatory = $false, ParameterSetName="TCID")]
[string]
$StorageAccountResourceGroupName = $ResourceGroupName,

[Parameter(Mandatory = $true, ParameterSetName="Local")]
[ValidateScript({Test-Path $_})]
[string]
$LocalImage,

[Parameter(Mandatory = $false, ParameterSetName="TCLatest")]
[Parameter(Mandatory = $false, ParameterSetName="TCNum")]
[Parameter(Mandatory = $false, ParameterSetName="Local")]
[Parameter(Mandatory = $false, ParameterSetName="TCID")]
[System.DateTime]
$WaitUntil

)

try
{
    $CreateNetScaler = $false #feature not fully working, so leaving it disabled.
    if (!$AdminCredential)
    {
    $AdminCredential = Get-Credential -Message "Admin Account Credentials" -UserName "ctxadmin"
    }

    if ($TCBuildId -or $TCBuildNumber -or $TCLatestBuild)
    {
        if (!$TCCredential)
        {
			$TCCredential = Get-Credential -Message "TeamCity Account Credentials"
        }
        try
        {
        if ($TCBuildNumber)
        {
			$tsstring = "https://ftltc01.eng.citrite.net/httpAuth/app/rest/builds/buildType:" + $TCBuildType + ",number:" + $TCBuildNumber
            $xmlTemp = [xml](Invoke-WebRequest -Uri $tsstring -Credential $TCCredential)
            $TCBuildId = $xmlTemp.build.id
        }
        elseif ($TCLatestBuild)
        {
			$tsstring = "https://ftltc01.eng.citrite.net/httpAuth/app/rest/builds/buildType:" + $TCBuildType + ",lookupLimit:1"
            $xmlTemp = [xml](Invoke-WebRequest -Uri $tsstring -Credential $TCCredential)
            $TCBuildId = $xmlTemp.build.id
        }
        }
        catch [System.Net.WebException]
        {
            #More informative error message for invalid teamcity account
            if ($_.Exception.Response.StatusCode -eq "Unauthorized")
            {
                Write-Host "ERROR: TeamCity account not authorized"
            } else
            {
                Write-Host "ERROR: WebRequest failed: $($_.Exception.Response.StatusCode)"
            }
            Exit
        }
     }

    if ($WaitUntil) {
        Write-Host "Waiting Until $WaitUntil"
        Sleep -Seconds (New-TimeSpan -End $WaitUntil).TotalSeconds
        Write-Host "Starting"
    }

	$azureenv = Get-AzureEnvironment -Name $AzureEnvironment

    $location = (Get-AzureRmresourceGroup -Name $ResourceGroupName).Location

    $LogPath = ($PSScriptRoot + "\" + $Prefix + "background.log")

    $Runspace = [RunspaceFactory]::CreateRunspace()
    $Runspace.Open()
    $Jobs = @()

    $Key = ((Get-AzureRmStorageAccountKey -ResourceGroupName $StorageAccountResourceGroupName -Name $StorageAccountName) | Where-Object {$_.KeyName -eq "key1"}).Value
    $Context = New-AzureStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $Key

    #TeamCity
    if ($TCBuildId -or $TCBuildNumber -or $TCLatestBuild)
    {
        $DownloadAsync = {
            param($_TCBuildId, $_TCCredential, $_Context, $_PSScriptRoot, $_Prefix, $_LogPath)

            "Starting Download" >> $_LogPath

            try
            {
                $blob = Get-AzureStorageBlob -Blob "$_TCBuildId.iso" -Container "isos" -Context $_Context -ErrorAction Stop
            
                #Already exists, don't need to download/upload
                "File $_TCBuildId.iso already exists in storage. Blob: $blob" >> $_LogPath
                $StartTime = Get-Date
                $EndTime = $StartTime.AddHours(5.0)
                $BlobUri = New-AzureStorageBlobSASToken -Container "isos" -Blob "$_TCBuildId.iso" -StartTime $StartTime -ExpiryTime $EndTime -Context $_Context -Permission r -FullUri
                Return $BlobUri
            }
            catch [Microsoft.WindowsAzure.Commands.Storage.Common.ResourceNotFoundException]
            {
                $url = "https://ftltc01.eng.citrite.net/httpAuth/app/rest/builds/id:$_TCBuildId/artifacts/children/Layout/Iso"
                $xml = [xml](Invoke-WebRequest -Uri $url -Credential $_TCCredential).Content
                $file = $xml.files.file | ? {$_.name -match "\.iso$"} | select -First 1
                $file >> $_LogPath
                if ($file)
                {
                    "Found TeamCity Iso File" >> $_LogPath
                    $FilePath = $_PSScriptRoot + "\" + $_TCBuildId + ".iso"
                    "File: $FilePath" >> $_LogPath
                    $href = $file.content.href
                    $source = "https://ftltc01.eng.citrite.net$href"
                    $TCBitsJob = Start-BitsTransfer -Source $source -Destination $FilePath -Credential $_TCCredential -Authentication Basic -DisplayName $_Prefix *>&1 >> $_LogPath
                    if (!$TCBitsJob)
                    {
                        "Finished Download of Iso" >> $_LogPath
                        if (@(Get-AzureStorageContainer -Context $_Context | ? {$_.Name -eq "isos"}).Count -eq 0)
                        {
                            New-AzureStorageContainer -Context $_Context -Name "isos" -Permission Off *>&1 >> $_LogPath
                        }
                        Set-AzureStorageBlobContent -File "$FilePath" -Container "isos" -Context $_Context -Blob "$_TCBuildId.iso" *>&1 >> $_LogPath
                        "Finished Upload of Iso" >> $_LogPath
                
                
                        $StartTime = Get-Date
                        $EndTime = $StartTime.AddHours(2.0)
                        $BlobUri = New-AzureStorageBlobSASToken -Container "isos" -Blob "$_TCBuildId.iso" -StartTime $StartTime -ExpiryTime $EndTime -Context $_Context -Permission r -FullUri
                        "Blob Uri: $BlobUri" >> $_LogPath
                        Return $BlobUri
                    }
                    else
                    {
                        "Iso Upload Failed" >> $_LogPath
                        "BitsJob State:" + $TCBitsJob.JobState >> $_LogPath
                    }
                }
                else
                {
                    "Couldn't find Iso File" >> $_LogPath
                }
            }
            
        }

        $Job = [powershell]::Create().AddScript($DownloadAsync).AddArgument($TCBuildId).AddArgument($TCCredential).AddArgument($Context)
        $Job.AddArgument($PSScriptRoot).AddArgument($Prefix).AddArgument($LogPath)
        $Job.Runspace = $Runspace
        $Jobs += New-Object PSObject -Property @{
            Pipe = $Job
            Result = $Job.BeginInvoke()
        }
    }

    #Local Image
    if ($LocalImage)
    {
        $FullPath = Resolve-Path -Path $LocalImage
        $UploadAsync = {
            param($_Context, $_PSScriptRoot, $_FullPath, $_Prefix, $_LogPath)
            $FileName = (Get-ChildItem $_FullPath).Name
            try
            {
                $null = Get-AzureStorageBlob -Blob "$FileName" -Container "isos" -Context $_Context -ErrorAction Stop
            
                #Already exists, don't need to download/upload
                "File already exists in storage." >> $_LogPath
                $StartTime = Get-Date
                $EndTime = $StartTime.AddHours(2.0)
                $BlobUri = New-AzureStorageBlobSASToken -Container "isos" -Blob $FileName -StartTime $StartTime -ExpiryTime $EndTime -Context $_Context -Permission r -FullUri
                "Blob Uri: $BlobUri" >> $_LogPath
                Return $BlobUri
            }
            catch [Microsoft.WindowsAzure.Commands.Storage.Common.ResourceNotFoundException]
            {            
                "Starting" >> $_LogPath
                if (@(Get-AzureStorageContainer -Context $_Context | ? {$_.Name -eq "isos"}).Count -eq 0)
                {
                    "Creating Storage Container" >> $_LogPath
                    New-AzureStorageContainer -Context $_Context -Name "isos" -Permission Off *>&1 >> $_LogPath
                }
                Set-AzureStorageBlobContent -File "$_FullPath" -Container "isos" -Context $_Context *>&1 >> $_LogPath
                "Finished Uploading ISO" >> $_LogPath
                $StartTime = Get-Date
                $EndTime = $StartTime.AddHours(2.0)

                $BlobUri = New-AzureStorageBlobSASToken -Container "isos" -Blob $FileName -StartTime $StartTime -ExpiryTime $EndTime -Context $_Context -Permission r -FullUri
                "Blob Uri: $BlobUri" >> $_LogPath
                Return $BlobUri
            }
        }

        $Job = [powershell]::Create().AddScript($UploadAsync).AddArgument($Context).AddArgument($PSScriptRoot)
        $Job.AddArgument($FullPath).AddArgument($Prefix).AddArgument($LogPath)
        $Job.Runspace = $Runspace
        $Jobs += New-Object PSObject -Property @{
            Pipe = $Job
            Result = $Job.BeginInvoke()
        }
    }

    $pass = $AdminCredential.Password
    $passPlainText = $AdminCredential.GetNetworkCredential().Password
    #Generates a storage name that is 24 characters long, starting with the prefix and filling the rest with random characters
    $storageName = $Prefix + (-join ((97..122) + (48..57) | Get-Random -Count (24 - $Prefix.Length) | % {[char]$_}))

	#TLR: Update to use defined in an azure environment.
    #$deploymentFQDN = $storageName + '.' + $location +  ".cloudapp.azure.com"

    $deploymentFQDN = $storageName + '.' + $location +  "." + $azureenv.StorageEndpointSuffix    #".cloudapp.azure.com"
    
    Write-Host "Deployment FQDN: " $deploymentFQDN

	$parameters = @{ 
		"namePrefix" = "$Prefix"; 
		"location" = "$location"; 
		"deploymentFQDNSuffix" = "$azureenv.StorageEndpointSuffix";
		"blobStorageSuffix" = "blob." + "$azureenv.StorageEndpointSuffix";
		"gatewayFQDNSuffix" = "xenapponazure.com";
		"vhdStorageAccount" = "$storageName"; 
		"domainName" = "$DomainName"; 
		"adminUsername" = "$($AdminCredential.UserName)"; 
		"adminPassword" = $pass; 
		"dcSize" = $DCSize; 
		"ddcSize" = $DDCSize
	}

    if ($CreateVDA) {
        $parameters.Add("createVDA", "Enabled")
        $parameters.Add("vdaSize", $VDASize)
    }
    if ($CreateNetScaler) {
        $parameters.Add("createNetScaler", "Enabled")
    }
    if ($UseLetsEncrypt) {
        $parameters.Add("certificateAuthority", "ACME")
    }
    else {
        #Generate local certificate
        $thumb = (New-SelfSignedCertificate -CertStoreLocation Cert:\LocalMachine\My -DnsName $deploymentFQDN).Thumbprint
        Export-PfxCertificate -cert "Cert:\LocalMachine\My\$thumb" -FilePath "$PSScriptRoot\$storageName.pfx" -Password $pass
        Import-PfxCertificate -FilePath "$PSScriptRoot\$storageName.pfx" -Password $pass -CertStoreLocation Cert:\LocalMachine\Root

        openssl pkcs12 -in "$PSScriptRoot\$storageName.pfx" -nocerts -out "$PSScriptRoot\$storageName.pem" -passin pass:$passPlainText -passout pass:$passPlainText
        openssl pkcs12 -in "$PSScriptRoot\$storageName.pfx" -nokeys -out "$PSScriptRoot\$storageName.crt" -passin pass:$passPlainText -passout pass:$passPlainText
        openssl rsa -in "$PSScriptRoot\$storageName.pem" -out "$PSScriptRoot\$StorageName.key" -passin pass:$passPlainText

        #Generate rdp file for connecting
        "full address:s:$deploymentFQDN" +
        "`r`nnegotiate security layer:i:1" +
        "`r`npromptcredentialonce:i:1" +
        "`r`nusername:s:$DomainName\$($AdminCredential.UserName)" > $PSScriptRoot\$storageName.rdp

        #Must use an external python script to sign the rdp file, as the Windows 10 rdpsign utility crashes
        .\rdpsign.py $PSScriptRoot\$storageName.rdp $PSScriptRoot\$storageName.rdp $PSScriptRoot\$storageName.crt -k $PSScriptRoot\$storageName.key 
        Remove-Item $PSScriptRoot\$storageName.crt
        Remove-Item $PSScriptRoot\$storageName.pem
        Remove-Item $PSScriptRoot\$storageName.key

        $content = [System.IO.File]::ReadAllBytes("$PSScriptRoot\$storageName.pfx")
        $base64 = [System.Convert]::ToBase64String($content)
        $parameters.Add("certificateAuthority", "Enterprise")
        $parameters.Add("certificateBase64", "$base64")
    }
    #Begin deployment
    New-AzureRmResourceGroupDeployment `
						-Verbose `
						-Name $DeploymentName `
	                    -ResourceGroupName $ResourceGroupName `
	                    -TemplateFile "$PSScriptRoot\mainTemplate.json" `
						-TemplateParameterObject $parameters

    if ($Jobs.count -gt 0)
    {
        Write-Host "Waiting For Download/Upload..."
        $percent = 0
        Do {
                $currPercent = ($Jobs.Pipe.Streams.Progress | Where-Object {$_.PercentComplete -ne -1} | select -First 1)
                if ($currPercent.PercentCompleted -gt $percent)
                {
                    $percent = $currPercent.PercentCompleted
                    $currPercent
                }
            Start-Sleep -Seconds 5
        } While ( $Jobs.Result.IsCompleted -contains $false )
        if ($Jobs.Pipe.Streams.Error)
        {
            Write-Host "Upload/Download Error: $($Jobs.Pipe.Streams.Error)"
            Exit
        }
        Write-Host "Iso Acquisition Completed!"
        $BlobUri = $Jobs.Pipe.EndInvoke($Jobs.Result)[0]
        "Iso Uri: " + $BlobUri
    }
    $DomainCreds = New-Object System.Management.Automation.PSCredential ("$DomainName\$($AdminCredential.UserName)", $Admincredential.Password)
    $DSCContent = [System.IO.File]::ReadAllBytes("$PSScriptRoot\Config.ps1")

    Invoke-Command -ComputerName $deploymentFQDN -UseSSL -Credential $DomainCreds -ScriptBlock {
        param($_BlobUri, $_AdminCredential, $_DomainCredential, $_DomainName, $_Prefix, $_DSCContent, $_FQDN, $_CreateVDA)
        
        if ($_CreateVDA)
        {
            '
            $Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ' + "$($_DomainCredential.UserName)" + ', (ConvertTo-SecureString "' + (ConvertFrom-SecureString $_DomainCredential.Password) + '")
            Invoke-Command -ComputerName ' + $_Prefix + '-VDA.' + $_DomainName + ' -Credential $Cred -ScriptBlock {
            
            #development builds do not trust the publisher for some reason, so I import the certificate to avoid having to approve the driver installation
            $Base64 = "MIIFMzCCBBugAwIBAgIQVHYjXDRU05t2gqGHNbDYezANBgkqhkiG9w0BAQUFADCBtDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQLEzJUZXJtcyBvZiB1c2UgYXQgaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykxMDEuMCwGA1UEAxMlVmVyaVNpZ24gQ2xhc3MgMyBDb2RlIFNpZ25pbmcgMjAxMCBDQTAeFw0xNTA4MTIwMDAwMDBaFw0xNjExMTAyMzU5NTlaMIGPMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEUMBIGA1UEBxMLU2FudGEgQ2xhcmExHTAbBgNVBAoUFENpdHJpeCBTeXN0ZW1zLCBJbmMuMRcwFQYDVQQLFA5YZW5BcHAoU2VydmVyKTEdMBsGA1UEAxQUQ2l0cml4IFN5c3RlbXMsIEluYy4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2mGLVJGtaUD9vQEk6Ci+sZ3Gwb1XV8n0sueXdybnkgah5m3rMvfPWVMLdYCze+Bvy3m5ZTH29bUIqJM8fA9tvLn6Xyp0I331+Sbc4rFN2+AwnUPp+9Jx152CC7pQWvIuDahgeKJp3mhY5FBDe5Zhmr8xg6EEaIejjyTX/0eHQu0GkqUbtDsxUe/bHv/CPbhZcVlPN/XdrJoS1V9HKW6BzdkBlFiywZ1tWNcRsyrF+4mwc01R9Hia17BGTW9IYo0R9kzgwy44/DytB4MvSDlgtPwj0gD0sr2zGH31byHFgBkgA8KZM2n9T+XtU9XrAxLHo0bIvIWMGpz+H83Vd/o63AgMBAAGjggFiMIIBXjAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIHgDArBgNVHR8EJDAiMCCgHqAchhpodHRwOi8vc2Yuc3ltY2IuY29tL3NmLmNybDBmBgNVHSAEXzBdMFsGC2CGSAGG+EUBBxcDMEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5zeW1jYi5jb20vY3BzMCUGCCsGAQUFBwICMBkMF2h0dHBzOi8vZC5zeW1jYi5jb20vcnBhMBMGA1UdJQQMMAoGCCsGAQUFBwMDMFcGCCsGAQUFBwEBBEswSTAfBggrBgEFBQcwAYYTaHR0cDovL3NmLnN5bWNkLmNvbTAmBggrBgEFBQcwAoYaaHR0cDovL3NmLnN5bWNiLmNvbS9zZi5jcnQwHwYDVR0jBBgwFoAUz5mp6nsm9EvJjo/X8AUm7+PSp50wHQYDVR0OBBYEFAlWo5RSr5tTjc/qoxYZL997nMITMA0GCSqGSIb3DQEBBQUAA4IBAQAvkG+CqtJXphvJOPSlxzUO0sCuqvLbWWeAnK0rzKwdoNlEx12qbBF1E3s8aSyRTgEg34tWKCV+luQSlizi9iKCJzSK1zHuOxl6QBzSAdnmFcqvtxPGjmynpsAmuCkJastAsFz0cuvc62qneJiiXeLuTLflrg4IjlvKiOJpYu5+lcm6H7grAq3gtDIrbJKjn9Z2V105okDzCd82/IEM5OdjvnueH1P2Cb2+geVlNkaARfnPRoZqbnRifCFWxRTa3EkEd0rc7K+d2OrBizPkUbvzTWPQp0MWUzagc5OJ0usnTlXZdbBsK+++4Jz2W8APV+0g6GV8heiWhHj5o24/QoNA"
            $Content = [System.Convert]::FromBase64String($Base64)
            
            #Must use .Net version of cert import, as double hop blocks the powershell version
            $ComputerName = "' + $_Prefix + '-VDA.' + $_DomainName + '"
            $CertStore = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList "\\$($ComputerName)\TrustedPublisher", "LocalMachine"
            $CertStore.Open("ReadWrite")
            $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $Certificate.Import($Content)
            $CertStore.Add($Certificate)

            $IsoPath = ("$env:TEMP\xa.iso")
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile("' + $_BlobUri + '", $IsoPath)
            $Disk = Mount-DiskImage -ImagePath $IsoPath -PassThru
            $Drive = ($Disk | Get-Volume).DriveLetter + ":\"
            $Destination = "C:\XAInstall"
    
            Copy-Item $Drive $Destination -Recurse
    
            $Disk | Dismount-DiskImage
            rm $IsoPath

            New-Item -Force -ItemType Directory -Path "C:\Logs" | Write-Verbose
            
            #vda
            $exe = $Destination + "\x64\XenDesktop Setup\XenDesktopVDASetup.exe"
            Start-Process -FilePath $exe -ArgumentList "/quiet /controllers ' + $_Prefix + '-DDC.' + $_DomainName + ' /enable_hdx_ports /logpath C:\Logs" -Wait
            }
            ' > $env:TEMP\script.ps1

            schtasks /create /tn 'Temp XA Task' /SC 'Once' /RL 'Highest' /RU "$($_DomainCredential.UserName)" /IT /RP $_DomainCredential.GetNetworkCredential().Password `
                /TR "powershell -noprofile -ExecutionPolicy Bypass -File $env:TEMP\script.ps1" /F /ST (Get-Date).AddMinutes(1).ToString("HH:mm") /SD (Get-Date).AddMinutes(1).ToString("MM/dd/yyyy")
        }
        Write-Host "Downloading ISO to VM..."
        $IsoPath = ("$env:TEMP\xa.iso")
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($_BlobUri, $IsoPath)
        $Disk = Mount-DiskImage -ImagePath $IsoPath -PassThru
        $Drive = ($Disk | Get-Volume).DriveLetter + ":\"
        $Destination = "C:\XAInstall"
        Write-Host "Copying ISO contents to VM..."
        Copy-Item $Drive $Destination -Recurse
        
        $Disk | Dismount-DiskImage
        rm $IsoPath
        
        New-Item -Force -ItemType Directory -Path "C:\Logs" | Write-Verbose
        
        '
        $Destination = "C:\XAInstall"
        $exe = $Destination + "\x64\XenDesktop Setup\XenDesktopServerSetup.exe"
        Start-Process -FilePath $exe -ArgumentList "/configure_firewall /quiet /logpath C:\Logs /noreboot" -Wait -NoNewWindow
        ' > $env:TEMP\script2.ps1

        schtasks /create /tn 'Temp XA Task2' /SC 'Once' /RL 'Highest' /RU "$($_DomainCredential.UserName)" /IT /RP $_DomainCredential.GetNetworkCredential().Password `
            /TR "powershell -noprofile -ExecutionPolicy Bypass -File $env:TEMP\script2.ps1" /F /ST (Get-Date).AddMinutes(1).ToString("HH:mm") /SD (Get-Date).AddMinutes(1).ToString("MM/dd/yyyy")
        
        Write-Host -NoNewline "Starting XD Install"
        Sleep -s 61
        Do {
            $Status = (schtasks.exe /query /TN "Temp XA Task2" /FO CSV | ConvertFrom-Csv | select -expandproperty Status -first 1)
            $NextRun = (schtasks.exe /query /TN "Temp XA Task2" /FO CSV | ConvertFrom-Csv | select -expandproperty "Next Run Time" -first 1)
            Write-Host -NoNewline "."
            sleep -s 10
        }
        While($Status -eq "Running" -or $NextRun -ne "N/A")
        Write-Host "Complete"        

        
        if ($_CreateVDA)
        {
            Write-Host -NoNewline "Starting VDA Install"
            Do {
                $Status = (schtasks.exe /query /TN "Temp XA Task" /FO CSV | ConvertFrom-Csv | select -expandproperty Status -first 1)
                $NextRun = (schtasks.exe /query /TN "Temp XA Task" /FO CSV | ConvertFrom-Csv | select -expandproperty "Next Run Time" -first 1)
                Write-Host -NoNewline "."
                sleep -s 10
            }
            While($Status -eq "Running" -or $NextRun -ne "N/A")
            
            #Then sleep an extra 10 minutes, to make sure VDA has rebooted (twice)
            For($i=0; $i -lt 10; $i++)
            {
                Write-Host -NoNewline "."
                Sleep -Seconds 60
            }
            Write-Host "Complete"
            
            #VDA should be hanging by now (it waits for user login for some reason, but can be manually triggered)
            
            '
            $Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ' + "$($_DomainCredential.UserName)" + ', (ConvertTo-SecureString "' + (ConvertFrom-SecureString $_DomainCredential.Password) + '")
            Invoke-Command -ComputerName ' + $_Prefix + '-VDA.' + $_DomainName + ' -Credential $Cred -ScriptBlock {
            $Destination = "C:\XAInstall"
            $exe = $Destination + "\x64\XenDesktop Setup\XenDesktopVDASetup.exe"
            Start-Process -FilePath $exe -ArgumentList "/quiet /controllers ' + $_Prefix + '-DDC.' + $_DomainName + ' /enable_hdx_ports /logpath C:\Logs" -Wait -NoNewWindow
            }
            ' > $env:TEMP\script.ps1
            schtasks /create /tn 'Temp XA Task3' /SC 'Once' /RL 'Highest' /RU "$($_DomainCredential.UserName)" /IT /RP $_DomainCredential.GetNetworkCredential().Password `
                /TR "powershell -noprofile -ExecutionPolicy Bypass -File $env:TEMP\script.ps1" /F /ST (Get-Date).AddMinutes(1).ToString("HH:mm") /SD (Get-Date).AddMinutes(1).ToString("MM/dd/yyyy")
        }

        #DDC Should be hanging, must complete it's install
        schtasks /create /tn 'Temp XA Task4' /SC 'Once' /RL 'Highest' /RU "$($_DomainCredential.UserName)" /IT /RP $_DomainCredential.GetNetworkCredential().Password `
            /TR "powershell -noprofile -ExecutionPolicy Bypass -File $env:TEMP\script2.ps1" /F /ST (Get-Date).AddMinutes(1).ToString("HH:mm") /SD (Get-Date).AddMinutes(1).ToString("MM/dd/yyyy")
        
        if ($_CreateVDA)
        {
            Write-Host -NoNewline "Finishing VDA Installation"
            Do {
                $Status = (schtasks.exe /query /TN "Temp XA Task3" /FO CSV | ConvertFrom-Csv | select -expandproperty Status -first 1)
                $NextRun = (schtasks.exe /query /TN "Temp XA Task3" /FO CSV | ConvertFrom-Csv | select -expandproperty "Next Run Time" -first 1)
                Write-Host -NoNewline "."
                sleep -s 10
            }
            While($Status -eq "Running" -or $NextRun -ne "N/A")
            Write-Host "Complete"
        }

        Write-Host -NoNewline "Finishing XD Install"
        Sleep -Seconds 61
        Do {
            $Status = (schtasks.exe /query /TN "Temp XA Task4" /FO CSV | ConvertFrom-Csv | select -expandproperty Status -first 1)
            $NextRun = (schtasks.exe /query /TN "Temp XA Task4" /FO CSV | ConvertFrom-Csv | select -expandproperty "Next Run Time" -first 1)
            Write-Host -NoNewline "."
            sleep -s 10
        }
        While($Status -eq "Running" -or $NextRun -ne "N/A")
        Write-Host "Complete"

        #Use DSC configuration to configure XenDesktop install
        #Prepare certificate for encrypting credentials in DSC
        $cert = gci "Cert:\LocalMachine\My" | Where-Object {$_.Subject -match "CN=AzureDSCExtension"} | select -First 1 
        Export-Certificate -FilePath "C:\Vault\cert.cer" -Cert $cert
        $thumb = $cert.Thumbprint


        #Just in case the powershell version changes
        $Settings = (gci -Path "C:\Packages\Plugins\Microsoft.Powershell.DSC" | select -First 1).FullName + "\RuntimeSettings\0.settings"
        $ConfigData= @{
            AllNodes = @( 
                @{  
                NodeName                    = "localhost"
                CertificateFile = "C:\Vault\cert.cer"
                Thumbprint = $thumb
                PSDscAllowDomainUser = $true
                }
            )
        }
        function Get-PsObjectHashTable
        {
            param($psObject)
        
            $ht = @{}
        
            $psObject | Get-Member -Type NoteProperty | ForEach-Object {
                    $parameterValue = $psObject | Select-Object -ExpandProperty $_.Name
                        $ht[$_.Name] = $parameterValue
            }
        
            $ht
        }
        
        
        $data = (Get-Content $Settings -Raw | ConvertFrom-Json).runtimeSettings[0].handlerSettings.publicSettings.Properties
        
        $parameters = Get-PsObjectHashTable -psObject $data
        
        $parameters.AdminCreds = $_Admincredential
        $parameters.CertificatePassword = $parameters.AdminCreds
        $parameters.AppGroups = $parameters.AppGroups | %{ Get-PsObjectHashTable -psObject $_ }
        
        [System.IO.File]::WriteAllBytes("$env:TEMP\Config.ps1", $_DSCContent)
        . "$env:TEMP\Config.ps1"
        cd $env:TEMP
        Config @parameters -ConfigurationData $ConfigData
        Start-DscConfiguration -Path .\Config -ComputerName localhost -Force -Wait -Verbose | Write-Output -Verbose
    } -ArgumentList @($BlobUri, $AdminCredential, $DomainCreds, $DomainName, $Prefix, $DSCContent, $deploymentFQDN, $CreateVDA)
    if ($CreateVDA)
    {
        Get-AzureRmVM -ResourceGroupName $ResourceGroupName -Name "$Prefix-VDA" | Stop-AzureRmVM -Force
    }
}

finally
{
    if ($Job) {
        $Job.Dispose()
        $Runspace.Close()
    }
}

$ConfigData= @{
    AllNodes = @( 
                    @{  
                    NodeName                    = "localhost"
                    PSDscAllowPlainTextPassword = $true
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

$data = (Get-Content ..\..\RuntimeSettings\0.settings -Raw | ConvertFrom-Json).
            runtimeSettings[0].handlerSettings.publicSettings.Properties

$parameters = Get-PsObjectHashTable -psObject $data

$parameters.AdminCreds = Get-Credential
$parameters.CertificatePassword = $parameters.AdminCreds
$parameters.AppGroups = $parameters.AppGroups | %{ Get-PsObjectHashTable -psObject $_ }

. .\DeliveryController.ps1

Remove-Item .\DeliveryController -Recurse -ErrorAction SilentlyContinue

DeliveryController @parameters -ConfigurationData $ConfigData

Start-DscConfiguration -Path .\DeliveryController -ComputerName localhost -Force -Wait -Verbose -Debug

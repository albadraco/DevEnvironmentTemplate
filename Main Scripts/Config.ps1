#
# Config.ps1
#
configuration Config 
{ 
   param 
   ( 
		# Credentials and domain
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds,

        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [String]$DomainController,
        
        [Parameter(Mandatory)]
        [String]$DomainControllerIp,

        [Parameter(Mandatory)]
        [String]$CreateNetScaler,

        [Parameter(Mandatory)]
        [string]$CreateVDA,

        [Parameter(Mandatory)]
        [string]$VDAName,
	    
	    # Delegated servers
        [Parameter(Mandatory)]
        [String]$SQLServer,

        [Parameter(Mandatory)]
        [String]$SQLServerInstance,

        [Parameter(Mandatory)]
        [String]$LicenseServer,

        [Parameter(Mandatory)]
        [String]$NetScalerIP,
	    
	    # StoreFront
        [Parameter(Mandatory)]
        [String]$StoreFront,

        [Parameter(Mandatory)]
        [String]$VirtualServerName,

        [Parameter(Mandatory)]
        [Int]$VirtualServerPort,

        [Parameter(Mandatory)]
        [Int]$ForwardServerPort,

        [Parameter(Mandatory)]
        [String]$StoreFrontGatewayName,

        [Parameter(Mandatory)]
        [String]$EmailAddress,

        [Parameter(Mandatory)]
	    [ValidateSet("ACME", "Enterprise")]
        [String]$Authority,

        [Parameter(Mandatory)]
        [String]$ACMEServer,

        [Parameter(Mandatory)]
        [String]$GatewayFQDN,

        [Parameter(Mandatory)]
        [String]$DeploymentFQDN,
        
        [Parameter(Mandatory)]
        [String]$ThemeUri,

        [Parameter(Mandatory)]
        [String]$HTML5Mode,

        [Parameter(Mandatory)]
        [Hashtable[]]$AppGroups,

        #[Parameter(Mandatory)]
        #[String]$License,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$CertificatePassword,

        [Parameter(Mandatory)]
        [string]$CertificateBase64,
	     
	    # Delivery controller
        [Parameter(Mandatory)]
        [String]$DeliveryController,

        [Parameter(Mandatory)]
        [String]$SiteName,

        [Int]$RetryCount = 10,
        [Int]$RetryIntervalSec = 60
    ) 

    Import-DscResource -ModuleName PSDesiredStateConfiguration #-ModuleVersion 1.1
    Import-DscResource -ModuleName xActiveDirectory, xComputerManagement, CitrixXenDesktopAutomation, xCertificate, xWebAdministration, CitrixNetscaler, CitrixMarketplace, ACMEPowerShell, ACMECertificate, xSmbShare, xNetworking, cChoco, xPendingReboot
 
    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)
    $certPassword = $CertificatePassword.GetNetworkCredential().Password

	$Interface=Get-NetAdapter|Where Name -Like "Ethernet*"|Select-Object -First 1
    $InterfaceAlias=$($Interface.Name)

    $siteDatabaseName = "Citrix" + $SiteName + "Site"
    $monitoringDatabaseName = "Citrix" + $SiteName + "Monitoring"
    $loggingDatabaseName = "Citrix" + $SiteName + "Logging"

	$iisPath = "C:\\inetpub\\wwwroot"
	$vaultPath = "C:\Vault"
	$keyFile = "$vaultPath\key.pem"
	$pairFile = "$vaultPath\pair.pem"
	$certFile = "$vaultPath\cert.pem"
    $pfxFile = "$vaultPath\cert.pfx"

    $studioMsc = "C:\Program Files\Citrix\Desktop Studio\Studio.msc"
    

    if ($CreateNetScaler -eq "Enabled")
    {
        $UsingNetScaler = $true
        $Depends = "[Citrix_XenDesktopStorefront]Storefront"
    }
    else 
    {
        $UsingNetScaler = $false
        $Depends = "[Script]ConfigureStorefront"
    }

    if ($CreateVDA -eq "Enabled")
    {
        $UsingVDA = $true
    }
    else 
    {
        $UsingVDA = $false
    }

    Node localhost
    {
        
        Script WaitForInstall
        {
            GetScript = { @{} }
                SetScript = {
                    Do {
                        $Process = Get-Process -Name "XenDesktopServerSetup" -ErrorAction SilentlyContinue
                        Sleep -Seconds 10
                        }
                    While($Process -ne $null)
                }
                TestScript = { $false }
        }
        #xPendingReboot Reboot
        #{
        #    Name = "BeforeRun"
        #}

        LocalConfigurationManager 
        { 
            RebootNodeIfNeeded = $true
			ConfigurationMode = "ApplyOnly"
        } 

        WindowsFeature ADPowershell
        {
            Name = "RSAT-AD-PowerShell"
            Ensure = "Present"
            DependsOn = "[Script]WaitForInstall"
        }

        #WindowsFeature InstallWebServer
        #{
        #    Name = "Web-Server"
        #    Ensure = "Present"
        #    DependsOn = "[WindowsFeature]ADPowershell"
        #}
        #
        #WindowsFeature InstallWebAsp
        #{
        #    Name = "Web-Asp-Net45"
        #    Ensure = "Present"
        #    DependsOn = "[WindowsFeature]InstallWebServer"
        #}
        #
        #WindowsFeature InstallWebConsole
        #{
        #    Name = "Web-Mgmt-Console"
        #    Ensure = "Present"
        #    DependsOn = "[WindowsFeature]InstallWebAsp"
        #}
        #
		#Citrix_MarketplaceConditionWait DomainCondition 
        #{ 
        #    Condition = "Domain"
		#	Machine = $DomainControllerIp
        #    PsDscRunAsCredential = $Admincreds
        #    DependsOn = "[WindowsFeature]InstallWebConsole" 
        #}  
        #
		#Script ResetAdapter
        #{ 
		#	GetScript = { @{} } #make sleep
		#	SetScript = { Start-Sleep -Seconds 300; ipconfig /release; ipconfig /renew; ipconfig /flushdns; }
		#	TestScript = { $false }
        #    DependsOn = "[Citrix_MarketplaceConditionWait]DomainCondition" 
        #}  
        #
		#xWaitForADDomain WaitForDomain 
        #{ 
        #    DomainName = $DomainName 
        #    DomainUserCredential= $Admincreds
        #    RetryCount = $RetryCount 
        #    RetryIntervalSec = $RetryIntervalSec
        #    DependsOn = "[Script]ResetAdapter" 
        #}
        #
        #xComputer DomainJoin
        #{
        #    Name = $env:COMPUTERNAME
        #    DomainName = $DomainName
        #    Credential = $DomainCreds
        #    DependsOn = "[xWaitForADDomain]WaitForDomain" 
        #}
        #
        #Script EnsureCA
        #{ 
		#	GetScript = { @{} }
		#	SetScript = { gpupdate /force }
		#	TestScript = {
        #        if(dir Cert:\LocalMachine\CA | ?{$_.Subject -match "DomainCA" })
        #        {
        #            Write-Verbose "The root CA certificate Already exists"
        #            return $true
        #        }
        #        else
        #        {
        #           Write-Verbose "The root CA certificate does not exist"
        #           return $false
        #        }
        #                
        #    }
        #    DependsOn = "[xComputer]DomainJoin"
        #       
        #}
        #
        #xCertReq SSLCert
        #{
        #    CARootName = 'DomainCA'
        #    CAServerFQDN = $DomainController
        #    Subject = $DeliveryController
        #    AutoRenew = $true
        #    Credential = $DomainCreds
        #    DependsOn = "[Script]EnsureCA"
        #}
        #
        #xWebSite DefaultWebSite {
        #    Name = 'Default Web Site';
        #    PhysicalPath = 'C:\inetpub\wwwroot';
        #    BindingInfo = @(
        #        MSFT_xWebBindingInformation  { Protocol = 'HTTPS'; Port = 443; CertificateThumbprint = $DeliveryController; CertificateStoreName = 'My'; }
        #        MSFT_xWebBindingInformation  { Protocol = 'HTTP'; Port = 80; }
        #    )
        #    DependsOn = '[xCertReq]SSLCert';
        #}
        
        Citrix_XenDesktopDatabase CreateSiteDatabase
        {
            SiteName = $SiteName
            DatabaseClass = "Site"			
            DatabaseServer = $SQLServer
            DatabaseServerInstance = $SQLServerInstance
            DatabaseName = $siteDatabaseName
            DatabaseCredential = $DomainCreds
            PsDscRunAsCredential = $DomainCreds
            DependsOn = "[WindowsFeature]ADPowershell"#"[xWebSite]DefaultWebSite"
        }
        
        Citrix_XenDesktopDatabase CreateLoggingDatabase
        {
            SiteName = $SiteName
            DatabaseClass = "Logging"			
            DatabaseServer = $SQLServer
            DatabaseServerInstance = $SQLServerInstance
            DatabaseName = $loggingDatabaseName
            DatabaseCredential = $DomainCreds
            PsDscRunAsCredential = $DomainCreds
            DependsOn = "[Citrix_XenDesktopDatabase]CreateSiteDatabase" 
        }
        
        Citrix_XenDesktopDatabase CreateMonitorDatabase
        {
            SiteName = $SiteName
            DatabaseClass = "Monitor"			
            DatabaseServer = $SQLServer
            DatabaseServerInstance = $SQLServerInstance
            DatabaseName = $monitoringDatabaseName
            DatabaseCredential = $DomainCreds
            PsDscRunAsCredential = $DomainCreds
            DependsOn = "[Citrix_XenDesktopDatabase]CreateLoggingDatabase" 
        }
        
        Citrix_XenDesktopSite CreateSite
        {
            DatabaseServer = $SQLServer
            DatabaseServerInstance = $SQLServerInstance
            UserToMakeAdmin = $DomainCreds.UserName
            XenDesktopController = "localhost:80"
            SiteName = $SiteName
            LicenseServer = $LicenseServer
            LicenseServerPort = 27000
            LoggingDatabaseName = $loggingDatabaseName
            MonitoringDatabaseName = $monitoringDatabaseName
            SiteDatabaseName = $siteDatabaseName
            Ensure = "Present"
            DependsOn = "[Citrix_XenDesktopDatabase]CreateMonitorDatabase" 
        }
        
		Citrix_XenDesktopDirector Director
        {
            XenDesktopController = $DeliveryController
            PsDscRunAsCredential = $DomainCreds
            DependsOn = "[Citrix_XenDesktopSite]CreateSite" 
        }
        
        Script ConfigureStorefront
        {
            GetScript = { @{} }
            SetScript = {
                $Script = {
                param($_StoreFront)
                    asnp citri*
                    New-SfCluster -AdminAddress "localhost" -FarmName "Site" -ServerName $_StoreFront -StorefrontUrl "http://$_StoreFront/" `
                    -XmlServices @("http://$_StoreFront/") -ErrorAction SilentlyContinue
                }
                Invoke-Command -ScriptBlock $Script -ComputerName "localhost" -ArgumentList @($using:StoreFront)
            }
            TestScript = { $false }
            DependsOn = "[Citrix_XenDesktopDirector]Director"
        }

        Citrix_XenDesktopStudioController StudioSetup
        {
			XenDesktopController = $DeliveryController
			StudioMsc = $studioMsc
            DependsOn = "[Script]ConfigureStorefront" 
        }
        
		
        #cChocoInstaller InstallChoco
        #{
        #    InstallDir = "C:\Choco"
        #    DependsOn = "[xWebSite]DefaultWebSite"
        #}
        #
        #
		#if($Authority -match "ACME")
		#{
        #    
        #    Citrix_MarketplaceDomain Domain
        #    { 
        #        DeploymentFQDN = $DeploymentFQDN
        #        GatewayFQDN = $GatewayFQDN
		#	    EmailAddress = $EmailAddress
		#	    IisRoot = $iisPath
        #        DependsOn = "[cChocoInstaller]InstallChoco"#"[Citrix_NetscalerRemoteFile]Theme" 
        #    }
        #
		#	ACME_CertificateRequest CertRequest
		#	{ 
		#		ACMEServer = $AcmeServer
		#		CommonName = $GatewayFQDN
		#		EmailAddress = $EmailAddress
		#		CertificatePassword = $CertificatePassword
		#		VaultPath = $vaultPath
		#		CertPath = $certFile
		#		KeyPath = $keyFile
		#		PairPath = $pairFile
		#		IISPath = $iisPath
		#		DependsOn = "[Citrix_MarketplaceDomain]Domain" 
		#	}
        #    
        #
        #    cChocoPackageInstaller InstallOpenSSL
        #    {
        #    Ensure = "Present"
        #    Name = "openssl.light"
        #    DependsOn = "[ACME_CertificateRequest]CertRequest"
        #    }
        #
        #
        #    Script InstallCert
        #    {
        #        GetScript = { @{} }
        #        SetScript = {
        #
        #         & "C:\Program Files\OpenSSL\bin\openssl.exe" pkcs12 -export -out $using:pfxFile -inkey $using:keyFile -in $using:certFile -passout "pass:$using:certPassword"
        #        Import-PfxCertificate -FilePath $using:pfxFile cert:\LocalMachine\My -Password (ConvertTo-SecureString -AsPlainText -Force $using:certPassword)
        #        }
        #        TestScript = { $false }
        #        DependsOn = "[cChocoPackageInstaller]InstallOpenSSL"
        #    }
        #
        #    Script RDP
        #    {
        #        GetScript = { @{} }
        #        SetScript = {
        #        $tsgs = gwmi -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'"
        #        $thumb = (gci -path cert:\LocalMachine\My | Where-Object {$_.Subject -like "*$using:GatewayFQDN*"} | select -first 1).Thumbprint
        #        swmi -path $tsgs.__path -argument @{SSLCertificateSHA1Hash="$thumb"}
        #        }
        #        TestScript = { $false }
        #        DependsOn = "[Script]InstallCert"
        #    }
        #
        #    Script RemotePowerShell
        #    {
        #        GetScript = { @{} }
        #        SetScript = {
        #        $thumb = (gci -path cert:\LocalMachine\My | Where-Object {$_.Subject -like "*$using:GatewayFQDN*"} | select -first 1).Thumbprint
        #        New-Item WSMan:\localhost\Listener -Address * -Transport HTTPS -HostName $using:GatewayFQDN -CertificateThumbPrint $thumb
        #        New-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5986
        #        }
        #        TestScript = { $false }
        #        DependsOn = "[Script]InstallCert"
        #    }
		#	#Citrix_NetscalerLocalFile Certificate 
		#	#{
		#	#	Filename = "/nsconfig/ssl/$certName"
		#	#	NetScalerIP = $NetScalerIP
		#	#	NetscalerCredential = $Admincreds
		#	#	LocalPath = $pairFile
		#	#	Ensure = "Present"
		#	#	DependsOn = "[ACME_CertificateRequest]CertRequest"
		#	#}
		#}
		#else
		#{
        #
		#	$certName = "certificate.pfx"
		#	$certPath = "$vaultPath\$certName"
        #    
        #    File CreateVault {
        #        Type = "Directory"
        #        DestinationPath = "$vaultPath"
        #        Ensure = "Present"
        #        DependsOn = "[cChocoInstaller]InstallChoco"
        #    }
        #
		#	Script DecodeCertificate
		#	{
		#		GetScript = { @{ } }
		#		SetScript = { 
        #            $content = [System.Convert]::FromBase64String($using:CertificateBase64)
        #            [IO.File]::WriteAllBytes($using:certPath, $content)
        #            Import-PfxCertificate -FilePath $using:certPath -Password (ConvertTo-SecureString -AsPlainText -Force $using:certPassword) -CertStoreLocation "Cert:\LocalMachine\My"
		#		}
		#		TestScript = { Test-Path $using:certPath }
		#		DependsOn = "[File]CreateVault"#"[Citrix_MarketplaceDomain]Domain" 
		#	}
        #
        #    Script RDP
        #    {
        #        GetScript = { @{} }
        #        SetScript = {
        #        $tsgs = gwmi -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'"
        #        $thumb = (gci -path cert:\LocalMachine\My | Where-Object {$_.Subject -eq "CN=$using:DeploymentFQDN"} | select -first 1).Thumbprint
        #        swmi -path $tsgs.__path -argument @{SSLCertificateSHA1Hash="$thumb"}
        #        }
        #        TestScript = { $false }
        #        DependsOn = "[Script]DecodeCertificate"
        #    }
        #
        #    Script RemotePowerShell
        #    {
        #        GetScript = { @{} }
        #        SetScript = {
        #        $thumb = (gci -path cert:\LocalMachine\My | Where-Object {$_.Subject -eq "CN=$using:DeploymentFQDN"} | select -first 1).Thumbprint
        #        New-Item WSMan:\localhost\Listener -Address * -Transport HTTPS -HostName $using:DeploymentFQDN -CertificateThumbPrint $thumb
        #        New-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5986
        #        }
        #        TestScript = { $false }
        #        DependsOn = "[Script]DecodeCertificate"
        #    }
        #
		#	#Citrix_NetscalerLocalFile Certificate 
		#	#{
		#	#	Filename = "/nsconfig/ssl/$certName"
		#	#	NetScalerIP = "10.0.0.11"
		#	#	NetscalerCredential = $Admincreds
		#	#	LocalPath = $certPath
		#	#	Ensure = "Present"
		#	#	DependsOn = "[Script]ExportSelfSigned"
		#	#}
		#}
        #
        #cChocoPackageInstallerSet InstallVCRedists
        #{
        #    Ensure = "Present"
        #    Name = @(
		#	    "vcredist2008"
		#	    "vcredist2010"
		#	    "vcredist2013"
		#    )
        #    DependsOn = "[Script]RemotePowerShell"
        #}
		#if ($UsingVDA)
        #{
        #    #taken from powershell output of manually doing this in Studio
        #    Script DeliveryConfig
        #    {
        #        GetScript = { @{} }
        #        SetScript = {
        #            $sid = (Get-ADComputer -Filter "name -eq '$using:VDAName'" -Properties sid).SID.Value
        #            $ddcPort = "$using:DeliveryController" + ":80"
        #            asnp citri*
        #            # Create Machine Catalog 'Catalog'
        #            New-BrokerCatalog  -AdminAddress $ddcPort -AllocationType "Random" -IsRemotePC $False -MachinesArePhysical $True -MinimumFunctionalLevel "L7_9" -Name "Catalog" -PersistUserChanges "OnLocal" -ProvisioningType "Manual" -Scope @() -SessionSupport "MultiSession"
        #            
        #            New-BrokerMachine  -AdminAddress $ddcPort -CatalogUid 2 -MachineName $sid
        #            
        #            # 
        #            # Create Machine 'Desktop' in Delivery Group 'Delivery'
        #            New-BrokerEntitlementPolicyRule  -AdminAddress $ddcPort -Description "" -DesktopGroupUid 2 -Enabled $True -IncludedUserFilterEnabled $False -IncludedUsers @() -Name "Desktop" -PublishedName "Desktop"
        #            
        #            # 
        #            # Create Delivery Group 'Delivery' 
        #            New-BrokerDesktopGroup  -AdminAddress $ddcPort -ColorDepth "TwentyFourBit" -DeliveryType "DesktopsAndApps" -DesktopKind "Shared" -InMaintenanceMode $False -IsRemotePC $False -MinimumFunctionalLevel "L7_9" -Name "Delivery" -OffPeakBufferSizePercent 10 -PeakBufferSizePercent 10 -PublishedName "Delivery" -Scope @() -SecureIcaRequired $False -SessionSupport "MultiSession" -ShutdownDesktopsAfterUse $False -TimeZone "UTC"
        #            
        #            Set-BrokerDesktopGroup  -AdminAddress $ddcPort -InputObject @(2) -PassThru -ZonePreferences @("ApplicationHome","UserHome","UserLocation")
        #            
        #            Add-BrokerMachine  -AdminAddress $ddcPort -DesktopGroup "Delivery" -InputObject @(1)
        #            
        #            Test-BrokerAppEntitlementPolicyRuleNameAvailable  -AdminAddress $ddcPort -Name @("Delivery")
        #            
        #            New-BrokerAppEntitlementPolicyRule  -AdminAddress $ddcPort -DesktopGroupUid 2 -Enabled $True -IncludedUserFilterEnabled $False -Name "Delivery"
        #            
        #            Set-Variable  -Name "brokerUsers" -Value @()
        #            
        #            Get-BrokerUser  -AdminAddress $ddcPort -Filter {(SID -in $brokerUsers)} -MaxRecordCount 2147483647
        #            
        #            Remove-Variable  -Name "brokerUsers"
        #            
        #            Test-BrokerAccessPolicyRuleNameAvailable  -AdminAddress $ddcPort -Name @("Delivery_Direct")
        #            
        #            New-BrokerAccessPolicyRule  -AdminAddress $ddcPort -AllowedConnections "NotViaAG" -AllowedProtocols @("HDX","RDP") -AllowedUsers "AnyAuthenticated" -AllowRestart $True -DesktopGroupUid 2 -Enabled $True -IncludedSmartAccessFilterEnabled $True -IncludedUserFilterEnabled $True -IncludedUsers @() -Name "Delivery_Direct"
        #            
        #            Test-BrokerAccessPolicyRuleNameAvailable  -AdminAddress "fullreal2-ddc.xenapp.local:80" -Name @("Delivery_AG")
        #            
        #            New-BrokerAccessPolicyRule  -AdminAddress $ddcPort -AllowedConnections "ViaAG" -AllowedProtocols @("HDX","RDP") -AllowedUsers "AnyAuthenticated" -AllowRestart $True -DesktopGroupUid 2 -Enabled $True -IncludedSmartAccessFilterEnabled $True -IncludedSmartAccessTags @() -IncludedUserFilterEnabled $True -IncludedUsers @() -Name "Delivery_AG"
        #                                
        #            # 
        #            # Create Application 'Notepad'
        #            New-BrokerApplication  -AdminAddress $ddcPort -ApplicationType "HostedOnDesktop" -CommandLineArguments "" -CommandLineExecutable "C:\Windows\system32\notepad.exe" -CpuPriorityLevel "Normal" -DesktopGroup 2 -Enabled $True -IconUid 2 -IgnoreUserHomeZone $False -MaxPerUserInstances 0 -MaxTotalInstances 0 -Name "Notepad" -Priority 0 -PublishedName "Notepad" -SecureCmdLineArgumentsEnabled $True -ShortcutAddedToDesktop $False -ShortcutAddedToStartMenu $False -UserFilterEnabled $False -Visible $True -WaitForPrinterCreation $False
        #
        #        }
        #        TestScript = { $false }
        #        DependsOn = "[Citrix_XenDesktopDirector]Director"
        #    }
        #
        #if ($UsingNetScaler)
        #{
		#    Citrix_NetscalerConfigureXD NSConfig 
		#    {
		#    	NetScalerIP = $NetScalerIP
		#    	NetscalerCredential = $Admincreds
		#    	DomainCredential = $Admincreds
		#    	CertificatePassword = $CertificatePassword
		#    	CertificateFile = $certFile
		#    	DomainName = $DomainName
		#    	DomainController= $DomainControllerIp
		#    	StorefrontServer = $StoreFront
		#    	DeliveryController = $DeliveryController
		#    	VirtualServerName = $VirtualServerName
		#    	VirtualServerPort = $VirtualServerPort
		#    	ForwardServerPort = $ForwardServerPort
		#    	DependsOn = "[Citrix_XenDesktopDirector]Director"
		#    }
        #
        #
        #    Citrix_XenDesktopStorefront Storefront
        #    {
        #        XenDesktopController = $DeliveryController
        #        StorefrontServer = $StoreFront
        #        NetScalerIp = $NetScalerIP
		#    	DomainName = $DomainName
        #        FQDN = $GatewayFQDN
        #        HTML5Mode = $HTML5Mode
        #        GatewayName = $StoreFrontGatewayName
		#    	AppGroups = $AppGroups | ConvertTo-Json
        #        SiteName = $SiteName
        #        Transport = "HTTPS"
        #        Port = 443
        #        PsDscRunAsCredential = $DomainCreds
        #        DependsOn = "[Citrix_NetscalerConfigureXD]NSConfig" 
        #    }
        #}
        #else
        #{
            #Script ConfigureStorefront
            #{
            #    GetScript = { @{} }
            #    SetScript = {
            #        asnp citri*
            #        New-SfCluster -AdminAddress "localhost" -FarmName "Site" -ServerName $using:StoreFront -StorefrontUrl "http://$using:StoreFront/" `
            #        -XmlServices @("http://$using:StoreFront/")
            #    }
            #    TestScript = { $false }
            #    DependsOn = "[Citrix_XenDesktopDirector]Director"
            #}
        #}
        

            #Citrix_XenDesktopVDA VDACatalog
            #{
            #    XenDesktopController = $DeliveryController
            #    CatalogName = "Administrative"
            #    DeliveryGroupName = "Administrative"
            #    PSDscRunAsCredential = $DomainCreds
            #    Users = @($DomainCreds.UserName)
            #    PublishedApplications = "[]"
		    #	StoreFrontUrl = $StoreFront
            #    ComputerName = $VDAName
            #    DependsOn = $Depends #"[Citrix_MarketplaceConditionWait]ControllerCondition" 
            #}

            #Citrix_XenDesktopStudioController StudioSetup
            #{
		    #	XenDesktopController = $DeliveryController
		    #	StudioMsc = $studioMsc
            #    DependsOn = "[Script]ConfigureStorefront" 
            #}
		#}

		
		#if($ACMEServer -match "staging")
		#{
		#	Script StagingCert
	    #    {
		#		SetScript = {
		#			$encodedCer = "MIIDETCCAfmgAwIBAgIJAJzxkS6o1QkIMA0GCSqGSIb3DQEBCwUAMB8xHTAbBgNVBAMMFGhhcHB5IGhhY2tlciBmYWtlIENBMB4XDTE1MDQwNzIzNTAzOFoXDTI1MDQwNDIzNTAzOFowHzEdMBsGA1UEAwwUaGFwcHkgaGFja2VyIGZha2UgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCCkd5mgXFErJ3F2M0E9dw+Ta/md5i8TDId01HberAApqmydG7UZYF3zLTSzNjlNSOmtybvrSGUnZ9r9tSQcL8VM6WUOM8tnIpiIjEA2QkBycMwvRmZ/B2ltPdYs/R9BqNwO1g18GDZrHSzUYtNKNeFI6Glamj7GK2Vr0SmiEamlNIR5ktAFsEErzf/d4jCF7sosMsJpMCm1p58QkP4LHLShVLXDa8BMfVoI+ipYcA08iNUFkgW8VWDclIDxcysa0psDDtMjX3+4aPkE/cefmP+1xOfUuDHOGV8XFynsP4EpTfVOZr0/g9gYQ7ZArqXX7GTQkFqduwPm/w5qxSPTarAgMBAAGjUDBOMB0GA1UdDgQWBBT7eE8S+WAVgyyfF380GbMuNupBiTAfBgNVHSMEGDAWgBT7eE8S+WAVgyyfF380GbMuNupBiTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAd9Da+Zv+TjMv7NTAmliqnWHY6d3UxEZN3hFEJ58IQVHbBZVZdW7zhRktBvR05Kweac0HJeK91TKmzvXl21IXLvh0gcNLU/uweD3no/snfdB4OoFompljThmglzBqiqWoKBJQrLCA8w5UB+ReomRYd/EYXF/6TAfzm6hr//Xt5mPiUHPdvYt75lMAovRxLSbF8TSQ6b7BYxISWjPgFASNNqJNHEItWsmQMtAjjwzb9cs01XH9pChVAWn9LoeMKa+SlHSYrWG93+EcrIH/dGU76uNOiaDzBSKvaehG53h25MHuO1anNICJvZovWrFo4Uv1EnkKJm3vJFe50eJGhEKlx"
		#			$binaryCer = [Convert]::FromBase64String($encodedCer)
        #
		#			$pfx = new-object System.Security.Cryptography.X509Certificates.X509Certificate2
		#			$pfx.import($binaryCer)
        #
		#			$store = new-object System.Security.Cryptography.X509Certificates.X509Store(
		#				[System.Security.Cryptography.X509Certificates.StoreName]::Root,
		#				"localmachine"
		#			)
        #
		#			$store.open("MaxAllowed")
		#			$store.add($pfx)
		#			$store.Close()
		#		}
		#		TestScript = { 
		#			Test-Path "Cert:\localmachine\Root\5F5968E72FFD87450DD50E5EE96A1B793F110D46"
		#		}
		#		GetScript = { 
		#			return @{ Key = "Test-Path Cert:\localmachine\Root\5F5968E72FFD87450DD50E5EE96A1B793F110D46" }
		#		}          
		#	}
		#}
    }
} 

$me = "ctxadmin@citrixxendesktop.onmicrosoft.de"
$mySubscription = "f7a3c75f-baa0-4cad-bbe7-bcd7b1258654"
$mySubName = "Germany - Sponsorship"
$rgName = "ctxderg"
$rgLoca = "germanycentral"
$prefix = "ctxde"
$saName = "ctxdesa"
$skuName = "Standard_LRS"
$ddcSize = "Standard_D2_v2"
$scriptDir = "c:\Create-ENV"
$azenv = "AzureGermanCloud"
$buildtype = "XAXD_OnPrem_FeatureAzureUsGovXA1025_Layout"

C:
cd $scriptDir

Login-AzureRmAccount -EnvironmentName $azenv
New-AzureRmResourceGroup -Name $rgName -Location $rgLoca
New-AzureRmStorageAccount -ResourceGroupName $rgName `
						  -Name $saName `
						  -SkuName $skuName `
						  -Location $rgLoca

cd $scriptDir
.\New-XDAzureDevEnv.ps1 -Prefix $prefix `
						-ResourceGroupName $rgName `
						-AzureEnvironment $azenv `
						-TCBuildType $buildtype `
						-TCLatestBuild `
						-StorageAccountName $saName `
						-CreateVDA `
						-DDCSize $ddcsize `
						-DomainName "xenapp.de.local"

#Get-AzureEnvironment
Write-Host "*** END ***"







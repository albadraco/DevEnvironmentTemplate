param(
  [Parameter(Mandatory = $true, ParameterSetName="Start")]
  [switch]
  $Start,

  [Parameter(Mandatory = $true, ParameterSetName="Stop")]
  [switch]
  $Stop,

  [Parameter(Mandatory = $true, ParameterSetName="Remove")]
  [switch]
  $Remove,

  [Parameter(Mandatory = $true, ParameterSetName="Start")]
  [Parameter(Mandatory = $true, ParameterSetName="Stop")]
  [Parameter(Mandatory = $true, ParameterSetName="Remove")]
  [string]
  $ResourceGroupName,

  [Parameter(Mandatory = $true, ParameterSetName="Start")]
  [Parameter(Mandatory = $true, ParameterSetName="Stop")]
  [Parameter(Mandatory = $true, ParameterSetName="Remove")]
  [string[]]
  $Prefix = "",

  [Parameter(Mandatory = $false, ParameterSetName="Start")]
  [Parameter(Mandatory = $false, ParameterSetName="Stop")]
  [Parameter(Mandatory = $false, ParameterSetName="Remove")]
  [string]
  $SubscriptionId = (Get-AzureRmSubscription).SubscriptionId,

  [Parameter(Mandatory = $false, ParameterSetName="Start")]
  [Parameter(Mandatory = $false, ParameterSetName="Stop")]
  [Parameter(Mandatory = $false, ParameterSetName="Remove")]
  [switch]
  $Prompt = $false,

  [Parameter(Mandatory = $false, ParameterSetName="Remove")]
  [switch]
  $KeepLogs,

  [Parameter(Mandatory = $false, ParameterSetName="Start")]
  [Parameter(Mandatory = $false, ParameterSetName="Stop")]
  [Parameter(Mandatory = $false, ParameterSetName="Remove")]
  [System.DateTime]
  $WaitUntil,

  [Parameter(Mandatory = $false, ParameterSetName="Remove")]
  [switch]
  $KeepDeployments
)
$ErrorAction = 'Stop'

#Make sure user is logged in
$null = Get-AzureRmSubscription
if ($WaitUntil) {
    Sleep -Seconds (New-TimeSpan -End $WaitUntil).TotalSeconds
}

$null = Set-AzureRmContext -SubscriptionId $SubscriptionId
#remove resources
$resourceList = @(
  'Microsoft.Compute/virtualMachineScaleSets'
  'Microsoft.Compute/virtualMachines'
  'Microsoft.Storage/storageAccounts'
  'Microsoft.Compute/availabilitySets'
  'Microsoft.ServiceBus/namespaces'
  'Microsoft.Network/connections'
  'Microsoft.Network/virtualNetworkGateways'
  'Microsoft.Network/loadBalancers'
  'Microsoft.Network/networkInterfaces'
  'Microsoft.Network/publicIPAddresses'
  'Microsoft.Network/networkSecurityGroups'
  'Microsoft.Network/virtualNetworks'

  #'*' # this will remove everything else in the resource group regardless of resource type
) 

ForEach ($_Prefix in $Prefix)
{
    "Prefix = $_Prefix"
      if ($Remove)
      {
          $resourceList | % {
          $params = @{
            'ResourceGroupNameContains' = $ResourceGroupName
          }
          "Resource Type: $_"
          if ($_ -ne '*') {
            $params.Add('ResourceType', $_)
          }

          $resources = Find-AzureRmResource @params
          $resources | Where-Object { $_.ResourceGroupName -eq $ResourceGroupName -and ($_.ResourceName.StartsWith($_Prefix))} | % { 
            if ($Prompt) {
            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Deletes the resource."
            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Moves on to the next resource."
            $message = ('Remove Resource {0}/{1}? [Y] or [N]' -f $_.ResourceType, $_.ResourceName)
            $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
            $result = $host.ui.PromptForChoice($title, $message, $options, 0) 
            $val = $_
            switch ($result)
                 {
                  0 {$val | Remove-AzureRmResource -Verbose -Force}
                 }

            } else {
             Write-Host ('Processing {0}/{1}' -f $_.ResourceType, $_.ResourceName)
            $_ | Remove-AzureRmResource -Verbose -Force
            }
          }
        }
        #remove deployments
        if (!$KeepDeployments)
          {
            $deployments = Get-AzureRmResourceGroupDeployment -ResourceGroupName $ResourceGroupName | Where-Object {$_.DeploymentName.StartsWith($_Prefix)}
            $deployments | % {
            if ($Prompt) {
                $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Deletes the resource."
                $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Moves on to the next resource."
                $message = ('Remove Resource {0}/{1}? [Y] or [N]' -f "Microsoft.Resources/deployment", $_.DeploymentName)
                $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                $result = $host.ui.PromptForChoice($title, $message, $options, 0) 
                $val = $_
                switch ($result)
                     {
                      0 {$val | Remove-AzureRmResourceGroupDeployment -Verbose -Force}
                     }

            } else {
             Write-Host ('Processing {0}/{1}' -f "Microsoft.Resources/deployment", $_.DeploymentName)
             $_ |Remove-AzureRmResourceGroupDeployment -Verbose -Force
            }
            }
          }

        #remove root CA

        (gci -Path Cert:\LocalMachine\Root | Where-Object {$_.Subject -match "^CN=$_Prefix.+(\.westus\.cloudapp\.azure\.com)$"}) | % {
        if ($Prompt) {
            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Deletes the resource."
            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Moves on to the next resource."
            $message = ('Remove Root Certificate {0}? [Y] or [N]' -f $_.Subject)
            $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
            $result = $host.ui.PromptForChoice($title, $message, $options, 0) 
            $val = $_
            switch ($result)
                 {
                  0 {$val | Remove-Item}
                 }

            } else {
                Write-Host ("Removing Certificate {0}" -f $_.Subject)
                $_ | Remove-Item
            }
        }

        #remove personal CA
        (gci -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -match "^CN=$_Prefix.+(\.westus\.cloudapp\.azure\.com)$"}) | % {
        if ($Prompt) {
            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Deletes the resource."
            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Moves on to the next resource."
            $message = ('Remove Personal Certificate {0}? [Y] or [N]' -f $_.Subject)
            $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
            $result = $host.ui.PromptForChoice($title, $message, $options, 0) 
            $val = $_
            switch ($result)
                 {
                  0 {$val | Remove-Item}
                 }

            } else {
                Write-Host ("Removing Certificate {0}" -f $_.Subject)
                $_ | Remove-Item
            }
        }

        #remove local copies of certificates
        (gci -Path $PSScriptRoot | Where-Object {$_.Name -match "^$_Prefix.+(\.pfx)$"}) | % {
            if ($Prompt) {
                $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Deletes the resource."
                $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Moves on to the next resource."
                $message = ('Remove Local Certificate {0}? [Y] or [N]' -f $_.FullName)
                $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                $result = $host.ui.PromptForChoice($title, $message, $options, 0) 
                $val = $_
                switch ($result)
                     {
                      0 {$val | Remove-Item}
                     }

                } else {
                    Write-Host ("Removing Certificate {0}" -f $_.FullName)
                    $_ | Remove-Item
                }
        }
        #remove logs
        if (!$KeepLogs)
        {
            (gci -Path $PSScriptRoot | Where-Object {$_.Name -match "^$_Prefix.+(\.log)$"}) | % {
                if ($Prompt) {
                    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Deletes the resource."
                    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Moves on to the next resource."
                    $message = ('Remove Log {0}? [Y] or [N]' -f $_.FullName)
                    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                    $result = $host.ui.PromptForChoice($title, $message, $options, 0) 
                    $val = $_
                    switch ($result)
                         {
                          0 {$val | Remove-Item}
                         }

                    } else {
                        Write-Host ("Removing Log {0}" -f $_.FullName)
                        $_ | Remove-Item
                    }
        }
        }

        #remove isos
        (gci -Path $PSScriptRoot | Where-Object {$_.Name -match "^$_Prefix.+(\.iso)$"}) | % {
            if ($Prompt) {
                $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Deletes the resource."
                $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Moves on to the next resource."
                $message = ('Remove Iso {0}? [Y] or [N]' -f $_.FullName)
                $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                $result = $host.ui.PromptForChoice($title, $message, $options, 0) 
                $val = $_
                switch ($result)
                     {
                      0 {$val | Remove-Item}
                     }

                } else {
                    Write-Host ("Removing Iso {0}" -f $_.FullName)
                    $_ | Remove-Item
                }
        }

        #remove rdp files
        (gci -Path $PSScriptRoot | Where-Object {$_.Name -match "^$_Prefix.+(\.rdp)$"}) | % {
            if ($Prompt) {
                $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Deletes the resource."
                $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Moves on to the next resource."
                $message = ('Remove Rdp File {0}? [Y] or [N]' -f $_.FullName)
                $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                $result = $host.ui.PromptForChoice($title, $message, $options, 0) 
                $val = $_
                switch ($result)
                     {
                      0 {$val | Remove-Item}
                     }

                } else {
                    Write-Host ("Removing Rdp File {0}" -f $_.FullName)
                    $_ | Remove-Item
                }
          }
      }
      elseif ($Start) {
        Find-AzureRmResource -ResourceType 'Microsoft.Compute/virtualMachines' -ResourceGroupNameContains $ResourceGroupName `
        | Where-Object {$_.ResourceName.StartsWith($_Prefix)} | % {
            if ($Prompt) {
                $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Starts the resource."
                $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Moves on to the next resource."
                $message = ('Start VM {0}? [Y] or [N]' -f $_.Name)
                $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                $result = $host.ui.PromptForChoice($title, $message, $options, 0) 
                $val = $_
                switch ($result)
                     {
                      0 {$val | Start-AzureRmVM}
                     }

                } else {
                    Write-Host ("Starting VM {0}" -f $_.Name)
                    $_ | Start-AzureRmVM
                }
            }
      
      } elseif ($Stop) {
        Find-AzureRmResource -ResourceType 'Microsoft.Compute/virtualMachines' -ResourceGroupNameContains $ResourceGroupName `
        | Where-Object {$_.ResourceName.StartsWith($_Prefix)} | % {
            if ($Prompt) {
                $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Stops the resource."
                $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Moves on to the next resource."
                $message = ('Stop VM {0}? [Y] or [N]' -f $_.Name)
                $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                $result = $host.ui.PromptForChoice($title, $message, $options, 0) 
                $val = $_
                switch ($result)
                     {
                      0 {$val | Stop-AzureRmVM -Force}
                     }

                } else {
                    Write-Host ("Stopping VM {0}" -f $_.Name)
                    $_ | Stop-AzureRmVM -Force
                }
            }
      }
  }
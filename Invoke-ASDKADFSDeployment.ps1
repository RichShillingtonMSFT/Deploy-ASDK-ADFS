<#
.SYNOPSIS
    Script to deploy ASDKs in Azure with ADFS.

.DESCRIPTION
    Use this script to deploy ASDKs in Azure that use ADFS for Identity

.EXAMPLE
    .\Invoke-ASDKADFSDeployment.ps1 `
        -NewSubscriptionName 'Development Subscription' `
        -NewSubscriptionOwnerUPN 'fred@contoso.com' `
        -ComputeQuotaVirtualMachineCount '100'
        -IncludeEventHubs `
        -IncludeAzureSiteRecovery
#>
[CmdletBinding()]
Param
(
    # Provide the full UPN for the Subscription Owner
	[Parameter(Mandatory=$false,HelpMessage="Provide the full UPN for the Azure Active Directory User")]
    [MailAddress]$AADUserName = 'rishilli@missionreadygov.onmicrosoft.com',

    # 
	[Parameter(Mandatory=$false,HelpMessage="")]
    [String]$LabResourceGroupName = 'ASDK-ADFS-RG',

    # 
	[Parameter(Mandatory=$false,HelpMessage="Provide the environment where you will register the ASDK")]
    [String]$AzureEnvironment = 'AzureUSGovernment',

    # 
	[Parameter(Mandatory=$false,HelpMessage="")]
    [String]$DataDiskSizeGB = '2048',

    # 
	[Parameter(Mandatory=$false,HelpMessage="")]
    [String]$DNSForwarder = '8.8.8.8',

    # 
	[Parameter(Mandatory=$false,HelpMessage="")]
    [Int]$NumberOfDataDisks = '5',

    # 
	[Parameter(Mandatory=$false,HelpMessage="")]
    [String]$TimeServer = '168.61.215.74',

    # 
	[Parameter(Mandatory=$false,HelpMessage="")]
    [String]$VirtualMachineAdminUserName = 'VMAdmin',

    # 
	[Parameter(Mandatory=$true,HelpMessage="")]
    [SecureString]$VirtualMachineAdminPassword,

    # 
	[Parameter(Mandatory=$false,HelpMessage="")]
    [String]$ASDKVersion = '2301',

    [Parameter(Mandatory=$false,HelpMessage="")]
    [String]$VirtualMachineNamePrefix = 'VA',

    [Parameter(Mandatory=$false,HelpMessage="")]
    [Int]$VirtualMachineCount = '1',

    [Parameter(Mandatory=$false,HelpMessage="")]
    [String]$VirtualMachineSize = 'Standard_E16s_v3',

    [Parameter(Mandatory=$false,HelpMessage="")]
    [String]$DNSPrefixForPublicIP = 'VA-HUB',

    [Parameter(Mandatory=$false,HelpMessage="")]
    [String]$VirtualNetworkName = 'AzSHub-VNet',

    [Parameter(Mandatory=$false,HelpMessage="")]
    [String]$VirtualNetworkPrefix = '10.0.0.0/16',

    [Parameter(Mandatory=$false,HelpMessage="")]
    [String]$SubnetName = "Subnet1",

    [Parameter(Mandatory=$false,HelpMessage="")]
    [String]$SubnetPrefix = "10.0.0.0/24",

    [Parameter(Mandatory=$false,HelpMessage="")]
    [String]$NetworkSecurityGroupName = "AzS-Hub-NSG",

    [Parameter(Mandatory=$false,HelpMessage="")]
    [String]$DiagnosticStorageAccountSku = "Standard_LRS",

    [Parameter(Mandatory=$false,HelpMessage="")]
    [String]$DiagnosticStorageAccountKind = "StorageV2",

    [Parameter(Mandatory=$false,HelpMessage="")]
    [String]$SourceAddressForRDP

)

$SourceAddressForRDP = ((Invoke-WebRequest -uri “https://api.ipify.org/”).Content + '/32')
$VirtualMachineAdminPassword = ConvertTo-SecureString -String '!A@S3d4f5g6h7j8k' -AsPlainText -Force

#region Connect to Azure

$Environments = Get-AzEnvironment
$Environment = $Environments | Out-GridView -Title "Please Select the Azure Enviornment." -PassThru

try
{
    Connect-AzAccount -Environment $($Environment.Name) -ErrorAction 'Stop'
}
catch
{
    Write-Error -Message $_.Exception
    break
}

try 
{
    $Subscriptions = Get-AzSubscription
    if ($Subscriptions.Count -gt '1')
    {
        $Subscription = $Subscriptions | Out-GridView -Title "Please Select the Subscription where you want to deploy the ASDK." -PassThru
        Set-AzContext $Subscription
    }
}
catch
{
    Write-Error -Message $_.Exception
    break
}

$Locations = Get-AzLocation
$Location = $Locations | Out-GridView -Title "Please Select the Azure Resource Deployment Region." -PassThru
#endregion

# region ASDK URLs
if ($ASDKVersion -eq '2301')
{
    $DownloadLinks = @(
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit-1.bin'
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit-10.bin'
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit-11.bin'
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit-12.bin'
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit-13.bin'
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit-14.bin'
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit-15.bin'
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit-16.bin'
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit-17.bin'
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit-18.bin'
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit-19.bin'
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit-2.bin'
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit-20.bin'
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit-21.bin'
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit-3.bin'
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit-4.bin'
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit-5.bin'
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit-6.bin'
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit-7.bin'
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit-8.bin'
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit-9.bin'
        'https://azurestackhub.azureedge.net/PR/download/ASDK_1.2301.0.14/AzureStackDevelopmentKit.exe'
    )
}

If (!(Get-AzResourceGroup -Name $LabResourceGroupName -Location $Location.Location))
{
    $LabResourceGroup = New-AzResourceGroup -Name $LabResourceGroupName -Location $Location.Location
}
else
{
    $LabResourceGroup = Get-AzResourceGroup -Name $LabResourceGroupName -Location $Location.Location
}

$TemplateParams = @{
    virtualMachineAdminUserName = $VirtualMachineAdminUserName
    virtualMachineAdminPassword = $VirtualMachineAdminPassword
    virtualMachineNamePrefix = $VirtualMachineNamePrefix
    virtualMachineCount = $VirtualMachineCount
    virtualMachineSize = $VirtualMachineSize
    location = $Location.Location
    virtualNetworkName = $VirtualNetworkName
    virtualNetworkPrefix = $VirtualNetworkPrefix
    dnsPrefixForPublicIP = $DNSPrefixForPublicIP
    SubnetName = $SubnetName
    subnetPrefix = $SubnetPrefix
    networkSecurityGroupName = $NetworkSecurityGroupName
    diagnosticStorageAccountSku = $DiagnosticStorageAccountSku
    diagnosticStorageAccountKind = $DiagnosticStorageAccountKind
    sourceAddressForRDP = $SourceAddressForRDP
}

New-AzResourceGroupDeployment -Name ASDKDeployment `
    -ResourceGroupName $LabResourceGroup.ResourceGroupName `
    -TemplateUri 'https://github.com/RichShillingtonMSFT/Deploy-ASDK-ADFS/blob/81c57b83736a7cad1c5ebeb8730248fbb0dcd7ce/azuredeploy.json' `
    -TemplateParameterObject $TemplateParams -Mode Incremental
    



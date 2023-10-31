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
    [String]$ASDKVersion = '2301'
)

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

$VirtualMachineAdminPassword = ConvertTo-SecureString -String '!A@S3d4f5g6h7j8k' -AsPlainText -Force

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

New-AzResourceGroupDeployment -Name ASDKDeployment `
    -ResourceGroupName $LabResourceGroup.ResourceGroupName `
    -TemplateParameterFile C:\Git\Deploy-ASDK-ADFS\azuredeploy.json `
    



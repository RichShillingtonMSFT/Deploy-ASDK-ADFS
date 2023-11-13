<#
.SYNOPSIS
    Script to restore the Contoso.local VMs in Hyper-V.

.DESCRIPTION
    Use this script to restore the Contoso.local domain VMs on the ASDK.

.EXAMPLE
    .\Restore-ASDKDomainVMs.ps1 -LabResourceGroupName 'ASDK-ADFS-RG'
#>
[CmdletBinding()]
Param
(
    # Provide the Resource Group Name
	[Parameter(Mandatory=$true,HelpMessage="Provide the Resource Group Name")]
    [String]$LabResourceGroupName,

    # Provide a Virtual Machine Admin Password
	[Parameter(Mandatory=$true,HelpMessage="Provide a Virtual Machine Admin Password")]
    [SecureString]$VirtualMachineAdminPassword
)

#region Functions & Variables
$WarningPreference = 'SilentlyContinue'

Function ConvertFrom-SecureStringToPlainText 
{
    param
    ( 
        [Parameter(Mandatory=$true)]
        [System.Security.SecureString]$SecurePassword
    )
    
    $PasswordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    
    $PlainTextPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($PasswordPointer)
    
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($PasswordPointer)
    
    return $PlainTextPassword
}

$AdminPassword = ConvertFrom-SecureStringToPlainText -SecurePassword $VirtualMachineAdminPassword -ErrorAction 'Stop'
#endregion

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

Write-Host "Connected to Azure" -ForegroundColor Green
Write-Host ""
#endregion

$LabResourceGroup = Get-AzResourceGroup -Name $LabResourceGroupName -Location $Location.Location -ErrorAction Stop

$VirtualMachines = Get-AzVM -ResourceGroupName $LabResourceGroup.ResourceGroupName

$StartTime = (Get-Date)
foreach ($VirtualMachine in $VirtualMachines)
{
    Write-host "$($VirtualMachine.Name) - Restoring the Contoso.local Domain VMs in Hyper-V." -ForegroundColor Green
    Write-Host ""

$ScriptString = @'
Get-NetAdapter | Where-Object {$_.Name -like "*ADSwitch*"} | Enable-NetAdapter

$Password = '[AdminPassword]' | ConvertTo-SecureString -asPlainText -Force
$Username = 'Contoso\Administrator'
$DomainCredential = New-Object System.Management.Automation.PSCredential($Username,$Password)

$Username = '.\Administrator'
$LocalCredential = New-Object System.Management.Automation.PSCredential($Username,$Password)

$Servers = @(
    @{ServerName = 'AD-01';IPAddress = '10.100.100.10'}
    @{ServerName = 'ADCS-01';IPAddress = '10.100.100.11'}
    @{ServerName = 'ADFS-01';IPAddress = '10.100.100.12'}
)

Foreach ($Server in $Servers)
{
    New-VM -Name $Server.ServerName -BootDevice VHD -VHDPath ('C:\VMDisks\' + $Server.ServerName + '.vhd') -MemoryStartupBytes 6GB -SwitchName 'ADSwitch'
    Set-VMProcessor -VMName $Server.ServerName -count 2
    Start-VM -Name $Server.ServerName
    Start-Sleep -Seconds 160
    if ($Server.ServerName -eq 'AD-01')
    {
        $InterfaceIndex = Invoke-Command -VMName $Server.ServerName -Credential $DomainCredential -ScriptBlock {(Get-NetAdapter).ifIndex}
        Invoke-Command -VMName $Server.ServerName -Credential $DomainCredential -ScriptBlock {
            Set-DnsClientServerAddress -InterfaceIndex $Using:InterfaceIndex -ServerAddresses 10.100.100.10,8.8.8.8;
            New-NetIPAddress -InterfaceIndex $Using:InterfaceIndex -IPAddress $Using:Server.IPAddress -PrefixLength 24 -DefaultGateway '10.100.100.1'
        }
    }
    else
    {
        $InterfaceIndex = Invoke-Command -VMName $Server.ServerName -Credential $LocalCredential -ScriptBlock {(Get-NetAdapter).ifIndex}
        Invoke-Command -VMName $Server.ServerName -Credential $LocalCredential -ScriptBlock {
            Set-DnsClientServerAddress -InterfaceIndex $Using:InterfaceIndex -ServerAddresses 10.100.100.10,8.8.8.8;
            New-NetIPAddress -InterfaceIndex $Using:InterfaceIndex -IPAddress $Using:Server.IPAddress -PrefixLength 24 -DefaultGateway '10.100.100.1'
        }
    }
    Enable-VMIntegrationService -VMName $Server.ServerName -Name "Guest Service Interface"
    Start-Sleep -Seconds 20
    Get-VM -Name $Server.ServerName | Restart-VM -Force -Wait
    Start-Sleep -Seconds 200
    if ($Server.ServerName -eq 'AD-01')
    {
        $InterfaceIndex = Invoke-Command -VMName $Server.ServerName -Credential $DomainCredential -ScriptBlock {(Get-NetAdapter).ifIndex} 
        $IPCheck = Invoke-Command -VMName $Server.ServerName -Credential $DomainCredential -ScriptBlock {Get-NetIPAddress -InterfaceIndex $Using:InterfaceIndex} 
        if ($IPCheck.IPAddress[1] -ne $Server.IPAddress)
        {
            Invoke-Command -VMName $Server.ServerName -Credential $DomainCredential -ScriptBlock {
                Set-DnsClientServerAddress -InterfaceIndex $Using:InterfaceIndex -ServerAddresses 10.100.100.10,8.8.8.8;
                New-NetIPAddress -InterfaceIndex $Using:InterfaceIndex -IPAddress $Using:Server.IPAddress -PrefixLength 24 -DefaultGateway '10.100.100.1'
            }
        }
    }
    else
    {
        $InterfaceIndex = Invoke-Command -VMName $Server.ServerName -Credential $LocalCredential -ScriptBlock {(Get-NetAdapter).ifIndex} 
        $IPCheck = Invoke-Command -VMName $Server.ServerName -Credential $LocalCredential -ScriptBlock {Get-NetIPAddress -InterfaceIndex $Using:InterfaceIndex} 
        if ($IPCheck.IPAddress[1] -ne $Server.IPAddress)
        {
            Invoke-Command -VMName $Server.ServerName -Credential $LocalCredential -ScriptBlock {
                Set-DnsClientServerAddress -InterfaceIndex $Using:InterfaceIndex -ServerAddresses 10.100.100.10,8.8.8.8;
                New-NetIPAddress -InterfaceIndex $Using:InterfaceIndex -IPAddress $Using:Server.IPAddress -PrefixLength 24 -DefaultGateway '10.100.100.1'
            }
        }
    }
}

New-ADUser -AccountPassword $Password -UserPrincipalName 'breakglass@azurestack.local' -PasswordNeverExpires:$true -Name breakglass -Enabled:$true
$User = Get-ADUser breakglass
$Groups = Get-ADGroup -Filter * | Where-Object {$_.Name -like "*admin*"}
foreach ($Group in $Groups)
{
    Add-ADGroupMember -Identity $Group.Name -Members $User.Name
}
'@

    $ScriptString = $ScriptString.Replace('[AdminPassword]',"$AdminPassword")

    Invoke-AzVMRunCommand -VMName $($VirtualMachine.Name) `
        -ResourceGroupName $LabResourceGroup.ResourceGroupName `
        -CommandId 'RunPowerShellScript' `
        -ScriptString $ScriptString -AsJob | Out-Null
}

$Result = Get-Job | Wait-Job | Receive-Job
$EndTime = (Get-Date)

if (($Result.Value.DisplayStatus | Select-Object -Unique) -ne 'Provisioning succeeded') 
{
    throw 'Failed to Restore Domain VMs!'
    break
}
else
{
    Write-Host "PowerShell Job $($Result.Value.DisplayStatus)" -ForegroundColor Green
    Write-Host "$($Result.Value.Message)" -ForegroundColor Green
    Write-Host "StartTime $($StartTime)" -ForegroundColor White
    Write-Host "EndTime $($EndTime)" -ForegroundColor White
    Write-Host $('Duration: {0:mm} min {0:ss} sec' -f ($EndTime - $StartTime)) -ForegroundColor White
    Write-Host ""
}
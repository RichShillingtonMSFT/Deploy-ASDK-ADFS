<#
.SYNOPSIS
    Script to deploy ASDKs in Azure with ADFS.

.DESCRIPTION
    Use this script to deploy ASDKs in Azure that use ADFS for Identity

.EXAMPLE
    .\Invoke-ASDKADFSDeployment.ps1 -LabResourceGroupName 'ASDK-ADFS-RG' `
        -DNSForwarder '8.8.8.8' -TimeServer '168.61.215.74' `
        -VirtualMachineAdminUserName 'VMAdmin' `
        -ASDKVersion '2108' -VirtualMachineNamePrefix 'HUB' `
        -VirtualMachineCount '1' -DNSPrefixForPublicIP 'asdk-'
#>
[CmdletBinding()]
Param
(
    # Provide the Resource Group Name
	[Parameter(Mandatory=$true,HelpMessage="Provide the Resource Group Name")]
    [String]$LabResourceGroupName,

    # Provide the number of Data Disks for the ASDK
	[Parameter(Mandatory=$false,HelpMessage="Provide the number of Data Disks for the ASDK")]
    [Int]$NumberOfDataDisks = '5',

    # Provide the size for the Data Disks
	[Parameter(Mandatory=$false,HelpMessage="Provide the size for the Data Disks")]
    [String]$DataDiskSizeGB = '2048',

    # Provide the DNS Forwarder to be used on the ASDK
	[Parameter(Mandatory=$true,HelpMessage="Provide the DNS Forwarder to be used on the ASDK")]
    [String]$DNSForwarder,

    # Provide a Time Server IP
	[Parameter(Mandatory=$true,HelpMessage="Provide a Time Server IP")]
    [String]$TimeServer,

    # Provide a Virtual Machine Admin Username
	[Parameter(Mandatory=$true,HelpMessage="Provide a Virtual Machine Admin Username")]
    [String]$VirtualMachineAdminUserName,

    # Provide a Virtual Machine Admin Password
	[Parameter(Mandatory=$true,HelpMessage="Provide a Virtual Machine Admin Password")]
    [SecureString]$VirtualMachineAdminPassword,

    # The version of ASDK to be deployed
	[Parameter(Mandatory=$true,HelpMessage="The version of ASDK to be deployed")]
    [ValidateSet('2301','2206','2108')]
    [String]$ASDKVersion,

    # The Virtual Machine Name Prefix
    [Parameter(Mandatory=$true,HelpMessage="The Virtual Machine Name Prefix")]
    [String]$VirtualMachineNamePrefix,

    [Parameter(Mandatory=$true,HelpMessage="Provide the count of ASDKs to Deploy")]
    [Int]$VirtualMachineCount,

    [Parameter(Mandatory=$false,HelpMessage="Select the Virtual Machine SKU Size.")]
    [String]$VirtualMachineSize = 'Standard_E16s_v3',

    [Parameter(Mandatory=$true,HelpMessage="Provide a DNS Prefix for the Public IP")]
    [String]$DNSPrefixForPublicIP,

    [Parameter(Mandatory=$false,HelpMessage="Provide a Name for the Virtual Network")]
    [String]$VirtualNetworkName = 'AzSHub-VNet',

    [Parameter(Mandatory=$false,HelpMessage="Provide a Network range for the Virtual Network")]
    [String]$VirtualNetworkPrefix = '10.0.0.0/16',

    [Parameter(Mandatory=$false,HelpMessage="Provide a Name for the Virtual Network Subnet")]
    [String]$SubnetName = "Subnet1",

    [Parameter(Mandatory=$false,HelpMessage="Provide a Network range for the Virtual Network Subnet")]
    [String]$SubnetPrefix = "10.0.0.0/24",

    [Parameter(Mandatory=$false,HelpMessage="Provide a Name for the Network Security Group")]
    [String]$NetworkSecurityGroupName = "AzS-Hub-NSG",

    [Parameter(Mandatory=$false,HelpMessage="Provide the Sku for Diagnostics Storage Account")]
    [String]$DiagnosticStorageAccountSku = "Standard_LRS",

    [Parameter(Mandatory=$false,HelpMessage="Provide the Kind for Diagnostics Storage Account")]
    [String]$DiagnosticStorageAccountKind = "StorageV2",

    [Parameter(Mandatory=$false,HelpMessage="Provide your External IP where you will connect to the ASDK from")]
    [String]$SourceAddressForRDP
)

#region Functions & Variables
$WarningPreference = 'SilentlyContinue'

$ScriptStartTime = (Get-Date)

$TemplateUri = 'https://raw.githubusercontent.com/RichShillingtonMSFT/Deploy-ASDK-ADFS/main/azuredeploy.json'

$ASDKLinkUri = "https://asdkdeploymentsa.blob.core.usgovcloudapi.net/asdks/$ASDKVersion/CloudBuilder.vhdx"

if (!($SourceAddressForRDP))
{
    $SourceAddressForRDP = ((Invoke-WebRequest -uri 'http://ifconfig.me/ip').Content + '/32')
}

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

#region Create Resource Group
$LabResourceGroup = Get-AzResourceGroup -Name $LabResourceGroupName -Location $Location.Location -ErrorAction SilentlyContinue
If (!($LabResourceGroup))
{
    $LabResourceGroup = New-AzResourceGroup -Name $LabResourceGroupName -Location $Location.Location
}
Write-Host "Resource Group $LabResourceGroupName is ready" -ForegroundColor Green
Write-Host ""
#endregion

#region Template Deployment
Write-host "Begining Template Deployment. This should only take a couple of minutes." -ForegroundColor Yellow
Write-Host ""

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

Write-Host "Template Deployment in progress..." -ForegroundColor Green
Write-Host ""

$StartTime = (Get-Date)

$Deployment = New-AzResourceGroupDeployment -Name ASDKDeployment `
    -ResourceGroupName $LabResourceGroup.ResourceGroupName `
    -TemplateUri $TemplateUri `
    -TemplateParameterObject $TemplateParams -Mode Incremental

$EndTime = (Get-Date)

$DeployedVirtualMachines = $Deployment.Outputs.Values.value

Write-Host "Template Deployment Complete" -ForegroundColor Green
Write-Host ""
Write-Host "Start Time $($StartTime)" -ForegroundColor White
Write-Host "End Time $($EndTime)" -ForegroundColor White
Write-Host $('Duration: {0:mm} min {0:ss} sec' -f ($EndTime - $StartTime)) -ForegroundColor White
Write-Host ""
#endregion

#region Export VM Information to Users Documents folder
$DataTable = New-Object System.Data.DataTable
$DataTable.Columns.Add("VMName","string") | Out-Null
$DataTable.Columns.Add("PublicIP","string") | Out-Null

foreach ($DeployedVirtualMachine in $DeployedVirtualMachines)
{
    $VM = Get-AzVM -ResourceGroupName $LabResourceGroup.ResourceGroupName -Name $DeployedVirtualMachine
    $NIC = $VM.NetworkProfile.NetworkInterfaces[0].Id.Split('/') | Select-Object -Last 1
    $PublicIPName =  (Get-AzNetworkInterface -ResourceGroupName $LabResourceGroup.ResourceGroupName -Name $NIC).IpConfigurations.PublicIpAddress.Id.Split('/') | Select-Object -Last 1
    $PublicIIAddress = (Get-AzPublicIpAddress -ResourceGroupName $LabResourceGroup.ResourceGroupName -Name $PublicIPName).IpAddress

    $NewRow = $DataTable.NewRow()
    $NewRow.VMName = $($DeployedVirtualMachine)
    $NewRow.PublicIP = $($PublicIIAddress)
    $DataTable.Rows.Add($NewRow)
}

$CSVFileName = $($LabResourceGroup.ResourceGroupName) + '-DeployedVMs-' + $(Get-Date -f yyyy-MM-dd) + '.csv'
$DataTable | Export-Csv "$ENV:UserProfile\Documents\$CSVFileName" -NoTypeInformation -Force
Write-Host ""
Write-Host ""
#endregion
Pause
#region Configure Virtual Machine Disks & Install Hyper-V
Write-host "I am now going to configure the Virtual Machine Disks & Install Hyper-V." -ForegroundColor Yellow
Write-host "This takes about 5 minutes. Please wait..." -ForegroundColor Yellow
Write-Host ""
$StartTime = (Get-Date)

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-host "$($VirtualMachineName) - Configure the Virtual Machine Disks & Install Hyper-V." -ForegroundColor Green
    Write-Host ""

$ScriptString = @"
`$Partition = Get-Partition -DriveLetter C
`$Size = (Get-PartitionSupportedSize -DiskNumber `$Partition.DiskNumber -PartitionNumber `$Partition.PartitionNumber)
Resize-Partition -DiskNumber `$Partition.DiskNumber -PartitionNumber `$Partition.PartitionNumber -Size `$Size.SizeMax

`@'
Select Disk 0
Select Partition 2
Extend
`'@ | DISKPart

`$RAWDisks = Get-Disk | Where-Object {`$_.PartitionStyle -eq 'RAW'}
foreach (`$RAWDisk in `$RAWDisks)
{
   Initialize-Disk `$RAWDisk.Number
}

Install-WindowsFeature -Name Hyper-V -IncludeManagementTools
"@

    Invoke-AzVMRunCommand -VMName $VirtualMachineName `
        -ResourceGroupName $LabResourceGroup.ResourceGroupName `
        -CommandId 'RunPowerShellScript' `
        -ScriptString $ScriptString -AsJob | Out-Null
}

$Result = Get-Job | Wait-Job | Receive-Job
$EndTime = (Get-Date)

if (($Result.Value.DisplayStatus | Select-Object -Unique) -ne 'Provisioning succeeded') 
{
    throw 'Failed to prepare VM Disks!'
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
#endregion
Pause
#region Copy Setup Files from Azure Storage
Write-host "I am now going to download setup files from Azure Storage." -ForegroundColor Yellow
Write-host "This takes about 5 minutes. Please wait..." -ForegroundColor Yellow
Write-Host ""
$StartTime = (Get-Date)

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-host "$($VirtualMachineName) - Downloading Setup files from Azure Storage." -ForegroundColor Green
    Write-Host ""

$ScriptString = @'
$InstallFilesDirectory = New-Item -Path C:\ -Name SetupFiles -ItemType Directory -Force;
Invoke-WebRequest -UseBasicParsing -Uri 'https://aka.ms/downloadazcopy-v10-windows' -OutFile "$($InstallFilesDirectory.FullName)\azcopy.zip";
Expand-Archive -Path "$($InstallFilesDirectory.FullName)\azcopy.zip" -DestinationPath "$($InstallFilesDirectory.FullName)\azcopy";
$AzCopyFile = Get-ChildItem "$($InstallFilesDirectory.FullName)\azcopy" -Recurse -Include *.exe;
Copy-Item -Path $AzCopyFile.FullName -Destination 'C:\Windows\System32' -Force;
Remove-Item "$($InstallFilesDirectory.FullName)\azcopy" -Force -Recurse;
Remove-Item "$($InstallFilesDirectory.FullName)\azcopy.zip" -Force;
azcopy copy '[ASDKLinkUri]' "$($InstallFilesDirectory.FullName)\CloudBuilder.vhdx";
azcopy copy 'https://asdkdeploymentsa.blob.core.usgovcloudapi.net/vhds/2019Server.vhd' "$($InstallFilesDirectory.FullName)\2019Server.vhd";
azcopy copy 'https://asdkdeploymentsa.blob.core.usgovcloudapi.net/software' $($InstallFilesDirectory.FullName) --recursive=true;
azcopy copy 'https://asdkdeploymentsa.blob.core.usgovcloudapi.net/dsc' $($InstallFilesDirectory.FullName) --recursive=true;
'@
    
    $ScriptString = $ScriptString.Replace('[ASDKLinkUri]',"$ASDKLinkUri")

    Invoke-AzVMRunCommand -VMName $VirtualMachineName `
        -ResourceGroupName $LabResourceGroup.ResourceGroupName `
        -CommandId 'RunPowerShellScript' `
        -ScriptString $ScriptString -AsJob | Out-Null
}

$Result = Get-Job | Wait-Job | Receive-Job
$EndTime = (Get-Date)

$Result.Value.Message | Out-File "$env:temp\temp.txt"
$Results = Get-Content "$env:temp\temp.txt"
if ((($Results |  Select-String -Pattern 'Number of File Transfers Failed: \s*\d+\s*' | Select-Object -Unique) -replace '\s','') -ne 'NumberofFileTransfersFailed:0')
{
    throw 'File Transfer Failed'
    break
}
else
{
    Write-Host "PowerShell Job $($Result.Status)" -ForegroundColor Green
    Write-Host "$($Result.Value.Message)" -ForegroundColor Green
    Write-Host "StartTime $($StartTime)" -ForegroundColor White
    Write-Host "EndTime $($EndTime)" -ForegroundColor White
    Write-Host $('Duration: {0:mm} min {0:ss} sec' -f ($EndTime - $StartTime)) -ForegroundColor White
    Write-Host ""
}
#endregion
Pause
#region Restart Virtual Machines
Write-host "Now I need to restart the Virtual Machines." -ForegroundColor Yellow
Write-host "This can take up to 5 minutes. Please wait..." -ForegroundColor Yellow
Write-Host ""
$StartTime = (Get-Date)

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-host "$($VirtualMachineName) - Restarting Virtual Machine." -ForegroundColor Green

    Restart-AzVM -ResourceGroupName $LabResourceGroup.ResourceGroupName -Name $VirtualMachineName -AsJob | Out-Null
}

$Result = Get-Job | Wait-Job | Receive-Job

foreach ($PublicIP in $DataTable.Rows.PublicIP)
{
    do 
    {
        $RDPTest = Test-NetConnection -ComputerName $PublicIP -Port 3389
    }
    until ($RDPTest.TcpTestSucceeded -eq $true)
}

$EndTime = (Get-Date)

if ($Result.Status -ne 'Succeeded') 
{
    throw 'Virtual Machines Failed to Restart'
    break
}
else
{
    Write-Host "PowerShell Job $($Result.Status)" -ForegroundColor Green
    Write-Host "StartTime $($StartTime)" -ForegroundColor White
    Write-Host "EndTime $($EndTime)" -ForegroundColor White
    Write-Host $('Duration: {0:mm} min {0:ss} sec' -f ($EndTime - $StartTime)) -ForegroundColor White
    Write-Host ""
}
#endregion
Pause
#region Prepare Virtual Machine Boot VHD & Configure OOBe Setup
Write-Host "Now it is time to expand & Convert the VHD." -ForegroundColor Yellow
Write-Host "Depending on Disk Speed, this can take a long time. Just relax...." -ForegroundColor Yellow
Write-Host ""
$StartTime = (Get-Date)

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{

Write-Host "$($VirtualMachineName) - Converting and Resizing Disks." -ForegroundColor Green
Write-Host ""

$ScriptString = @'

If ((Get-Service -Name 'Hyper-V Virtual Machine Management').Status -ne 'Running')
{
    Get-Service -Name 'Hyper-V Virtual Machine Management' | Start-Service -ErrorAction Stop
}

Import-Module Hyper-V

#Convert-VHD -Path "C:\SetupFiles\CloudBuilder.vhdx" -VHDType Fixed -DestinationPath "C:\SetupFiles\ASDK.vhdx" -DeleteSource -ErrorAction Stop
Rename-Item -Path "C:\SetupFiles\CloudBuilder.vhdx" -NewName "ASDK.vhdx" -Force
Resize-VHD -Path "C:\SetupFiles\ASDK.vhdx" -SizeBytes 1500gb
'@
}

Invoke-AzVMRunCommand -VMName $VirtualMachineName `
-ResourceGroupName $LabResourceGroup.ResourceGroupName `
-CommandId 'RunPowerShellScript' `
-ScriptString $ScriptString -AsJob | Out-Null

$Result = Get-Job | Wait-Job | Receive-Job
$EndTime = (Get-Date)

if (($Result.Value.DisplayStatus | Select-Object -Unique) -ne 'Provisioning succeeded') 
{
    throw 'Failed to prepare VM Disks!'
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

#endregion
Pause
#region Prepare VM for VHD Boot
foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Preparing Virtual Machine VHDs and Configuring it for VHD Boot." -ForegroundColor Green
    Write-Host ""

$ScriptString = @"
`$Prepare_Vhdx_Path = "C:\SetupFiles\ASDK.vhdx"

#Remove boot from previous deployment
`$bootOptions = bcdedit /enum  | Select-String 'path' -Context 2,1
`$bootOptions | ForEach-Object {
if (((`$_.Context.PreContext[1] -replace '^device +') -like '*ASDK.vhdx*') -and ((`$_.Context.PostContext[0] -replace '^description +') -eq 'Azure Stack'))
    {
        `$BootID = '"' + (`$_.Context.PreContext[0] -replace '^identifier +') + '"'
        bcdedit /delete `$BootID
    }
}

# Disable Autoplay
If (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\StorageOnArrival") 
{
    `$Autoplay = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\StorageOnArrival").'(default)'
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\StorageOnArrival" -Name '(default)' -Type String -Value 'MSTakeNoAction'
}

# Mount Disk Image
`$Prepare_Vhdx_Mounted = Mount-DiskImage -ImagePath `$Prepare_Vhdx_Path -PassThru | Get-DiskImage | Get-Disk    
`$Prepare_Vhdx_Partitions = `$Prepare_Vhdx_Mounted | Get-Partition | Sort-Object -Descending -Property Size
`$Prepare_Vhdx_DriveLetter = `$Prepare_Vhdx_Partitions[0].DriveLetter

# Copy Azure VM Agent and configure SetupComplete.cmd
`$WindowsAzureVmAgent = Get-ChildItem -Path C:\SetupFiles\software -Filter *WindowsAzureVmAgent*.msi
Copy-Item -Path `$WindowsAzureVmAgent.FullName -Destination (`$Prepare_Vhdx_DriveLetter + ':\')
`$SetupCompleteFile = New-Item -ItemType File -Path (`$Prepare_Vhdx_DriveLetter + ':\Windows\Setup\Scripts\SetupComplete.cmd') -Force
Add-Content -Path `$SetupCompleteFile.FullName -Value "msiexec.exe /i C:\`$(`$WindowsAzureVmAgent.Name) /quiet"

# Set EFI Partition MbrType
Get-Partition -UniqueId `$Prepare_Vhdx_Partitions[1].UniqueId | Set-Partition -MbrType 0x1c

# Reset Autoplay to original value
If (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\StorageOnArrival")
{
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\StorageOnArrival" -Name '(default)' -Type String -Value `$Autoplay
}

#Add bootfiles to OS
Write-Host "Adding bootfiles to OS"
bcdboot `$Prepare_Vhdx_DriveLetter':\Windows'

#Add Boot entry
`$bootOptions = bcdedit /enum  | Select-String 'path' -Context 2,1
`$bootOptions | ForEach-Object {
    if ((((`$_.Context.PreContext[1] -replace '^device +') -eq ('partition='+`$Prepare_Vhdx_DriveLetter+':') -or ((`$_.Context.PreContext[1] -replace '^device +') -like '*ASDK.vhdx*')) -and ((`$_.Context.PostContext[0] -replace '^description +') -ne 'Azure Stack'))) {
        `$BootID = '"' + (`$_.Context.PreContext[0] -replace '^identifier +') + '"'
        bcdedit /set `$BootID description "Azure Stack"
    }
}

# Unattend
[XML]`$U_Unattend = `@"
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <UserData>
        <ProductKey>
          <Key>74YFP-3QFB3-KQT8W-PMXWJ-7M648</Key>
        </ProductKey>
        <FullName>Microsoft</FullName>
        <Organization>Microsoft</Organization>
        <AcceptEula>true</AcceptEula>
      </UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-TerminalServices-RDP-WinStationExtensions" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <UserAuthentication>0</UserAuthentication>
    </component>
    <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <fDenyTSConnections>false</fDenyTSConnections>
    </component>
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add">
          <Description>Enable LocalAdmin Account</Description>
          <Order>1</Order>
          <Path>cmd /c net user administrator /active:yes</Path>
        </RunSynchronousCommand>
      </RunSynchronous>
    </component>
    <component name="Microsoft-Windows-IE-ESC" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <IEHardenAdmin>false</IEHardenAdmin>
      <IEHardenUser>false</IEHardenUser>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <TimeZone>UTC</TimeZone>
      <ComputerName>`$ENV:COMPUTERNAME</ComputerName>
    </component>
    <component name="Networking-MPSSVC-Svc" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <FirewallGroups>
        <FirewallGroup wcm:action="add" wcm:keyValue="EnableRemoteDesktop">
          <Active>true</Active>
          <Group>@FirewallAPI.dll,-28752</Group>
          <Profile>all</Profile>
        </FirewallGroup>
      </FirewallGroups>
    </component>
  </settings>
</unattend>
`"@


#oobeSystem
[XML]`$U_Unattend_oobeSysten_AdminPassword=`@"
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <UserAccounts>
            <AdministratorPassword>
                <Value>$AdminPassword</Value>
                <PlainText>true</PlainText>
            </AdministratorPassword>
        </UserAccounts>
        <OOBE>
            <SkipMachineOOBE>true</SkipMachineOOBE>
        </OOBE>
    </component>
  </settings>
</unattend>
`"@


`$U_Unattend.unattend.AppendChild(`$U_Unattend.ImportNode(`$U_Unattend_oobeSysten_AdminPassword.unattend.settings, `$true))
`$U_Unattend.OuterXml | Out-File (`$Prepare_Vhdx_DriveLetter+":\unattend.xml") -Encoding ascii -Force
"@

    Invoke-AzVMRunCommand -VMName $VirtualMachineName `
        -ResourceGroupName $LabResourceGroup.ResourceGroupName `
        -CommandId 'RunPowerShellScript' `
        -ScriptString $ScriptString -AsJob | Out-Null
}

$Result = Get-Job | Wait-Job | Receive-Job
$EndTime = (Get-Date)

if (($Result.Value.DisplayStatus | Select-Object -Unique) -ne 'Provisioning succeeded') 
{
    throw 'Failed to prepare VM Disks!'
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
#endregion

#region Restart Virtual Machines
Write-host "Now I need to restart the Virtual Machines." -ForegroundColor Yellow
Write-host "This can take up to 5 minutes. Please wait..." -ForegroundColor Yellow
Write-Host ""
$StartTime = (Get-Date)

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-host "$($VirtualMachineName) - Restarting Virtual Machine." -ForegroundColor Green
    Write-Host ""

    Restart-AzVM -ResourceGroupName $LabResourceGroup.ResourceGroupName -Name $VirtualMachineName -AsJob | Out-Null
}

$Result = Get-Job | Wait-Job | Receive-Job

foreach ($PublicIP in $DataTable.Rows.PublicIP)
{
    do 
    {
        $RDPTest = Test-NetConnection -ComputerName $PublicIP -Port 3389
    }
    until ($RDPTest.TcpTestSucceeded -eq $true)
}

$EndTime = (Get-Date)

if ($Result.Status -ne 'Succeeded') 
{
    throw 'Virtual Machines Failed to Restart'
    break
}
else
{
    Write-Host "PowerShell Job $($Result.Status)" -ForegroundColor Green
    Write-Host "StartTime $($StartTime)" -ForegroundColor White
    Write-Host "EndTime $($EndTime)" -ForegroundColor White
    Write-Host $('Duration: {0:mm} min {0:ss} sec' -f ($EndTime - $StartTime)) -ForegroundColor White
    Write-Host ""
}
#endregion

#region resize OS Disk & Install Software
Write-Host "Now I will expand the OS Disk and Install some additional Software." -ForegroundColor Yellow
Write-host "This should take less than 5 minutes. Please wait..." -ForegroundColor Yellow
Write-Host ""
$StartTime = (Get-Date)

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Resizing the OS Disk and Installing Software." -ForegroundColor Green
    Write-Host ""

$ScriptString = @'
$Partition = Get-Partition -DriveLetter C
$Size = (Get-PartitionSupportedSize -DiskNumber $Partition.DiskNumber -PartitionNumber $Partition.PartitionNumber)
Resize-Partition -DiskNumber $Partition.DiskNumber -PartitionNumber $Partition.PartitionNumber -Size $Size.SizeMax

#Install Edge Browser
$EdgeBrowser = Get-ChildItem -Path E:\SetupFiles\software -Filter *MicrosoftEdgeEnterprise*.msi
Start-Process msiexec.exe -ArgumentList "/i $($EdgeBrowser.FullName) /quiet" -Wait

#Install VSCode
$VSCodeSetup = Get-ChildItem -Path E:\SetupFiles\software -Filter *VSCodeSetup*.exe
$installerArguments = '/verysilent /tasks=addcontextmenufiles,addcontextmenufolders,addtopath'
Start-Process $($VSCodeSetup.FullName) -ArgumentList $installerArguments -Wait
#$Extensions = Get-ChildItem -Path 'E:\SetupFiles\software\VSCodeExtensions'
#foreach ($Extension in $Extensions) 
#{
#    & "C:\Program Files\Microsoft VS Code\Code.exe" --install-extension $Extension
#}

'@

    Invoke-AzVMRunCommand -VMName $VirtualMachineName `
        -ResourceGroupName $LabResourceGroup.ResourceGroupName `
        -CommandId 'RunPowerShellScript' `
        -ScriptString $ScriptString -AsJob | Out-Null
}

$Result = Get-Job | Wait-Job | Receive-Job
$EndTime = (Get-Date)

if (($Result.Value.DisplayStatus | Select-Object -Unique) -ne 'Provisioning succeeded') 
{
    throw 'Failed to install software!'
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
#endregion

#region Run Windows Update on ASDK VHD
Write-Host "Now I need to run Windows Update to make these VMs all safe and stuff." -ForegroundColor Yellow
Write-host "I will reboot them when it is done. Please wait..." -ForegroundColor Yellow
Write-Host ""
$StartTime = (Get-Date)

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Running Windows Update." -ForegroundColor Green
    Write-Host ""

$ScriptString = @'
$RestartOption = 'IgnoreReboot'
$ForceOnlineUpdate = $true

# Get Script Start Time and Date
$DateTime = (Get-Date)

# Set Verbose and ErrorAction Preference
$VerbosePreference = 'Continue'
$ErrorActionPreference = 'Stop'

# Create Script Log File
$ScriptLogFilePath = New-Item -Path "$env:TEMP\InvokeWindowsUpdate.log" -ItemType File -Force
Add-Content -Path $ScriptLogFilePath -Value "Script Processing Started at $DateTime"

Function Invoke-WindowsUpdate
{
	[CmdletBinding()]	
	Param
	(	
		#Mode options
		[Switch]$AcceptAll,
		[Switch]$AutoReboot,
		[Switch]$IgnoreReboot,
        [Switch]$ForceOnlineUpdate
	)
	
    # Get updates list
	Write-Verbose "Getting updates list"
    Add-Content -Path $ScriptLogFilePath -Value "Getting updates list"
	$objServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager" 
		
	Write-Verbose "Create Microsoft.Update.Session object"
    Add-Content -Path $ScriptLogFilePath -Value "Create Microsoft.Update.Session object"
	$SessionObject = New-Object -ComObject "Microsoft.Update.Session" 
		
	Write-Verbose "Create Microsoft.Update.Session.Searcher object"
    Add-Content -Path $ScriptLogFilePath -Value "Create Microsoft.Update.Session.Searcher object"
	$objSearcher = $SessionObject.CreateUpdateSearcher()
    
    # Check the registry for Windows Update settings and set searcher service
    $WindowsUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $WindowsUpdateAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

    if (!($ForceOnlineUpdate))
    {
        $WSUSRegistryValue = (Get-ItemProperty -Path $WindowsUpdatePath -Name WUServer -ErrorAction SilentlyContinue).WUServer
        if ($WSUSRegistryValue)
        {
            Write-Verbose "Computer is set to use WSUS Server $WSUSRegistryValue"
            Add-Content -Path $ScriptLogFilePath -Value "Computer is set to use WSUS Server $WSUSRegistryValue"
            $objSearcher.ServerSelection = 1
        }

        if ([String]::IsNullOrEmpty($WSUSRegistryValue))
        {
            $FeaturedSoftwareRegistryValue = (Get-ItemProperty -Path $WindowsUpdateAUPath -Name EnableFeaturedSoftware -ErrorAction SilentlyContinue).EnableFeaturedSoftware
            if ($FeaturedSoftwareRegistryValue)
            {
                Write-Verbose "Set source of updates to Microsoft Update"
                Add-Content -Path $ScriptLogFilePath -Value "Set source of updates to Microsoft Update"
                $serviceName = $null
                foreach ($objService in $objServiceManager.Services) 
                {
	                If($objService.Name -eq "Microsoft Update")
	                {
		                $objSearcher.ServerSelection = 3
		                $objSearcher.ServiceID = $objService.ServiceID
		                $serviceName = $objService.Name
		                Break
	                }
                }
            }
            else
            {
                Write-Verbose "Set source of updates to Windows Update"
                Add-Content -Path $ScriptLogFilePath -Value "Set source of updates to Windows Update"
		        $objSearcher.ServerSelection = 2
		        $serviceName = "Windows Update"
            }
        }
    }

    if ($ForceOnlineUpdate)
    {
        $FeaturedSoftwareRegistryValue = (Get-ItemProperty -Path $WindowsUpdateAUPath -Name EnableFeaturedSoftware -ErrorAction SilentlyContinue).EnableFeaturedSoftware
        if ($FeaturedSoftwareRegistryValue)
        {
            Write-Verbose "Set source of updates to Microsoft Update"
            Add-Content -Path $ScriptLogFilePath -Value "Set source of updates to Microsoft Update"
            $serviceName = $null
            foreach ($objService in $objServiceManager.Services) 
            {
	            If($objService.Name -eq "Microsoft Update")
	            {
		            $objSearcher.ServerSelection = 3
		            $objSearcher.ServiceID = $objService.ServiceID
		            $serviceName = $objService.Name
		            Break
	            }
            }
        }
        else
        {
            Write-Verbose "Set source of updates to Windows Update"
            Add-Content -Path $ScriptLogFilePath -Value "Set source of updates to Windows Update"
		    $objSearcher.ServerSelection = 2
		    $serviceName = "Windows Update"
        }
    }
		
	Write-Verbose "Connecting to $serviceName server. Please wait..."
    Add-Content -Path $ScriptLogFilePath -Value "Connecting to $serviceName server. Please wait..."

	Try
	{
		# Search for updates
        $Search = 'IsInstalled = 0'
        $objResults = $objSearcher.Search($Search)
	}
	Catch
	{
		If($_ -match "HRESULT: 0x80072EE2")
		{
			Write-Warning "Cannot connect to Windows Update server"
            Add-Content -Path $ScriptLogFilePath -Value "Cannot connect to Windows Update server"
		}
		Return
	}

	$objCollectionUpdate = New-Object -ComObject "Microsoft.Update.UpdateColl" 
		
	$NumberOfUpdate = 1
	$UpdatesExtraDataCollection = @{}
	$PreFoundUpdatesToDownload = $objResults.Updates.count

	Write-Verbose "Found $($PreFoundUpdatesToDownload) Updates in pre search criteria"	
    Add-Content -Path $ScriptLogFilePath -Value "Found $($PreFoundUpdatesToDownload) Updates in pre search criteria"	
        
    # Set updates to install variable
    $UpdatesToInstall = $objResults.Updates

	Foreach($Update in $UpdatesToInstall)
	{
		$UpdateAccess = $true
		Write-Verbose "Found Update: $($Update.Title)"
        Add-Content -Path $ScriptLogFilePath -Value "Found Update: $($Update.Title)"
			
		If($UpdateAccess -eq $true)
		{
			# Convert update size so it is readable
			Switch($Update.MaxDownloadSize)
			{
				{[System.Math]::Round($_/1KB,0) -lt 1024} { $Size = [String]([System.Math]::Round($_/1KB,0))+" KB"; break }
				{[System.Math]::Round($_/1MB,0) -lt 1024} { $Size = [String]([System.Math]::Round($_/1MB,0))+" MB"; break }  
				{[System.Math]::Round($_/1GB,0) -lt 1024} { $Size = [String]([System.Math]::Round($_/1GB,0))+" GB"; break }    
				{[System.Math]::Round($_/1TB,0) -lt 1024} { $Size = [String]([System.Math]::Round($_/1TB,0))+" TB"; break }
				default { $Size = $_+"B" }
			}
		
			# Convert KB Article IDs so it is readable
			If($Update.KBArticleIDs -ne "")    
			{
				$KB = "KB"+$Update.KBArticleIDs
			}
			Else 
			{
				$KB = ""
			}
				
            # Add updates
			$objCollectionUpdate.Add($Update) | Out-Null
			$UpdatesExtraDataCollection.Add($Update.Identity.UpdateID,@{KB = $KB; Size = $Size})
		}

		$NumberOfUpdate++
	}
		
	Write-Verbose "Update Search Completed"
    Add-Content -Path $ScriptLogFilePath -Value "Update Search Completed"
		
    $FoundUpdatesToDownload = $objCollectionUpdate.count

	If($FoundUpdatesToDownload -eq 0)
	{
        Write-Verbose 'No updates were found to download'
        Add-Content -Path $ScriptLogFilePath -Value 'No updates were found to download'		
        Return
	}

	Write-Verbose "Found $($FoundUpdatesToDownload) Updates"
    Add-Content -Path $ScriptLogFilePath -Value "Found $($FoundUpdatesToDownload) Updates"
		
	$NumberOfUpdate = 1
			
	$UpdateCollectionObject = New-Object -ComObject "Microsoft.Update.UpdateColl"

	Foreach($Update in $objCollectionUpdate)
	{	
		$Size = $UpdatesExtraDataCollection[$Update.Identity.UpdateID].Size
		Write-Verbose "Selected Update $($Update.Title)"

		$Status = "Accepted"

		If($Update.EulaAccepted -eq 0)
		{ 
			$Update.AcceptEula() 
		}
			
		Write-Verbose "Adding update to collection"
		$UpdateCollectionObject.Add($Update) | Out-Null

		$log = New-Object PSObject -Property @{
			Title = $Update.Title
			KB = $UpdatesExtraDataCollection[$Update.Identity.UpdateID].KB
			Size = $UpdatesExtraDataCollection[$Update.Identity.UpdateID].Size
			Status = $Status
			X = 2
		}
				
		Add-Content -Path $ScriptLogFilePath -Value $log
				
		$NumberOfUpdate++
	}

	Write-Verbose "Update Selection Completed"
    Add-Content -Path $ScriptLogFilePath -Value "Update Selection Completed"
			
	$AcceptUpdatesToDownload = $UpdateCollectionObject.count
	Write-Verbose "$($AcceptUpdatesToDownload) Updates to Download"
    Add-Content -Path $ScriptLogFilePath -Value "$($AcceptUpdatesToDownload) Updates to Download"
			
	If($AcceptUpdatesToDownload -eq 0)
	{
		Return
	}
			
	Write-Verbose "Downloading updates"
    Add-Content -Path $ScriptLogFilePath -Value "Downloading updates"

	$NumberOfUpdate = 1
	$UpdateDownloadCollectionObject = New-Object -ComObject "Microsoft.Update.UpdateColl" 

	Foreach($Update in $UpdateCollectionObject)
	{
		Write-Verbose "$($Update.Title) will be downloaded"
        Add-Content -Path $ScriptLogFilePath -Value "$($Update.Title) will be downloaded"

		$TempUpdateCollectionObject = New-Object -ComObject "Microsoft.Update.UpdateColl"
		$TempUpdateCollectionObject.Add($Update) | Out-Null
					
		$Downloader = $SessionObject.CreateUpdateDownloader() 
		$Downloader.Updates = $TempUpdateCollectionObject

		Try
		{
			Write-Verbose "Attempting to download update $($Update.Title)"
            Add-Content -Path $ScriptLogFilePath -Value "Attempting to download update $($Update.Title)"
			$DownloadResult = $Downloader.Download()
		}
		Catch
		{
			If ($_ -match "HRESULT: 0x80240044")
			{
				Write-Warning "Your security policy does not allow a non-administator to perform this task"
			}
					
			Return
		}
				
		Write-Verbose "Check ResultCode"
		Switch -exact ($DownloadResult.ResultCode)
		{
			0   { $Status = "NotStarted" }
			1   { $Status = "InProgress" }
			2   { $Status = "Downloaded" }
			3   { $Status = "DownloadedWithErrors" }
			4   { $Status = "Failed" }
			5   { $Status = "Aborted" }
		}

		$log = New-Object PSObject -Property @{
			Title = $Update.Title
			KB = $UpdatesExtraDataCollection[$Update.Identity.UpdateID].KB
			Size = $UpdatesExtraDataCollection[$Update.Identity.UpdateID].Size
			Status = $Status
			X = 3
		}
				
		Add-Content -Path $ScriptLogFilePath -Value "Update $($log.Title) KB $($log.KB) Size $($log.Size) Download Status $($log.Status)"
				
		If($DownloadResult.ResultCode -eq 2)
		{
			Write-Verbose "$($Update.Title) Downloaded"
            Add-Content -Path $ScriptLogFilePath -Value "$($Update.Title) Downloaded"
			$UpdateDownloadCollectionObject.Add($Update) | Out-Null
		}
				
		$NumberOfUpdate++
				
	}

	Write-Verbose "Downloading Updates Completed"
    Add-Content -Path $ScriptLogFilePath -Value "Downloading Updates Completed"

	$ReadyUpdatesToInstall = $UpdateDownloadCollectionObject.count
	Write-Verbose "Downloaded $($ReadyUpdatesToInstall) Updates to Install"
    Add-Content -Path $ScriptLogFilePath -Value "Downloaded $($ReadyUpdatesToInstall) Updates to Install"
		
	If($ReadyUpdatesToInstall -eq 0)
	{
        Write-Verbose "No Updates are ready to Install"
        Add-Content -Path $ScriptLogFilePath -Value "No Updates are ready to Install"		
        Return
	}

			
	Write-Verbose "Installing updates"
    Add-Content -Path $ScriptLogFilePath -Value "Installing updates"

	$NumberOfUpdate = 1			
	#install updates	
	Foreach($Update in $UpdateDownloadCollectionObject)
	{
		Write-Verbose "Update to install: $($Update.Title)"
        Add-Content -Path $ScriptLogFilePath -Value "Update to install: $($Update.Title)"

		$TempUpdateCollectionObject = New-Object -ComObject "Microsoft.Update.UpdateColl"
		$TempUpdateCollectionObject.Add($Update) | Out-Null
					
		$InstallerObject = $SessionObject.CreateUpdateInstaller()
		$InstallerObject.Updates = $TempUpdateCollectionObject
						
		Try
		{
			Write-Verbose "Attempting to install update"
            Add-Content -Path $ScriptLogFilePath -Value "Attempting to install update"
			$InstallResult = $InstallerObject.Install()
		}
		Catch
		{
			If($_ -match "HRESULT: 0x80240044")
			{
				Write-Warning "Your security policy does not allow a non-administator to perform this task"
                Add-Content -Path $ScriptLogFilePath -Value "Your security policy does not allow a non-administator to perform this task"
			}
			Return
		}
					
		Switch -exact ($InstallResult.ResultCode)
		{
			0   { $Status = "NotStarted"}
			1   { $Status = "InProgress"}
			2   { $Status = "Installed"}
			3   { $Status = "InstalledWithErrors"}
			4   { $Status = "Failed"}
			5   { $Status = "Aborted"}
		}

		$log = New-Object PSObject -Property @{
			Title = $Update.Title
			KB = $UpdatesExtraDataCollection[$Update.Identity.UpdateID].KB
			Size = $UpdatesExtraDataCollection[$Update.Identity.UpdateID].Size
			Status = $Status
			X = 4
		}
		
        Add-Content -Path $ScriptLogFilePath -Value "Update $($log.Title) KB $($log.KB) Size $($log.Size) Install Status $($log.Status)"
		$NumberOfUpdate++
	}

	Write-Verbose "Installing updates Completed"
    Add-Content -Path $ScriptLogFilePath -Value "Installing updates Completed"
}

Try
{
	$SystemInfoObject = New-Object -ComObject "Microsoft.Update.SystemInfo"	
	If($SystemInfoObject.RebootRequired)
	{
		Write-Warning "Reboot is required to continue"
		If($RestartOption -eq 'AutoReboot')
		{
			Restart-Computer -Force
		}
	}
}
Catch
{
	Write-Warning $_
}

if ($ForceOnlineUpdate)
{
    Invoke-WindowsUpdate -AcceptAll -ForceOnlineUpdate
}
else
{
    Invoke-WindowsUpdate -AcceptAll
}

$DateTime = (Get-Date)
Add-Content -Path $ScriptLogFilePath -Value "Script Processing Completed at $DateTime"

Try
{
	$SystemInfoObject = New-Object -ComObject "Microsoft.Update.SystemInfo"	
	If($SystemInfoObject.RebootRequired)
	{
		Write-Warning "Reboot is required to continue"
		If($RestartOption -eq 'AutoReboot')
		{
			Set-Content -Path $ScriptLogFilePath
			Restart-Computer -Force
		}
				
	}
}
Catch
{
	Write-Warning $_
}
'@
    Invoke-AzVMRunCommand -VMName $VirtualMachineName `
        -ResourceGroupName $LabResourceGroup.ResourceGroupName `
        -CommandId 'RunPowerShellScript' `
        -ScriptString $ScriptString -AsJob | Out-Null
}

$Result = Get-Job | Wait-Job | Receive-Job
$EndTime = (Get-Date)

if (($Result.Value.DisplayStatus | Select-Object -Unique) -ne 'Provisioning succeeded') 
{
    throw 'Failed to update VMs!'
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
#endregion

#region Restart Virtual Machines
Write-host "Now I need to restart the Virtual Machines." -ForegroundColor Yellow
Write-host "This can take up to 5 minutes. Please wait..." -ForegroundColor Yellow
Write-Host ""
$StartTime = (Get-Date)

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-host "$($VirtualMachineName) - Restarting Virtual Machine." -ForegroundColor Green
    Write-Host ""

    Restart-AzVM -ResourceGroupName $LabResourceGroup.ResourceGroupName -Name $VirtualMachineName -AsJob | Out-Null
}

$Result = Get-Job | Wait-Job | Receive-Job

foreach ($PublicIP in $DataTable.Rows.PublicIP)
{
    do 
    {
        $RDPTest = Test-NetConnection -ComputerName $PublicIP -Port 3389
    }
    until ($RDPTest.TcpTestSucceeded -eq $true)
}

$EndTime = (Get-Date)

if ($Result.Status -ne 'Succeeded') 
{
    throw 'Virtual Machines Failed to Restart'
    break
}
else
{
    Write-Host "PowerShell Job $($Result.Status)" -ForegroundColor Green
    Write-Host "StartTime $($StartTime)" -ForegroundColor White
    Write-Host "EndTime $($EndTime)" -ForegroundColor White
    Write-Host $('Duration: {0:mm} min {0:ss} sec' -f ($EndTime - $StartTime)) -ForegroundColor White
    Write-Host ""
}
#endregion

#region Create AD,CA & ADFS Virtual Machines
Write-Host "Now I must Configure the Hyper-V host and setup the Domain Controller, Certificate Services & ADFS" -ForegroundColor Yellow
Write-host "This should take about 25 minutes. I am doing lots of work for you. Settle Down..." -ForegroundColor Yellow
Write-Host ""
$StartTime = (Get-Date)

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Configuring Hyper-V to host the Domain Controller, Certificate Services & ADFS" -ForegroundColor Green
    Write-Host ""

$ScriptString = @'

$VerbosePreference = 'Continue'

New-VMSwitch -SwitchType Internal -Name 'ADSwitch' -Verbose
$InterfaceIndex = $((Get-NetAdapter | Where-Object {$_.Name -like "*ADSwitch*"} | Select-Object ifIndex).ifIndex)
New-NetIPAddress -IPAddress '10.100.100.1' -PrefixLength '24' -InterfaceIndex $InterfaceIndex

$Servers = @(
    @{ServerName = 'AD-01';IPAddress = '10.100.100.10'}
    @{ServerName = 'ADCS-01';IPAddress = '10.100.100.11'}
    @{ServerName = 'ADFS-01';IPAddress = '10.100.100.12'}
)

$VirtualMachinePassword = ConvertTo-SecureString -String '[AdminPassword]' -AsPlainText -Force

$Username = '.\Administrator'
$LocalCredential = New-Object System.Management.Automation.PSCredential($Username,$VirtualMachinePassword)

$Username = 'Contoso\Administrator'
$DomainCredential = New-Object System.Management.Automation.PSCredential($Username,$VirtualMachinePassword)

$VMDisksDirectory = New-Item -Path C:\ -Name VMDisks -ItemType Directory -Force  -Verbose

Copy-Item -Path 'E:\Windows\System32\azcopy.exe' -Destination 'C:\Windows\System32' -Force;

Foreach ($Server in $Servers)
{
    azcopy copy 'https://asdkdeploymentsa.blob.core.usgovcloudapi.net/vhds/2019Server.vhd' "$($VMDisksDirectory.FullName)\2019Server.vhd"
    Rename-Item -Path "$($VMDisksDirectory.FullName)\2019Server.vhd" -NewName ($Server.ServerName + '.vhd') -Verbose

    # Disable Autoplay
    If (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\StorageOnArrival") 
    {
        $Autoplay = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\StorageOnArrival").'(default)'
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\StorageOnArrival" -Name '(default)' -Type String -Value 'MSTakeNoAction'
    }

    $Prepare_Vhdx_Path = 'C:\VMDisks\' + $Server.ServerName + '.vhd'

    # Mount Disk Image
    $Prepare_Vhdx_Mounted = Mount-DiskImage -ImagePath $Prepare_Vhdx_Path -PassThru | Get-DiskImage | Get-Disk    
    $Prepare_Vhdx_Partitions = $Prepare_Vhdx_Mounted | Get-Partition | Sort-Object -Descending -Property Size
    $Prepare_Vhdx_DriveLetter = $Prepare_Vhdx_Partitions[0].DriveLetter

    # Reset Autoplay to original value
    If (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\StorageOnArrival")
    {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\StorageOnArrival" -Name '(default)' -Type String -Value $Autoplay
    }

# Unattend
[XML]$U_Unattend = @"
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <UserData>
        <ProductKey>
          <Key>74YFP-3QFB3-KQT8W-PMXWJ-7M648</Key>
        </ProductKey>
        <FullName>Microsoft</FullName>
        <Organization>Microsoft</Organization>
        <AcceptEula>true</AcceptEula>
      </UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-TerminalServices-RDP-WinStationExtensions" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <UserAuthentication>0</UserAuthentication>
    </component>
    <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <fDenyTSConnections>false</fDenyTSConnections>
    </component>
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add">
          <Description>Enable LocalAdmin Account</Description>
          <Order>1</Order>
          <Path>cmd /c net user administrator /active:yes</Path>
        </RunSynchronousCommand>
      </RunSynchronous>
    </component>
    <component name="Microsoft-Windows-IE-ESC" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <IEHardenAdmin>false</IEHardenAdmin>
      <IEHardenUser>false</IEHardenUser>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <TimeZone>UTC</TimeZone>
      <ComputerName>$($Server.ServerName)</ComputerName>
    </component>
    <component name="Networking-MPSSVC-Svc" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <FirewallGroups>
        <FirewallGroup wcm:action="add" wcm:keyValue="EnableRemoteDesktop">
          <Active>true</Active>
          <Group>@FirewallAPI.dll,-28752</Group>
          <Profile>all</Profile>
        </FirewallGroup>
      </FirewallGroups>
    </component>
  </settings>
</unattend>
"@

#oobeSystem
[XML]$U_Unattend_oobeSysten_AdminPassword=@"
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <UserAccounts>
            <AdministratorPassword>
                <Value>[AdminPassword]</Value>
                <PlainText>true</PlainText>
            </AdministratorPassword>
        </UserAccounts>
        <OOBE>
            <SkipMachineOOBE>true</SkipMachineOOBE>
        </OOBE>
    </component>
  </settings>
</unattend>
"@

$U_Unattend.unattend.AppendChild($U_Unattend.ImportNode($U_Unattend_oobeSysten_AdminPassword.unattend.settings, $true))
$U_Unattend.OuterXml | Out-File ($Prepare_Vhdx_DriveLetter+":\unattend.xml") -Encoding ascii -Force

    Dismount-DiskImage -ImagePath $Prepare_Vhdx_Path -Verbose
}

Foreach ($Server in $Servers)
{
    New-VM -Name $Server.ServerName -BootDevice VHD -VHDPath ('C:\VMDisks\' + $Server.ServerName + '.vhd') -MemoryStartupBytes 12GB -SwitchName 'ADSwitch'
    Set-VMProcessor -VMName $Server.ServerName -count 6
    Start-VM -Name $Server.ServerName
    Start-Sleep -Seconds 160
    $InterfaceIndex = Invoke-Command -VMName $Server.ServerName -Credential $LocalCredential -ScriptBlock {(Get-NetAdapter).ifIndex}
    Invoke-Command -VMName $Server.ServerName -Credential $LocalCredential -ScriptBlock {
        Set-DnsClientServerAddress -InterfaceIndex $Using:InterfaceIndex -ServerAddresses 10.100.100.10,8.8.8.8;
        New-NetIPAddress -InterfaceIndex $Using:InterfaceIndex -IPAddress $Using:Server.IPAddress -PrefixLength 24 -DefaultGateway '10.100.100.1'
    }
    Enable-VMIntegrationService -VMName $Server.ServerName -Name "Guest Service Interface"
    Start-Sleep -Seconds 20
    Get-VM -Name $Server.ServerName | Restart-VM -Force -Wait
    Start-Sleep -Seconds 160
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
'@

    $ScriptString = $ScriptString.Replace('[AdminPassword]',"$AdminPassword")

    Invoke-AzVMRunCommand -VMName $VirtualMachineName `
        -ResourceGroupName $LabResourceGroup.ResourceGroupName `
        -CommandId 'RunPowerShellScript' `
        -ScriptString $ScriptString -AsJob | Out-Null
}

$Result = Get-Job | Wait-Job | Receive-Job
$EndTime = (Get-Date)

if (($Result.Value.DisplayStatus | Select-Object -Unique) -ne 'Provisioning succeeded') 
{
    throw 'Failed to create Domain VMs!'
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
#endregion

#region Install Active Directory & add ADFS and ADCS to the Domain
Write-Host "Now I will install Active Directory" -ForegroundColor Yellow
Write-Host "I am also going to add ADFS and ADCS Servers to the Domain." -ForegroundColor Yellow
Write-host "This should take about 15 minutes." -ForegroundColor Yellow
Write-Host ""
$StartTime = (Get-Date)

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Installing Active Directory & adding ADFS & ADCS Servers to the Domain" -ForegroundColor Green
    Write-Host ""

$ScriptString = @'
#Configure AD

$VirtualMachinePassword = ConvertTo-SecureString -String '[AdminPassword]' -AsPlainText -Force

$Username = '.\Administrator'
$LocalCredential = New-Object System.Management.Automation.PSCredential($Username,$VirtualMachinePassword)

$Username = 'Contoso\Administrator'
$DomainCredential = New-Object System.Management.Automation.PSCredential($Username,$VirtualMachinePassword)

Invoke-Command -VMName 'AD-01' -Credential $LocalCredential -ScriptBlock {Install-WindowsFeature AD-Domain-Services -IncludeManagementTools} -Verbose
Invoke-Command -VMName 'AD-01' -Credential $LocalCredential -ScriptBlock {
Install-ADDSForest -DomainName "contoso.local" `
    -InstallDNS `
    -SafeModeAdministratorPassword $Using:VirtualMachinePassword `
    -DomainNetbiosName Contoso -Force
}

Start-Sleep -Seconds 420

do
{
    $ADTest = Invoke-Command -VMName 'AD-01' -Credential $DomainCredential -ScriptBlock {Get-Service -Name 'ADWS'}
}
until ($ADTest.Status -eq 'Running')

do
{
    $ADTest = Invoke-Command -VMName 'AD-01' -Credential $DomainCredential -ScriptBlock {& NETDOM QUERY /D:contoso.local PDC}
}
until ($ADTest -contains "AD-01.contoso.local")

Invoke-Command -VMName 'ADCS-01' -Credential $LocalCredential -ScriptBlock {Add-Computer -ComputerName localhost -LocalCredential $Using:LocalCredential -DomainName 'contoso.local' -Credential $Using:DomainCredential -Restart -Force -PassThru -Verbose}

Start-Sleep -Seconds 120

Invoke-Command -VMName 'ADFS-01' -Credential $LocalCredential -ScriptBlock {Add-Computer -ComputerName localhost -LocalCredential $Using:LocalCredential -DomainName 'contoso.local' -Credential $Using:DomainCredential -Restart -Force -PassThru -Verbose}
'@

    $ScriptString = $ScriptString.Replace('[AdminPassword]',"$AdminPassword")

    Invoke-AzVMRunCommand -VMName $VirtualMachineName `
        -ResourceGroupName $LabResourceGroup.ResourceGroupName `
        -CommandId 'RunPowerShellScript' `
        -ScriptString $ScriptString -AsJob | Out-Null
}

$Result = Get-Job | Wait-Job | Receive-Job
$EndTime = (Get-Date)

if (($Result.Value.DisplayStatus | Select-Object -Unique) -ne 'Provisioning succeeded') 
{
    throw 'Failed to install Active Directory!'
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
#endregion

#region Install Certificate Services
Write-Host "Now I will install Certificate Services." -ForegroundColor Yellow
Write-host "This should take less than 10 minutes." -ForegroundColor Yellow
Write-Host ""
$StartTime = (Get-Date)

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Installing Certificate Services" -ForegroundColor Green
    Write-Host ""

$ScriptString = @'
$VirtualMachinePassword = ConvertTo-SecureString -String '[AdminPassword]' -AsPlainText -Force

$Username = 'Contoso\Administrator'
$DomainCredential = New-Object System.Management.Automation.PSCredential($Username,$VirtualMachinePassword)
    
winrm s winrm/config/client '@{TrustedHosts="*"}'
    
$ADSession = New-PSSession -ComputerName '10.100.100.11' -Credential $DomainCredential
    
Copy-Item E:\SetupFiles\software\HubModules.zip -Destination C:\ -ToSession $ADSession
Copy-Item E:\SetupFiles\software\Scripts.zip -Destination C:\ -ToSession $ADSession
Copy-Item E:\SetupFiles\DSC\Modules -Destination 'C:\Program Files\WindowsPowerShell' -Force -Recurse -ToSession $ADSession | Out-Null
Copy-Item E:\SetupFiles\DSC\DSCConfigs -Destination 'C:\' -Force -Recurse -ToSession $ADSession | Out-Null

Invoke-Command -Session $ADSession -ScriptBlock {
    Expand-Archive -Path C:\HubModules.zip -DestinationPath 'C:\Program Files\WindowsPowerShell\Modules' -Force
}

Invoke-Command -Session $ADSession -ScriptBlock {

    $VirtualMachinePassword = ConvertTo-SecureString -String '[AdminPassword]' -AsPlainText -Force
    
    $Username = 'Contoso\Administrator'
    $DomainCredential = New-Object System.Management.Automation.PSCredential($Username,$VirtualMachinePassword)
    
    $configFunc = "CaRootConfig"
    Set-Location 'C:\DSCConfigs'
    $scriptFilePathName = ".\CaRootConfig.ps1"
    Write-Verbose "Dot sourcing functions in PS1 script '$scriptFilePathName'"
    . $scriptFilePathName # load the DSC configuration functions into session
    
    $dscParameters = @{
        Hostname = $ENV:Computername
        Credential = $DomainCredential
        CaCommonName = 'ADCS-01-CA' 
        DomainDistinguishedName = 'CN=ADCS-01-CA,DC=Contoso,DC=local' 
        DomainName = 'contoso.local'
    }
    
    $DscWorkPath = 'C:\DSCConfigs'
    $certificateFilePathName = Join-Path -Path $DscWorkPath -ChildPath "$(hostname).cer"
    $cert = Get-ChildItem -Path 'Cert:\LocalMachine\My' -DocumentEncryptionCert | Where-Object -FilterScript { $psItem.Subject -eq "DSC Document Encryption" }
    if ($null -eq $cert) 
    {
        $cert = New-SelfSignedCertificate -Subject "DSC Document Encryption" -Type DocumentEncryptionCert -TextExtension "2.5.29.17={text}DNS=localhost" -CertStoreLocation Cert:\LocalMachine\My -ErrorAction Stop
    }
    $null = $cert | Export-Certificate -Type CERT -FilePath $certificateFilePathName -Force
    
    Configuration LcmSettings {
        param(
            [Parameter(Mandatory = $true)]
            [Alias("Thumbprint")]
            [ValidateNotNullOrEmpty()]
            [string]
            $CertificateId
        )
    
        node localhost {
            LocalConfigurationManager {
                ConfigurationMode = "ApplyAndAutoCorrect"
                RebootNodeIfNeeded = $true
                DebugMode = "ForceModuleImport"
                CertificateId = $CertificateId
            }
        }
    }
    
    & LcmSettings -CertificateId $cert.Thumbprint -OutputPath $DscWorkPath -Verbose
    
    Set-DscLocalConfigurationManager -Path $DscWorkPath -Force -Verbose
    
    $commonConfigurationData = @{
        AllNodes = @(
            @{
                NodeName = 'localhost'
                PsDscAllowDomainUser = $true
                CertificateFile = "$certificateFilePathName"
                Thumbprint = "$($cert.Thumbprint)"
            }
        )
    }

    & $configFunc @dscParameters -ConfigurationData $commonConfigurationData -OutputPath $DscWorkPath

    Start-DscConfiguration -Path .\ -Force -Wait -Verbose

} -Verbose
    
[String]$ExceptionErrors = $Error.Exception

if ($ExceptionErrors -like "*You cannot call a method on a null-valued*")
{
    $Error.Clear()
    Get-VM -Name AD-01 | Restart-VM -Force
    Start-Sleep -Seconds 240
    $ADSession = New-PSSession -ComputerName '10.100.100.10' -Credential $DomainCredential

    Invoke-Command -VMName AD-01 -Credential $DomainCredential -ScriptBlock {
        $VirtualMachinePassword = ConvertTo-SecureString -String '[AdminPassword]' -AsPlainText -Force
    
        $Username = 'Contoso\Administrator'
        $DomainCredential = New-Object System.Management.Automation.PSCredential($Username,$VirtualMachinePassword)
    
        $configFunc = "CaRootConfig"
        Set-Location 'C:\DSCConfigs'
        $scriptFilePathName = ".\CaRootConfig.ps1"
        Write-Verbose "Dot sourcing functions in PS1 script '$scriptFilePathName'"
        . $scriptFilePathName # load the DSC configuration functions into session
    
        $dscParameters = @{
            Hostname = $ENV:Computername
            Credential = $DomainCredential
            CaCommonName = 'ADCS-01-CA' 
            DomainDistinguishedName = 'CN=ADCS-01-CA,DC=Contoso,DC=local' 
            DomainName = 'contoso.local'
        }
    
        $DscWorkPath = 'C:\DSCConfigs'
        $certificateFilePathName = Join-Path -Path $DscWorkPath -ChildPath "$(hostname).cer"
        $cert = Get-ChildItem -Path 'Cert:\LocalMachine\My' -DocumentEncryptionCert | Where-Object -FilterScript { $psItem.Subject -eq "DSC Document Encryption" }

        if ($null -eq $cert) 
        {
            $cert = New-SelfSignedCertificate -Subject "DSC Document Encryption" -Type DocumentEncryptionCert -TextExtension "2.5.29.17={text}DNS=localhost" -CertStoreLocation Cert:\LocalMachine\My -ErrorAction Stop
        }

        $null = $cert | Export-Certificate -Type CERT -FilePath $certificateFilePathName -Force
    
        Configuration LcmSettings {
            param(
                [Parameter(Mandatory = $true)]
                [Alias("Thumbprint")]
                [ValidateNotNullOrEmpty()]
                [string]
                $CertificateId
            )
            node localhost {
                LocalConfigurationManager {
                    ConfigurationMode = "ApplyAndAutoCorrect"
                    RebootNodeIfNeeded = $true
                    DebugMode = "ForceModuleImport"
                    CertificateId = $CertificateId
                }
            }
        }
    
        & LcmSettings -CertificateId $cert.Thumbprint -OutputPath $DscWorkPath -Verbose
    
        Set-DscLocalConfigurationManager -Path $DscWorkPath -Force -Verbose
    
        $commonConfigurationData = @{
            AllNodes = @(
                @{
                    NodeName = 'localhost'
                    PsDscAllowDomainUser = $true
                    CertificateFile = "$certificateFilePathName"
                    Thumbprint = "$($cert.Thumbprint)"
                }
            )
        }

        & $configFunc @dscParameters -ConfigurationData $commonConfigurationData -OutputPath $DscWorkPath
        Start-DscConfiguration -Path .\ -Force -Wait -Verbose
    }
}

[String]$ExceptionErrors = $Error.Exception
    
if ($ExceptionErrors)
{
    $Error.Clear()

    if ($ExceptionErrors -like "*Failed to start service `'Active Directory Certificate Services (certsvc)`'*")
    {
        $Error.Clear()
        Invoke-Command -Session $ADSession -ScriptBlock {

            Get-Service CertSvc | Start-Service
        
            $VirtualMachinePassword = ConvertTo-SecureString -String '[AdminPassword]' -AsPlainText -Force
    
            $Username = 'Contoso\Administrator'
            $DomainCredential = New-Object System.Management.Automation.PSCredential($Username,$VirtualMachinePassword)
    
            $configFunc = "CaRootConfig"
            Set-Location 'C:\DSCConfigs'
            $scriptFilePathName = ".\CaRootConfig.ps1"
            Write-Verbose "Dot sourcing functions in PS1 script '$scriptFilePathName'"
            . $scriptFilePathName # load the DSC configuration functions into session
    
            $dscParameters = @{
                Hostname = $ENV:Computername
                Credential = $DomainCredential
                CaCommonName = 'ADCS-01-CA' 
                DomainDistinguishedName = 'CN=ADCS-01-CA,DC=Contoso,DC=local' 
                DomainName = 'contoso.local'
            }
    
            $DscWorkPath = 'C:\DSCConfigs'
            $certificateFilePathName = Join-Path -Path $DscWorkPath -ChildPath "$(hostname).cer"
            $cert = Get-ChildItem -Path 'Cert:\LocalMachine\My' -DocumentEncryptionCert | Where-Object -FilterScript { $psItem.Subject -eq "DSC Document Encryption" }

            if ($null -eq $cert) 
            {
                $cert = New-SelfSignedCertificate -Subject "DSC Document Encryption" -Type DocumentEncryptionCert -TextExtension "2.5.29.17={text}DNS=localhost" -CertStoreLocation Cert:\LocalMachine\My -ErrorAction Stop
            }

            $null = $cert | Export-Certificate -Type CERT -FilePath $certificateFilePathName -Force
    
            Configuration LcmSettings {
                param(
                    [Parameter(Mandatory = $true)]
                    [Alias("Thumbprint")]
                    [ValidateNotNullOrEmpty()]
                    [string]
                    $CertificateId
                )
    
                node localhost {
                    LocalConfigurationManager {
                        ConfigurationMode = "ApplyAndAutoCorrect"
                        RebootNodeIfNeeded = $true
                        DebugMode = "ForceModuleImport"
                        CertificateId = $CertificateId
                    }
                }
            }
    
            & LcmSettings -CertificateId $cert.Thumbprint -OutputPath $DscWorkPath -Verbose
    
            Set-DscLocalConfigurationManager -Path $DscWorkPath -Force -Verbose
    
            $commonConfigurationData = @{
                AllNodes = @(
                    @{
                        NodeName = 'localhost'
                        PsDscAllowDomainUser = $true
                        CertificateFile = "$certificateFilePathName"
                        Thumbprint = "$($cert.Thumbprint)"
                    }
                )
            }

            & $configFunc @dscParameters -ConfigurationData $commonConfigurationData -OutputPath $DscWorkPath

            Start-DscConfiguration -Path .\ -Force -Wait -Verbose
        }
    }
}
    
if ($Error)
{
    Throw $($Error.Exception)
    break
}
'@

    $ScriptString = $ScriptString.Replace('[AdminPassword]',"$AdminPassword")

    Invoke-AzVMRunCommand -VMName $VirtualMachineName `
        -ResourceGroupName $LabResourceGroup.ResourceGroupName `
        -CommandId 'RunPowerShellScript' `
        -ScriptString $ScriptString -AsJob | Out-Null
}

$Result = Get-Job | Wait-Job | Receive-Job
$EndTime = (Get-Date)

if (($Result.Value.DisplayStatus | Select-Object -Unique) -ne 'Provisioning succeeded') 
{
    throw 'Failed to install Certificate Services!'
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
#endregion

#region Set Certificate Template Permissions & Make the Azure Stack Certificate Template available for Enroll
Write-Host "Now I am going to set Certificate Template Permissions & Make the Azure Stack Certificate Template available for Enroll" -ForegroundColor Yellow
Write-Host "This should take about 5 minutes." -ForegroundColor Yellow
Write-Host ""
$StartTime = (Get-Date)

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Making the Azure Stack Certificate Template available" -ForegroundColor Green
    Write-Host ""

$ScriptString = @'
$VirtualMachinePassword = ConvertTo-SecureString -String '[AdminPassword]' -AsPlainText -Force

$Username = 'Contoso\Administrator'
$DomainCredential = New-Object System.Management.Automation.PSCredential($Username,$VirtualMachinePassword)

winrm s winrm/config/client '@{TrustedHosts="*"}'
    
$ADSession = New-PSSession -ComputerName '10.100.100.10' -Credential $DomainCredential
$CSSession = New-PSSession -ComputerName '10.100.100.11' -Credential $DomainCredential

Invoke-Command -Session $ADSession -ScriptBlock {
    $azureStackCaTemplateName = "AzureStack"
    $azureStackCaTemplateDisplayName = "Azure Stack"

    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $pdc = $domain.PdcRoleOwner.Name
    $rootDSE = [adsi]"LDAP://$pdc/rootdse"

    # distinguishedName where the certificate templates are stored in AD
    $certificateTemplatesBaseDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$($rootDSE.configurationNamingContext)"
    $certificateTemplatesBaseDE = [adsi]"LDAP://$pdc/$certificateTemplatesBaseDN"

    $templateName = 'AzureStack'

    # Create  DirectoryEntry for the new template
    $templateDE = $certificateTemplatesBaseDE.Children.Add("CN=$templateName", "pKICertificateTemplate")

    # Set property values
    $templateDE.Properties["displayname"].Value = 'Azure Stack'
    $templateDE.Properties["flags"].Value = 131649
    $templateDE.Properties["pKICriticalExtensions"].Value = "2.5.29.15"
    $templateDE.Properties["pKIDefaultCSPs"].Value = @("1,Microsoft RSA SChannel Cryptographic Provider", "2,Microsoft DH SChannel Cryptographic Provider")
    $templateDE.Properties["pKIDefaultKeySpec"].Value = 1

    # EKU for both server and client auth
    $templateDE.Properties["pKIExtendedKeyUsage"].Value = @("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2")
    # XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE + XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE
    $templateDE.Properties["pKIKeyUsage"].Value = [byte[]]@(160, 0)

    # 10 year validity
    $expirationTimespan = [TimeSpan]::FromDays(365 * 10)
    $templateDE.Properties["pKIExpirationPeriod"].Value = [System.BitConverter]::GetBytes($expirationTimespan.Negate().Ticks)
    # Allow renewal 6 weeks before expiration
    $overlapTimespan = [TimeSpan]::FromDays(7 * 6)
    $templateDE.Properties["pKIOverlapPeriod"].Value = [System.BitConverter]::GetBytes($overlapTimespan.Negate().Ticks)

    $templateDE.Properties["pKIMaxIssuingDepth"].Value = 0
    $templateDE.Properties["msPKI-Cert-Template-OID"].Value = "1.3.6.1.4.1.311.21.8.7638725.13898300.1985460.3383425.7519116.119.16408497.1716293"
    $templateDE.Properties["msPKI-Certificate-Application-Policy"].Value = @("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2")
    $templateDE.Properties["msPKI-Certificate-Name-Flag"].Value = 1
    $templateDE.Properties["msPKI-Enrollment-Flag"].Value = 0
    $templateDE.Properties["msPKI-Minimal-Key-Size"].Value = 2048
    $templateDE.Properties["msPKI-Private-Key-Flag"].Value = 16842768
    $templateDE.Properties["msPKI-RA-Signature"].Value = 0
    $templateDE.Properties["msPKI-Template-Minor-Revision"].Value = 0
    $templateDE.Properties["msPKI-Template-Schema-Version"].Value = 2
    $templateDE.Properties["revision"].Value = 100
    $templateDE.CommitChanges()
    $templateDE.RefreshCache()
}

Invoke-Command -Session $ADSession -ScriptBlock {
    $PkiAdminsGroupName = "Contoso\Domain Admins"
    Write-Verbose "PkiAdminsGroupName='$PkiAdminsGroupName'"

    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $pdc = $domain.PdcRoleOwner.Name
    $rootDSE = [adsi]"LDAP://$pdc/rootdse"
    $certificateTemplatesDE = [adsi]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$($rootDSE.configurationNamingContext)"

    # values we want present in the ACL
    $actor = ([System.Security.Principal.NTAccount]$PkiAdminsGroupName).Translate([System.Security.Principal.SecurityIdentifier])
    $right = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
    $accessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $objectType = [System.Guid]"0e10c968-78fb-11d2-90d4-00c04f79dc55"
    $inheritanceFlags = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    $templateDE = $certificateTemplatesDE.Children | Where-Object {$_.distinguishedName -like "CN=AzureStack*"}
    try
    {
        # add GenericAll right
        try
        {
            Write-Verbose "Adding GenericRead, GenericWrite, WriteDacl, WriteOwner for '$PkiAdminsGroupName' on template '$($templateDE.name)'"
            $ace = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
                $actor,
                [System.DirectoryServices.ActiveDirectoryRights]"GenericRead, GenericWrite, WriteDacl, WriteOwner",
                $accessControlType)
            $templateDE.ObjectSecurity.AddAccessRule($ace)
            $templateDE.CommitChanges()
            $templateDE.RefreshCache()

        }
        catch
        {
            Write-Error -Message "Error adding GenericRead, GenericWrite, WriteDacl, WriteOwner rights on template '$($templateDE.name)': $($_.Exception.Message)" -Exception $_.Exception
        }

        $templateDE.RefreshCache()

        # add Enroll extended right
        try
        {
            Write-Verbose "Adding Enroll right for '$PkiAdminsGroupName' on template '$($templateDE.name)'"
            $ace = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
                $actor,
                $right,
                $accessControlType,
                $objectType,
                $inheritanceFlags)
            $templateDE.ObjectSecurity.AddAccessRule($ace)
            $templateDE.CommitChanges()
            $templateDE.RefreshCache()

        }
        catch
        {
            Write-Error -Message "Error adding Enroll right on template '$($templateDE.name)': $($_.Exception.Message)" -Exception $_.Exception
        }
    }
    finally
    {
        if ($templateDE)
        {
            $templateDE.Dispose()
        }
    }

    $GroupToAdd = 'Contoso\Domain Computers'
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $pdc = $domain.PdcRoleOwner.Name
    $rootDSE = [adsi]"LDAP://$pdc/rootdse"
    $certificateTemplatesDE = [adsi]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$($rootDSE.configurationNamingContext)"

    # values we want present in the ACL
    $actor = ([System.Security.Principal.NTAccount]$GroupToAdd).Translate([System.Security.Principal.SecurityIdentifier])
    $right = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
    $accessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $objectType = [System.Guid]"0e10c968-78fb-11d2-90d4-00c04f79dc55"
    $inheritanceFlags = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    $templateDE = $certificateTemplatesDE.Children | Where-Object {$_.distinguishedName -like "CN=AzureStack*"}

    $ace = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
        $actor,
        [System.DirectoryServices.ActiveDirectoryRights]"GenericRead",
        $accessControlType)
    $templateDE.ObjectSecurity.AddAccessRule($ace)
    $templateDE.CommitChanges()
    $templateDE.RefreshCache()

    $ace = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
        $actor,
        $right,
        $accessControlType,
        $objectType,
        $inheritanceFlags)
    $templateDE.ObjectSecurity.AddAccessRule($ace)
    $templateDE.CommitChanges()
    $templateDE.RefreshCache()
    $templateDE.Dispose()
}

Invoke-Command -Session $ADSession -ScriptBlock {
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$pdc = $domain.PdcRoleOwner.Name
$rootDSE = [adsi]"LDAP://$pdc/rootdse"

$EnrollmentServicesBaseDN = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$($rootDSE.configurationNamingContext)"
$EnrollmentServicesBaseDE = [adsi]"LDAP://$pdc/$EnrollmentServicesBaseDN"
$EnrollmentServicesBaseDE.Children.distinguishedName

$Object = Get-ADObject -Identity "$($EnrollmentServicesBaseDE.Children.distinguishedName)" -Properties certificateTemplates
$Object.certificateTemplates.Add('AzureStack')
Set-ADObject -Instance $Object
}

Start-Sleep -Seconds 300
'@

    $ScriptString = $ScriptString.Replace('[AdminPassword]',"$AdminPassword")

    Invoke-AzVMRunCommand -VMName $VirtualMachineName `
        -ResourceGroupName $LabResourceGroup.ResourceGroupName `
        -CommandId 'RunPowerShellScript' `
        -ScriptString $ScriptString -AsJob | Out-Null
}

$Result = Get-Job | Wait-Job | Receive-Job
$EndTime = (Get-Date)

$Result.Value.Message | Out-File "$env:temp\temp.txt"
$Results = Get-Content "$env:temp\temp.txt"

if ((($Results |  Select-String -Pattern 'template does not exist in the domain' | Select-Object -Unique) -replace '\s','') -eq 'The"AzureStack"templatedoesnotexistinthedomain.')
{
    throw 'Failed to add the Azure Stack Template'
    break
}

else
{
    Write-Host "PowerShell Job $($Result.Status)" -ForegroundColor Green
    Write-Host "$($Result.Value.Message)" -ForegroundColor Green
    Write-Host "StartTime $($StartTime)" -ForegroundColor White
    Write-Host "EndTime $($EndTime)" -ForegroundColor White
    Write-Host $('Duration: {0:mm} min {0:ss} sec' -f ($EndTime - $StartTime)) -ForegroundColor White
    Write-Host ""
}
#endregion

#region Generate Deployment Certificates
Write-Host "Now we are getting close. Just a few more things to take care of..." -ForegroundColor Yellow
Write-Host "I need to generate the Azure Stack Deployment Certificates." -ForegroundColor Yellow
Write-Host "This should take about 3 minutes." -ForegroundColor Yellow
Write-Host ""
$StartTime = (Get-Date)

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Generating the Azure Stack Deployment Certificates." -ForegroundColor Green
    Write-Host ""

$ScriptString = @'
$VirtualMachinePassword = ConvertTo-SecureString -String '[AdminPassword]' -AsPlainText -Force

$Username = '.\Administrator'
$LocalCredential = New-Object System.Management.Automation.PSCredential($Username,$VirtualMachinePassword)

$Username = 'Contoso\Administrator'
$DomainCredential = New-Object System.Management.Automation.PSCredential($Username,$VirtualMachinePassword)

Invoke-Command -VMName 'ADCS-01' -Credential $DomainCredential -ScriptBlock {

$REQOutputDirectory = 'C:\AzureStackCerts\REQ'
$IdentitySystem = 'ADFS'
$RegionName = 'local'
$ExternalFQDN = 'azurestack.external'
$Subject = 'C=US,ST=Washington,L=Redmond,O=Microsoft,OU=Azure Stack Hub'

if (!(Test-Path $REQOutputDirectory))
{
    New-Item -ItemType Directory -Path $REQOutputDirectory -Force
}

# Generate certificate signing requests for deployment:
New-AzsHubDeploymentCertificateSigningRequest -RegionName $RegionName -FQDN $ExternalFQDN -subject $Subject -OutputRequestPath $REQOutputDirectory -IdentitySystem $IdentitySystem

# Azure Container Registry
New-AzsHubAzureContainerRegistryCertificateSigningRequest -RegionName $RegionName -FQDN $ExternalFQDN -subject $Subject -OutputRequestPath $REQOutputDirectory
}

Invoke-Command -VMName 'ADCS-01' -Credential $DomainCredential -ScriptBlock {
$REQOutputDirectory = "C:\AzureStackCerts\REQ"
$CEROutputDirectory = "C:\AzureStackCerts\CER"
Import-Module Microsoft.AzureStack.ReadinessChecker
if (!(Test-Path $CEROutputDirectory))
{
    New-Item -ItemType Directory -Path $CEROutputDirectory -Force
}

$REQFiles = Get-ChildItem -Path $REQOutputDirectory -Filter *.req

foreach ($REQFile in $REQFiles)
{
    $CerFileName = $REQFile.Name.Substring(0,$REQFile.Name.IndexOf('_Cert')) + '.cer'
    certreq -submit -attrib "CertificateTemplate:AzureStack" -config - $REQFile.FullName.ToString() $CEROutputDirectory\$CerFileName
}

$RSPFiles = Get-ChildItem -Path $CEROutputDirectory -Filter *.rsp
foreach ($RSPFile in $RSPFiles)
{
    Remove-Item $RSPFile.FullName -Force
}
}

Invoke-Command -VMName 'ADCS-01' -Credential $DomainCredential -ScriptBlock {
$CERPath = 'C:\AzureStackCerts\CER'
$PFXExportPath = 'C:\AzureStackCerts\PFX'
Import-Module Microsoft.AzureStack.ReadinessChecker
$PFXPassword = '[AdminPassword]' | ConvertTo-SecureString -asPlainText -Force

if (!(Test-Path $PFXExportPath))
{
    New-Item -ItemType Directory -Path $PFXExportPath -Force
}

ConvertTo-AzsPFX -Path $CERPath -pfxPassword $PFXPassword -ExportPath $PFXExportPath
}
'@

    $ScriptString = $ScriptString.Replace('[AdminPassword]',"$AdminPassword")

    Invoke-AzVMRunCommand -VMName $VirtualMachineName `
        -ResourceGroupName $LabResourceGroup.ResourceGroupName `
        -CommandId 'RunPowerShellScript' `
        -ScriptString $ScriptString -AsJob | Out-Null
}

$Result = Get-Job | Wait-Job | Receive-Job
$EndTime = (Get-Date)

if (($Result.Value.Message -contains "error") -and ($Result.Value.Message -notlike "*errorid*")) 
{
    throw $($Error[0])
    break
}
else
{
    Write-Host "PowerShell Job $($Result.Status)" -ForegroundColor Green
    Write-Host "$($Result.Value.Message)" -ForegroundColor Green
    Write-Host "StartTime $($StartTime)" -ForegroundColor White
    Write-Host "EndTime $($EndTime)" -ForegroundColor White
    Write-Host $('Duration: {0:mm} min {0:ss} sec' -f ($EndTime - $StartTime)) -ForegroundColor White
    Write-Host ""
}
#endregion

#region Copy Deployment Certificates
Write-Host "Going to use PowerShell Remoting to copy the certificate files from the CA to the Setup Folder." -ForegroundColor Yellow
Write-Host "Only 6 more steps. It is sooooo close now!" -ForegroundColor Yellow
Write-Host ""
$StartTime = (Get-Date)

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Copying the Azure Stack Deployment Certificates." -ForegroundColor Green
    Write-Host ""

$ScriptString = @'
$VirtualMachinePassword = ConvertTo-SecureString -String '[AdminPassword]' -AsPlainText -Force
$Username = 'Contoso\Administrator'
$DomainCredential = New-Object System.Management.Automation.PSCredential($Username,$VirtualMachinePassword)

Remove-Item -Path 'C:\CloudDeployment\Setup\Certificates\ADFS' -Recurse -Force
winrm s winrm/config/client '@{TrustedHosts="*"}'
$ADSession = New-PSSession -ComputerName '10.100.100.11' -Credential $DomainCredential
Copy-Item -FromSession $ADSession -Path 'C:\AzureStackCerts\PFX\local.azurestack.external\Deployment' -Destination 'C:\CloudDeployment\Setup\Certificates\ADFS' -Force -Recurse -Container
Remove-PSSession $ADSession
'@

    $ScriptString = $ScriptString.Replace('[AdminPassword]',"$AdminPassword")

    Invoke-AzVMRunCommand -VMName $VirtualMachineName `
        -ResourceGroupName $LabResourceGroup.ResourceGroupName `
        -CommandId 'RunPowerShellScript' `
        -ScriptString $ScriptString -AsJob | Out-Null
}

$Result = Get-Job | Wait-Job | Receive-Job
$EndTime = (Get-Date)

if (($Result.Value.DisplayStatus | Select-Object -Unique) -ne 'Provisioning succeeded') 
{
    throw 'Failed to Copy Deployment Certificates!'
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
#endregion

#region Create Azure Stack Deployment Script
Write-Host "I need to replace the Azure Stack Deployment Script with one I made just for you!" -ForegroundColor Yellow
Write-Host "Do you feel special now?" -ForegroundColor Yellow
Write-Host ""
$StartTime = (Get-Date)

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Creating the Azure Stack Deployment Script." -ForegroundColor Green
    Write-Host ""

$ScriptString = @"
`$InstallScript = New-Item -Path C:\CloudDeployment\Setup -Name InstallAzureStackPOC.ps1 -ItemType File -Force

`$InstallAzureStackPOCScript = @'
<#############################################################
 #                                                           #
 # Copyright (C) Microsoft Corporation. All rights reserved. #
 #                                                           #
 #############################################################>
<#
 .Synopsis
      Unpacks deployment scripts and deploys a one node Azure Stack POC.
 .Parameter AdminPassword
     Password for the local administrator account and all other accounts that will be created as part of the POC deployment.  Must match the current local administrator password on the host.
 .Parameter InfraAzureDirectoryTenantAdminCredential
     Sets the Azure Active Directory user name and password. These Azure credentials can be either an Org ID or a Microsoft Account. To use Microsoft Account credentials, do not include this parameter in the cmdlet, thus prompting the Azure Authentication popup during deployment (this will create the authentication and refresh tokens used during deployment).
 .Parameter InfraAzureDirectoryTenantName
     Sets the tenant directory. Use this parameter to specify a specific directory where the AAD account has permissions to manage multiple directories. Full Name of an AAD Directory Tenant in the format of <directoryName>.onmicrosoft.com.
 .Parameter InfraAzureEnvironment
     Select which Azure environment to register this Azure Stack Installation with.
 .Parameter DNSForwarder
     A DNS server is created as part of the Azure Stack deployment. To allow computers inside of the solution to resolve names outside of the stamp, provide your existing infrastructure DNS server. The in-stamp DNS server will forward unknown name resolution requests to this server.
 .Parameter TimeServer
     Use this parameter to specify a time server.
 .Parameter UseADFS
    If set, deployment will use ADFS instead of Azure AD.
 .Parameter Rerun
     Use this flag to re-run idempotent deployment from the last failed step. All previous input will be used.
     Re-entering data once provided is not supported because several unique values are generated and used for deployment.
 .Parameter BackupStorePath
    The external SMB share to retrieve and store backup data.
 .Parameter BackupStoreCredential
    Credential required to access the external SMB share to retrieve and store backup data.
 .Parameter BackupDecryptionCertPassword
    Backup data decryption cert password
.Example
     If no parameters are provided, the script prompts for input and uses DHCP for NAT.
     InstallAzureStackPOC.ps1
.Example
     # If you need to re-run a failed deployment use this flag, which restarts deployment using all previous input from the failure point. 
     InstallAzureStackPOC.ps1 -Rerun 
#>
[CmdletBinding(SupportsShouldProcess=`$true, ConfirmImpact="Medium", PositionalBinding=`$false, DefaultParameterSetName="DefaultSet")]
param (
    [Parameter(Mandatory=`$true, ParameterSetName="DefaultSet")]
    [Parameter(Mandatory=`$true, ParameterSetName="ADFSSet")]
    [Parameter(Mandatory=`$true, ParameterSetName="RestoreSet")]
    [ValidateNotNullOrEmpty()]
    [SecureString]
    `$AdminPassword,
    [Parameter(Mandatory=`$false, ParameterSetName="DefaultSet")]
    [Parameter(Mandatory=`$false, ParameterSetName="RestoreSet")]
    [ValidateNotNullOrEmpty()]
    [PSCredential]
    `$InfraAzureDirectoryTenantAdminCredential,
    [Parameter(Mandatory=`$false, ParameterSetName="DefaultSet")]
    [Parameter(Mandatory=`$false, ParameterSetName="RestoreSet")]
    [ValidateNotNullOrEmpty()]
    [String]
    `$InfraAzureDirectoryTenantName,
    [Parameter(Mandatory=`$false, ParameterSetName="DefaultSet")]
    [Parameter(Mandatory=`$false, ParameterSetName="RestoreSet")]
    [ValidateSet("AzureCloud", "AzureChinaCloud", "AzureGermanCloud", "AzureUSGovernment", "CustomCloud")]
    [String]
    `$InfraAzureEnvironment = "AzureCloud",
    [Parameter(Mandatory=`$false, ParameterSetName="RestoreSet")]
    [Parameter(Mandatory=`$false, ParameterSetName="DefaultSet")]
    [Parameter(Mandatory=`$false, ParameterSetName="ADFSSet")]
    [ValidateNotNullOrEmpty()]
    [String[]]
    `$DNSForwarder,
    [Parameter(Mandatory=`$true, ParameterSetName="DefaultSet")]
    [Parameter(Mandatory=`$true, ParameterSetName="ADFSSet")]
    [Parameter(Mandatory=`$true, ParameterSetName="RestoreSet")]
    [ValidateNotNullOrEmpty()]
    [string]
    `$TimeServer,
    [Parameter(Mandatory=`$false, ParameterSetName="ADFSSet")]
    [Switch]
    `$UseADFS,
    [Parameter(Mandatory=`$false, ParameterSetName="DefaultSet")]
    [Parameter(Mandatory=`$false, ParameterSetName="ADFSSet")]
    [Parameter(Mandatory=`$false, ParameterSetName="RestoreSet")]
    [ValidateRange(0,3)]
    [int]
    `$InternalRetryAttempts = 2,
    [Parameter(Mandatory=`$true, ParameterSetName="RerunSet")]
    [Switch]
    `$Rerun,
    [Parameter(Mandatory=`$false)]
    [ValidateNotNullOrEmpty()]
    [String]
    `$DeploymentScriptPath = "`$env:SystemDrive\CloudDeployment\Setup\DeploySingleNode.ps1",
    [Parameter(Mandatory=`$false)]
    [ValidateNotNullOrEmpty()]
    [string]
    `$NuGetManifestPath = "`$env:SystemDrive\CloudDeployment\Setup\CloudBuilderNuGets.xml",
    [Parameter(Mandatory=`$false)]
    [ValidateNotNullOrEmpty()]
    [string]
    `$NugetStorePath = "`$env:SystemDrive\CloudDeployment\NuGetStore",
    [Parameter(Mandatory=`$false)]
    [switch]
    `$ForceUnpack = `$false,
    [Parameter(Mandatory=`$false, ParameterSetName="DefaultSet")]
    [Parameter(Mandatory=`$false, ParameterSetName="ADFSSet")]
    [Parameter(Mandatory=`$true, ParameterSetName="RestoreSet")]
    [ValidateNotNullOrEmpty()]
    [string]
    `$BackupStorePath,
    [Parameter(Mandatory=`$false, ParameterSetName="DefaultSet")]
    [Parameter(Mandatory=`$false, ParameterSetName="ADFSSet")]
    [Parameter(Mandatory=`$true, ParameterSetName="RestoreSet")]
    [ValidateNotNullOrEmpty()]
    [PSCredential]
    `$BackupStoreCredential,
    [Parameter(Mandatory=`$false, ParameterSetName="DefaultSet")]
    [Parameter(Mandatory=`$false, ParameterSetName="ADFSSet")]
    [Parameter(Mandatory=`$true, ParameterSetName="RestoreSet")]
    [ValidateNotNullOrEmpty()]
    [SecureString]
    `$BackupDecryptionCertPassword,
    [Parameter(Mandatory=`$true, ParameterSetName="RestoreSet")]
    [ValidateNotNullOrEmpty()]
    [Guid]
    `$BackupId,
    [Parameter(Mandatory=`$true, ParameterSetName="RestoreSet")]
    [ValidateNotNullOrEmpty()]
    [SecureString]
    `$ExternalCertPassword,
    [Parameter(Mandatory=`$false)]
    [ValidateNotNullOrEmpty()]
    [SecureString]
    `$SqlActivationKey,
    
    [Parameter(Mandatory=`$false)]
    [string] `$WPADConfigIP,
    [Parameter(Mandatory=`$false)]
    [string] `$ProxyIPAddress,
    [Parameter(Mandatory=`$false)]
    [ValidateRange(0, 65535)]
    [int] `$ProxyIPPort,
    [Parameter(Mandatory=`$false, ParameterSetName="DefaultSet")]
    [Parameter(Mandatory=`$false, ParameterSetName="ADFSSet")]
    [string]`$CloudJSONFilePath
)
Write-Verbose "Getting `$PSBoundParameters"
`$PassthroughParameters = `$PSBoundParameters
`$null = `$PassthroughParameters.Remove("DeploymentScriptPath")
`$null = `$PassthroughParameters.Remove("NuGetManifestPath")
`$null = `$PassthroughParameters.Remove("NugetStorePath")
`$null = `$PassthroughParameters.Remove("ForceUnpack")
if (!`$ForceUnpack -and (Test-Path `$DeploymentScriptPath))
{
    Write-Verbose "Deployment NuGets have already been unpacked. Calling `$DeploymentScriptPath."
}
else
{
    . "`$PSScriptRoot\BootstrapAzureStackDeployment.ps1" -NuGetManifestPath `$NuGetManifestPath -NugetStorePath `$NugetStorePath
}
if (`$PassthroughParameters.ContainsKey('CloudJSONFilePath'))
{
    if (Test-Path `$CloudJSONFilePath)
    {
        `$cloudJson = Get-Content `$CloudJSONFilePath -Raw | ConvertFrom-Json
        `$cloudJsonContent = `$cloudJson.DeploymentData
        if(`$cloudJsonContent.CustomEnvironmentEndpoints.CustomCloudARMEndpoint)
        {
            `$PassthroughParameters.Add("CustomCloudARMEndpoint", `$cloudJsonContent.CustomEnvironmentEndpoints.CustomCloudARMEndpoint)
        }
        if (`$cloudJsonContent.CustomEnvironmentEndpoints.ExternalDSMSEndpoint)
        {
            `$PassthroughParameters.Add("ExternalDSMSEndpoint", `$cloudJsonContent.CustomEnvironmentEndpoints.ExternalDSMSEndpoint)
        }
        
        if (`$cloudJsonContent.PEPPublicCert)
        {
            try
            {
                `$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                `$cert.Import([System.Convert]::FromBase64String(`$cloudJsonContent.PEPPublicCert))
            }
            catch
            {
                throw (`$LocalizedData.PEPPublicCertInvalid)
            }
            `$PassthroughParameters.Add("PEPPublicCert", `$cloudJsonContent.PEPPublicCert)
        }
        if (`$cloudJsonContent.ExternalDSMSIssuers)
        {
            `$PassthroughParameters.Add("ExternalDSMSIssuer", `$cloudJsonContent.ExternalDSMSIssuers)
        }
        if (`$cloudJsonContent.CustomCloudVerificationKey)
        {
            `$PassthroughParameters.Add("CustomCloudVerificationKey", `$cloudJsonContent.CustomCloudVerificationKey)
        }
    }
    `$null = `$PassthroughParameters.Remove("CloudJSONFilePath")
}
if (`$PSCmdlet.ParameterSetName -eq "RestoreSet")
{
    # Add parameters from backup
    Import-Module "`$env:SystemDrive\CloudDeployment\Setup\RestoreDeploymentParametersHelper.psm1"
    Import-Module "`$env:SystemDrive\CloudDeployment\Common\RestoreHelpers.psm1"
    # Get deployment related parameters from the backup
    `$backupDecryptionCertBase64 = Get-DecryptionCertBase64
    `$ParameterFromBackup = Get-AsDeploymentParameterFromBackup `
        -BackupStorePath `$BackupStorePath `
        -BackupStoreCredential `$BackupStoreCredential `
        -DecryptionCertBase64 `$backupDecryptionCertBase64 `
        -DecryptionCertPassword `$BackupDecryptionCertPassword `
        -BackupId `$BackupId `
        -VersionCheck -Verbose
    Add-ParametersFromBackup -ParamHash `$PassthroughParameters -ParameterFromBackup `$ParameterFromBackup
    `$null = `$PassthroughParameters.Remove("CompanyName")
    `$null = `$PassthroughParameters.Remove("DVMName")
    `$null = `$PassthroughParameters.Remove("AzureStackEnhancedEncryptionMethod")
    `$null = `$PassthroughParameters.Remove("LegalNoticeCaption")
    `$null = `$PassthroughParameters.Remove("LegalNoticeText")
    # NOTE: ExternalDomainFQDN from the backup is actually just ExternalDomainSuffix.
    `$PassthroughParameters.Add("ExternalDomainSuffix", `$ParameterFromBackup.ExternalDomainFQDN)
    `$null = `$PassthroughParameters.Remove("ExternalDomainFQDN")
    # Pass through the unwrapped key if decryption cert is specified
    if (![string]::IsNullOrEmpty(`$backupDecryptionCertBase64) -and `$BackupDecryptionCertPassword)
    {
        `$restoreTempFolder = "`$env:SystemDrive\CloudDeployment\RestoreTempFolder"
        `$roleNames = @("ECE", "Domain", "CertificateManagement")
        if (`$ParameterFromBackup.UseADFS)
        {
            `$roleNames += "ADFS"
        }
        try
        {
            `$drive = New-PSDrive -Name Backup -Root `$BackupStorePath -PSProvider FileSystem -Credential `$BackupStoreCredential
            `$backupId = `$ParamHash["BackupId"]
            `$allSnapshotsFromBackup = Get-ChildItem "`$BackupStorePath\MASBackup\progressivebackup" -Recurse -Filter "*`$BackupId*"
            foreach (`$roleName in `$roleNames)
            {
                `$repos = `$allSnapshotsFromBackup | ? { `$_.Directory.Name.StartsWith("`$roleName;") -and `$_ -like "*.zip"}
                foreach (`$repo in `$repos)
                {
                    `$s = `$repo.Directory.Name -split ";"
                    Write-Output "Downloading backup '`$(`$repo.FullName)' to `$restoreTempFolder"
                    Copy-AsBackupData -BackupId `$BackupId `
                        -BackupStorePath `$BackupStorePath `
                        -ShareCredential `$BackupStoreCredential `
                        -DecryptionCertBase64 `$backupDecryptionCertBase64 `
                        -DecryptionCertPassword `$BackupDecryptionCertPassword `
                        -TargetPath `$restoreTempFolder `
                        -RoleName `$s[0] `
                        -ComponentName `$s[1] `
                        -PartitionId `$s[2] `
                        -RepositoryName `$s[3]
                }
            }
        }
        catch
        {
            throw "Cannot download backup data. Exception: `$_"
        }
        finally
        {
            try
            {
                `$drive | Remove-PSDrive -ErrorAction Stop
            }
            catch {}
        }
        `$PassthroughParameters["BackupDecryptionCertBase64"] = `$backupDecryptionCertBase64
    }
}
`$ExternalCertPassword = ConvertTo-SecureString '[AdminPassword]' -AsPlainText -Force 
`$PassthroughParameters.Add("ExternalCertPassword", `$ExternalCertPassword)
if (!(Test-Path `$DeploymentScriptPath))
{
    Throw "Deployment Scripts are not at the expected location: `$DeploymentScriptPath"
}
else
{
    Write-Output "CloudDeployment NuGets have finished unpacking. Calling `$DeploymentScriptPath."
    . `$DeploymentScriptPath @PassthroughParameters
    return
}
'@

Add-Content -Path `$InstallScript.FullName -Value `$InstallAzureStackPOCScript -Force | Set-Content -Force

"@

    $ScriptString = $ScriptString.Replace('[AdminPassword]',"$AdminPassword")

    Invoke-AzVMRunCommand -VMName $VirtualMachineName `
        -ResourceGroupName $LabResourceGroup.ResourceGroupName `
        -CommandId 'RunPowerShellScript' `
        -ScriptString $ScriptString -AsJob | Out-Null
}

$Result = Get-Job | Wait-Job | Receive-Job
$EndTime = (Get-Date)

if (($Result.Value.DisplayStatus | Select-Object -Unique) -ne 'Provisioning succeeded') 
{
    throw 'Failed to Create Azure Stack Deployment Script!'
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
#endregion

#region Remove Hyper-V Virtual Machines
Write-Host "Only 4 more steps. Nearly there!" -ForegroundColor Yellow
Write-Host ""
$StartTime = (Get-Date)

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Removing AD & ADFS Virtual Machines." -ForegroundColor Green
    Write-Host ""

$ScriptString = @'
Get-vm | Stop-VM -Force
Get-vm | Remove-VM -Force
Get-NetAdapter | Where-Object {$_.Name -like "*ADSwitch*"} | Disable-NetAdapter -Confirm:$false
'@

    Invoke-AzVMRunCommand -VMName $VirtualMachineName `
        -ResourceGroupName $LabResourceGroup.ResourceGroupName `
        -CommandId 'RunPowerShellScript' `
        -ScriptString $ScriptString -AsJob | Out-Null
}

$Result = Get-Job | Wait-Job | Receive-Job
$EndTime = (Get-Date)

if (($Result.Value.DisplayStatus | Select-Object -Unique) -ne 'Provisioning succeeded') 
{
    throw 'Failed to remove the Domain Controller or ADFS Server!'
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
#endregion

#region Setup ASDK Install Job
Write-Host "Only 2 more steps after this! hang in there buddy..." -ForegroundColor Yellow
Write-Host ""
$StartTime = (Get-Date)

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Starting ASDK Deployment." -ForegroundColor Green

$ScriptString = @"
`$AADscriptToExecute = @'
    net stop w32time | w32tm /unregister | w32tm /register | net start w32time | 
    w32tm /resync /rediscover | w32tm /config /manualpeerlist:`$TimeServer /syncfromflags:MANUAL /reliable:yes /update | w32tm /query /status 

    `$adminpass = ConvertTo-SecureString '[AdminPassword]' -AsPlainText -Force 
    cd C:\CloudDeployment\Setup
    .\InstallAzureStackPOC.ps1 -AdminPassword `$adminpass -TimeServer [TimeServerIp] -DNSForwarder [DNSForwarder] -UseADFS
'@

        
#Autologon
`$AutoLogonRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path `$AutoLogonRegPath -Name "AutoAdminLogon" -Value "1" -type String 
Set-ItemProperty -Path `$AutoLogonRegPath -Name "DefaultUsername" -Value "`$env:ComputerName\Administrator" -type String  
Set-ItemProperty -Path `$AutoLogonRegPath -Name "DefaultPassword" -Value "[AdminPassword]" -type String
Set-ItemProperty -Path `$AutoLogonRegPath -Name "AutoLogonCount" -Value "1" -type DWord

`$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument `$AADscriptToExecute

`$registrationParams = @{
	TaskName = 'ASDKDeployment'
	TaskPath = '\'
	Action = `$action
	Settings = New-ScheduledTaskSettingsSet -Priority 4
	Force = `$true
	Trigger = New-JobTrigger -AtLogOn
	Runlevel = 'Highest'
}
# The order of the script matters

Register-ScheduledTask @registrationParams -User "`$env:ComputerName\Administrator"
"@
   
    $ScriptString = $ScriptString.Replace('[AdminPassword]',"$AdminPassword")
    $ScriptString = $ScriptString.Replace('[TimeServerIp]',"$TimeServer")
    $ScriptString = $ScriptString.Replace('[DNSForwarder]',"$DNSForwarder")

    Invoke-AzVMRunCommand -VMName $VirtualMachineName `
        -ResourceGroupName $LabResourceGroup.ResourceGroupName `
        -CommandId 'RunPowerShellScript' `
        -ScriptString $ScriptString -AsJob | Out-Null
}

$Result = Get-Job | Wait-Job | Receive-Job
$EndTime = (Get-Date)

if (($Result.Value.DisplayStatus | Select-Object -Unique) -ne 'Provisioning succeeded') 
{
    throw 'Failed to Setup ASDK Install Job!'
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
#endregion

#region Create Script to Finalize the Install
Write-Host "Just need to drop a script on the C Drive for you to use later." -ForegroundColor Yellow
Write-Host ""
$StartTime = (Get-Date)

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Creating Post Deployment Script." -ForegroundColor Green

$ScriptString = @"
`$PostInstallScript = New-Item -Path C:\ -Name FinalizeServers.ps1 -ItemType File -Force

`$FinalizeAzureStackPOCScript = @'
Get-NetAdapter | Where-Object {`$_.Name -like "*ADSwitch*"} | Enable-NetAdapter

`$Password = '[AdminPassword]' | ConvertTo-SecureString -asPlainText -Force
`$Username = 'Contoso\Administrator'
`$Credential = New-Object System.Management.Automation.PSCredential(`$Username,`$Password)

`$Servers = @(
    @{ServerName = 'AD-01';IPAddress = '10.100.100.10'}
    @{ServerName = 'ADCS-01';IPAddress = '10.100.100.11'}
    @{ServerName = 'ADFS-01';IPAddress = '10.100.100.12'}
)

Foreach (`$Server in `$Servers)
{
    New-VM -Name `$Server.ServerName -BootDevice VHD -VHDPath ('C:\VMDisks\' + `$Server.ServerName + '.vhd') -MemoryStartupBytes 4GB -SwitchName 'ADSwitch'
    Set-VMProcessor -VMName `$Server.ServerName -count 2
    Start-VM -Name `$Server.ServerName
    Start-Sleep -Seconds 200
    `$InterfaceIndex = Invoke-Command -VMName `$Server.ServerName -Credential `$Credential -ScriptBlock {(Get-NetAdapter).ifIndex}
    Invoke-Command -VMName `$Server.ServerName -Credential `$Credential -ScriptBlock {
        Set-DnsClientServerAddress -InterfaceIndex `$Using:InterfaceIndex -ServerAddresses 10.100.100.10,8.8.8.8;
        New-NetIPAddress -InterfaceIndex `$Using:InterfaceIndex -IPAddress `$Using:Server.IPAddress -PrefixLength 24 -DefaultGateway '10.100.100.1'
    }
    Start-Sleep -Seconds 20
    Get-VM -Name `$Server.ServerName | Restart-VM -Force -Wait
    Start-Sleep -Seconds 200
    `$InterfaceIndex = Invoke-Command -VMName `$Server.ServerName -Credential `$Credential -ScriptBlock {(Get-NetAdapter).ifIndex} 
    `$IPCheck = Invoke-Command -VMName `$Server.ServerName -Credential `$Credential -ScriptBlock {Get-NetIPAddress -InterfaceIndex `$Using:InterfaceIndex} 
    if (`$IPCheck.IPAddress[1] -ne `$Server.IPAddress)
    {
        Invoke-Command -VMName `$Server.ServerName -Credential `$Credential -ScriptBlock {
            Set-DnsClientServerAddress -InterfaceIndex `$Using:InterfaceIndex -ServerAddresses 10.100.100.10,8.8.8.8;
            New-NetIPAddress -InterfaceIndex `$Using:InterfaceIndex -IPAddress `$Using:Server.IPAddress -PrefixLength 24 -DefaultGateway '10.100.100.1'
        }
    }
}

New-ADUser -AccountPassword `$Password -UserPrincipalName 'breakglass@azurestack.local' -PasswordNeverExpires:`$true -Name breakglass -Enabled:`$true
`$User = Get-ADUser breakglass
`$Groups = Get-ADGroup -Filter * | Where-Object {`$_.Name -like "*admin*"}
foreach (`$Group in `$Groups)
{
    Add-ADGroupMember -Identity `$Group.Name -Members `$User.Name
}
'@

Add-Content -Path `$PostInstallScript.FullName -Value `$FinalizeAzureStackPOCScript -Force | Set-Content -Force

"@
    $ScriptString = $ScriptString.Replace('[AdminPassword]',"$AdminPassword")

    Invoke-AzVMRunCommand -VMName $VirtualMachineName `
        -ResourceGroupName $LabResourceGroup.ResourceGroupName `
        -CommandId 'RunPowerShellScript' `
        -ScriptString $ScriptString -AsJob | Out-Null
}

$Result = Get-Job | Wait-Job | Receive-Job
$EndTime = (Get-Date)

if (($Result.Value.DisplayStatus | Select-Object -Unique) -ne 'Provisioning succeeded') 
{
    throw 'Failed to Create Script to Finalize the Install!'
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
#endregion

#region Restart Server to begin ASDK Install
Write-host "Now I need to restart the Virtual Machines." -ForegroundColor Yellow
Write-host "This can take up to 5 minutes. Please wait..." -ForegroundColor Yellow
Write-Host ""
$StartTime = (Get-Date)

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-host "$($VirtualMachineName) - Restarting Virtual Machine." -ForegroundColor Green

    Restart-AzVM -ResourceGroupName $LabResourceGroup.ResourceGroupName -Name $VirtualMachineName -AsJob | Out-Null
}

$Result = Get-Job | Wait-Job | Receive-Job

foreach ($PublicIP in $DataTable.Rows.PublicIP)
{
    do 
    {
        $RDPTest = Test-NetConnection -ComputerName $PublicIP -Port 3389
    }
    until ($RDPTest.TcpTestSucceeded -eq $true)
}

$EndTime = (Get-Date)

if ($Result.Status -ne 'Succeeded') 
{
    throw 'Virtual Machines Failed to Restart'
    break
}
else
{
    Write-Host "PowerShell Job $($Result.Status)" -ForegroundColor Green
    Write-Host "StartTime $($StartTime)" -ForegroundColor White
    Write-Host "EndTime $($EndTime)" -ForegroundColor White
    Write-Host $('Duration: {0:mm} min {0:ss} sec' -f ($EndTime - $StartTime)) -ForegroundColor White
    Write-Host ""
}
#endregion

$ScriptEndTime = (Get-Date)

Write-Host "Deployment Jobs are complete." -ForegroundColor Green
Write-Host $('Total Duration: {0:mm} min {0:ss} sec' -f ($ScriptEndTime-$ScriptStartTime)) -ForegroundColor Yellow
Write-Host ''
Write-Host "Depending on the Virtual Machine Sku, it can take 12-18 Hours to complete the ASDK Install." -ForegroundColor Yellow
Write-Host ''
Write-Host "You can connect to the ASDK Virtual Machines using RDP to monitor the progress." -ForegroundColor White
Write-Host "A list of VMs and their Public IPs can be found here:" -ForegroundColor White
Write-Host "$ENV:UserProfile\Documents\$CSVFileName" -ForegroundColor Green
Write-Host ""
Write-Host "Prior to Domain Setup completion, the login UserName will be .\Administrator" -ForegroundColor White
Write-Host "Once the ASDK Domain Setup is complete, the login UserName will be AzureStack\AzureStackAdmin" -ForegroundColor White
Write-Host ""
Write-Host "When the Fabric install is done, run C:\FinalizeServers.ps1 from an elevated PowerShell Console." -ForegroundColor White
Write-Host "That script will put the AD & ADFS VMs back so you can use them." -ForegroundColor White
Write-Host ""
Write-Host ""
Write-Host "Have fun!!" -ForegroundColor White
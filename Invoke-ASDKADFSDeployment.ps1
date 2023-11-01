<#
.SYNOPSIS
    Script to deploy ASDKs in Azure with ADFS.

.DESCRIPTION
    Use this script to deploy ASDKs in Azure that use ADFS for Identity

.EXAMPLE
    .\Invoke-ASDKADFSDeployment.ps1
#>
[CmdletBinding()]
Param
(
    # Provide the full UPN for the Azure Active Directory User for ASDK Registration
	[Parameter(Mandatory=$false,HelpMessage="Provide the full UPN for the Azure Active Directory User for ASDK Registration")]
    [MailAddress]$AADUserName = 'rishilli@missionreadygov.onmicrosoft.com',

    # Provide the Resource Group Name
	[Parameter(Mandatory=$false,HelpMessage="Provide the Resource Group Name")]
    [String]$LabResourceGroupName = 'ASDK-ADFS-RG2',

    # Provide the environment where you will register the ASDK
	[Parameter(Mandatory=$false,HelpMessage="Provide the environment where you will register the ASDK")]
    [String]$AzureEnvironment = 'AzureUSGovernment',

    # Provide the number of Data Disks for the ASDK
	[Parameter(Mandatory=$false,HelpMessage="Provide the number of Data Disks for the ASDK")]
    [Int]$NumberOfDataDisks = '5',

    # Provide the size for the Data Disks
	[Parameter(Mandatory=$false,HelpMessage="Provide the size for the Data Disks")]
    [String]$DataDiskSizeGB = '2048',

    # Provide the DNS Forwarder to be used on the ASDK
	[Parameter(Mandatory=$false,HelpMessage="Provide the DNS Forwarder to be used on the ASDK")]
    [String]$DNSForwarder = '8.8.8.8',

    # Provide a Time Server IP
	[Parameter(Mandatory=$false,HelpMessage="Provide a Time Server IP")]
    [String]$TimeServer = '168.61.215.74',

    # Provide a Virtual Machine Admin Username
	[Parameter(Mandatory=$false,HelpMessage="Provide a Virtual Machine Admin Username")]
    [String]$VirtualMachineAdminUserName = 'VMAdmin',

    # Provide a Virtual Machine Admin Password
	[Parameter(Mandatory=$true,HelpMessage="Provide a Virtual Machine Admin Password")]
    [SecureString]$VirtualMachineAdminPassword,

    # The version of ASDK to be deployed
	[Parameter(Mandatory=$false,HelpMessage="The version of ASDK to be deployed")]
    [ValidateSet('2301','2206','2108')]
    [String]$ASDKVersion = '2301',

    # The Virtual Machine Name Prefix
    [Parameter(Mandatory=$false,HelpMessage="The Virtual Machine Name Prefix")]
    [String]$VirtualMachineNamePrefix = 'HUB',

    [Parameter(Mandatory=$false,HelpMessage="Provide the count of ASDKs to Deploy")]
    [Int]$VirtualMachineCount = '1',

    [Parameter(Mandatory=$false,HelpMessage="Select the Virtual Machine SKU Size.")]
    [String]$VirtualMachineSize = 'Standard_E16s_v3',

    [Parameter(Mandatory=$false,HelpMessage="Provide a DNS Prefix for the Public IP")]
    [String]$DNSPrefixForPublicIP = 'vaasdk-',

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

$ASDKLinkUri = "https://asdkdeploymentsa.blob.core.usgovcloudapi.net/asdks/$ASDKVersion/CloudBuilder.vhdx"
$SourceAddressForRDP = ((Invoke-WebRequest -uri “https://api.ipify.org/”).Content + '/32')
#$VirtualMachineAdminPassword = ConvertTo-SecureString -String '!A@S3d4f5g6h7j8k' -AsPlainText -Force

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

#region Create Resource Group
$LabResourceGroup = Get-AzResourceGroup -Name $LabResourceGroupName -Location $Location.Location -ErrorAction SilentlyContinue
If (!($LabResourceGroup))
{
    $LabResourceGroup = New-AzResourceGroup -Name $LabResourceGroupName -Location $Location.Location
}
#endregion

#region Template Deployment
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

$Deployment = New-AzResourceGroupDeployment -Name ASDKDeployment `
    -ResourceGroupName $LabResourceGroup.ResourceGroupName `
    -TemplateFile 'C:\Git\Deploy-ASDK-ADFS\azuredeploy.json' `
    -TemplateParameterObject $TemplateParams -Mode Incremental -DeploymentDebugLogLevel All

$DeployedVirtualMachines = $Deployment.Outputs.Values.value
#endregion

#region Configure Virtual Machine, Disks, Copy Setup Files from Azure Storage & Restart
foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-host "$($VirtualMachineName) - Configuring VM Disks. Please wait..." -ForegroundColor Green

$ScriptString = @"
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

    $Job = Invoke-AzVMRunCommand -VMName $VirtualMachineName `
        -ResourceGroupName $LabResourceGroup.ResourceGroupName `
        -CommandId 'RunPowerShellScript' `
        -ScriptString $ScriptString -AsJob

    Get-Job | Wait-Job

    Write-host "$($VirtualMachineName) - Downloading Setup files from Azure Storage. This may take some time. Please wait..." -ForegroundColor Green
$ScriptString = @"
`$InstallFilesDirectory = New-Item -Path C:\ -Name SetupFiles -ItemType Directory -Force;
Invoke-WebRequest -UseBasicParsing -Uri 'https://aka.ms/downloadazcopy-v10-windows' -OutFile "`$(`$InstallFilesDirectory.FullName)\azcopy.zip";
Expand-Archive -Path "`$(`$InstallFilesDirectory.FullName)\azcopy.zip" -DestinationPath "`$(`$InstallFilesDirectory.FullName)\azcopy";
`$AzCopyFile = Get-ChildItem "`$(`$InstallFilesDirectory.FullName)\azcopy" -Recurse -Include *.exe;
Copy-Item -Path `$AzCopyFile.FullName -Destination 'C:\Windows\System32' -Force;
Remove-Item "$($InstallFilesDirectory.FullName)\azcopy" -Force -Recurse;
Remove-Item "$($InstallFilesDirectory.FullName)\azcopy.zip" -Force;
azcopy copy $ASDKLinkUri "`$(`$InstallFilesDirectory.FullName)\CloudBuilder.vhdx";
azcopy copy 'https://asdkdeploymentsa.blob.core.usgovcloudapi.net/vhds/2019Server.vhd' "`$(`$InstallFilesDirectory.FullName)\2019Server.vhd";
azcopy copy 'https://asdkdeploymentsa.blob.core.usgovcloudapi.net/software' `$(`$InstallFilesDirectory.FullName) --recursive=true;
"@

    $Job = Invoke-AzVMRunCommand -VMName $VirtualMachineName `
        -ResourceGroupName $LabResourceGroup.ResourceGroupName `
        -CommandId 'RunPowerShellScript' `
        -ScriptString $ScriptString -AsJob

    Get-Job -Id $Job.Id | Wait-Job -Verbose

    Write-host "$($VirtualMachineName) - Restarting Virtual Machine. Please wait..." -ForegroundColor Green
    $Job = Restart-AzVM -ResourceGroupName $LabResourceGroup.ResourceGroupName -Name $VirtualMachineName -AsJob
    Get-Job -Id $Job.Id | Wait-Job -Verbose
}
#endregion

#region Prepare Virtual Machine Boot VHD & Configure OOBe Setup
foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Preparing Virtual Machine VHDs and Configuring it for VHD Boot." -ForegroundColor Green
    Write-Host "$($VirtualMachineName) - This will take a bit of time. Just relax...." -ForegroundColor Yellow

    $AdminPassword = ConvertFrom-SecureStringToPlainText -SecurePassword $VirtualMachineAdminPassword

$ScriptString = @"
Import-Module Hyper-V

Convert-VHD -Path "C:\SetupFiles\CloudBuilder.vhdx" -VHDType Fixed -DestinationPath "C:\SetupFiles\ASDK.vhdx" -DeleteSource -ErrorAction Stop

Resize-VHD -Path "C:\SetupFiles\ASDK.vhdx" -SizeBytes 650gb

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
Write-Host "Addiing bootfiles to OS"
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

    $Job = Invoke-AzVMRunCommand -VMName $VirtualMachineName `
        -ResourceGroupName $LabResourceGroup.ResourceGroupName `
        -CommandId 'RunPowerShellScript' `
        -ScriptString $ScriptString -AsJob

    Get-Job -Id $Job.Id | Wait-Job -Verbose

    Write-host "$($VirtualMachineName) - Restarting Virtual Machine. Please wait..." -ForegroundColor Green
    $Job = Restart-AzVM -ResourceGroupName $LabResourceGroup.ResourceGroupName -Name $VirtualMachineName -AsJob
    Get-Job -Id $Job.Id | Wait-Job -Verbose
}
#endregion

#region resize OS Disk & Install Software
foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Resizing the OS Disk and Installing Software." -ForegroundColor Green

$ScriptString = @'
$Partition = Get-Partition -DriveLetter C
$Size = (Get-PartitionSupportedSize -DiskNumber $Partition.DiskNumber -PartitionNumber $Partition.PartitionNumber)
Resize-Partition -DiskNumber $Partition.DiskNumber -PartitionNumber $Partition.PartitionNumber -Size $Size.SizeMax

#Install Edge Browser
$EdgeBrowser = Get-ChildItem -Path E:\SetupFiles\software -Filter *MicrosoftEdgeEnterprise*.msi
Start-Process msiexec.exe -ArgumentList "/i $($EdgeBrowser.FullName) /quiet" -Wait

#Install VSCode
$VSCodeSetup = Get-ChildItem -Path E:\SetupFiles\software -Filter *VSCodeSetup*.exe
$installerArguments = "/silent /mergetasks='!runcode,addcontextmenufiles,addcontextmenufolders,associatewithfiles,addtopath'"
Start-Process $($VSCodeSetup.FullName) -ArgumentList $installerArguments -Wait
'@

    $Job = Invoke-AzVMRunCommand -VMName $VirtualMachineName `
        -ResourceGroupName $LabResourceGroup.ResourceGroupName `
        -CommandId 'RunPowerShellScript' `
        -ScriptString $ScriptString -AsJob

    Get-Job -Id $Job.Id | Wait-Job -Verbose

}
#endregion

#region Create AD,CA & ADFS Virtual Machines
foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Configuring Hyper-V." -ForegroundColor Green

$ScriptString = @'
[CmdletBinding()]
Param
(
    $VirtualMachinePassword
)

$VerbosePreference = 'Continue'

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

New-VMSwitch -SwitchType Internal -Name 'ADSwitch' -Verbose
$InterfaceIndex = $((Get-NetAdapter | Where-Object {$_.Name -like "*ADSwitch*"} | Select-Object ifIndex).ifIndex)
New-NetIPAddress -IPAddress '10.100.100.1' -PrefixLength '24' -InterfaceIndex $InterfaceIndex

$Servers = @(
    @{ServerName = 'AD-01';IPAddress = '10.100.100.10'}
    @{ServerName = 'ADFS-01';IPAddress = '10.100.100.11'}
)

$AdminPassword = ConvertFrom-SecureStringToPlainText -SecurePassword $VirtualMachinePassword -ErrorAction 'Stop'
$Username = '.\Administrator'
$LocalCredential = New-Object System.Management.Automation.PSCredential($Username,$VirtualMachinePassword)

$Username = 'Contoso\Administrator'
$DomainCredential = New-Object System.Management.Automation.PSCredential($Username,$VirtualMachinePassword)

$VMDisksDirectory = New-Item -Path C:\ -Name VMDisks -ItemType Directory -Force  -Verbose

Foreach ($Server in $Servers)
{
    Copy-Item -Path E:\SetupFiles\2019Server.vhd -Destination $VMDisksDirectory.FullName -Verbose
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
"@


$U_Unattend.unattend.AppendChild($U_Unattend.ImportNode($U_Unattend_oobeSysten_AdminPassword.unattend.settings, $true))
$U_Unattend.OuterXml | Out-File ($Prepare_Vhdx_DriveLetter+":\unattend.xml") -Encoding ascii -Force

    Dismount-DiskImage -ImagePath $Prepare_Vhdx_Path -Verbose
}

Foreach ($Server in $Servers)
{
    New-VM -Name $Server.ServerName -BootDevice VHD -VHDPath ('C:\VMDisks\' + $Server.ServerName + '.vhd') -MemoryStartupBytes 4GB -SwitchName 'ADSwitch'
    Set-VMProcessor -VMName $Server.ServerName -count 2
    Start-VM -Name $Server.ServerName
    Start-Sleep -Seconds 120
    $InterfaceIndex = Invoke-Command -VMName $Server.ServerName -Credential $LocalCredential -ScriptBlock {(Get-NetAdapter).ifIndex}
    Invoke-Command -VMName $Server.ServerName -Credential $LocalCredential -ScriptBlock {
        Set-DnsClientServerAddress -InterfaceIndex $Using:InterfaceIndex -ServerAddresses 10.100.100.10,8.8.8.8;
        New-NetIPAddress -InterfaceIndex $Using:InterfaceIndex -IPAddress $Using:Server.IPAddress -PrefixLength 24 -DefaultGateway '10.100.100.1'
    }
    Start-Sleep -Seconds 20
    Get-VM -Name $Server.ServerName | Restart-VM -Force -Wait
    Start-Sleep -Seconds 120
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

#Configure AD CS
Invoke-Command -VMName 'AD-01' -Credential $LocalCredential -ScriptBlock {Install-WindowsFeature AD-Domain-Services -IncludeManagementTools} -Verbose
Invoke-Command -VMName 'AD-01' -Credential $LocalCredential -ScriptBlock {
Install-ADDSForest -DomainName "contoso.local" `
    -InstallDNS `
    -SafeModeAdministratorPassword $Using:VirtualMachineAdminPassword `
    -DomainNetbiosName Contoso -Force
}
Start-Sleep -Seconds 200
Invoke-Command -VMName 'AD-01' -Credential $DomainCredential -ScriptBlock {Install-WindowsFeature ADCS-Cert-Authority} -Verbose
Invoke-Command -VMName 'AD-01' -Credential $DomainCredential -ScriptBlock {Install-WindowsFeature RSAT-ADCS-Mgmt} -Verbose
Invoke-Command -VMName 'AD-01' -Credential $DomainCredential -ScriptBlock {
$params = @{
    CAType              = 'EnterpriseRootCa'
    CryptoProviderName  = "RSA#Microsoft Software Key Storage Provider"
    KeyLength           = '4096'
    HashAlgorithmName   = 'SHA256'
    ValidityPeriod      = 'Years'
    ValidityPeriodUnits = '3'
}
Install-AdcsCertificationAuthority @params -Force
}


Invoke-Command -VMName 'AD-01' -Credential $DomainCredential -ScriptBlock {
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
$templateDE.Dispose()

Add-CATemplate -Name "AzureStack" -Force
} -Verbose

winrm s winrm/config/client '@{TrustedHosts="*"}'
$ADSession = New-PSSession -ComputerName 'AD-01' -Credential $DomainCredential
Copy-Item E:\SetupFiles\software\HubModules.zip -Destination C:\ -ToSession $ADSession
Copy-Item E:\SetupFiles\software\Scripts.zip -Destination C:\ -ToSession $ADSession
Invoke-Command -VMName 'AD-01' -Credential $DomainCredential -ScriptBlock {
Expand-Archive -Path "C:\HubModules.zip" -DestinationPath "$env:ProgramFiles\WindowsPowerShell\Modules" -Force
Expand-Archive -Path "C:\Scripts.zip" -DestinationPath "C:\Scripts" -Force
}

# Configure ADFS
Invoke-Command -VMName 'ADFS-01' -Credential $LocalCredential -ScriptBlock {Add-Computer -DomainName 'Contoso.local' -Credential $Using:DomainCredential -Restart} -Verbose
'@

    $Job = Invoke-AzVMRunCommand -VMName $VirtualMachineName `
        -ResourceGroupName $LabResourceGroup.ResourceGroupName `
        -CommandId 'RunPowerShellScript' `
        -ScriptString $ScriptString -Parameter @{VirtualMachinePassword = $VirtualMachineAdminPassword}

    Get-Job -Id $Job.Id | Wait-Job -Verbose
}
#endregion

#region Generate Deployment Certificates
foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
$ScriptString = @'
[CmdletBinding()]
Param
(
    $VirtualMachinePassword
)

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

$AdminPassword = ConvertFrom-SecureStringToPlainText -SecurePassword $VirtualMachinePassword
$Username = '.\Administrator'
$LocalCredential = New-Object System.Management.Automation.PSCredential($Username,$VirtualMachinePassword)

$Username = 'Contoso\Administrator'
$DomainCredential = New-Object System.Management.Automation.PSCredential($Username,$VirtualMachinePassword)

winrm s winrm/config/client '@{TrustedHosts="*"}'
$ADSession = New-PSSession -ComputerName 'AD-01' -Credential $DomainCredential
Copy-Item E:\SetupFiles\software\HubModules.zip -Destination C:\ -ToSession $ADSession
Copy-Item E:\SetupFiles\software\Scripts.zip -Destination C:\ -ToSession $ADSession
Invoke-Command -VMName 'AD-01' -Credential $DomainCredential -ScriptBlock {
    Expand-Archive -Path "C:\HubModules.zip" -DestinationPath "$env:ProgramFiles\WindowsPowerShell\Modules" -Force
    Expand-Archive -Path "C:\Scripts.zip" -DestinationPath "C:\Scripts" -Force
}

# Configure ADFS
Invoke-Command -VMName 'ADFS-01' -Credential $LocalCredential -ScriptBlock {Add-Computer -DomainName 'Contoso.local' -Credential $Using:DomainCredential -Restart} -Verbose



'@


}








Add-DnsServerConditionalForwarderZone -MasterServers '10.100.100.10' -Name 'contoso.local'

Invoke-Command -VMName 'AD-01' -Credential $DomainCredential -ScriptBlock {
    if (!(Test-Path 'C:\AzureStackCerts\REQ'))
    {
        New-Item -ItemType Directory -Path 'C:\AzureStackCerts\REQ' -Force
    }

    Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""C:\Scripts\Create-AzSHubDeploymentCertRequests.ps1""' -Verb RunAs -Wait
}

Invoke-Command -VMName 'AD-01' -Credential $DomainCredential -ScriptBlock {
    if (!(Test-Path C:\AzureStackCerts\CER))
    {
        New-Item -ItemType Directory -Path 'C:\AzureStackCerts\CER' -Force
    }

    Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""C:\Scripts\Submit-AzSHubCertRequests.ps1""' -Verb RunAs -Wait
}

Invoke-Command -VMName 'AD-01' -Credential $DomainCredential -ScriptBlock {
    if (!(Test-Path 'C:\AzureStackCerts\PFX'))
    {
        New-Item -ItemType Directory -Path 'C:\AzureStackCerts\PFX' -Force
    }

    Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""C:\Scripts\Prepare-AzSHubCertificates.ps1""' -Verb RunAs -Wait
}

Remove-Item -Path 'C:\CloudDeployment\Setup\Certificates\ADFS' -Recurse -Force
winrm s winrm/config/client '@{TrustedHosts="*"}'
$ADSession = New-PSSession -ComputerName '10.100.100.10' -Credential $Credential
Copy-Item -FromSession $ADSession -Path 'C:\AzureStackCerts\PFX\local.azurestack.external\Deployment' -Destination 'C:\CloudDeployment\Setup\Certificates\ADFS' -Force -Recurse -Container
Remove-PSSession $ADSession

Copy-Item -Path 'E:\ASDK_Setup\Setup\InstallFiles\InstallAzureStackPOC.ps1' -Destination 'C:\CloudDeployment\Setup' -Force

Get-vm | Stop-VM -Force
Get-vm | Remove-VM -Force
Get-NetAdapter | Where-Object {$_.Name -like "*ADSwitch*"} | Disable-NetAdapter -Confirm:$false
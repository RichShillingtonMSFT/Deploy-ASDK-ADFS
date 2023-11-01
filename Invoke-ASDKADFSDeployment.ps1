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

Write-Host "Connected to Azure" -ForegroundColor Green

#region Create Resource Group
$LabResourceGroup = Get-AzResourceGroup -Name $LabResourceGroupName -Location $Location.Location -ErrorAction SilentlyContinue
If (!($LabResourceGroup))
{
    $LabResourceGroup = New-AzResourceGroup -Name $LabResourceGroupName -Location $Location.Location
}
Write-Host "Resource Group $LabResourceGroupName is ready" -ForegroundColor Green
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

Write-Host "Starting Template Deployment" -ForegroundColor Green
$StartTime = Get-Date -DisplayHint Time
$Deployment = New-AzResourceGroupDeployment -Name ASDKDeployment `
    -ResourceGroupName $LabResourceGroup.ResourceGroupName `
    -TemplateUri 'https://raw.githubusercontent.com/RichShillingtonMSFT/Deploy-ASDK-ADFS/main/azuredeploy.json' `
    -TemplateParameterObject $TemplateParams -Mode Incremental

$EndTime = Get-Date -DisplayHint Time
$DeployedVirtualMachines = $Deployment.Outputs.Values.value
Write-Host "Template Deployment Complete" -ForegroundColor Green
Write-Host "Start Time $($StartTime)" -ForegroundColor White
Write-Host "End Time $($EndTime)" -ForegroundColor White
#endregion

#region Configure Virtual Machine Disks
Write-host "I am now going to configure the Virtual Machine Disks & Install Hyper-V." -ForegroundColor Yellow
Write-host "This takes about 5 minutes. Please wait..." -ForegroundColor Yellow

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-host "$($VirtualMachineName) - Configure the Virtual Machine Disks & Install Hyper-V." -ForegroundColor Green

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

    try
    {
        $StartTime = Get-Date -DisplayHint Time

        $Job = Invoke-AzVMRunCommand -VMName $VirtualMachineName `
            -ResourceGroupName $LabResourceGroup.ResourceGroupName `
            -CommandId 'RunPowerShellScript' `
            -ScriptString $ScriptString -AsJob

        $Result = Get-Job -Id $Job.Id | Wait-Job | Receive-Job

        $EndTime = Get-Date -DisplayHint Time

        if ($Result.Value.Message -like "*error*") 
        {
            throw $($Error[0])
        }
        else
        {
            Write-Host "PowerShell Job $($Result.Status)" -ForegroundColor Green
            Write-Host "$($Result.Value.Message)" -ForegroundColor Green
            Write-Host "StartTime $($StartTime)" -ForegroundColor White
            Write-Host "EndTime $($EndTime)" -ForegroundColor White
            
        }
    }
    catch
    {
        Write-Host "Job Failed: `n $($Result.Value.Message)" -ForegroundColor Red
        Write-Host "Error while running the PowerShell Job" -ForegroundColor Red
    }
}
#endregion

#region Copy Setup Files from Azure Storage
Write-host "I am now going to Downloading Setup files from Azure Storage." -ForegroundColor Yellow
Write-host "This takes about 5 minutes. Please wait..." -ForegroundColor Yellow

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-host "$($VirtualMachineName) - Downloading Setup files from Azure Storage." -ForegroundColor Green

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
'@

    try
    {
        $ScriptString = $ScriptString.Replace('[ASDKLinkUri]',"$ASDKLinkUri")

        $StartTime = Get-Date -DisplayHint Time

        $Job = Invoke-AzVMRunCommand -VMName $VirtualMachineName `
            -ResourceGroupName $LabResourceGroup.ResourceGroupName `
            -CommandId 'RunPowerShellScript' `
            -ScriptString $ScriptString -AsJob

        $Result = Get-Job -Id $Job.Id | Wait-Job | Receive-Job

        $EndTime = Get-Date -DisplayHint Time

        if ($Result.Value.Message -like "*error*") 
        {
            throw $($Error[0])
        }
        else
        {
            Write-Host "PowerShell Job $($Result.Status)" -ForegroundColor Green
            Write-Host "$($Result.Value.Message)" -ForegroundColor Green
            Write-Host "StartTime $($StartTime)" -ForegroundColor White
            Write-Host "EndTime $($EndTime)" -ForegroundColor White
            
        }
    }
    catch
    {
        Write-Host "Job Failed: `n $($Result.Value.Message)" -ForegroundColor Red
        Write-Host "Error while running the PowerShell Job" -ForegroundColor Red
    }
}
#endregion

#region Restart Virtual Machines
Write-host "Now I need to restart the Virtual Machines." -ForegroundColor Yellow
Write-host "This takes about 2 minutes. Please wait..." -ForegroundColor Yellow

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-host "$($VirtualMachineName) - Restarting Virtual Machine." -ForegroundColor Green
    try
    {
        $StartTime = Get-Date -DisplayHint Time

        $Job = Restart-AzVM -ResourceGroupName $LabResourceGroup.ResourceGroupName -Name $VirtualMachineName -AsJob

        $Result = Get-Job -Id $Job.Id | Wait-Job | Receive-Job

        $EndTime = Get-Date -DisplayHint Time

        if ($Result.Value.Message -like "*error*") 
        {
            throw $($Error[0])
        }
        else
        {
            Write-Host "PowerShell Job $($Result.Status)" -ForegroundColor Green
            Write-Host "$($Result.Value.Message)" -ForegroundColor Green
            Write-Host "StartTime $($StartTime)" -ForegroundColor White
            Write-Host "EndTime $($EndTime)" -ForegroundColor White
            
        }
    }
    catch
    {
        Write-Host "Job Failed: `n $($Result.Value.Message)" -ForegroundColor Red
        Write-Host "Error while running the PowerShell Job" -ForegroundColor Red
    }
}
#endregion

#region Prepare Virtual Machine Boot VHD & Configure OOBe Setup
Write-Host "Now it is time to prepare the Virtual Machine VHDs and Configure the VM to boot from a VHD." -ForegroundColor Yellow
Write-Host "Depending on Disk Speed, this can take a few minutes. Just relax...." -ForegroundColor Yellow

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Preparing Virtual Machine VHDs and Configuring it for VHD Boot." -ForegroundColor Green

$ScriptString = @"
Import-Module Hyper-V

#Convert-VHD -Path "C:\SetupFiles\CloudBuilder.vhdx" -VHDType Fixed -DestinationPath "C:\SetupFiles\ASDK.vhdx" -DeleteSource -ErrorAction Stop
Rename-Item -Path C:\SetupFiles\CloudBuilder.vhdx -NewName ASDK.vhdx -Force
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

    try
    {
        $StartTime = Get-Date -DisplayHint Time

        $Job = Invoke-AzVMRunCommand -VMName $VirtualMachineName `
            -ResourceGroupName $LabResourceGroup.ResourceGroupName `
            -CommandId 'RunPowerShellScript' `
            -ScriptString $ScriptString -AsJob

        $Result = Get-Job -Id $Job.Id | Wait-Job | Receive-Job

        $EndTime = Get-Date -DisplayHint Time

        if ($Result.Value.Message -like "*error*") 
        {
            throw $($Error[0])
        }
        else
        {
            Write-Host "PowerShell Job $($Result.Status)" -ForegroundColor Green
            Write-Host "$($Result.Value.Message)" -ForegroundColor Green
            Write-Host "StartTime $($StartTime)" -ForegroundColor White
            Write-Host "EndTime $($EndTime)" -ForegroundColor White
            
        }
    }
    catch
    {
        Write-Host "Job Failed: `n $($Result.Value.Message)" -ForegroundColor Red
        Write-Host "Error while running the PowerShell Job" -ForegroundColor Red
    }
}
#endregion

#region Restart Virtual Machines
Write-host "Now I need to restart the Virtual Machines." -ForegroundColor Yellow
Write-host "This takes about 2 minutes. Please wait..." -ForegroundColor Yellow

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-host "$($VirtualMachineName) - Restarting Virtual Machine." -ForegroundColor Green
    try
    {
        $StartTime = Get-Date -DisplayHint Time

        $Job = Restart-AzVM -ResourceGroupName $LabResourceGroup.ResourceGroupName -Name $VirtualMachineName -AsJob

        $Result = Get-Job -Id $Job.Id | Wait-Job | Receive-Job

        $EndTime = Get-Date -DisplayHint Time

        if ($Result.Value.Message -like "*error*") 
        {
            throw $($Error[0])
        }
        else
        {
            Write-Host "PowerShell Job $($Result.Status)" -ForegroundColor Green
            Write-Host "$($Result.Value.Message)" -ForegroundColor Green
            Write-Host "StartTime $($StartTime)" -ForegroundColor White
            Write-Host "EndTime $($EndTime)" -ForegroundColor White
            
        }
    }
    catch
    {
        Write-Host "Job Failed: `n $($Result.Value.Message)" -ForegroundColor Red
        Write-Host "Error while running the PowerShell Job" -ForegroundColor Red
    }
}
#endregion

Write-host "Now we need to wait a few minutes for the Virtual Machines to complete setup..." -ForegroundColor Yellow
Write-host "This takes about 7-10 minutes. Please wait..." -ForegroundColor Yellow
Start-Sleep -Seconds 500

#region resize OS Disk & Install Software
Write-Host "Now I will expand the OS Disk and Install some additional Software." -ForegroundColor Yellow
Write-host "This takes about 5-10 minutes. Please wait..." -ForegroundColor Yellow

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
$installerArguments = '/verysilent /tasks=addcontextmenufiles,addcontextmenufolders,addtopath'
Start-Process $($VSCodeSetup.FullName) -ArgumentList $installerArguments -Wait
#$Extensions = Get-ChildItem -Path 'E:\SetupFiles\software\VSCodeExtensions'
#foreach ($Extension in $Extensions) 
#{
#    & "C:\Program Files\Microsoft VS Code\Code.exe" --install-extension $Extension
#}

'@

    try 
    {
        $StartTime = Get-Date -DisplayHint Time

        $Job = Invoke-AzVMRunCommand -VMName $VirtualMachineName `
            -ResourceGroupName $LabResourceGroup.ResourceGroupName `
            -CommandId 'RunPowerShellScript' `
            -ScriptString $ScriptString -AsJob

        $Result = Get-Job -Id $Job.Id | Wait-Job | Receive-Job

        $EndTime = Get-Date -DisplayHint Time

        if ($Result.Value.Message -like "*error*") 
        {
            throw $($Error[0])
        }
        else
        {
            Write-Host "PowerShell Job $($Result.Status)" -ForegroundColor Green
            Write-Host "$($Result.Value.Message)" -ForegroundColor Green
            Write-Host "StartTime $($StartTime)" -ForegroundColor White
            Write-Host "EndTime $($EndTime)" -ForegroundColor White
            
        }
    }
    catch
    {
        Write-Host "Job Failed: `n $($Result.Value.Message)" -ForegroundColor Red
        Write-Host "Error while running the PowerShell Job" -ForegroundColor Red
    }
}
#endregion

#region Create AD,CA & ADFS Virtual Machines
Write-Host "Now I must Configure the Hyper-V host and setup the Domain Controller, Certificate Services & ADFS" -ForegroundColor Yellow
Write-host "This takes about 35 minutes. I am doing lots of work for you. Settle Down..." -ForegroundColor Yellow

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Configuring Hyper-V to host the Domain Controller/Certificate Services & ADFS" -ForegroundColor Green

$ScriptString = @'

$VerbosePreference = 'Continue'

New-VMSwitch -SwitchType Internal -Name 'ADSwitch' -Verbose
$InterfaceIndex = $((Get-NetAdapter | Where-Object {$_.Name -like "*ADSwitch*"} | Select-Object ifIndex).ifIndex)
New-NetIPAddress -IPAddress '10.100.100.1' -PrefixLength '24' -InterfaceIndex $InterfaceIndex

$Servers = @(
    @{ServerName = 'AD-01';IPAddress = '10.100.100.10'}
    @{ServerName = 'ADFS-01';IPAddress = '10.100.100.11'}
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
    New-VM -Name $Server.ServerName -BootDevice VHD -VHDPath ('C:\VMDisks\' + $Server.ServerName + '.vhd') -MemoryStartupBytes 4GB -SwitchName 'ADSwitch'
    Set-VMProcessor -VMName $Server.ServerName -count 2
    Start-VM -Name $Server.ServerName
    Start-Sleep -Seconds 160
    $InterfaceIndex = Invoke-Command -VMName $Server.ServerName -Credential $LocalCredential -ScriptBlock {(Get-NetAdapter).ifIndex}
    Invoke-Command -VMName $Server.ServerName -Credential $LocalCredential -ScriptBlock {
        Set-DnsClientServerAddress -InterfaceIndex $Using:InterfaceIndex -ServerAddresses 10.100.100.10,8.8.8.8;
        New-NetIPAddress -InterfaceIndex $Using:InterfaceIndex -IPAddress $Using:Server.IPAddress -PrefixLength 24 -DefaultGateway '10.100.100.1'
    }
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
    
    try 
    {
        $StartTime = Get-Date -DisplayHint Time

        $Job = Invoke-AzVMRunCommand -VMName $VirtualMachineName `
            -ResourceGroupName $LabResourceGroup.ResourceGroupName `
            -CommandId 'RunPowerShellScript' `
            -ScriptString $ScriptString -AsJob

        $Result = Get-Job -Id $Job.Id | Wait-Job | Receive-Job

        $EndTime = Get-Date -DisplayHint Time

        if ($Result.Value.Message -like "*error*") 
        {
            throw $($Error[0])
        }
        else
        {
            Write-Host "PowerShell Job $($Result.Status)" -ForegroundColor Green
            Write-Host "$($Result.Value.Message)" -ForegroundColor Green
            Write-Host "StartTime $($StartTime)" -ForegroundColor White
            Write-Host "EndTime $($EndTime)" -ForegroundColor White
        }
    }
    catch
    {
        Write-Host "Job Failed: `n $($Result.Value.Message)" -ForegroundColor Red
        Write-Host "Error while running the PowerShell Job" -ForegroundColor Red
    }
}
#endregion

#region Install Active Directory and Configure Certificate Services
foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Installing Active Directory and Certificate Services" -ForegroundColor Green

$ScriptString = @'
#Configure AD CS

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

Start-Sleep -Seconds 600

Invoke-Command -VMName 'AD-01' -Credential $DomainCredential -ScriptBlock {Install-WindowsFeature ADCS-Cert-Authority} -Verbose
Invoke-Command -VMName 'AD-01' -Credential $DomainCredential -ScriptBlock {Install-WindowsFeature RSAT-ADCS-Mgmt} -Verbose
Invoke-Command -VMName 'AD-01' -Credential $DomainCredential -ScriptBlock {
    $params = @{
        CAType              = 'EnterpriseRootCa'
        CryptoProviderName  = 'RSA#Microsoft Software Key Storage Provider'
        KeyLength           = '4096'
        HashAlgorithmName   = 'SHA256'
        ValidityPeriod      = 'Years'
        ValidityPeriodUnits = '3'
    }
    Install-AdcsCertificationAuthority @params -Force
}

Start-Sleep -Seconds 120

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
$templateDE.RefreshCache()

Start-Sleep -Seconds 30

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

Start-Sleep -Seconds 120

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

    $ScriptString = $ScriptString.Replace('[AdminPassword]',"$AdminPassword")

    try 
    {
        $StartTime = Get-Date -DisplayHint Time

        $Job = Invoke-AzVMRunCommand -VMName $VirtualMachineName `
            -ResourceGroupName $LabResourceGroup.ResourceGroupName `
            -CommandId 'RunPowerShellScript' `
            -ScriptString $ScriptString -AsJob

        $Result = Get-Job -Id $Job.Id | Wait-Job | Receive-Job

        $EndTime = Get-Date -DisplayHint Time

        if ($Result.Value.Message -like "*error*") 
        {
            throw $($Error[0])
        }
        else
        {
            Write-Host "PowerShell Job $($Result.Status)" -ForegroundColor Green
            Write-Host "$($Result.Value.Message)" -ForegroundColor Green
            Write-Host "StartTime $($StartTime)" -ForegroundColor White
            Write-Host "EndTime $($EndTime)" -ForegroundColor White
        }
    }
    catch
    {
        Write-Host "Job Failed: `n $($Result.Value.Message)" -ForegroundColor Red
        Write-Host "Error while running the PowerShell Job" -ForegroundColor Red
    }
}
#endregion

#region Generate Deployment Certificates
foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
   Write-Host "$($VirtualMachineName) - Generating the Azure Stack Deployment Certificates." -ForegroundColor Green

$ScriptString = @'
$VirtualMachinePassword = ConvertTo-SecureString -String '[AdminPassword]' -AsPlainText -Force

$Username = '.\Administrator'
$LocalCredential = New-Object System.Management.Automation.PSCredential($Username,$VirtualMachinePassword)

$Username = 'Contoso\Administrator'
$DomainCredential = New-Object System.Management.Automation.PSCredential($Username,$VirtualMachinePassword)

Invoke-Command -VMName 'AD-01' -Credential $DomainCredential -ScriptBlock {

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

Invoke-Command -VMName 'AD-01' -Credential $DomainCredential -ScriptBlock {
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

Invoke-Command -VMName 'AD-01' -Credential $DomainCredential -ScriptBlock {
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

    try
    {
        $StartTime = Get-Date -DisplayHint Time

        $Job = Invoke-AzVMRunCommand -VMName $VirtualMachineName `
            -ResourceGroupName $LabResourceGroup.ResourceGroupName `
            -CommandId 'RunPowerShellScript' `
            -ScriptString $ScriptString -AsJob

        $Result = Get-Job -Id $Job.Id | Wait-Job | Receive-Job

        $EndTime = Get-Date -DisplayHint Time

        if ($Result.Value.Message -like "*error*") 
        {
            throw $($Error[0])
        }
        else
        {
            Write-Host "PowerShell Job $($Result.Status)" -ForegroundColor Green
            Write-Host "$($Result.Value.Message)" -ForegroundColor Green
            Write-Host "StartTime $($StartTime)" -ForegroundColor White
            Write-Host "EndTime $($EndTime)" -ForegroundColor White
        }
    }
    catch
    {
        Write-Host "Job Failed: `n $($Result.Value.Message)" -ForegroundColor Red
        Write-Host "Error while running the PowerShell Job" -ForegroundColor Red
    }
}
#endregion

#region Copy Deployment Certificates
foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Copying the Azure Stack Deployment Certificates." -ForegroundColor Green

$ScriptString = @'
$VirtualMachinePassword = ConvertTo-SecureString -String '[AdminPassword]' -AsPlainText -Force
$Username = 'Contoso\Administrator'
$DomainCredential = New-Object System.Management.Automation.PSCredential($Username,$VirtualMachinePassword)

Remove-Item -Path 'C:\CloudDeployment\Setup\Certificates\ADFS' -Recurse -Force
winrm s winrm/config/client '@{TrustedHosts="*"}'
$ADSession = New-PSSession -ComputerName '10.100.100.10' -Credential $DomainCredential
Copy-Item -FromSession $ADSession -Path 'C:\AzureStackCerts\PFX\local.azurestack.external\Deployment' -Destination 'C:\CloudDeployment\Setup\Certificates\ADFS' -Force -Recurse -Container
Remove-PSSession $ADSession
'@

    $ScriptString = $ScriptString.Replace('[AdminPassword]',"$AdminPassword")

    try
    {
        $StartTime = Get-Date -DisplayHint Time

        $Job = Invoke-AzVMRunCommand -VMName $VirtualMachineName `
            -ResourceGroupName $LabResourceGroup.ResourceGroupName `
            -CommandId 'RunPowerShellScript' `
            -ScriptString $ScriptString -AsJob

        $Result = Get-Job -Id $Job.Id | Wait-Job | Receive-Job

        $EndTime = Get-Date -DisplayHint Time

        if ($Result.Value.Message -like "*error*") 
        {
            throw $($Error[0])
        }
        else
        {
            Write-Host "PowerShell Job $($Result.Status)" -ForegroundColor Green
            Write-Host "$($Result.Value.Message)" -ForegroundColor Green
            Write-Host "StartTime $($StartTime)" -ForegroundColor White
            Write-Host "EndTime $($EndTime)" -ForegroundColor White
        }
    }
    catch
    {
        Write-Host "Job Failed: `n $($Result.Value.Message)" -ForegroundColor Red
        Write-Host "Error while running the PowerShell Job" -ForegroundColor Red
    }
}
#endregion

#region Create Azure Stack Deployment Script
foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Creating the Azure Stack Deployment Script." -ForegroundColor Green

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

    try
    {
        $StartTime = Get-Date -DisplayHint Time

        $Job = Invoke-AzVMRunCommand -VMName $VirtualMachineName `
            -ResourceGroupName $LabResourceGroup.ResourceGroupName `
            -CommandId 'RunPowerShellScript' `
            -ScriptString $ScriptString -AsJob

        $Result = Get-Job -Id $Job.Id | Wait-Job | Receive-Job

        $EndTime = Get-Date -DisplayHint Time

        if ($Result.Value.Message -like "*error*") 
        {
            throw $($Error[0])
        }
        else
        {
            Write-Host "PowerShell Job $($Result.Status)" -ForegroundColor Green
            Write-Host "$($Result.Value.Message)" -ForegroundColor Green
            Write-Host "StartTime $($StartTime)" -ForegroundColor White
            Write-Host "EndTime $($EndTime)" -ForegroundColor White
        }
    }
    catch
    {
        Write-Host "Job Failed: `n $($Result.Value.Message)" -ForegroundColor Red
        Write-Host "Error while running the PowerShell Job" -ForegroundColor Red
    }
}
#endregion

#region Remove Hyper-V Virtual Machines
foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-Host "$($VirtualMachineName) - Removing AD & ADFS Virtual Machines." -ForegroundColor Green

$ScriptString = @'
Get-vm | Stop-VM -Force
Get-vm | Remove-VM -Force
Get-NetAdapter | Where-Object {$_.Name -like "*ADSwitch*"} | Disable-NetAdapter -Confirm:$false
'@

    try
    {
        $StartTime = Get-Date -DisplayHint Time

        $Job = Invoke-AzVMRunCommand -VMName $VirtualMachineName `
            -ResourceGroupName $LabResourceGroup.ResourceGroupName `
            -CommandId 'RunPowerShellScript' `
            -ScriptString $ScriptString -AsJob

        $Result = Get-Job -Id $Job.Id | Wait-Job | Receive-Job

        $EndTime = Get-Date -DisplayHint Time

        if ($Result.Value.Message -like "*error*") 
        {
            throw $($Error[0])
        }
        else
        {
            Write-Host "PowerShell Job $($Result.Status)" -ForegroundColor Green
            Write-Host "$($Result.Value.Message)" -ForegroundColor Green
            Write-Host "StartTime $($StartTime)" -ForegroundColor White
            Write-Host "EndTime $($EndTime)" -ForegroundColor White
        }
    }
    catch
    {
        Write-Host "Job Failed: `n $($Result.Value.Message)" -ForegroundColor Red
        Write-Host "Error while running the PowerShell Job" -ForegroundColor Red
    }
}
#endregion

#region Setup ASDK Install Job
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

    try
    {
        $StartTime = Get-Date -DisplayHint Time

        $Job = Invoke-AzVMRunCommand -VMName $VirtualMachineName `
            -ResourceGroupName $LabResourceGroup.ResourceGroupName `
            -CommandId 'RunPowerShellScript' `
            -ScriptString $ScriptString -AsJob

        $Result = Get-Job -Id $Job.Id | Wait-Job | Receive-Job

        $EndTime = Get-Date -DisplayHint Time

        if ($Result.Value.Message -like "*error*") 
        {
            throw $($Error[0])
        }
        else
        {
            Write-Host "PowerShell Job $($Result.Status)" -ForegroundColor Green
            Write-Host "$($Result.Value.Message)" -ForegroundColor Green
            Write-Host "StartTime $($StartTime)" -ForegroundColor White
            Write-Host "EndTime $($EndTime)" -ForegroundColor White
        }
    }
    catch
    {
        Write-Host "Job Failed: `n $($Result.Value.Message)" -ForegroundColor Red
        Write-Host "Error while running the PowerShell Job" -ForegroundColor Red
    }
}
#endregion

#region Restart Server to begin ASDK Install
Write-host "Now I need to restart the Virtual Machines." -ForegroundColor Yellow
Write-host "This takes about 2 minutes. Please wait..." -ForegroundColor Yellow

foreach ($VirtualMachineName in $DeployedVirtualMachines)
{
    Write-host "$($VirtualMachineName) - Restarting Virtual Machine." -ForegroundColor Green
    try
    {
        $StartTime = Get-Date -DisplayHint Time

        $Job = Restart-AzVM -ResourceGroupName $LabResourceGroup.ResourceGroupName -Name $VirtualMachineName -AsJob

        $Result = Get-Job -Id $Job.Id | Wait-Job | Receive-Job

        $EndTime = Get-Date -DisplayHint Time

        if ($Result.Value.Message -like "*error*") 
        {
            throw $($Error[0])
        }
        else
        {
            Write-Host "PowerShell Job $($Result.Status)" -ForegroundColor Green
            Write-Host "$($Result.Value.Message)" -ForegroundColor Green
            Write-Host "StartTime $($StartTime)" -ForegroundColor White
            Write-Host "EndTime $($EndTime)" -ForegroundColor White
            
        }
    }
    catch
    {
        Write-Host "Job Failed: `n $($Result.Value.Message)" -ForegroundColor Red
        Write-Host "Error while running the PowerShell Job" -ForegroundColor Red
    }
}
#endregion

Write-Host "Deployment Jobs are complete." -ForegroundColor Green
Write-Host "Depending on the Virtual Machine Sku, it can take 12-18 Hours to complete the ASDK Install." -ForegroundColor Yellow
Write-Host "You can connect to the ASDK Virtual Machines using RDP to monitor the progress." -ForegroundColor Green
Write-Host "Prior to Domain Setup completion, the login UserName will be .\Administrator" -ForegroundColor Green
Write-Host "Once the ASDK Domain Setup is complete, the login UserName will be AzureStack\AzureStackAdmin" -ForegroundColor Green
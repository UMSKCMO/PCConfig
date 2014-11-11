
# ------------------------------ Functions --------------------------------------
function Use-RunAs {    
    # Check if script is running as Administrator and if not use RunAs 
    # Use Check Switch to check if admin 
    
    param([Switch]$Check) 
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") 
    if ($Check) { return $IsAdmin }     
    if ($MyInvocation.ScriptName -ne "") 
    {  
        if (-not $IsAdmin)  
        {  
            try 
            {  
                $arg = "-file `"$($MyInvocation.ScriptName)`"" 
                Start-Process "$psHome\powershell.exe" -Verb Runas -ArgumentList $arg -ErrorAction 'stop'  
            } 
            catch 
            { 
                Write-Warning "Error - Failed to restart script with runas"  
                break               
            } 
            exit # Quit this session of powershell 
        }  
    }  
    else  
    {  
        Write-Warning "Error - Script must be saved as a .ps1 file first"  
        break  
    }  
}
# -------------------------------------------------------------------------------
# Start log transcript, this will log results of what the script is doing and place it in the same directory the script is being ran from
Start-Transcript -Path ($MyInvocation.MyCommand.Definition -replace 'ps1','log') -Append | out-null

######### Step 1: DOWNLOAD WINDOWS UPDATES ########

$UpdateSession = New-Object -Com Microsoft.Update.Session
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
 
Write-Host("Searching for applicable updates...") -Fore Green
 
$SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software'")
 
Write-Host("")
Write-Host("List of applicable items on the machine:") -Fore Green
For ($X = 0; $X -lt $SearchResult.Updates.Count; $X++){
    $Update = $SearchResult.Updates.Item($X)
    Write-Host( ($X + 1).ToString() + "&gt; " + $Update.Title)
}
 
If ($SearchResult.Updates.Count -eq 0) {
    Write-Host("There are no applicable updates.")
    Exit
}
 
#Write-Host("")
#Write-Host("Creating collection of updates to download:") -Fore Green
 
$UpdatesToDownload = New-Object -Com Microsoft.Update.UpdateColl
 
For ($X = 0; $X -lt $SearchResult.Updates.Count; $X++){
    $Update = $SearchResult.Updates.Item($X)
    #Write-Host( ($X + 1).ToString() + "&gt; Adding: " + $Update.Title)
    $Null = $UpdatesToDownload.Add($Update)
}
 
Write-Host("")
Write-Host("Downloading Updates...")  -Fore Green
 
$Downloader = $UpdateSession.CreateUpdateDownloader()
$Downloader.Updates = $UpdatesToDownload
$Null = $Downloader.Download()
 
#Write-Host("")
#Write-Host("List of Downloaded Updates...") -Fore Green
 
$UpdatesToInstall = New-Object -Com Microsoft.Update.UpdateColl
 
For ($X = 0; $X -lt $SearchResult.Updates.Count; $X++){
    $Update = $SearchResult.Updates.Item($X)
    If ($Update.IsDownloaded) {
        #Write-Host( ($X + 1).ToString() + "&gt; " + $Update.Title)
        $Null = $UpdatesToInstall.Add($Update)        
    }
}
 
$Install = [System.String]$Args[0]
$Reboot  = [System.String]$Args[1]
 
If (!$Install){
    $Install = Read-Host("Would you like to install these updates now? (Y/N)")
}
 
If ($Install.ToUpper() -eq "Y" -or $Install.ToUpper() -eq "YES"){
    Write-Host("")
    Write-Host("Installing Updates...") -Fore Green
 
    $Installer = $UpdateSession.CreateUpdateInstaller()
    $Installer.Updates = $UpdatesToInstall
 
    $InstallationResult = $Installer.Install()
 
    Write-Host("")
    Write-Host("List of Updates Installed with Results:") -Fore Green
 
    For ($X = 0; $X -lt $UpdatesToInstall.Count; $X++){
        Write-Host($UpdatesToInstall.Item($X).Title + ": " + $InstallationResult.GetUpdateResult($X).ResultCode)
    }
 
    Write-Host("")
    Write-Host("Installation Result: " + $InstallationResult.ResultCode)
    Write-Host("    Reboot Required: " + $InstallationResult.RebootRequired)
 
    If ($InstallationResult.RebootRequire -eq $True){
        If (!$Reboot){
            $Reboot = Read-Host("Would you like to install these updates now? (Y/N)")
        }
 
        If ($Reboot.ToUpper() -eq "Y" -or $Reboot.ToUpper() -eq "YES"){
            Write-Host("")
            Write-Host("Rebooting...") -Fore Green
            (Get-WMIObject -Class Win32_OperatingSystem).Reboot()
        }
    }
}

######### Step 2: DISABLE THE LOCAL "USER" ACCOUNT ########
## Disable the local "User" account ##
write-host ("Disable the User account") -Fore Green
invoke-command { net user User /active:no }
######### Step 3: ENABLE LOCAL ADMINISTRATOR ACCOUNT ########
## Enable the local Administrator ##
write-host ("Enable the local Administrator account") -Fore Green
invoke-command { net user Administrator /active:yes }
######### Step 4: DISABLE UAC ########
## Disable UAC ##
write-host ("Disable UAC (Will Require a reboot!) ") -Fore Green
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
######### Step 5: ENABLE REMOTE DESKTOP ########
## Enable Remote Desktop ##
write-host ("Enable Remote Desktop") -Fore Green
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
######### Step 6: ALLOW RDP IN FIREWALL ########
## Allow RDP In Firewall ##
write-host ("Allow port 3389 in the firewall for RDP") -Fore Green
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
######### Step 7: TURN OFF DISPLAY AFTER 20MIN ########
## Turn off display after 20 min ##
write-host ("Change monitor timeout to 20min") -Fore Green
powercfg -change -monitor-timeout-ac 20min
######### Step 8: DISABLE PUTTING THE COMPUTER TO SLEEP ########
## Disable putting the computer to sleep ##
write-host ("Disable putting the computer to sleep") -Fore Green
powercfg -change -standby-timeout-ac 0

######### Step 9: DISABLE TURN OFF THIS DEVICE TO SAVE POWER FOR NIC MANAGEMENT ########
##### Disable turn off this device to save power for NIC Power Management ######
Function Disable-OSCNetAdapterPnPCaptitlies
{
	#find only physical network,if value of properties of adaptersConfigManagerErrorCode is 0,  it means device is working properly. 
	#even covers enabled or disconnected devices.
	#if the value of properties of configManagerErrorCode is 22, it means the adapter was disabled. 
	$PhysicalAdapters = Get-WmiObject -Class Win32_NetworkAdapter|Where-Object{$_.PNPDeviceID -notlike "ROOT\*" `
	-and $_.Manufacturer -ne "Microsoft" -and $_.ConfigManagerErrorCode -eq 0 -and $_.ConfigManagerErrorCode -ne 22} 
	
	Foreach($PhysicalAdapter in $PhysicalAdapters)
	{
		$PhysicalAdapterName = $PhysicalAdapter.Name
		#check the unique device id number of network adapter in the currently environment.
		$DeviceID = $PhysicalAdapter.DeviceID
		If([Int32]$DeviceID -lt 10)
		{
			$AdapterDeviceNumber = "000"+$DeviceID
		}
		Else
		{
			$AdapterDeviceNumber = "00"+$DeviceID
		}
		
		#check whether the registry path exists.
		$KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$AdapterDeviceNumber"
		If(Test-Path -Path $KeyPath)
		{
			$PnPCapabilitiesValue = (Get-ItemProperty -Path $KeyPath).PnPCapabilities
			If($PnPCapabilitiesValue -eq 24)
			{
				Write-Warning """$PhysicalAdapterName"" - The option ""Allow the computer to turn off this device to save power"" has been disabled already."
			}
			If($PnPCapabilitiesValue -eq 0)
			{
				#check whether change value was successed.
				Try
				{	
					#setting the value of properties of PnPCapabilites to 24, it will disable save power option.
					Set-ItemProperty -Path $KeyPath -Name "PnPCapabilities" -Value 24 | Out-Null
					Write-Host """$PhysicalAdapterName"" - The option ""Allow the computer to turn off this device to save power"" was disabled."
					
					Write-Warning "It will take effect after reboot, do you want to reboot right now?"
					[string]$Reboot = Read-Host -Prompt "[Y] Yes  [N] No   (default is 'N')"
					If ($Reboot -eq "y" -or $Reboot -eq "yes") 
					{
						Restart-Computer -Force
					}
				}
				Catch
				{
					Write-Host "Setting the value of properties of PnpCapabilities failed." -ForegroundColor Red
				}
			}
			If($PnPCapabilitiesValue -eq $null)
			{
				Try
				{
					New-ItemProperty -Path $KeyPath -Name "PnPCapabilities" -Value 24 -PropertyType DWord | Out-Null
					Write-Host """$PhysicalAdapterName"" - The option ""Allow the computer to turn off this device to save power"" was disabled."
					
					Write-Warning "It will take effect after reboot, do you want to reboot right now?"
					[string]$Reboot = Read-Host -Prompt "[Y] Yes  [N] No   (default is 'N')"
					If ($Reboot -eq "y" -or $Reboot -eq "yes") 
					{
						Restart-Computer -Force
					}
				}
				Catch
				{
					Write-Host "Setting the value of properties of PnpCapabilities failed." -ForegroundColor Red
				}
			}
		}
		Else
		{
			Write-Warning "The path ($KeyPath) not found."
		}
	}
}

Disable-OSCNetAdapterPnPCaptitlies


# Stop writing to log file
Stop-Transcript | out-null

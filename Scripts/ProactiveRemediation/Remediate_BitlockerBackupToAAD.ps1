<#
.SYNOPSIS
	The remediation script is used to back up the BitLocker recovery key(s) to Azure AD.

.DESCRIPTION
	The remediation script will check if the device is protected by BitLocker and attempt to back up the BitLocker recovery key(s) to Azure AD.

	-------------------------------------------------------
	Proactive Remediation Information
	-------------------------------------------------------
	Required settings for the script package in Endpoint analytics | Proactive remediations.

		Run this script using the logged-on credentials: No
		Enforce script signature check: No
		Run script in 64-bit PowerShell: Yes

	-------------------------------------------------------
	Proactive Remediation Scenarios and detection output
	-------------------------------------------------------
	Scenario: The script is not running in system context.
	Output: "PREREQ: The script is not running in system context. - Please run the script as system."

	Scenario: The script is not running in 64-bit PowerShell.
	Output: "PREREQ: The script is not running in 64-bit PowerShell. - Please run the script in 64-bit PowerShell."

	Scenario: The drive (For example, 'C:') is not protected by BitLocker.
	Output: "NOT PROTECTED: BitLocker protection status on drive 'C:' is = Off. - Please ensure that the BitLocker protection is turned on and not temporarily suspended."

	Scenario: BitLocker recovery key(s) is not stored in Azure AD.
	Output: "PROTECTED - RUN REMEDIATION: BitLocker recovery key(s) is not stored in Azure AD. - Run remediation script..."

	Scenario: The proactive remediation script failed.
	Output: "ERROR: Whoopsie... Something failed at line 36: Error message"

	-------------------------------------------------------
	Proactive Remediation Functions
	-------------------------------------------------------
	Function (Write-Log)

		This is a CMTrace friendly log function with UTF-8 encoding, and correct log entry format.
		You can use this function with the pre-defined log variables or change them to fit your needs.
		The only mandatory parameter in this function is the message parameter.

		The available message severity in this log function:
			1 = Information (Default)
			2 = Warning
			3 = Error

		Valid example(s):
		Write-Log -Message "CMTrace, is the best log viewer on the planet!"
		Write-Log -Message "CMTrace, is the best log viewer on the planet!" -ComponentName "Demo"
		Write-Log -Message "CMTrace, is the best log viewer on the planet!" -ComponentName "Demo" -Severity "3"

	Function (Split-Log)

		This function is called by the Write-Log function to split the log file when it reaches the specified max size.

	Function (Check-EventLog)

		You can use this function with the default pre-defined variables or specify your values when calling the function.
		Be aware that all parameters in this function are mandatory!

		Valid example(s):
		Check-EventLog -EventProviderName "Microsoft-Windows-BitLocker-API" -EventMessage "volume C: was backed up successfully to your Azure AD." -EventTime "01/01/2022 00:00:00" -EventID "845"

	Function (Convert-RegistryKey)

		This function is called by the Check-RegistryKey and Set-RegistryKey functions to convert the registry key hive to the full path.

	Function (Check-RegistryKey)

		You can use this function with the default pre-defined variables or specify your values when calling the function.
		This function can be used to check a registry key path, name, and value.
		The only mandatory parameter in this function is the registry key parameter.

		-------------------------------------------------------
		Registry Hive               Abbreviation
		-------------------------------------------------------
		HKEY_LOCAL_MACHINE          HKLM
		HKEY_CURRENT_USER           HKCU
		HKEY_USERS                  HKU
		HKEY_CURRENT_CONFIG         HKCC
		HKEY_CLASSES_ROOT           HKCR
		-------------------------------------------------------

		Valid example(s) (HKEY_LOCAL_MACHINE):
		Check-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "(Default)" -Value ""
		Check-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "SystemRoot" -Value "C:\WINDOWS"
		Check-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "SystemRoot" -Value ""
		Check-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "" -Value ""

		Valid example(s) (HKEY_CURRENT_USER):
		Check-RegistryKey -Key "HKCU:\Control Panel\Desktop" -Name "(Default)" -Value ""
		Check-RegistryKey -Key "HKCU:\Control Panel\Desktop" -Name "WallPaper" -Value "C:\Windows\web\wallpaper\Windows\img19.jpg"
		Check-RegistryKey -Key "HKCU:\Control Panel\Desktop" -Name "WallPaper" -Value ""
		Check-RegistryKey -Key "HKCU:\Control Panel\Desktop" -Name "" -Value ""

		Valid example(s) (HKEY_CLASSES_ROOT):
		Check-RegistryKey -Key "HKCR:\MIME\Database\Content Type\application/hta" -Name "(Default)" -Value ""
		Check-RegistryKey -Key "HKCR:\MIME\Database\Content Type\application/hta" -Name "Extension" -Value ".hta"
		Check-RegistryKey -Key "HKCR:\MIME\Database\Content Type\application/hta" -Name "Extension" -Value ""
		Check-RegistryKey -Key "HKCR:\MIME\Database\Content Type\application/hta" -Name "" -Value ""

	Function (Set-RegistryKey)

		You can use this function with the default pre-defined variables or specify your values when calling the function.
		This function can be used to create/set a registry key path, name, and value.
		Be aware that the registry key, name, and type parameters in this function are mandatory.

		-------------------------------------------------------
		Registry Hive               Abbreviation
		-------------------------------------------------------
		HKEY_LOCAL_MACHINE          HKLM
		HKEY_CURRENT_USER           HKCU
		HKEY_USERS                  HKU
		HKEY_CURRENT_CONFIG         HKCC
		HKEY_CLASSES_ROOT           HKCR
		--------------------------------------------------------------------------------------------------------------
		Registry Types              Description
		--------------------------------------------------------------------------------------------------------------
		String                      Specifies a null-terminated string. Equivalent to REG_SZ.
		ExpandString                Specifies a null-terminated string that contains unexpanded references to environment variables that are expanded when the value is retrieved. Equivalent to REG_EXPAND_SZ.
		Binary                      Specifies binary data in any form. Equivalent to REG_BINARY.
		DWord                       Specifies a 32-bit binary number. Equivalent to REG_DWORD.
		MultiString                 Specifies an array of null-terminated strings terminated by two null characters. Equivalent to REG_MULTI_SZ.
		Qword                       Specifies a 64-bit binary number. Equivalent to REG_QWORD.
		Unknown                     Indicates an unsupported registry data type, such as REG_RESOURCE_LIST.
		--------------------------------------------------------------------------------------------------------------

		Valid example(s) (HKEY_LOCAL_MACHINE):
		Set-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "(Default)" -Value "" -Type "STRING"
		Set-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "SystemRoot" -Value "C:\WINDOWS" -Type "STRING"
		Set-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "SystemRoot" -Value "" -Type "STRING"

		Valid example(s) (HKEY_CURRENT_USER):
		Set-RegistryKey -Key "HKCU:\Control Panel\Desktop" -Name "(Default)" -Value "" -Type "STRING"
		Set-RegistryKey -Key "HKCU:\Control Panel\Desktop" -Name "WallPaper" -Value "C:\Windows\web\wallpaper\Windows\img19.jpg" -Type "STRING"
		Set-RegistryKey -Key "HKCU:\Control Panel\Desktop" -Name "WallPaper" -Value "" -Type "STRING"

		Valid example(s) (HKEY_CLASSES_ROOT):
		Set-RegistryKey -Key "HKCR:\MIME\Database\Content Type\application/hta" -Name "(Default)" -Value "" -Type "STRING"
		Set-RegistryKey -Key "HKCR:\MIME\Database\Content Type\application/hta" -Name "Extension" -Value ".hta" -Type "STRING"
		Set-RegistryKey -Key "HKCR:\MIME\Database\Content Type\application/hta" -Name "Extension" -Value "" -Type "STRING"

	Function (Check-BitLockerProtectionStatus)

		This function is called to check if the drive (For example, 'C:') is protected by BitLocker.

	Function (Check-BitLockerVolumeStatus)

		This function is called to check if the drive (For example, 'C:') is fully encrypted by BitLocker.

	Function (Invoke-BitLockerBackupToAAD)

		This function will attempt to back up the BitLocker recovery key(s) to Azure AD.

	Function (Exit-Script)

		This function is called to exit the script based on an exit code. - It does also support an exit message (Write-Output).
		The only mandatory parameter in this function is the exit code parameter.

		Valid example(s):
		Exit-Script -ExitCode "1" -ExitMessage "Remediation is required."

.PARAMETER

.EXAMPLE

.NOTES
	Created on:   26-11-2021
	Modified:     17-11-2023
	Author:       Sune Thomsen
	Version:      3.1
	Mail:         stn@mindcore.dk
	Twitter:      https://twitter.com/SuneThomsenDK

	Changelog:
	----------
	26-11-2021 - v1.0 - The Creation date of this script
	03-05-2022 - v1.1 - Detection for BitLocker protection status added to the script
	17-06-2022 - v1.2 - New logic and better reporting have been added to the script
	07-10-2022 - v1.3 - Code review and cleanup of the script
	09-10-2022 - v1.4 - Minor changes to the script output
	20-10-2022 - v1.5 - Minor changes to the detection of BitLocker protection status and script output
	09-12-2022 - v2.0 - The script has been rewritten and now contains a prerequisite check, new logic, structure, functions, etc.
	04-05-2022 - v2.1 - Minor changes to the Write-Log function.
	09-06-2023 - v3.0 - The script has been rewritten to support multiple fixed drives. -> Set the "$Global:CheckAllDrives" to "$true" under "Set system variable(s)" if you want the script to check all available fixed drives.
	06-10-2023 - v3.1 - Minor changes to the script output

.LINK
	https://github.com/SuneThomsenDK
#>

## Variables
## Set the global variable(s) used throughout the script

	## Set system variable(s)
	[String]$Global:ScriptName = $MyInvocation.MyCommand.Name
	[String]$Global:UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
	[Bool]$Global:IsPowerShell64bitVersion = [Environment]::Is64BitProcess
	[Bool]$Global:IsSystemContext = [System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem
	[Bool]$Global:SkipPrereq = $false ## <---- Change this to "$true" if you want the script to skip the prerequisite check. (Default is $false)
	[Bool]$Global:CheckAllDrives = $false ## <---- Change this to "$true" if you want the script to check all available fixed drives. (Default is $false)

		If (($Global:CheckAllDrives)) {
			[Array]$Global:GetDrives = (get-wmiobject -class win32_logicaldisk | where {$_.DriveType -eq "3"}).DeviceID
		}
		Else {
			[String]$Global:GetDrives = $env:SystemDrive
		}

	## Set log variable(s)
	[String]$Global:LogLocation = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
	[String]$Global:LogName = "IntuneProactiveRemediation"
	[String]$Global:LogComponent = "RemediationScript"
	[String]$Global:LogSubject = "BitLocker Backup to AAD"
	[Int]$Global:LogMaxSize = 250KB

	## Set registry variable(s)
	[String]$Global:DefaultRegistryKey = "HKLM:\SOFTWARE\CompanyName\BitLocker" ## <---- Change "CompanyName" to your own company name.
	[String]$Global:DefaultRegistryName = "Drive_{0}_BitLockerBackupToAAD"
	[String]$Global:DefaultRegistryType = "STRING"
	[String]$Global:DefaultRegistryValue = "True"

	## Set event log variable(s)
	[String]$Global:DefaultEventProviderName = "Microsoft-Windows-BitLocker-API"
	[String]$Global:DefaultEventMessage = "volume {0} was backed up successfully to your Azure AD."
	[DateTime]$Global:DefaultEventTime = "01/01/2022 00:00:00" ## <---- MM/dd/yyyy HH:mm:ss
	[Int]$Global:DefaultEventID = "845"

	## Set exit variable(s)
	[Int]$Global:ExitCode = 0

	## ----------------------------------------------------------------------- ##
	## Do NOT make changes below this line unless you know what you are doing! ##
	## ----------------------------------------------------------------------- ##

## Remediation
$Remediation = {
	## Invoke remediation
	$Msg = (" ----------------------------------------------------- Invoke Remediation ({0}) ----------------------------------------------------- " -f $Global:UserName)
	Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg)

	Try {
		## The script checks whether it runs under the system account and in the 64-bit version of PowerShell.
		$Msg = "The script checks whether it runs under the system account and in the 64-bit version of PowerShell."
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg)

		If (!($Global:SkipPrereq)) {
			If (!($Global:IsSystemContext)) {
				$Msg = "The script is not running under the system account. - Please run the script as system."
				Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -Severity 3
				$Global:ExitCode = 1
			}
			ElseIf (!($Global:IsPowerShell64bitVersion)) {
				$Msg = "The script is not running in 64-bit PowerShell. - Please run the script in 64-bit PowerShell."
				Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -Severity 3
				$Global:ExitCode = 1
			}
			Else {
				$Msg = "Prerequisite check passed. - The script will continue..."
				Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg)
			}

			If (!($Global:ExitCode -eq 0)) {
				Exit-Script -ExitCode $Global:ExitCode
			}
		}
		Else {
			$Msg = "Prerequisite check skipped. - The script will continue..."
			Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -Severity 2
		}

		Foreach ($Global:Drive in $Global:GetDrives) {
			## The script is detecting if the drive (For example, 'C:') is protected and fully encrypted by BitLocker.
			If (((Check-BitLockerVolumeStatus) -match 'FullyEncrypted')) {
				$Msg = ("Drive '{0}' is fully encrypted by BitLocker. - The script will continue..." -f $Global:Drive)
				Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg)

				If (((Check-BitLockerProtectionStatus) -eq 'On')) {
					$Msg = ("Drive '{0}' is protected by BitLocker. - The script will continue..." -f $Global:Drive)
					Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg)

					## The script checks the event log and registry to confirm that the BitLocker recovery key(s) has not been stored in Azure AD.
					$Msg = "The script checks the event log and registry to confirm that the BitLocker recovery key(s) has not been stored in Azure AD."
					Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg)

					If ((!(Check-EventLog)) -and (!(Check-RegistryKey))) {
						## The script will attempt to back up the BitLocker recovery key(s) to Azure AD.
						$Msg = "The script will attempt to back up the BitLocker recovery key(s) to Azure AD."
						Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg)

						Invoke-BitLockerBackupToAAD

						## Okay, let's check if the BitLocker recovery key(s) has been successfully backed up to Azure AD.
						$Msg = "Okay, let's check if the BitLocker recovery key(s) has been successfully backed up to Azure AD."
						Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg)

						If ((Check-EventLog)) {
							$Msg = ("BitLocker recovery key(s) from drive '{0}' was successfully backed up to Azure AD." -f $Global:Drive)
							Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg)
						}
						Else {
							$Msg = ("The Proactive Remediation script failed to back up the BitLocker recovery key(s) from drive '{0}' to Azure AD." -f $Global:Drive)
							Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -Severity 3
							$Global:ExitCode = 1
						}
					}
					Else {
						$Msg = ("BitLocker recovery key(s) from drive '{0}' is stored in Azure AD, do nothing." -f $Global:Drive)
						Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg)
					}
				}
				Else {
					$Msg = ("BitLocker protection status of drive '{0}' is = {1}. - Please ensure that the BitLocker protection is turned on and not temporarily suspended." -f $Global:Drive, $Global:GetBitLockerProtectionStatus)
					Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -Severity 3
					$Global:ExitCode = 1
				}
			}
			Else {
				$Msg = ("BitLocker encryption status of drive '{0}' is = {1}. - This drive was skipped." -f $Global:Drive, $Global:GetBitLockerVolumeStatus)
				Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -Severity 2
			}
		}
	}
	Catch {
		$ErrMsg = ("Whoopsie... Something failed at line {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $ErrMsg) -Severity 3
		$Global:ExitCode = 1
	}
}

## Functions
Function Write-Log {
	Param (
		[Parameter(Mandatory=$true, HelpMessage = "Provide a message to the log file (Mandatory)")]
		[ValidateNotNullOrEmpty()]
		[String]$Message,

		[Parameter(Mandatory=$false, HelpMessage = "Specify a component name to the log file (Optional)")]
		[ValidateNotNullOrEmpty()]
		[String]$ComponentName = $Global:LogComponent,

		[Parameter(Mandatory=$false, HelpMessage = "Specify the severity of the message. 1 = Information, 2 = Warning, 3 = Error (Optional)")]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("1", "2", "3")]
		[Int]$Severity = "1"
	)

	## Trying to create the log directory and filename if it does not exist
	If (!(Test-Path -LiteralPath $Global:LogLocation)) {
		Try {
			New-Item -Path $Global:LogLocation -ItemType 'Directory' -Force | Out-Null
		}
		Catch {
			## Log directory creation failed. Write error on screen and stop the script.
			$ErrMsg = ("Log directory creation failed at line {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
			Write-Error -Message $ErrMsg -ErrorAction 'Stop'
		}
	}

	## Combine log location with log file
	If (([String]::IsNullOrWhitespace($Global:LogFilePath))) {
		$Global:LogFilePath = ($Global:LogLocation + '\' + $Global:LogName + '.log')
	}

	## Creating timestamp for the log entry
	If (([String]::IsNullOrWhitespace($LogTime))) {
		[String]$LogTime = (Get-Date -Format 'HH":"mm":"ss"."fffffff')
	}
	If (([String]::IsNullOrWhitespace($LogDate))) {
		[String]$LogDate = (Get-Date -Format 'MM-dd-yyyy')
	}

	## Creating context and log entry
	If (([String]::IsNullOrWhitespace($LogContext))) {
		$LogContext = $Global:UserName
	}

	## Construct the log entry format
	$LogEntry = ('<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="{4}" type="{5}" thread="{6}" file="{7}">' -f $Message, $LogTime, $LogDate, $ComponentName, $LogContext, $Severity, $PID, $Global:ScriptName)

	## Trying to write log entry to log file
	If (!([String]::IsNullOrWhitespace($Global:LogFilePath))) {
		Try {
			$LogEntry | Out-File -FilePath $Global:LogFilePath -Append -NoClobber -Force -Encoding 'Default' -ErrorAction 'Stop'
		}
		Catch {
			## Failed to append log entry. Write warning on screen but let the script continue.
			$Msg = ("Failed to append log entry to {0}. - Error message at line {1}: {2}" -f $Global:LogFilePath, $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
			Write-Warning -Message $Msg
		}
	}
	Else {
		## Failed to append log entry. Write warning on screen but let the script continue.
		$Msg = "Failed to append log entry. - Error message: Log file not found."
		Write-Warning -Message $Msg
	}

	## Check log size and split if it's greather than 250KB
	If ((Test-Path -LiteralPath $Global:LogFilePath) -and (Get-ChildItem -LiteralPath $Global:LogFilePath).Length -ge $Global:LogMaxSize) {
		Try {
			Split-Log
			$Msg = ("The log file has been split, older log entries can be found here: {0}" -f $Global:SplitLogFilePath)
			Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name) -Severity 2
		}
		Catch {
			## Failed to split the log file. Write warning on screen but let the script continue.
			$Msg = "Failed to split the log file."
			Write-Warning -Message $Msg
		}
	}
}

Function Split-Log {
	$SplitLogFileTime = (Get-Date).ToString('yyyyMMdd-HHmmss')
	$Global:SplitLogFilePath = ($Global:LogLocation + '\' + $Global:LogName + '-' + $SplitLogFileTime + '.log')

	$Reader = [System.IO.StreamReader]::new($Global:LogFilePath)
	While (!(($Line = $Reader.ReadLine()) -eq $Null)) {
		Add-Content -LiteralPath $Global:SplitLogFilePath -Value $Line
	}
	$Reader.Close()
	$Reader.Dispose()

	## Remove old log file
	Remove-Item -LiteralPath $Global:LogFilePath -Force

	## Compress the archived log file
	Compact /C $Global:SplitLogFilePath | Out-Null
}

Function Check-EventLog {
	Param (
		[Parameter(Mandatory=$false, HelpMessage = "Specify an event provider name (Mandatory)")]
		[String]$EventProviderName = $Global:DefaultEventProviderName,
		
		[Parameter(Mandatory=$false, HelpMessage = "Specify an event message (Mandatory)")]
		[String]$EventMessage = ("$Global:DefaultEventMessage" -f $Global:Drive),

		[Parameter(Mandatory=$false, HelpMessage = "Specify an event timestamp (Mandatory)")]
		[DateTime]$EventTime = $Global:DefaultEventTime,

		[Parameter(Mandatory=$false, HelpMessage = "Specify an event ID (Mandatory")]
		[Int]$EventID = $Global:DefaultEventID
	)

	Try {
		## Checking the event log...
		$Msg = "Checking the event log..."
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name)

		## The script checks that the specified event provider name parameter is not null or empty.
		If (!([String]::IsNullOrWhitespace($EventProviderName))) {
			## The script checks that the specified event provider name exists.
			$CheckEventProvider = (Get-WinEvent -ListProvider $EventProviderName -ErrorAction 'SilentlyContinue').Name

			If (!($CheckEventProvider)) {
				$Msg = "The event provider name does not exist. - Please specify a valid event provider name."
				Throw $Msg
			}
		}
		Else {
			$Msg = "The event provider name parameter is null or empty. - Please specify a valid event provider name."
			Throw $Msg
		}

		## The script checks that the specified event message parameter is not null or empty.
		If (([String]::IsNullOrWhitespace($EventMessage))) {
			$Msg = "The event message parameter is null or empty. - Please specify a valid event message."
			Throw $Msg
		}

		## The script checks that the specified event ID parameter is not null or empty.
		If (!($EventID)) {
			$Msg = "The event ID parameter is null or empty. - Please specify a valid event ID."
			Throw $Msg
		}

		## The script checks the event log for events that match the specified event ID.
		$GetEventID = (Get-WinEvent -ProviderName $EventProviderName -ErrorAction 'SilentlyContinue' | Where-Object {($_.TimeCreated -gt $EventTime) -and ($_.Message -match $EventMessage)}).ID | Sort-Object -Unique

		If (($GetEventID -eq $EventID)) {
			$Msg = ("The event ID '{0}' was found in the event log." -f $EventID)
			Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name)

			## Return result
			Return $true
		}
		Else {
			$Msg = "No matching event ID was found in the event log."
			Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name) -Severity 2

			## Return result
			Return $false
		}
	}
	Catch {
		$ErrMsg = ("The function called '{0}' failed at line {1}: {2}" -f $MyInvocation.MyCommand.Name, $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $ErrMsg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name) -Severity 3
		Write-Error $ErrMsg -ErrorAction 'Stop'
	}
}

Function Convert-RegistryKey {
	Param (
		[Parameter(Mandatory=$true, HelpMessage = "Specify a registry key to convert (Mandatory)")]
		[ValidateNotNullOrEmpty()]
		[String]$Key
	)

	Try {
		## Converting the registry key hive to the full path...
		$Msg = "Converting the registry key hive to the full path..."
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name)

		## Convert the registry key hive to the full path, only match if at the beginning of the line
		If (($Key -match '^HKLM')) {
			$Key = $Key -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\' -replace '^HKLM:', 'HKEY_LOCAL_MACHINE\' -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\'
		}
		ElseIf (($Key -match '^HKCR')) {
			$Key = $Key -replace '^HKCR:\\', 'HKEY_CLASSES_ROOT\' -replace '^HKCR:', 'HKEY_CLASSES_ROOT\' -replace '^HKCR\\', 'HKEY_CLASSES_ROOT\'
		}
		ElseIf (($Key -match '^HKCU')) {
			$Key = $Key -replace '^HKCU:\\', 'HKEY_CURRENT_USER\' -replace '^HKCU:', 'HKEY_CURRENT_USER\' -replace '^HKCU\\', 'HKEY_CURRENT_USER\'
		}
		ElseIf (($Key -match '^HKU')) {
			$Key = $Key -replace '^HKU:\\', 'HKEY_USERS\' -replace '^HKU:', 'HKEY_USERS\' -replace '^HKU\\', 'HKEY_USERS\'
		}
		ElseIf (($Key -match '^HKCC')) {
			$Key = $Key -replace '^HKCC:\\', 'HKEY_CURRENT_CONFIG\' -replace '^HKCC:', 'HKEY_CURRENT_CONFIG\' -replace '^HKCC\\', 'HKEY_CURRENT_CONFIG\'
		}
		ElseIf (($Key -match '^HKPD')) {
			$Key = $Key -replace '^HKPD:\\', 'HKEY_PERFORMANCE_DATA\' -replace '^HKPD:', 'HKEY_PERFORMANCE_DATA\' -replace '^HKPD\\', 'HKEY_PERFORMANCE_DATA\'
		}

		## Append the PowerShell provider to the registry key path
		If (!($Key -match '^Registry::')) {[String]$Key = "Registry::$Key"}

		## Return result
		Return $Key
	}
	Catch {
		$ErrMsg = ("The function called '{0}' failed at line {1}: {2}" -f $MyInvocation.MyCommand.Name, $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $ErrMsg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name) -Severity 3
		Write-Error $ErrMsg -ErrorAction 'Stop'
	}
}

Function Check-RegistryKey {
	Param (
		[Parameter(Mandatory=$false, HelpMessage = "Specify a registry key (Mandatory)")]
		[String]$Key = $Global:DefaultRegistryKey,

		[Parameter(Mandatory=$false, HelpMessage = "Specify a registry name (Optional)")]
		[String]$Name = ("$Global:DefaultRegistryName" -f $Global:Drive -replace '[:]',''),

		[Parameter(Mandatory=$false, HelpMessage = "Sepcify a registry value (Optional)")]
		[String]$Value = $Global:DefaultRegistryValue
	)

	Try {
		## Checking the registry...
		$Msg = "Checking the registry..."
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name)

		## The script checks that the specified registry key parameter is not null or empty.
		If (!([String]::IsNullOrWhitespace($Key))) {
			## The script converts the specified registry key to a format that is compatible with built-in PowerShell cmdlets
			[String]$Key = Convert-RegistryKey -Key $Key

			## The script checks that the converted registry key is valid.
			If (!($Key -match '^Registry::HKEY_')) {
				$Msg = ("The registry key '{0}' is not valid. - Please specify a valid registry key." -f ($Key -split ':')[-1])
				Throw $Msg
			}
		}
		Else {
			$Msg = "The registry key parameter is null or empty. - Please specify a valid registry key."
			Throw $Msg
		}

		## The script checks if the specified registry key, name, or value exists.
		If ((Test-Path -LiteralPath $Key)) {
			If (($Name)) {
				If (($Name -like '(Default)')) {
					[String]$GetRegistryValue = $(Get-Item -LiteralPath $Key -ErrorAction 'Stop').GetValue($Null, $Null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
				}
				Else {
					## The script checks if the specified registry name exists.
					$GetRegistryName = Get-Item -LiteralPath $Key -ErrorAction 'Stop' | Select-Object -ExpandProperty 'Property' -ErrorAction 'Stop'

					If (!($GetRegistryName -contains $Name)) {
						$Msg = ("The registry key '{0}' with the name '{1}' does not exist." -f ($Key -split ':')[-1], $Name)
						Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name) -Severity 2

						## Return result
						Return $false
					}
					Else {
						[String]$GetRegistryValue = $(Get-Item -LiteralPath $Key -ErrorAction 'Stop').GetValue($Name, $Null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
					}
				}
				## The script checks if the specified registry value exists.
				If (($GetRegistryValue -eq $Value)) {
					$Msg = ("The registry key '{0}' with the name '{1}' and with the value '{2}' does exist." -f ($Key -split ':')[-1], $Name, $Value)
					Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name)

					## Return result
					Return $true
				}
				Else {
					$Msg = ("The registry key '{0}' with the name '{1}' and with the value '{2}' does not exist." -f ($Key -split ':')[-1], $Name, $Value)
					Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name) -Severity 2

					## Return result
					Return $false
				}
			}
			Else {
				$Msg = ("The registry key '{0}' does exist." -f ($Key -split ':')[-1])
				Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name)

				## Return result
				Return $true
			}
		}
		Else {
			$Msg = ("The registry key '{0}' does not exist." -f ($Key -split ':')[-1])
			Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name) -Severity 2

			## Return result
			Return $false
		}
	}
	Catch {
		$ErrMsg = ("The function called '{0}' failed at line {1}: {2}" -f $MyInvocation.MyCommand.Name, $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $ErrMsg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name) -Severity 3
		Write-Error $ErrMsg -ErrorAction 'Stop'
	}
}

Function Set-RegistryKey {
	Param (
		[Parameter(Mandatory=$false, HelpMessage = "Specify a registry key (Mandatory)")]
		[String]$Key = $Global:DefaultRegistryKey,

		[Parameter(Mandatory=$false, HelpMessage = "Specify a registry name (Mandatory)")]
		[String]$Name = ("$Global:DefaultRegistryName" -f $Global:Drive -replace '[:]',''),

		[Parameter(Mandatory=$false, HelpMessage = "Sepcify a registry type STRING, DWORD, etc. (Mandatory)")]
		[String]$Type = $Global:DefaultRegistryType,

		[Parameter(Mandatory=$false, HelpMessage = "Sepcify a registry value (Optional)")]
		[String]$Value = $Global:DefaultRegistryValue
	)

	$RegistryTypeArray = @(
		'STRING'
		'EXPANDSTRING'
		'BINARY'
		'DWORD'
		'MULTISTRING'
		'QWORD'
		'UNKNOWN'
	)

	Try {
		## Writing to the registry...
		$Msg = "Writing to the registry..."
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name)

		## The script checks that the specified registry key parameter is not null or empty.
		If (!([String]::IsNullOrWhitespace($Key))) {
			## The script converts the specified registry key to a format that is compatible with built-in PowerShell cmdlets
			[String]$Key = Convert-RegistryKey -Key $Key

			## The script checks that the converted registry key is valid.
			If (!($Key -match '^Registry::HKEY_')) {
				$Msg = ("The registry key '{0}' is not valid. - Please specify a valid registry key." -f ($Key -split ':')[-1])
				Throw $Msg
			}
		}
		Else {
			$Msg = "The registry key parameter is null or empty. - Please specify a valid registry key."
			Throw $Msg
		}
		## The script checks that the specified registry name parameter is not null or empty.
		If (([String]::IsNullOrWhitespace($Name))) {
			$Msg = "The registry name parameter is null or empty. - Please specify a valid registry name."
			Throw $Msg
		}
		## The script checks that the specified registry type parameter is not null or empty.
		If (!([String]::IsNullOrWhitespace($Type))) {
			## The script checks that the specified registry type is valid.
			If (!($Type -in $RegistryTypeArray)) {
				$Msg = ("The registry type '{0}' is not valid. - Please specify a valid registry type." -f $Type)
				Throw $Msg
			}
		}
		Else {
			$Msg = "The registry type parameter is null or empty. - Please specify a valid registry type."
			Throw $Msg
		}

		## The script will create the specified registry key, name and value if it does not exists.
		$Msg = ("Setting the specified registry key '{0}' with the name '{1}' and with the value '{2}'" -f ($Key -split ':')[-1], $Name, $Value)
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name)

		## The script will create the specified registry key if it does not exists.
		If (!(Test-Path -LiteralPath $Key)) {
			[Bool]$KeyPathMatchForwardSlash = ($Key -match '/')
			If (($KeyPathMatchForwardSlash)) {
				$SetRegistryKey = & "$env:windir\System32\reg.exe" add "$(($Key).Substring($Key.IndexOf('::') + 2))"
			}
			Else {
				New-Item -Path $Key -ItemType 'Registry' -Force -ErrorAction 'Stop' | Out-Null
			}
		}

		## The script will create the specified registry name if it does not exists.
		$GetRegistryName = Get-Item -LiteralPath $Key -ErrorAction 'Stop' | Select-Object -ExpandProperty 'Property' -ErrorAction 'Stop'

		If (!($GetRegistryName -contains $Name)) {
			New-ItemProperty -LiteralPath $Key -Name $Name -Value $Value -PropertyType $Type -ErrorAction 'Stop' | Out-Null
		}
		Else {
			## The script will set the specified registry value
			If (($Name -eq '(Default)')) {
				## Setting the '(Default)' value with the following workaround because Set-ItemProperty contains a bug.
				$(Get-Item -LiteralPath $Key -ErrorAction 'Stop').OpenSubKey('','ReadWriteSubTree').SetValue($Null, $Value)
			}
			Else {
				Set-ItemProperty -LiteralPath $Key -Name $Name -Type $Type -Value $Value -ErrorAction 'Stop' | Out-Null
			}
		}
	}
	Catch {
		$ErrMsg = ("The function called '{0}' failed at line {1}: {2}" -f $MyInvocation.MyCommand.Name, $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $ErrMsg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name) -Severity 3
		Write-Error $ErrMsg -ErrorAction 'Stop'
	}
}

Function Check-BitLockerProtectionStatus {
	Try {
		$Msg = ("The script detects if the drive '{0}' is protected by BitLocker." -f $Global:Drive)
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name)

		## The script is detecting if the drive (For example, 'C:') is protected by BitLocker.
		$Global:GetBitLockerProtectionStatus = (Get-BitLockerVolume -MountPoint $Global:Drive).ProtectionStatus

		## Return result
		Return $Global:GetBitLockerProtectionStatus
	}
	Catch {
		$ErrMsg = ("The function called '{0}' failed at line {1}: {2}" -f $MyInvocation.MyCommand.Name, $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $ErrMsg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name) -Severity 3
		Write-Error $ErrMsg -ErrorAction 'Stop'
	}
}

Function Check-BitLockerVolumeStatus {
	Try {
		$Msg = ("The script detects if the drive '{0}' is fully encrypted by BitLocker." -f $Global:Drive)
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name)

		## The script is detecting if the drive (For example, 'C:') is fully encrypted by BitLocker.
		$Global:GetBitLockerVolumeStatus = (Get-BitLockerVolume -MountPoint $Global:Drive).VolumeStatus

		If (([String]::IsNullOrWhitespace($GetBitLockerVolumeStatus))) {
			$Global:GetBitLockerVolumeStatus = "Unknown"
		}

		## Return result
		Return $Global:GetBitLockerVolumeStatus
	}
	Catch {
		$ErrMsg = ("The function called '{0}' failed at line {1}: {2}" -f $MyInvocation.MyCommand.Name, $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $ErrMsg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name) -Severity 3
		Write-Error $ErrMsg -ErrorAction 'Stop'
	}
}

Function Invoke-BitLockerBackupToAAD {
	Try {
		## Set wait variable for WinEvent check.
		[Int]$WaitForWinEvent = 0

		## The script will gather the key protector data from the drive (For example, 'C:').
		$KeyProtector = (Get-BitLockerVolume -MountPoint $Global:Drive).KeyProtector | Where-Object {$_.keyProtectorType -eq 'RecoveryPassword'}

		## The script will back up each key protector ID to Azure AD.
		Foreach ($Member in $KeyProtector) {
			BackupToAAD-BitLockerKeyProtector -MountPoint $Global:Drive -KeyProtectorId $Member.KeyProtectorId | Out-Null
			$Msg = ("The Key Protector ID '{0}' will be backed up to Azure AD." -f $Member.KeyProtectorID)
			Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name)
		}

		## Wait for Event log to be created - It will time-out after 30 minutes!
		$Msg = "Wait for the BitLocker recovery key(s) to be transferred to Azure AD..."
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name)

		While ($WaitForWinEvent -lt 180) {
			## The script will wait 5 seconds before checking the event log.
			Start-Sleep -Seconds 5

			## The script checks the event log to see if the BitLocker recovery key(s) has been stored in Azure AD.
			If ((Check-EventLog)) {
				If (!(Check-RegistryKey)) {
					## The script will create the specified registry key, name, type and value.
					Set-RegistryKey
				}
				$Msg = "BitLocker recovery key(s) was transferred to Azure AD. - The script will continue..."
				Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name)

				$WaitForWinEvent = 180
				Start-Sleep -Seconds 5
			}
			Else {
				$Msg = "Whoopsie... Transferring the BitLocker recovery key(s) to Azure AD is taking a bit longer than expected! - The script will try again in 10 seconds."
				Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name) -Severity 2
				Start-Sleep -Seconds 5
			}
			$WaitForWinEvent++
		}
	}
	Catch {
		$ErrMsg = ("The function called '{0}' failed at line {1}: {2}" -f $MyInvocation.MyCommand.Name, $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $ErrMsg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name) -Severity 3
		Write-Error $ErrMsg -ErrorAction 'Stop'
	}
}

Function Exit-Script {
	Param (
		[Parameter(Mandatory=$true, HelpMessage="Provide an exit code (Mandatory)")]
		[ValidateNotNullOrEmpty()]
		[String]$ExitCode,

		[Parameter(Mandatory=$false, HelpMessage = "Specify an exit message (Optional)")]
		[ValidateNotNullOrEmpty()]
		[String]$ExitMessage
	)

	## Exit script
	If (($ExitCode -eq 0)) {
		$Msg = ("Exit code '{0}' - Remediation succeded." -f $ExitCode)
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name)
		Exit $ExitCode
	}
	Else {
		$Msg = ("Exit code '{0}' - Remediation failed." -f $ExitCode)
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name) -Severity 3
		Exit $ExitCode
	}
}

## Invoke remediation
& $Remediation

## Exit
Exit-Script -ExitCode $Global:ExitCode
<#
.SYNOPSIS
	The detection script is used to check if the Bitlocker recovery key(s) is stored in Azure AD.

.DESCRIPTION
	The detection script will check if the device is protected by Bitlocker and if the Bitlocker recovery key(s) is stored in Azure AD.

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

	Scenario: The system drive (For example, 'C:') is not protected by Bitlocker.
	Output: "NOT PROTECTED: Bitlocker protection status on system drive 'C:' is = Off. - Please ensure that the Bitlocker protection is turned on and not temporarily suspended."

	Scenario: Bitlocker recovery key(s) is stored in Azure AD.
	Output: "PROTECTED - ALL IS OK: Bitlocker recovery key(s) is stored in Azure AD, do nothing."

	Scenario: Bitlocker recovery key(s) is not stored in Azure AD.
	Output: "PROTECTED - START REMEDIATION: Bitlocker recovery key(s) is not stored in Azure AD. - Starting remediation script..."

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

		Valid examples:
		Write-Log -Message "You message here"
		Write-Log -Message "You message here" -ComponentName "Demo"
		Write-Log -Message "You message here" -ComponentName "Demo" -Severity "3"

	Function (Split-Log)

		This function is called by the Write-Log function to split the log file when it reaches the specified max size.

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

		Valid examples (HKEY_LOCAL_MACHINE)
		Check-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "(Default)" -Value ""
		Check-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "SystemRoot" -Value "C:\WINDOWS"
		Check-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "SystemRoot" -Value ""
		Check-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "" -Value ""

		Valid examples (HKEY_CURRENT_USER)
		Check-RegistryKey -Key "HKCU:\Control Panel\Desktop" -Name "(Default)" -Value ""
		Check-RegistryKey -Key "HKCU:\Control Panel\Desktop" -Name "WallPaper" -Value "C:\Windows\web\wallpaper\Windows\img19.jpg"
		Check-RegistryKey -Key "HKCU:\Control Panel\Desktop" -Name "WallPaper" -Value ""
		Check-RegistryKey -Key "HKCU:\Control Panel\Desktop" -Name "" -Value ""

		Valid examples (HKEY_CLASSES_ROOT)
		Check-RegistryKey -Key "HKCR:\MIME\Database\Content Type\application/hta" -Name "(Default)" -Value ""
		Check-RegistryKey -Key "HKCR:\MIME\Database\Content Type\application/hta" -Name "Extension" -Value ".hta"
		Check-RegistryKey -Key "HKCR:\MIME\Database\Content Type\application/hta" -Name "Extension" -Value ""
		Check-RegistryKey -Key "HKCR:\MIME\Database\Content Type\application/hta" -Name "" -Value ""

	Function (Convert-RegistryKey)

		This function is called by the Check-RegistryKey function to convert the registry key hive to the full path.

	Function (Check-EventLog)

		You can use this function with the default pre-defined variables or specify your values when calling the function.
		Be aware that all parameters in this function are mandatory.

		Valid examples:
		Check-EventLog -EventProviderName "Microsoft-Windows-BitLocker-API" -EventTime "01/01/2022 00:00:00" -EventID "845"

	Function (Check-BitlockerProtectionStatus)

		This function is called to check if the system drive (For example, 'C:') is protected by Bitlocker.

.PARAMETER

.EXAMPLE

.NOTES
	Created on:   26-11-2021
	Modified:     09-12-2022
	Author:       Sune Thomsen
	Version:      2.0
	Mail:         stn@mindcore.dk
	Twitter:      https://twitter.com/SuneThomsenDK

	Changelog:
	----------
	26-11-2021 - v1.0 - The Creation date of this script
	03-05-2022 - v1.1 - Detection for Bitlocker protection status added to the script
	17-06-2022 - v1.2 - New logic and better reporting have been added to the script
	07-10-2022 - v1.3 - Code review and cleanup of the script
	09-10-2022 - v1.4 - Minor changes to the script output
	20-10-2022 - v1.5 - Minor changes to the detection of Bitlocker protection status and script output
	09-12-2022 - v2.0 - The script has been rewritten and now contains a prerequisite check, new logic, structure, functions, etc.

.LINK
	https://github.com/SuneThomsenDK
#>

## Variables
## Set the global variable(s) used throughout the script

	## Set syestem variable(s)
	[String]$Global:ScriptName = $MyInvocation.MyCommand.Name
	[String]$Global:SystemDrive = $env:SystemDrive
	[String]$Global:UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
	[Bool]$Global:IsPowerShell64bitVersion = [Environment]::Is64BitProcess
	[Bool]$Global:IsSystemContext = [System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem
	[Bool]$Global:SkipPrereq = $false

	## Set log variable(s)
	[String]$Global:LogLocation = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
	[String]$Global:LogName = "IntuneProactiveRemediation"
	[String]$Global:LogComponent = "DetectionScript"
	[String]$Global:LogSubject = "Bitlocker Backup to AAD"
	[Int]$Global:LogMaxSize = 250KB

	## Set registry variable(s)
	[String]$Global:DefaultRegistryKey = "HKLM:\SOFTWARE\CompanyName\Bitlocker" ## <---- Change "CompanyName" to your own company name.
	[String]$Global:DefaultRegistryName = "BitlockerBackupToAAD"
	[String]$Global:DefaultRegistryValue = "True"

	## Set event log variable(s)
	[String]$Global:DefaultEventProviderName = "Microsoft-Windows-BitLocker-API"
	[DateTime]$Global:DefaultEventTime = "01/01/2022 00:00:00" ## <---- MM/dd/yyyy HH:mm:ss
	[Int]$Global:DefaultEventID = "845"

## Detection
$Detection = {
	## Detection - Do NOT make changes below this line unless you know what you are doing!
	$Msg = (" ----------------------------------------------------- Invoke Detection ({0}) ----------------------------------------------------- " -f $Global:UserName)
	Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg)

	Try {
		## The script checks whether it runs under the system account and in the 64-bit version of PowerShell.
		$Msg = "The script checks whether it runs under the system account and in the 64-bit version of PowerShell."
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg)

		If (!($Global:SkipPrereq)) {
			If (!($Global:IsSystemContext)) {
				$Msg = "The script is not running under the system account. - Please run the script as system."
				Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -Severity 2
				Write-Output ("PREREQ: {0}" -f $Msg)
				Exit 1
			}
			ElseIf (!($Global:IsPowerShell64bitVersion)) {
				$Msg = "The script is not running in 64-bit PowerShell. - Please run the script in 64-bit PowerShell."
				Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -Severity 2
				Write-Output ("PREREQ: {0}" -f $Msg)
				Exit 1
			}
			Else {
				$Msg = "Prerequisite check passed. - The script will continue..."
				Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg)
			}
		}
		Else {
			$Msg = "Prerequisite check skipped. - The script will continue..."
			Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -Severity 2
		}

		## The script is detecting if the system drive (For example, 'C:') is protected by Bitlocker.
		If (((Check-BitlockerProtectionStatus) -eq 'On')) {
			$Msg = ("System drive '{0}' is protected by Bitlocker. - The script will continue..." -f $Global:SystemDrive)
			Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg)
		}
		Else {
			$Msg = ("Bitlocker protection status of system drive '{0}' is = {1}. - Please ensure that the Bitlocker protection is turned on and not temporarily suspended." -f $Global:SystemDrive, $Global:GetBitlockerProtectionStatus)
			Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -Severity 2
			Write-Output ("NOT PROTECTED: {0}" -f $Msg)
			Exit 1
		}

		## The script checks the event log or the registry to see if the Bitlocker recovery key(s) has been stored in Azure AD.
		$Msg = "The script checks the event log or registry to see if the Bitlocker recovery key(s) has been stored in Azure AD."
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg)

		If (((Check-EventLog)) -or ((Check-RegistryKey))) {
			$Msg = "Bitlocker recovery key(s) is stored in Azure AD, do nothing."
			Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg)
			Write-Output ("PROTECTED - ALL IS OK: {0}" -f $Msg)
			Exit 0
		}
		Else {
			$Msg = "Bitlocker recovery key(s) is not stored in Azure AD. - Starting remediation script..."
			Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -Severity 2
			Write-Output ("PROTECTED - START REMEDIATION: {0}" -f $Msg)
			Exit 1
		}
	}
	Catch {
		$ErrMsg = ("Whoopsie... Something failed at line {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $ErrMsg) -Severity 3
		Write-Output ("ERROR: {0}" -f $ErrMsg)
		Exit 1
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
		[String]$LogTime = (Get-Date -Format 'HH:mm:ss.fffffff')
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
		## The script checks that the specified event ID parameter is not null or empty.
		If (!($EventID)) {
			$Msg = "The event ID parameter is null or empty. - Please specify a valid event ID."
			Throw $Msg
		}

		## The script checks the event log for events that match the specified event ID.
		$GetEventID = (Get-WinEvent -ProviderName $EventProviderName -ErrorAction 'SilentlyContinue' | Where-Object {($_.TimeCreated -gt $EventTime) -and ($_.ID -match $EventID)}).ID | Sort-Object -Unique

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
		[String]$Name = $Global:DefaultRegistryName,

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

Function Check-BitlockerProtectionStatus {
	Try {
		$Msg = ("The script detects if the system drive '{0}' is protected by Bitlocker." -f $Global:SystemDrive)
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $Msg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name)

		## The script is detecting if the system drive (For example, 'C:') is protected by Bitlocker.
		$Global:GetBitlockerProtectionStatus = (Get-BitLockerVolume -MountPoint $Global:SystemDrive).ProtectionStatus

		## Return result
		Return $Global:GetBitlockerProtectionStatus
	}
	Catch {
		$ErrMsg = ("The function called '{0}' failed at line {1}: {2}" -f $MyInvocation.MyCommand.Name, $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
		Write-Log -Message ("[{0}]: {1}" -f $Global:LogSubject, $ErrMsg) -ComponentName ("{0}-({1})" -f $Global:LogComponent, $MyInvocation.MyCommand.Name) -Severity 3
		Write-Error $ErrMsg -ErrorAction 'Stop'
	}
}

## Invoke detection
& $Detection
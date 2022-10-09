<#
.DESCRIPTION
	Detection script will check if bitlocker key has been backed up to Azure AD.

	The recommended settings in Endpoint analytics | Proactive remediations

		Run this script using the logged-on credentials: No
		Enforce script signature check: No
		Run script in 64-bit PowerShell: Yes

.NOTES
	Created on:   26-11-2021
	Modified:     09-10-2022
	Author:       Sune Thomsen
	Version:      1.4
	Mail:         stn@mindcore.dk
	Twitter:      https://twitter.com/SuneThomsenDK

	Changelog:
	----------
	26-11-2021 - v1.0 - The Creation date of this script
	03-05-2022 - v1.1 - Detection for Bitlocker protection status added to the script
	17-06-2022 - v1.2 - New logic and better reporting have been added to the script
	07-10-2022 - v1.3 - Code review and cleanup of the script
	09-10-2022 - v1.4 - Minor changes to the script output

.LINK
	https://github.com/SuneThomsenDK
#>

# Functions
Function Write-Log {
	Param (
		[Parameter(Mandatory=$true, HelpMessage = "Message added to the log file.")]
		[ValidateNotNullOrEmpty()]
		[String]$Message,

		[Parameter(Mandatory=$false, HelpMessage = "Specify severity for the message. 1 = Information, 2 = Warning, 3 = Error.")]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("1", "2", "3")]
		[String]$Severity = "1"
	)

	#Set log file max size
	If (($LogMaxSize -eq $Null)) {
		$Script:LogMaxSize = 250KB
	}

	# Trying to create log directory and filename if it does not exist
	If (!(Test-Path -Path "$LogDir")) {
		Try {
			New-Item -Path $LogDir -ItemType Directory | Out-Null
			$Script:LogDirFound = "True"
		}
		Catch {
			# Log directory creation failed. Write error on screen and stop the script.
			Write-Error -Message "Log directory creation failed. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)" -ErrorAction Stop
		}
	}
	Else {
		If (($LogDirFound -eq $Null)) {
			$Script:LogDirFound = "True"
		}
	}

	If (($LogFile -eq $Null)) {
		$Script:LogFile = "$($LogFileName).log"
	}

	# Combine log directory with log file
	If (($LogFilePath -eq $Null)) {
		$Script:LogFilePath = Join-Path -Path "$LogDir" -ChildPath "$LogFile"
	}

	# Creating timestamp for the log entry
	If (($Global:TimezoneBias -eq $Null)) {
		[Int]$Global:TimezoneBias = [System.TimeZone]::CurrentTimeZone.GetUtcOffset([DateTime]::Now).TotalMinutes
	}

	If (!($LogTime -eq $Null)) {
		$Script:LogTime = -Join @((Get-Date -Format "HH:mm:ss.fff"), $TimezoneBias)
	}
	Else {
		$Script:LogTime = -Join @((Get-Date -Format "HH:mm:ss.fff"), $TimezoneBias)
	}

	If (!($LogDate -eq $Null)) {
		$Script:LogDate = (Get-Date -Format "MM-dd-yyyy")
	}
	Else {
		$Script:LogDate = (Get-Date -Format "MM-dd-yyyy")
	}

	# Creating context, component and log entry
	If (($LogContext -eq $Null)) {
		$Script:LogContext = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
	}

	If (($LogComponent -eq $Null)) {
		$Script:LogComponent = "ProactiveRemediation"
	}

	$LogEntry = "<![LOG[$($Message)]LOG]!><time=""$($LogTime)"" date=""$($LogDate)"" component=""$($LogComponent)"" context=""$($LogContext)"" type=""$($Severity)"" thread=""$($PID)"" file=""$($LogFileName)"">"

	# Trying to write log entry to log file
	If (!($LogFilePath -eq $Null)) {
		Try {
			Out-File -InputObject $LogEntry -Append -NoClobber -Encoding Default -FilePath $LogFilePath
		}
		Catch {
			# Failed to append log entry. Write warning on screen but let the script continue.
			Write-Warning -Message "Failed to append log entry to $($LogFile). Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
		}
	}
	Else {
		# Failed to append log entry. Write warning on screen but let the script continue.
		Write-Warning -Message "Failed to append log entry. Error message: Log file not found."
	}

	# Check log size and split if it's greather than 250KB
	If ((Test-Path -Path "$LogFilePath") -and (Get-ChildItem -Path $LogFilePath).Length -ge $LogMaxSize) {
		Try {
			Invoke-SplitLog
			Write-Log -Message "The log file has been split, older log entries can be found here:  $($SplitLogFilePath)" -Severity 2
		}
		Catch {
			# Failed to split the log file. Write warning on screen but let the script continue.
			Write-Warning -Message "Failed to split the log file."
		}
	}
}

Function Invoke-SplitLog {
	$SplitLogFileTime = (Get-Date).toString("yyyyMMdd-HHmmss")
	$SplitLogFile = "$($LogFileName)_$($SplitLogFileTime).log"
	$Script:SplitLogFilePath = Join-Path -Path "$LogDir" -ChildPath "$SplitLogFile"

	$Reader = New-Object System.IO.StreamReader("$LogFilePath")
	While(($Line = $Reader.ReadLine()) -ne $Null) {
		Add-Content -Path $SplitLogFilePath -Value $Line
	}
	$Reader.Close()

	# Remove old log file
	Remove-Item -Path $LogFilePath -Force

	# Compress the archived log file
	Compact /C $SplitLogFilePath | Out-Null
}

# Proactive Remediation Script

	# Set log variable(s)
	$LogDir = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
	$LogFileName = "IntuneProactiveRemediation"
	$Subject = "Bitlocker key to AAD"

	# Set bitlocker variabl(s)
	# Used for detecting if the mount point (For example, drive letter 'C:\') is protected by Bitlocker.
	$BitlockerStatus = (Get-BitLockerVolume -MountPoint "$env:SystemDrive").ProtectionStatus

	# Set registry variable(s)
	$RegistryPath = "HKLM:\SOFTWARE\CompanyName\Bitlocker" # <---- Change "CompanyName" to your own company name.
	$RegistryName = "BitlockerKeyToAAD"
	$RegistryValue = "True"

	# Set event log variable(s)
	$EventLogTime = "01/01/2022 00:00:00" # <---- MM/dd/yyyy HH:mm:ss
	$EventLogIDValue = "845" # <---- Do NOT change this value!

# Detection - Do NOT make changes below this line unless you know what you are doing!
$Msg = " ----------------------------------------------------- Detection ----------------------------------------------------- "
Write-Host $Msg
Write-Log -Message "[$($Subject)]: $($Msg)"

	If (($BitlockerStatus -eq "On")) {
		$Msg = "Mount point '$("$env:SystemDrive")' is protected by Bitlocker. The script will continue..."
		Write-Host $Msg
		Write-Log -Message "[$($Subject)]: $($Msg)"

		# Set registry variable(s) - Do NOT changes these variables!
		$GetRegistryValue = (Get-ItemProperty $RegistryPath -ErrorAction SilentlyContinue).$RegistryName

		# Set event log variable(s) - Do NOT changes these variables!
		$GetEventLogID = (Get-WinEvent -ProviderName Microsoft-Windows-BitLocker-API -ErrorAction SilentlyContinue | Where-Object {($_.TimeCreated -gt $EventLogTime) -and ($_.ID -match "$EventLogIDValue")}).ID | Sort-Object -Unique

		Try {
			If ((($GetRegistryValue -eq $RegistryValue)) -or (($GetEventLogID -eq $EventLogIDValue))) {
				$Msg = "Bitlocker key(s) is stored in Azure AD, do nothing."
				Write-Host "PROTECTED - ALL IS OK: $($Msg)"
				Write-Log -Message "[$($Subject)]: $($Msg)"
				Exit 0
			}
			Else {
				$Msg = "Bitlocker key(s) is NOT stored in Azure AD. Starting remediation script..."
				Write-Host "PROTECTED - START REMEDIATION: $($Msg)"
				Write-Log -Message "[$($Subject)]: $($Msg)" -Severity 2
				Exit 1
			}
		}
		Catch {
			$Msg = "The Proactive Remediation script failed. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
			Write-Host "ERROR: $($Msg)"
			Write-Log -Message "[$($Subject)]: $Msg" -Severity 3
			Exit 1
		}
	}
	Else {
		$Msg = "Bitlocker protection status on mount point '$("$env:SystemDrive")' is = $((Get-BitLockerVolume -MountPoint "$env:SystemDrive").ProtectionStatus). Ensure that the Bitlocker protection is turned on and not temporarily suspended."
		Write-Host "NOT PROTECTED: $($Msg)"
		Write-Log -Message "[$($Subject)]: $($Msg)" -Severity 2
		Exit 0
	}
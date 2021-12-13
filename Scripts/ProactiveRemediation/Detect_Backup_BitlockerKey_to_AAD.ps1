<#
.DESCRIPTION
	Detection script will check if bitlocker key has been backed up to Azure AD.

.NOTES
	Created on:   26-11-2021
	Modified:     03-12-2021
	Author:       Sune Thomsen
	Version:      1.0.2
	Mail:         stn@mindcore.dk
	Twitter:      https://twitter.com/SuneThomsenDK

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

	# Set variables
	$LogDir = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
	$LogFileName = "IntuneProactiveRemediation"
	$Subject = "Bitlocker Key to AAD"

	$RegistryPath = "HKLM:\Software\Xellia\Bitlocker"
	$RegistryName = "BackedUpToAAD"
	$RegistryValue = "TRUE"

	$GetRegistry = Get-ItemProperty $RegistryPath -Name $RegistryName -ErrorAction SilentlyContinue
	$GetRegistryValue = $GetRegistry.$RegistryName

	$EventLogTime = "12/03/2021 00:00:00"
	$EventLogIDValue = "845"
	$GetEventLog = Get-WinEvent -ProviderName Microsoft-Windows-BitLocker-API | Where-Object {($_.TimeCreated -gt $EventLogTime)}
	$EventLogID = $GetEventLog.ID

	Try {
		If ((($GetRegistryValue -eq $RegistryValue)) -or (($EventLogID -eq $EventLogIDValue))) {
			$Msg = "Bitlocker Key is backed up to Azure AD, do nothing."
			Write-Host $Msg
			Write-Log -Message "[$($Subject)]: $($Msg)"
			Exit 0
		}
		Else {
			$Msg = "Bitlocker Key is NOT backed up to Azure AD. Starting remediation script..."
			Write-Host $Msg
			Write-Log -Message "[$($Subject)]: $($Msg)" -Severity 2
			Exit 1
		}
	}
	Catch {
		$ErrMsg = $_.Exception.Message
		Write-Log -Message "[$($Subject)]: The Proactive Remediation script failed. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($ErrMsg)" -Severity 3
		Write-Error $ErrMsg
		Exit 1
	}
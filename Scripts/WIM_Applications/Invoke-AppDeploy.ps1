<#
.SYNOPSIS
	Mount WIM, Install, Uninstall or Repair Application and Unmount WIM.

.DESCRIPTION
	The purpose of this script is to mount a WIM containing an application that will
	be installed, uninstalled or repaired and then unmount the WIM again.

	So before using this script, you must capture the application into a WIM file and
	this can be done with the DISM example further down in this description.

	Capturing applications as WIM and the use of this script reduces our application
	deployment time through Configuration Manager by 30-60% depending on the hardware
	configuration and the application size.

	We are old school and we use CMD scripts for application deployment in our environment.
	But it's pretty easy to modify the deployment mode variables found in the "Begin" script
	block to support other formats like .msi, .exe or .ps1 file.


	DISM Example.
	                    Dism.exe /Capture-Image /ImageFile:C:\Temp\Application.wim /CaptureDir:"C:\Temp\Java" /Name:"Oracle" /Description:"Java" /Compress:fast

	NOTE. I'll recommend using "/Compress:fast" if you are using deduplication. Some wise people state that
	      "/Compress:max" is no good if you are using deduplication. And I tend to listen to wise people ;)


	CMD Example (Current).

	                    $FilePath = Join-Path -Path "$MountDir" -ChildPath "Install.cmd"
	                    $Process = "cmd.exe"
	                    $Arguments = @(
	                        "/c",
	                        """$FilePath""",
	                        "> nul",
	                        "&& exit"
	                    )


	MSI Example.

	    Change this ->  $FilePath = Join-Path -Path "$MountDir" -ChildPath "app.msi"
	    Change this ->  $Process = "msiexec.exe"
	    Change this ->  $Arguments = @(
	                        "/I",
	                        """$FilePath""",
	                        "/qn",
	                        "REBOOT=ReallySuppress"
	                    )


	EXE Example.

	    Change this ->  $FilePath = Join-Path -Path "$MountDir" -ChildPath "app.exe"
	    Change this ->  $Process = "cmd.exe"
	    Change this ->  $Arguments = @(
	                        "/c",
	                        """$FilePath""",
	                        "/s",
	                        "&& Exit"
	                    )


	PS1 Example.

	    Change this ->  $FilePath = Join-Path -Path "$MountDir" -ChildPath "Install.ps1"
	    Change this ->  $Process = "powershell.exe"
	    Change this ->  $Arguments = @(
	                        "-NoProfile",
	                        "-File",
	                        """$FilePath""",
	                        "-Param_1 ""ParamValue""",
	                        "-Param_2 ""ParamValue"""
	                    )


.PARAMETER MountDir
	Changes the default location from ".\Mount" to the location specified.

.PARAMETER SourceWIM
	Changes the default location and filename from ".\Application.wim" to the location and filename specified.

.PARAMETER LogDir
	Changes the default location from "$env:SystemRoot\Temp" (C:\WINDOWS\Temp) to the location specified.

.PARAMETER AppName
	Specify a name of the application to be deployed, e.g. Microsoft Office Professional Plus 2019.

.PARAMETER DeploymentMode
	Specify whether to Install, Uninstall or Repair the application, e.g. .\Invoke-AppDeploy.ps1 -DeploymentMode "Install" -AppName "Microsoft Office Professional Plus 2019"

.EXAMPLE
	.
	# Mount WIM to the default location, install the application, unmount WIM and cleanup the mount directory.
	.\Invoke-AppDeploy.ps1 -DeploymentMode "Install" -AppName "Microsoft Office Professional Plus 2019"

	# Mount WIM to the default location, repair the application, unmount WIM and cleanup the mount directory.
	.\Invoke-AppDeploy.ps1 -DeploymentMode "Repair" -AppName "Microsoft Office Professional Plus 2019"

	# Mount WIM to the default location, uninstall the application, unmount WIM and cleanup the mount directory.
	.\Invoke-AppDeploy.ps1 -DeploymentMode "Uninstall" -AppName "Microsoft Office Professional Plus 2019"

	# Mount WIM to the default location, install the application, unmount WIM and cleanup the mount directory, with -Verbose added for troubleshooting purposes.
	.\Invoke-AppDeploy.ps1 -DeploymentMode "Install" -AppName "Microsoft Office Professional Plus 2019" -Verbose

	# Mount WIM to the default location, use a custom log location, install the application, unmount WIM and cleanup the mount directory.
	.\Invoke-AppDeploy.ps1 -DeploymentMode "Install" -AppName "Microsoft Office Professional Plus 2019" -LogDir "C:\Temp\Log"

	# Mount WIM to an custom location, install the application, unmount WIM and cleanup the mount directory.
	.\Invoke-AppDeploy.ps1 -MountDir "C:\Temp\Mount" -DeploymentMode "Install" -AppName "Microsoft Office Professional Plus 2019"

	# Mount WIM to an custom location, use a custom log location, install the application, unmount WIM and cleanup the mount directory.
	.\Invoke-AppDeploy.ps1 -MountDir "C:\Temp\Mount" -DeploymentMode "Install" -AppName "Microsoft Office Professional Plus 2019" -LogDir "C:\Temp\Log"

.NOTES
	Version:       1.0.4
	Filename:      Invoke-AppDeploy.ps1
	Author:        Sune Thomsen
	Contact:       @SuneThomsenDK
	Created:       24-08-2020
	Modified:      06-10-2020

	Contributors:  @MDaugaard_DK

	Version History:
	1.0.0 - (24-08-2020) Script created.
	1.0.1 - (28-08-2020) Added correct exit code and changed the logic in the Invoke-ApplicationDeployment function.
	1.0.2 - (31-08-2020) Added Invoke-SplitLog function to the script, which will split logs when it become larger than 250KB.
	1.0.3 - (01-09-2020) Added VERBOSE to the script.
	1.0.4 - (06-10-2020) Added check for already mounted images.

.LINK
	https://github.com/SuneThomsenDK
#>
[CmdletBinding(SupportsShouldProcess = $true)]Param (
	[Parameter(Mandatory = $false, HelpMessage = 'Changes the default location from ".\Mount" to the location specified.')]
	[ValidateNotNullOrEmpty()]
	[System.IO.FileInfo]
	[String]$MountDir = ".\Mount",

	[Parameter(Mandatory = $false, HelpMessage = 'Changes the default location and filename from ".\Application.wim" to the location and filename specified.')]
	[ValidateNotNullOrEmpty()]
	[System.IO.FileInfo]
	[String]$SourceWIM = ".\Application.wim",

	[Parameter(Mandatory = $false, HelpMessage = 'Changes the default location from "$env:SystemRoot\Temp" (C:\WINDOWS\Temp) to the location specified.')]
	[ValidateNotNullOrEmpty()]
	[System.IO.FileInfo]
	[String]$LogDir = "$env:SystemRoot\Temp",

	[Parameter(Mandatory = $true, HelpMessage = 'Specify a name of the application to be deployed, e.g. Microsoft Office Professional Plus 2019.')]
	[ValidateNotNullOrEmpty()]
	[string]$AppName,

	[Parameter(Mandatory = $true, HelpMessage = 'Specify whether to Install, Uninstall or Repair the application, e.g. Invoke-AppDeploy.ps1 -DeploymentMode "Install" -AppName "Microsoft Office Professional Plus 2019".')]
	[ValidateNotNullOrEmpty()]
	[ValidateSet("Install", "Uninstall", "Repair")]
	[string]$DeploymentMode
)

Begin {
	# Set the variables used throughout the script
	$ScriptName = $MyInvocation.MyCommand.Name
	Write-Verbose "Script name:  $($ScriptName)"

	$ReturnCode = 0
	Write-Verbose "Return code:  $($ReturnCode)"

	Switch ($DeploymentMode) {
		"Install" {
			$FilePath = Join-Path -Path "$MountDir" -ChildPath "Install.cmd"
			$Process = "cmd.exe"
			$Arguments = @(
				"/c",
				"""$FilePath""",
				"> nul",
				"&& exit"
			)
		}
		"Uninstall" {
			$FilePath = Join-Path -Path "$MountDir" -ChildPath "Uninstall.cmd"
			$Process = "cmd.exe"
			$Arguments = @(
				"/c",
				"""$FilePath""",
				"> nul",
				"&& exit"
			)
		}
		"Repair" {
			$FilePath = Join-Path -Path "$MountDir" -ChildPath "Repair.cmd"
			$Process = "cmd.exe"
			$Arguments = @(
				"/c",
				"""$FilePath""",
				"> nul",
				"&& exit"
			)
		}
	}
	Write-Verbose "Deployment Mode:  $($DeploymentMode)"
	Write-Verbose "Deployment FilePath:  $($FilePath)"
	Write-Verbose "Deployment Process:  $($Process)"
	Write-Verbose "Deployment Arguments:  $($Arguments)"
}
Process {
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
			Write-Verbose "Write-Log - Log Max Size:  $($LogMaxSize) Bytes"
		}

		# Trying to create log directory and filename if it does not exist
		If (!(Test-Path -Path "$LogDir")) {
			Try {
				New-Item -Path $LogDir -ItemType Directory | Out-Null
				$Script:LogDirFound = "True"
				Write-Verbose "Write-Log - Log Directory:  $($LogDir)"
			}
			Catch {
				# Log directory creation failed. Write error on screen and stop the script.
				Write-Error -Message "Log directory creation failed. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)" -ErrorAction Stop
			}
		}
		Else {
			If (($LogDirFound -eq $Null)) {
				$Script:LogDirFound = "True"
				Write-Verbose "Write-Log - Log Directory:  $($LogDir)"
			}
		}

		If (($LogFile -eq $Null)) {
			$Script:LogFile = "$($ScriptName).log"
			Write-Verbose "Write-Log - Log Filename:  $($LogFile)"
		}

		# Combine log directory with log file
		If (($LogFilePath -eq $Null)) {
			$Script:LogFilePath = Join-Path -Path "$LogDir" -ChildPath "$LogFile"
			Write-Verbose "Write-Log - Log Path:  $($LogFilePath)"
		}

		# Creating timestamp for the log entry
		If (($Global:TimezoneBias -eq $Null)) {
			[Int]$Global:TimezoneBias = [System.TimeZone]::CurrentTimeZone.GetUtcOffset([DateTime]::Now).TotalMinutes
			Write-Verbose "Write-Log - Log Timezone Bias:  $($TimezoneBias)"
		}

		If (!($LogTime -eq $Null)) {
			$Script:LogTime = -Join @((Get-Date -Format "HH:mm:ss.fff"), $TimezoneBias)
		}
		Else {
			$Script:LogTime = -Join @((Get-Date -Format "HH:mm:ss.fff"), $TimezoneBias)
			Write-Verbose "Write-Log - Log Time:  $($LogTime)"
		}

		If (!($LogDate -eq $Null)) {
			$Script:LogDate = (Get-Date -Format "MM-dd-yyyy")
		}
		Else {
			$Script:LogDate = (Get-Date -Format "MM-dd-yyyy")
			Write-Verbose "Write-Log - Log Date:  $($LogDate)"
		}

		# Creating context, component and log entry
		If (($LogContext -eq $Null)) {
			$Script:LogContext = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
			Write-Verbose "Write-Log - Log Context:  $($LogContext)"
		}

		If (($LogComponent -eq $Null)) {
			$Script:LogComponent = "ApplicationDeployment"
			Write-Verbose "Write-Log - Log Component:  $($LogComponent)"
		}

		$LogEntry = "<![LOG[$($Message)]LOG]!><time=""$($LogTime)"" date=""$($LogDate)"" component=""$($LogComponent)"" context=""$($LogContext)"" type=""$($Severity)"" thread=""$($PID)"" file=""$($ScriptName)"">"

		# Trying to write log entry to log file
		If (!($LogFilePath -eq $Null)) {
			Try {
				Out-File -InputObject $LogEntry -Append -NoClobber -Encoding Default -FilePath $LogFilePath
				Write-Verbose "Write-Log - Log Entry:  $($LogEntry)"
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
		$SplitLogFile = "$($ScriptName)_$($SplitLogFileTime).log"
		$Script:SplitLogFilePath = Join-Path -Path "$LogDir" -ChildPath "$SplitLogFile"
		Write-Verbose "Invoke-SplitLog - Log Split Timestamp:  $($SplitLogFileTime)"
		Write-Verbose "Invoke-SplitLog - Log Split Filename:  $($SplitLogFile)"
		Write-Verbose "Invoke-SplitLog - Log Split Path:  $($SplitLogFilePath)"

		$Reader = New-Object System.IO.StreamReader("$LogFilePath")
		While(($Line = $Reader.ReadLine()) -ne $Null) {
			Add-Content -Path $SplitLogFilePath -Value $Line
		}
		$Reader.Close()

		# Remove old log file
		Remove-Item -Path $LogFilePath -Force
		Write-Verbose "Invoke-SplitLog - Log File Deleted:  $($LogFilePath)"

		# Compress the archived log file
		Compact /C $SplitLogFilePath | Out-Null
		Write-Verbose "Invoke-SplitLog - Archived Log File Compressed:  $($SplitLogFilePath)"
	}

	Function Invoke-MountImage {
		Write-Log -Message "  - Directory mount verification . . ."
		# Trying to create mount directory if it does not exist
		If (!(Test-Path -Path "$MountDir")) {
			Try {
				Write-Log -Message "  - A mount directory was not found. Trying to create mount directory:  $($MountDir)" -Severity 2
				New-Item -Path $MountDir -ItemType Directory | Out-Null
				Write-Verbose "Invoke-MountImage - Mount Directory:  $($MountDir)"
				Write-Log -Message "  - Creation of the mount directory was successful"
			}
			Catch {
				# Mount directory creation failed. Set return code and write log entry.
				$Script:ReturnCode = 1
				Write-Verbose "Invoke-MountImage - Return code:  $($ReturnCode)"
				Write-Log -Message "  - Mount directory creation failed. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)" -Severity 3
			}
		}
		Else {
			Write-Verbose "Invoke-MountImage - Mount Directory:  $($MountDir)"
			Write-Log -Message "  - A mount directory was found:  $($MountDir)"
		}

		If (($ReturnCode -eq 0)) {
			# Checking for already mounted images.
			Write-Log -Message "  - Checking for already mounted images . . ."
			$CheckMount = Get-WindowsImage -Mounted
			If (($CheckMount)) {
				Write-Log -Message "  - A mounted image was found." -Severity 2
				Write-Log -Message "  - Path:  $($CheckMount.path)" -Severity 2
				Write-Log -Message "  - ImagePath:  $($CheckMount.ImagePath)" -Severity 2
				Write-Log -Message "  - ImageIndex:  $($CheckMount.ImageIndex)" -Severity 2
				Write-Log -Message "  - MountMode:  $($CheckMount.MountMode)" -Severity 2
				Write-Log -Message "  - MountStatus:  $($CheckMount.MountStatus)" -Severity 2
				Write-Log -Message "  - Trying to unmount image:  $($CheckMount.ImagePath)"

					Get-WindowsImage -Mounted | ForEach-Object {$_ | Dismount-WindowsImage -Discard -ErrorVariable wimerr | Out-Null; if ([bool]$wimerr) {$errflag = $true}}; If (-not $errflag) {Clear-WindowsCorruptMountPoint | Out-Null}

				# Checking for already mounted images again.
				$CheckMount = Get-WindowsImage -Mounted
				If (!($CheckMount)) {
					Write-Log -Message "  - Image unmount was successful"
					Write-Log -Message "  - Trying to mount image:  $($SourceWIM)"
				}
				Else {
					Write-Log -Message "  - Image unmount failed. But the script will try to mount image:  $($SourceWIM)"
				}
			}
			Else {
				Write-Log -Message "  - No mounted images was found. Trying to mount image:  $($SourceWIM)"
			}

			Try {
				# Trying to mount image
				Mount-WindowsImage -ImagePath "$SourceWIM" -Index 1 -Path $MountDir | Out-Null
				Write-Verbose "Invoke-MountImage - Mounted Image:  $($SourceWIM)"
				Write-Log -Message "  - Image mount was successful"
			}
			Catch {
				# Image mount failed. Set return code and provide help for further investigation.
				$Script:ReturnCode = 1
				Write-Verbose "Invoke-MountImage - Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
				Write-Verbose "Invoke-MountImage - Return code:  $($ReturnCode)"
				Write-Log -Message "  - Image mount failed. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)" -Severity 3
				If (($_.Exception.Message -Match "wim is already mounted") -or ($_.Exception.Message -Match "wim er allerede tilsluttet") -or ($_.Exception.Message -Match "wim er allerede montert")) {
					Write-Log -Message "For further information, please examine the DISM log:  C:\WINDOWS\Logs\DISM\dism.log" -Severity 2
					Write-Log -Message " " -Severity 2
					Write-Log -Message "Check for mounted image with one of the below commands" -Severity 2
					Write-Log -Message "-------------------------------------------------------------------" -Severity 2
					Write-Log -Message "DISM command:  Dism /Get-MountedImageInfo" -Severity 2
					Write-Log -Message 'PowerShell command:  Get-WindowsImage -Mounted' -Severity 2
					Write-Log -Message " " -Severity 2
					Write-Log -Message "Try unmounting the image with one of the below commands" -Severity 2
					Write-Log -Message "-------------------------------------------------------------------" -Severity 2
					Write-Log -Message "DISM command:  Dism /Unmount-Image /MountDir:$($MountDir) /Discard" -Severity 2
					Write-Log -Message 'PowerShell command:  Get-WindowsImage -Mounted | ForEach-Object {$_ | Dismount-WindowsImage -Discard -ErrorVariable wimerr; if ([bool]$wimerr) {$errflag = $true}}; If (-not $errflag) {Clear-WindowsCorruptMountPoint}' -Severity 2
					Write-Log -Message " " -Severity 2
					Write-Log -Message "Please visit Microsoft Docs for further information about DISM or Get-WindowsImage." -Severity 2
					Write-Log -Message "https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-image-management-command-line-options-s14" -Severity 2
					Write-Log -Message "https://docs.microsoft.com/en-us/powershell/module/dism/get-windowsimage" -Severity 2
				}
				Else {
					Invoke-MountCleanup
				}
			}
		}
	}

	Function Invoke-UnmountImage {
		Try {
			# Trying to unmount image
			Write-Log -Message "  - Trying to unmount image:  $($SourceWIM)"
			Dismount-WindowsImage -Path $MountDir -Discard | Out-Null
			Write-Verbose "Invoke-UnmountImage - Unmounting Image:  $($SourceWIM)"
			Write-Log -Message "  - Image unmount was successful"

			If ((Test-Path -Path "$MountDir")) {
				Invoke-MountCleanup
			}
		}
		Catch {
			# Image mount failed. Set return code and provide help for further investigation.
			$Script:ReturnCode = 1
			Write-Verbose "Invoke-UnmountImage - Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
			Write-Verbose "Invoke-UnmountImage - Return code:  $($ReturnCode)"
			Write-Log -Message "  - Image unmount failed. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)" -Severity 3
			Write-Log -Message "For further information, please examine the DISM log:  C:\WINDOWS\Logs\DISM\dism.log" -Severity 2
			Write-Log -Message " " -Severity 2
			Write-Log -Message "Check for mounted image with one of the below commands" -Severity 2
			Write-Log -Message "-------------------------------------------------------------------" -Severity 2
			Write-Log -Message "DISM command:  Dism /Get-MountedImageInfo" -Severity 2
			Write-Log -Message 'PowerShell command:  Get-WindowsImage -Mounted' -Severity 2
			Write-Log -Message " " -Severity 2
			Write-Log -Message "Try unmounting the image with one of the below commands" -Severity 2
			Write-Log -Message "-------------------------------------------------------------------" -Severity 2
			Write-Log -Message "DISM command:  Dism /Unmount-Image /MountDir:$($MountDir) /Discard" -Severity 2
			Write-Log -Message 'PowerShell command:  Get-WindowsImage -Mounted | ForEach-Object {$_ | Dismount-WindowsImage -Discard -ErrorVariable wimerr; if ([bool]$wimerr) {$errflag = $true}}; If (-not $errflag) {Clear-WindowsCorruptMountPoint}' -Severity 2
			Write-Log -Message " " -Severity 2
			Write-Log -Message "Please visit Microsoft Docs for further information about DISM or Get-WindowsImage." -Severity 2
			Write-Log -Message "https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-image-management-command-line-options-s14" -Severity 2
			Write-Log -Message "https://docs.microsoft.com/en-us/powershell/module/dism/get-windowsimage" -Severity 2
		}
	}

	Function Invoke-MountCleanup {
		Try {
			# Trying to cleanup the mount directory
			Write-Log -Message "  - Trying to cleanup the mount directory"
			Remove-Item -Path $MountDir -Recurse -ErrorAction SilentlyContinue | Out-Null
			Write-Verbose "Invoke-MountCleanup - Mount Cleanup:  $($MountDir)"
			Write-Log -Message "  - Mount cleanup was successful"
		}
		Catch {
			# Mount cleanup failed. Write log entry.
			Write-Verbose "Invoke-MountCleanup - Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
			Write-Log -Message "  - Mount cleanup was unsuccessful" -Severity 2
		}
	}

	Function Invoke-ApplicationDeployment {
		Param (
			[Parameter(Mandatory=$true, HelpMessage = "Specify a process for the deployment process.")]
			[ValidateNotNullOrEmpty()]
			[String]$Process,

			[Parameter(Mandatory=$true, HelpMessage = "Specify arguments for the deployment process.")]
			[ValidateNotNullOrEmpty()]
			[String[]]$Arguments
		)

		Try {
			# Trying to execute the install process
			Write-Log -Message "  - Trying to $($DeploymentMode.ToLower()) $($AppName)"
			If (($Host.Name -Match "ConsoleHost")) {
				Write-Verbose "Invoke-ApplicationDeployment - Install Process:  $($Process) $($Arguments)"
				$Install = Start-Process -FilePath $Process -ArgumentList $Arguments -PassThru -NoNewWindow -Wait
			}
			Else {
				Write-Verbose "Invoke-ApplicationDeployment - Install Process:  $($Process) $($Arguments)"
				$Install = Start-Process -FilePath $Process -ArgumentList $Arguments -PassThru -WindowStyle Hidden -Wait
			}
			$Install.WaitForExit()
			$Script:ReturnCode = $Install.ExitCode

			# Validate the install process
			If (($ReturnCode -eq 0) -or ($ReturnCode -eq 3010)) {
				Write-Verbose "Invoke-ApplicationDeployment - Return Code:  $($ReturnCode)"
				Write-Log -Message "  - The $($DeploymentMode.ToLower()) was successful"
			}
			Else {
				Write-Verbose "Invoke-ApplicationDeployment - Return Code:  $($ReturnCode)"
				Write-Log -Message "  - The $($DeploymentMode.ToLower()) did not complete successfully.  Return code $($ReturnCode)" -Severity 2
				Invoke-UnmountImage
			}
		}
		Catch {
			# The deployment failed. Set return code and write log entry.
			$Script:ReturnCode = 1
			Write-Verbose "Invoke-ApplicationDeployment - Return Code:  $($ReturnCode)"
			Write-Log -Message "  - The $($DeploymentMode.ToLower()) failed. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)" -Severity 3
			Invoke-UnmountImage
		}
	}

	# Start Logging
	Write-Log -Message "Successfully initialized logging for Application Deployment"
	Write-Log -Message "[GatherInfo]: Starting gathering information . . ."
	Write-Log -Message "  - Username:  $Env:USERDOMAIN\$Env:USERNAME"
	Write-Log -Message "  - Computername:  $Env:USERDOMAIN\$env:COMPUTERNAME$"
	Write-Log -Message "  - Application:  $($AppName)"
	Write-Log -Message "  - Deployment mode:  $($DeploymentMode)"
	Write-Log -Message "  - Log location:  $($LogFilePath)"
	Write-Log -Message "[GatherInfo]: Completed gathering information"

	# Trying to mount image
	If (($ReturnCode -eq 0)) {
		Write-Log -Message "[MountImage]: Starting mounting image . . ."
		Invoke-MountImage

		# Validate the image mount
		If (($ReturnCode -eq 0)) {
			Write-Log -Message "[MountImage]: Completed mounting image"
		}
		Else {
			Write-Log -Message "[MountImage]: Mounting image was unsuccessful"
		}
	}

	# Trying to deploy the application
	If (($ReturnCode -eq 0)) {
		Write-Log -Message "[ApplicationDeployment]: Starting application deployment in ''$($DeploymentMode)'' mode . . ."
		Invoke-ApplicationDeployment -Process $Process -Arguments $Arguments
		
		# Validate the application deployment
		If (($ReturnCode -eq 0) -or ($ReturnCode -eq 3010)) {
			Write-Log -Message "[ApplicationDeployment]: Completed application deployment in ''$($DeploymentMode)'' mode"
		}
		Else {
			Write-Log -Message "[ApplicationDeployment]: Application deployment in ''$($DeploymentMode)'' mode was unsuccessful"
		}
	}

	# Trying to unmount image
	If (($ReturnCode -eq 0) -or ($ReturnCode -eq 3010)) {
		Write-Log -Message "[UnmountImage]: Starting unmounting image . . ."
		Invoke-UnmountImage

		# Validate the image unmount
		If (($ReturnCode -eq 0) -or ($ReturnCode -eq 3010)) {
			Write-Log -Message "[UnmountImage]: Completed unmounting image"
		}
		Else {
			Write-Log -Message "[UnmountImage]: Unmounting image was unsuccessful"
		}
	}
}
End {
	# End Logging
	Write-Log -Message "Application Deployment is exiting with return code $($ReturnCode)"
	Write-Log -Message "Successfully finalized logging for Application Deployment"

	# Set Exit Code
	Write-Verbose "Exiting with return code $($ReturnCode)"
	Exit $ReturnCode
}

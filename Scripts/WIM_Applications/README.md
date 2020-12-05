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

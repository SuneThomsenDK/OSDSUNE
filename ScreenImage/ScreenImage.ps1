<#
.SYNOPSIS
	Set Wallpaper and LockScreen in Windows 10 Enterprise.

.DESCRIPTION
	The purpose of this script is to set Wallpaper and LockScreen in Windows 10 with a SCCM package 
	deployed as a program or during OS Deployment.

	This script takes ownership and set permissions on the default folders in "SystemDrive\Windows\Web\*"
	it will replace the default images and set LockScreen settings in Registry.

.NOTES
	Version: 1.9.3.29
	Author: Sune Thomsen
	Creation date: 27-03-2019
	Last modified date: 29-03-2019

.LINK
	https://github.com/SuneThomsenDK
#>

	#=========================================================================================
	#	Requirements
	#=========================================================================================
	#Requires -Version 4
	#Requires -RunAsAdministrator

	#=========================================================================================
	#	Source and Destination Path
	#=========================================================================================

	$Source4K = "$PSScriptRoot\4K"
	$SourceScreen = "$PSScriptRoot\Screen"
	$SourceWallpaper = "$PSScriptRoot\Wallpaper"
	$Destination4K = "$Env:SystemRoot\Web\4K\Wallpaper\Windows"
	$DestinationScreen = "$Env:SystemRoot\Web\Screen"
	$DestinationWallpaper = "$Env:SystemRoot\Web\Wallpaper\Windows"

	#=========================================================================================
	#	Take Ownership of Files
	#=========================================================================================

	TAKEOWN /f $Destination4K\*.*
	TAKEOWN /f $DestinationScreen\*.*
	TAKEOWN /f $DestinationWallpaper\*.*

	#=========================================================================================
	#	Set Permissions for SYSTEM Account
	#=========================================================================================

	ICACLS $Destination4K\*.* /Grant 'System:(F)'
	ICACLS $DestinationScreen\*.* /Grant 'System:(F)'
	ICACLS $DestinationWallpaper\*.* /Grant 'System:(F)'

	#=========================================================================================
	#	Delete Destination Files
	#=========================================================================================

	Remove-Item $Destination4K\*.*
	Remove-Item $DestinationScreen\*.*
	Remove-Item $DestinationWallpaper\*.*

	#=========================================================================================
	#	Mirror Files from Source to Destination
	#=========================================================================================

	Robocopy $Source4K $Destination4K /MIR /R:120 /W:60 /NP /NJH
	Robocopy $SourceScreen $DestinationScreen /MIR /R:120 /W:60 /NP /NJH
	Robocopy $SourceWallpaper $DestinationWallpaper /MIR /R:120 /W:60 /NP /NJH

	#=========================================================================================
	#	Set Registry Settings
	#=========================================================================================

	$Reg = "HKLM:\Software\Policies\Microsoft\Windows\Personalization"
	$Name01 = "LockScreenImage"
	$Name02 = "NoChangingLockScreen"
	$Value01 = "$DestinationScreen\img100.jpg"
	$Value02 = "1"
	$Type01 = "String"
	$Type02 = "DWORD"

		Try {
			if (!(Test-Path $Reg)) {
				New-Item -Path $Reg -Force | Out-Null
				New-ItemProperty -Path $Reg -Name $Name01 -PropertyType $Type01 -Value $Value01 -Force | Out-Null
				New-ItemProperty -Path $Reg -Name $Name02 -PropertyType $Type02 -Value $Value02 -Force | Out-Null
				Write-Host "Attention: $Reg did not exist but were created." -ForegroundColor "Cyan"
				Write-Host "Information: $Name01 were created with the following value $Value01" -ForegroundColor "Green"
				Write-Host "Information: $Name02 were created with the following value $Value02" -ForegroundColor "Green"
			}
			else {
				New-ItemProperty -Path $Reg -Name $Name01 -PropertyType $Type01 -Value $Value01 -Force | Out-Null
				New-ItemProperty -Path $Reg -Name $Name02 -PropertyType $Type02 -Value $Value02 -Force | Out-Null
				Write-Host "Information: Registry value $Value01 were set on $Reg\$Name01" -ForegroundColor "Green"
				Write-Host "Information: Registry value $Value02 were set on $Reg\$Name02" -ForegroundColor "Green"
			}
		}
		Catch {
			Write-Host "Warning: Something went wrong while setting registry settings." -ForegroundColor "Yellow"
			Return $Null
		}
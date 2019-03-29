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
	#	Set LockScreenImage in Registry
	#=========================================================================================

	$Reg = "HKLM:\Software\Policies\Microsoft\Windows\Personalization"
	$Name = "LockScreenImage"
	$Value = "$DestinationScreen\img100.jpg"
	$Type = "String"

		if (!(Test-Path $Reg)) {
			New-Item -Path $Reg -Force | Out-Null
			New-ItemProperty -Path $Reg -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
		}
		else {
			New-ItemProperty -Path $Reg -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
		}

	#=========================================================================================
	#	Disable Changing LockScreen in Registry
	#=========================================================================================

	$Reg = "HKLM:\Software\Policies\Microsoft\Windows\Personalization"
	$Name = "NoChangingLockScreen"
	$Value = "1"
	$Type = "DWORD"

		if (!(Test-Path $Reg)) {
			New-Item -Path $Reg -Force | Out-Null
			New-ItemProperty -Path $Reg -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
		}
		else {
			New-ItemProperty -Path $Reg -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
		}
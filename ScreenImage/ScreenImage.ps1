<#
.SYNOPSIS
	Set Wallpaper and LockScreen in Windows 10 Enterprise.

.DESCRIPTION
	The purpose of this script is to set Wallpaper and LockScreen in Windows 10 with a SCCM package 
	deployed as a program or during OS Deployment.

	This script takes ownership and set permissions on the default folders in "SystemDrive\Windows\Web\*"
	it will replace the default images and set LockScreen settings in Registry.

.NOTES
	Version: 1.9.3.30
	Author: Sune Thomsen
	Creation date: 27-03-2019
	Last modified date: 30-03-2019

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
	$Source4K = "$PSScriptRoot\4K".ToLower()
	$SourceScreen = "$PSScriptRoot\Screen".ToLower()
	$SourceWallpaper = "$PSScriptRoot\Wallpaper".ToLower()
	$Destination4K = "$Env:SystemRoot\Web\4K\Wallpaper\Windows".ToLower()
	$DestinationScreen = "$Env:SystemRoot\Web\Screen".ToLower()
	$DestinationWallpaper = "$Env:SystemRoot\Web\Wallpaper\Windows".ToLower()

	#=========================================================================================
	#	Taking Ownership of the Files
	#=========================================================================================
	Write-Host "`n"
	Write-Host "=========================================================================================" -ForegroundColor "DarkGray"
	Write-Host "Taking ownership of the files"
	Write-Host "=========================================================================================" -ForegroundColor "DarkGray"
	TAKEOWN /f $Destination4K\*.*
	TAKEOWN /f $DestinationScreen\*.*
	TAKEOWN /f $DestinationWallpaper\*.*
	Write-Host "`n"
	Write-Host "`tAs every cat owner knows, nobody owns a cat ~ Ellen Perry Berkeley" -ForegroundColor "DarkGray"
	Write-Host "`n"

	#=========================================================================================
	#	Set Permissions for SYSTEM Account
	#=========================================================================================
	Write-Host "=========================================================================================" -ForegroundColor "DarkGray"
	Write-Host "Set permissions for SYSTEM account"
	Write-Host "=========================================================================================" -ForegroundColor "DarkGray"
	ICACLS $Destination4K\*.* /Grant 'System:(F)'
	ICACLS $DestinationScreen\*.* /Grant 'System:(F)'
	ICACLS $DestinationWallpaper\*.* /Grant 'System:(F)'
	Write-Host "`n"

	#=========================================================================================
	#	Delete Destination Files
	#=========================================================================================
	Remove-Item $Destination4K\*.*
	Remove-Item $DestinationScreen\*.*
	Remove-Item $DestinationWallpaper\*.*

	#=========================================================================================
	#	Mirror Files from Source to Destination
	#=========================================================================================
	Write-Host "=========================================================================================" -ForegroundColor "DarkGray"
	Write-Host "Mirror files from source to destination"
	Write-Host "=========================================================================================" -ForegroundColor "DarkGray"
	Robocopy $Source4K $Destination4K /MIR /R:120 /W:60 /NP /NS /NC /NDL /NJH
	Robocopy $SourceScreen $DestinationScreen /MIR /R:120 /W:60 /NP /NS /NC /NDL /NJH
	Robocopy $SourceWallpaper $DestinationWallpaper /MIR /R:120 /W:60 /NP /NS /NC /NDL /NJH

	#=========================================================================================
	#	Set Registry Settings
	#=========================================================================================
	Write-Host "=========================================================================================" -ForegroundColor "DarkGray"
	Write-Host "Set registry settings"
	Write-Host "=========================================================================================" -ForegroundColor "DarkGray"
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
				Write-Host "Information: $Name01 were created in registry with the following value $Value01" -ForegroundColor "Green"
				Write-Host "Information: $Name02 were created in registry with the following value $Value02" -ForegroundColor "Green"
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
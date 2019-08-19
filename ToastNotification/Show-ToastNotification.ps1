<#
.SYNOPSIS
	Language detection for toasted notifications in Windows 10.

.DESCRIPTION
	This script will check for "System Local" language in registry.
	0414 = nb_NO
	0406 = da_DK
	0409 = en_US

.NOTES
	Version: 1.9.8.19
	Author: Sune Thomsen
	Creation date: 15-08-2019
	Last modified date: 19-08-2019

.LINK
	https://www.osdsune.com
#>

$RegKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language"
$RegName = "Default"
$RegValue_daDK = "0406"
$RegValue_nbNO = "0414"
$OSLanguage = Get-ItemPropertyValue -Path $RegKey -Name $RegName -ErrorAction SilentlyContinue

	if ($OSLanguage -eq "$RegValue_daDK"){
		PowerShell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -File $PSScriptRoot\New-ToastNotification.ps1 -Config "$PSScriptRoot\Config\config-toast-update-daDK.xml"
		break
	}

	if ($OSLanguage -eq "$RegValue_nbNO"){
		PowerShell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -File $PSScriptRoot\New-ToastNotification.ps1 -Config "$PSScriptRoot\Config\config-toast-update-nbNO.xml"
		break
	}

	if (($OSLanguage -ne "$RegValue_daDK") -and ($OSLanguage -ne "$RegValue_nbNO")){
		PowerShell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -File $PSScriptRoot\New-ToastNotification.ps1 -Config "$PSScriptRoot\Config\config-toast-update-enUS.xml"
		break
	}
<#
.SYNOPSIS
	Fix Domain Relationship

.DESCRIPTION
	Fix domain relationship if corrupt

.NOTES
	Version: 1.0.0.1
	Author: Sune Thomsen
	Creation date: 26-02-2020
	Last modified date: 26-02-2020

.LINK
	https://github.com/SuneThomsenDK
#>

#===============================================
# Check if domain relationship is corrupt
#===============================================
    if (!(Test-ComputerSecureChannel)) {
        $Secret = 'IwAxADAAbABOAG8AZwAxAGEAbgBkADEA'
        $DecodedText = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($Secret))
        $Username = 'MOE\Administrator'
        $password = convertto-securestring -String $DecodedText -AsPlainText -Force
        $ADRepairCred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $password
        Test-ComputerSecureChannel -Repair -Credential $ADRepairCred
    }
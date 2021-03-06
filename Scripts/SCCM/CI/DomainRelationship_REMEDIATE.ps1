﻿<#
.SYNOPSIS
	Fix Domain Relationship

.DESCRIPTION
	Fix domain relationship if corrupt

.NOTES
	Version: 1.0.0.1
	Author: Sune Thomsen
	Creation date: 26-02-2020
	Last modified date: 06-03-2020

.LINK
	https://github.com/SuneThomsenDK
#>

#===============================================
# Check if domain relationship is corrupt
#===============================================

#Create EncodedPass
#$Password = 'Enter Admin Password Here'
#$EncodedPass = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Password))
#$EncodedPass

    if (!(Test-ComputerSecureChannel)) {
    	$Compliance = "Non-Compliant"
        $EncodedPass = 'RQBuAHQAZQByAEEAZABtAGkAbgBQAGEAcwBzAHcAbwByAGQASABlAHIAZQA'
        $DecodedPass = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedPass))
        $Username = 'DOMAIN\Administrator'
        $Password = convertto-securestring -String $DecodedPass -AsPlainText -Force
        $ADRepairCred = new-object -typename System.Management.Automation.PSCredential -argumentlist $Username, $Password
        Test-ComputerSecureChannel -Repair -Credential $ADRepairCred
	
	# Check domain relationship again
	if ((Test-ComputerSecureChannel)) {$Compliance = "Compliant"}
    }
    else {$Compliance = "Compliant"}

$Compliance

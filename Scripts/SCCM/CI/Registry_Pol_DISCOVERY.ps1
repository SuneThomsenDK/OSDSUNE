<#
.SYNOPSIS
	Check Registry.pol health

.DESCRIPTION
	Check the health of the clients Machine and User registry.pol file.

	A special thanks go to Martin Bengtsson!
	https://twitter.com/mwbengtsson

.NOTES
	Version: 1.0.0.1
	Author: Sune Thomsen
	Creation date: 25-02-2020
	Last modified date: 26-02-2020

.LINK
	https://github.com/SuneThomsenDK
#>

$MachineRegistryFile = "$env:Windir\System32\GroupPolicy\Machine\Registry.pol"
$UserRegistryFile = "$env:Windir\System32\GroupPolicy\User\Registry.pol"
$MachineFileContent = ((Get-Content -Encoding Byte -Path $MachineRegistryFile -TotalCount 4 -ErrorAction SilentlyContinue) -join '')
$UserFileContent = ((Get-Content -Encoding Byte -Path $UserRegistryFile -TotalCount 4 -ErrorAction SilentlyContinue) -join '')

#=====================================================
# Check if Machine Registry.pol is corrupt or missing
#=====================================================
	if (!(Test-Path -Path $MachineRegistryFile -PathType Leaf)) {
		$MachineFileStatus = $true
		#Write-Host "Machine registry.pol file not found."
	}
	else {
		if ($MachineFileContent -ne '8082101103') {
			$MachineFileStatus = $false
			#Write-Host "Machine registry.pol file is corrupt."

			try {
				#Write-Host "Trying to remove the machine registry.pol file."
			}
			catch {
				#Write-Host "Failed to remove machine registry.pol file."
				#Write-Host "$_.Exception.Message"
			}
		}
		else {
			$MachineFileStatus = $true
			#Write-Host "Machine policy file is good. Do nothing."
		}
	}

#=====================================================
# Check if User Registry.pol is corrupt or missing
#=====================================================
	if (!(Test-Path -Path $UserRegistryFile -PathType Leaf)) {
		$UserFileStatus = $true
		#Write-Host "User registry.pol file not found."
	}
	
	else {
		if ($UserFileContent -ne '8082101103') {
			$UserFileStatus = $false
			#Write-Host "User registry.pol file is corrupt."

			try {
				#Write-Host "Trying to remove the user registry.pol file"
			}
			catch {
				#Write-Host "Failed to remove user registry.pol file."
				#Write-Host "$_.Exception.Message"
			}
		}
		else {
			$UserFileStatus = $true
			#Write-Host -Message "User policy file is good. Do nothing."
		}
	}

	if (($MachineFileStatus -eq $true) -and ($UserFileStatus -eq $true)) {
		$Compliance = "Compliant"
		#Write-Host "Both registry.pol files are good. Do nothing."
	}
	elseif (($MachineFileStatus -eq $false) -or ($UserFileStatus -eq $false)) {
		$Compliance = "Non-Compliant"
	}

$Compliance
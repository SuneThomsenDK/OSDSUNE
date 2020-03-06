<#
.SYNOPSIS
	Fix BITS transfer issues

.DESCRIPTION
	Trying to fix issues with BITS transfers

	A special thanks go to Martin Bengtsson!
	https://twitter.com/mwbengtsson

.NOTES
	Version: 1.0.0.1
	Author: Sune Thomsen
	Creation date: 26-02-2020
	Last modified date: 26-02-2020

.LINK
	https://github.com/SuneThomsenDK
#>

#===============================================
# Check if client has issues with BITS transfers
#===============================================
$BitsCheckEnabled = $false

	try {
		Import-Module BitsTransfer -ErrorAction Stop
		$BitsCheckEnabled = $true
	}
	catch {
		$BitsCheckEnabled = $false 
	}

	if ($BitsCheckEnabled -eq $true) {
		#Write-Host "Retrieving BITS transfers with issues for all users."
		$BitsErrors = Get-BitsTransfer -AllUsers | Where-Object { ($_.JobState -like "TransientError") -or ($_.JobState -like "Transient_Error") -or ($_.JobState -like "Error") }

		if ($BitsErrors -ne $null) {
			#Write-Host "BITS transfers with issues found. Continuing remediation."

			try {
				#Write-Host "Trying to remove BITS transfers with issues."
				$BitsErrors | Remove-BitsTransfer -ErrorAction SilentlyContinue
				$BitsErrors = Get-BitsTransfer -AllUsers | Where-Object { ($_.JobState -like "TransientError") -or ($_.JobState -like "Transient_Error") -or ($_.JobState -like "Error") }

				if ($BitsErrors -eq $null) {
					#Write-Host "Great! No more BITS transfers with issues found."
				}

				elseif ($BitsErrors -ne $null) {
					#Write-Host "Client still has BITS transfers with issues - please investigate."
				}
			}
			catch {
				#Write-Host "Failed to remove BITS transfers with issues."
			}
		}
		else {
			#Write-Host "No BITS transfers with issues found."
		}
	}
	else {
		#Write-Host "PowerShell Module BitsTransfer missing. Skipping check."
	}
<#
.SYNOPSIS
	Check Domain Relationship

.DESCRIPTION
	Check if domain relationship is corrupt

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

#========================================
# Check if domain relationship is corrupt
#========================================
    if (!(Test-ComputerSecureChannel)) {
        $Compliance = "Non-Compliant"
    }
	else {
		$Compliance = "Compliant"
	}

$Compliance
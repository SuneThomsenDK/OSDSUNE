.SYNOPSIS
	The remediation script is used to back up the BitLocker recovery key(s) to Entra ID.

.DESCRIPTION
	The remediation script will check if the device is protected by BitLocker and attempt to back up the BitLocker recovery key(s) to Entra ID.

	-------------------------------------------------------
	Proactive Remediation Information
	-------------------------------------------------------
	Required settings for the script package in Endpoint analytics | Proactive remediations.

		Run this script using the logged-on credentials: No
		Enforce script signature check: No
		Run script in 64-bit PowerShell: Yes

	-------------------------------------------------------
	Proactive Remediation Scenarios and detection output
	-------------------------------------------------------
	Scenario: The script is not running in system context.
	Output: "PREREQ: The script is not running in system context. - Please run the script as system."

	Scenario: The script is not running in 64-bit PowerShell.
	Output: "PREREQ: The script is not running in 64-bit PowerShell. - Please run the script in 64-bit PowerShell."

	Scenario: The drive (For example, 'C:') is not protected by BitLocker.
	Output: "NOT PROTECTED: BitLocker protection status on drive 'C:' is = Off. - Please ensure that the BitLocker protection is turned on and not temporarily suspended."

	Scenario: BitLocker recovery key(s) is not stored in Entra ID.
	Output: "PROTECTED - RUN REMEDIATION: BitLocker recovery key(s) is not stored in Entra ID. - Run remediation script..."

	Scenario: The proactive remediation script failed.
	Output: "ERROR: Whoopsie... Something failed at line 36: Error message"

	-------------------------------------------------------
	Proactive Remediation Functions
	-------------------------------------------------------
	Function (Write-Log)

		This is a CMTrace friendly log function with UTF-8 encoding, and correct log entry format.
		You can use this function with the pre-defined log variables or change them to fit your needs.
		The only mandatory parameter in this function is the message parameter.

		The available message severity in this log function:
			1 = Information (Default)
			2 = Warning
			3 = Error

		Valid example(s):
		Write-Log -Message "CMTrace, is the best log viewer on the planet!"
		Write-Log -Message "CMTrace, is the best log viewer on the planet!" -ComponentName "Demo"
		Write-Log -Message "CMTrace, is the best log viewer on the planet!" -ComponentName "Demo" -Severity "3"

	Function (Split-Log)

		This function is called by the Write-Log function to split the log file when it reaches the specified max size.

	Function (Check-EventLog)

		You can use this function with the default pre-defined variables or specify your values when calling the function.
		Be aware that all parameters in this function are mandatory!

		Valid example(s):
		Check-EventLog -EventProviderName "Microsoft-Windows-BitLocker-API" -EventMessage "volume C: was backed up successfully to your Entra ID." -EventTime "01/01/2022 00:00:00" -EventID "845"

	Function (Convert-RegistryKey)

		This function is called by the Check-RegistryKey and Set-RegistryKey functions to convert the registry key hive to the full path.

	Function (Check-RegistryKey)

		You can use this function with the default pre-defined variables or specify your values when calling the function.
		This function can be used to check a registry key path, name, and value.
		The only mandatory parameter in this function is the registry key parameter.

		-------------------------------------------------------
		Registry Hive               Abbreviation
		-------------------------------------------------------
		HKEY_LOCAL_MACHINE          HKLM
		HKEY_CURRENT_USER           HKCU
		HKEY_USERS                  HKU
		HKEY_CURRENT_CONFIG         HKCC
		HKEY_CLASSES_ROOT           HKCR
		-------------------------------------------------------

		Valid example(s) (HKEY_LOCAL_MACHINE):
		Check-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "(Default)" -Value ""
		Check-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "SystemRoot" -Value "C:\WINDOWS"
		Check-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "SystemRoot" -Value ""
		Check-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "" -Value ""

		Valid example(s) (HKEY_CURRENT_USER):
		Check-RegistryKey -Key "HKCU:\Control Panel\Desktop" -Name "(Default)" -Value ""
		Check-RegistryKey -Key "HKCU:\Control Panel\Desktop" -Name "WallPaper" -Value "C:\Windows\web\wallpaper\Windows\img19.jpg"
		Check-RegistryKey -Key "HKCU:\Control Panel\Desktop" -Name "WallPaper" -Value ""
		Check-RegistryKey -Key "HKCU:\Control Panel\Desktop" -Name "" -Value ""

		Valid example(s) (HKEY_CLASSES_ROOT):
		Check-RegistryKey -Key "HKCR:\MIME\Database\Content Type\application/hta" -Name "(Default)" -Value ""
		Check-RegistryKey -Key "HKCR:\MIME\Database\Content Type\application/hta" -Name "Extension" -Value ".hta"
		Check-RegistryKey -Key "HKCR:\MIME\Database\Content Type\application/hta" -Name "Extension" -Value ""
		Check-RegistryKey -Key "HKCR:\MIME\Database\Content Type\application/hta" -Name "" -Value ""

	Function (Set-RegistryKey)

		You can use this function with the default pre-defined variables or specify your values when calling the function.
		This function can be used to create/set a registry key path, name, and value.
		Be aware that the registry key, name, and type parameters in this function are mandatory.

		-------------------------------------------------------
		Registry Hive               Abbreviation
		-------------------------------------------------------
		HKEY_LOCAL_MACHINE          HKLM
		HKEY_CURRENT_USER           HKCU
		HKEY_USERS                  HKU
		HKEY_CURRENT_CONFIG         HKCC
		HKEY_CLASSES_ROOT           HKCR
		--------------------------------------------------------------------------------------------------------------
		Registry Types              Description
		--------------------------------------------------------------------------------------------------------------
		String                      Specifies a null-terminated string. Equivalent to REG_SZ.
		ExpandString                Specifies a null-terminated string that contains unexpanded references to environment variables that are expanded when the value is retrieved. Equivalent to REG_EXPAND_SZ.
		Binary                      Specifies binary data in any form. Equivalent to REG_BINARY.
		DWord                       Specifies a 32-bit binary number. Equivalent to REG_DWORD.
		MultiString                 Specifies an array of null-terminated strings terminated by two null characters. Equivalent to REG_MULTI_SZ.
		Qword                       Specifies a 64-bit binary number. Equivalent to REG_QWORD.
		Unknown                     Indicates an unsupported registry data type, such as REG_RESOURCE_LIST.
		--------------------------------------------------------------------------------------------------------------

		Valid example(s) (HKEY_LOCAL_MACHINE):
		Set-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "(Default)" -Value "" -Type "STRING"
		Set-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "SystemRoot" -Value "C:\WINDOWS" -Type "STRING"
		Set-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "SystemRoot" -Value "" -Type "STRING"

		Valid example(s) (HKEY_CURRENT_USER):
		Set-RegistryKey -Key "HKCU:\Control Panel\Desktop" -Name "(Default)" -Value "" -Type "STRING"
		Set-RegistryKey -Key "HKCU:\Control Panel\Desktop" -Name "WallPaper" -Value "C:\Windows\web\wallpaper\Windows\img19.jpg" -Type "STRING"
		Set-RegistryKey -Key "HKCU:\Control Panel\Desktop" -Name "WallPaper" -Value "" -Type "STRING"

		Valid example(s) (HKEY_CLASSES_ROOT):
		Set-RegistryKey -Key "HKCR:\MIME\Database\Content Type\application/hta" -Name "(Default)" -Value "" -Type "STRING"
		Set-RegistryKey -Key "HKCR:\MIME\Database\Content Type\application/hta" -Name "Extension" -Value ".hta" -Type "STRING"
		Set-RegistryKey -Key "HKCR:\MIME\Database\Content Type\application/hta" -Name "Extension" -Value "" -Type "STRING"

	Function (Check-BitLockerProtectionStatus)

		This function is called to check if the drive (For example, 'C:') is protected by BitLocker.

	Function (Check-BitLockerVolumeStatus)

		This function is called to check if the drive (For example, 'C:') is fully encrypted by BitLocker.

	Function (Invoke-BitLockerBackupToEntraID)

		This function will attempt to back up the BitLocker recovery key(s) to Entra ID.

	Function (Exit-Script)

		This function is called to exit the script based on an exit code. - It does also support an exit message (Write-Output).
		The only mandatory parameter in this function is the exit code parameter.

		Valid example(s):
		Exit-Script -ExitCode "1" -ExitMessage "Remediation is required."

.PARAMETER

.EXAMPLE

.NOTES
	Created on:   26-11-2021
	Modified:     27-05-2025
	Author:       Sune Thomsen
	Version:      3.2
	Mail:         stn@mindcore.dk
	Twitter:      https://twitter.com/SuneThomsenDK

	Changelog:
	----------
	26-11-2021 - v1.0 - The Creation date of this script
	03-05-2022 - v1.1 - Detection for BitLocker protection status added to the script
	17-06-2022 - v1.2 - New logic and better reporting have been added to the script
	07-10-2022 - v1.3 - Code review and cleanup of the script
	09-10-2022 - v1.4 - Minor changes to the script output
	20-10-2022 - v1.5 - Minor changes to the detection of BitLocker protection status and script output
	09-12-2022 - v2.0 - The script has been rewritten and now contains a prerequisite check, new logic, structure, functions, etc.
	04-05-2022 - v2.1 - Minor changes to the Write-Log function.
	09-06-2023 - v3.0 - The script has been rewritten to support multiple fixed drives. -> Set the "$Global:CheckAllDrives" to "$true" under "Set system variable(s)" if you want the script to check all available fixed drives.
	06-10-2023 - v3.1 - Minor changes to the script output
	27-05-2025 - v3.2 - Replaced "Azure AD" with "Entra ID" throughout the script and added new detection logic for event log messages.

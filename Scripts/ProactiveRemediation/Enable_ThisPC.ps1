# Enable This PC icon on desktop.
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
$RegistryName = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"

$RegistryValue = Get-ItemProperty $RegistryPath -Name $RegistryName -ErrorAction SilentlyContinue
$RegistryValue = $RegistryValue.'{20D04FE0-3AEA-1069-A2D8-08002B30309D}'

	try {
        if (!($RegistryValue -eq "0")) {     
        Set-ItemProperty $RegistryPath -Name $RegistryName -Value 0 -ErrorAction SilentlyContinue
        Write-Host "This PC icon was successfully enabled."
        exit 0
        }
        Else {Write-Host "This PC icon is enabled"}
    }

	catch {
		$ErrMsg = $_.Exception.Message
		Write-Error $ErrMsg
		exit 1
	}
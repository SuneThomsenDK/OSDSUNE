# Define Group Policy Variables
$OU = "OU=xxxxx,DC=xxxxx,DC=local"
$AllSubOUs = Get-ADOrganizationalUnit -SearchBase $OU -SearchScope Subtree -Filter * | Select-Object DistinguishedName, Name, LinkedGroupPolicyObjects
$LimitedSubOUs = $AllSubOUs | Where-Object {($_.DistinguishedName -like "*Ou=xxx*") -or ($_.DistinguishedName -like "Ou=xxx*")}
$AllGPOStats = @()

# Defining General Variables
$Date1 = Get-Date –f "dd-MM-yyyy HH:mm:ss"
$Date2 = Get-Date –f "dd_MM_yyyy"
$VarDays = 8
$ReportPath = "C:\Temp\GPOMonitoring"
$ReportLocation = "$ReportPath\GPO_Report_$Date2.html"

# Defining Variables for EMAIL Reporting
$SMTPServer = "mailrelay.mail.com"
$SMTPPort = 25
$To = "Sune Thomsen1 <sune.thomsen1@mail.com>", "Sune Thomsen2 <sune.thomsen2@mail.com>"
$Bcc = "Sune Thomsen1 <sune.thomsen1@mail.com>", "Sune Thomsen2 <sune.thomsen2@mail.com>"
$From = "GPO Monitoring Report <noreply@mail.com>"

# Checking whether report path exist.
If (!(Test-Path -PathType Container $ReportPath)){
	New-Item -ItemType Directory -Path $ReportPath
}

# Main Script
ForEach ($BaseOU in $LimitedSubOUs){

	ForEach ($LinkedGroupPolicyObjects in $BaseOU.LinkedGroupPolicyObjects){

		# Extraxt GUID from policy object
		$GUID = $LinkedGroupPolicyObjects | Select-String -Pattern '{[-0-9A-F]+?}' -AllMatches | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value

		# Collect data if not already run for this GPO
		If ($GUID -notin $AllGPOStats.Guid){

			$GPO = $null
			Try {
				$GPO = Get-GPO -Guid $GUID | Where {((Get-Date)-[datetime]$_.ModificationTime).days -lt $VarDays}
			}
			Catch {
				#Write-Host ("Error getting infromation for the GPO with the GUID: {0}" -f $GUID)
			}


			If ($GPO){
				#Write-Host ("Adding information for the GPO with the GUID: {0} to the AllGPOStats object" -f $GUID)
				# Define PSCustomObject
				$Obj = [PSCustomObject]@{

					#Variables
					DisplayName = $GPO.DisplayName
					GPOStatus = $GPO.GPOStatus
					CreationTime = $GPO.CreationTime
					ModificationTime = $GPO.ModificationTime
					Guid = ("{" + ('{0}') -f ($GPO.Id).Tostring() + "}").ToUpper()
				}

				# Add to report
				$AllGPOStats += $Obj

				# HTML style
				$HeadStyle = "<style>"
				$HeadStyle = $HeadStyle + "BODY{background-color:White;}"
				$HeadStyle = $HeadStyle + "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}"
				$HeadStyle = $HeadStyle + "TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:YellowGreen}"
				$HeadStyle = $HeadStyle + "TD{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:Gainsboro}"
				$HeadStyle = $HeadStyle + "</style>"

				Write-Output $AllGPOStats
				$AllGPOStats | ConvertTo-Html -Head $HeadStyle -Body "<h2>$($ENV:ComputerName) Report - $Date1</h2>" | Out-File $ReportLocation -Force
			}
		}
	}
}

# Send GPO Monitoring Report if exist.
If ((Get-item $ReportLocation).length -gt 1.5KB){
	Send-MailMessage -To $To -From $From -Bcc $Bcc -Subject "GPO_Monitoring_Report $Date1" -SmtpServer $SMTPServer -Attachments $ReportLocation -Port $SMTPPort
}
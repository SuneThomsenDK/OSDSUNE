$OURoot = "DC=xxxxx,DC=local" # Add the domain root here.
$OUName = "*" # Add specific OU name or use * for every OU.
$GPOName = "" # Add a key word for the GPO you want to export or keep it empty to export every linked and enabled GPO.

$OUs = Get-ADOrganizationalUnit -SearchBase $OURoot -Filter 'Name -like $OUName'

$LinkedGPOs = ForEach ($OU in $OUs){
 $Links = (Get-GPInheritance -Target $OU).GpoLinks

 ForEach ($Link in $Links){

  if ($Link.Enabled){
   Get-GPO -Name ($Link.DisplayName) | Where-Object {$Link.DisplayName -match "$GPOName"} | Select-Object DisplayName
  }
 }
}

$LinkedGPOs | Sort-Object -Property DisplayName -Unique | ForEach-Object {Get-GPOReport -Name $_.DisplayName -ReportType XML -Path "C:\temp\$($_.DisplayName).xml"}
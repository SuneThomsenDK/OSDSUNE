Install-Module Microsoft.Graph.Intune
Import-Module Microsoft.Graph.Intune
Connect-MSGraph

# Example: How to gather and delete specific GPOs from Intune Group Policy analytics.
# -----------------------------------------------------------------------------------

$Get_GPO_Reports = (Invoke-MSGraphRequest -Url "https://graph.microsoft.com/beta/deviceManagement/groupPolicyMigrationReports" -HttpMethod GET).Value

$Search = "*Add Key Word Here*"
$Get_GPO = $Get_GPO_Reports | where {$_.ouDistinguishedName -like $Search}
$Get_GPO_ID = $Get_GPO.ID


ForEach ($GPO_ID in $Get_GPO_ID){

$RequestURL = ("https://graph.microsoft.com/beta/deviceManagement/groupPolicyMigrationReports('{0}')" -f [uri]::EscapeDataString($GPO_ID))
$RequestURL

Invoke-MSGraphRequest -Url $RequestURL -HttpMethod DELETE -ErrorAction Stop | Out-Null

}


# Example: How to gather and delete all GPOs from Intune Group Policy analytics.
# ------------------------------------------------------------------------------

$Get_GPO_Reports = (Invoke-MSGraphRequest -Url "https://graph.microsoft.com/beta/deviceManagement/groupPolicyMigrationReports" -HttpMethod GET).Value
$Get_GPO_ID = $Get_GPO_Reports.ID


ForEach ($GPO_ID in $Get_GPO_ID){

$RequestURL = ("https://graph.microsoft.com/beta/deviceManagement/groupPolicyMigrationReports('{0}')" -f [uri]::EscapeDataString($GPO_ID))
$RequestURL

Invoke-MSGraphRequest -Url $RequestURL -HttpMethod DELETE -ErrorAction Stop | Out-Null

}
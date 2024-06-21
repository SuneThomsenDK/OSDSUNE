# Set ExecutionPolicy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Install and connects to the relevant Microsoft Graph scope
Install-Module Microsoft.Graph -Scope CurrentUser
Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All"

# Example: How to gather and delete specific GPOs from Intune Group Policy analytics.
# -----------------------------------------------------------------------------------

$Get_GPO_Reports = (Invoke-MgGraphRequest -Method GET "https://graph.microsoft.com/beta/deviceManagement/groupPolicyMigrationReports").Value

$Search = "*<Keyword Here>*"
$Get_GPO = $Get_GPO_Reports | Where-Object {$_.ouDistinguishedName -like $Search}
$Get_GPO_ID = $Get_GPO.ID


ForEach ($GPO_ID in $Get_GPO_ID){

$RequestURL = ("https://graph.microsoft.com/beta/deviceManagement/groupPolicyMigrationReports('{0}')" -f [uri]::EscapeDataString($GPO_ID))
$RequestURL

Invoke-MgGraphRequest -Method DELETE $RequestURL -ErrorAction Stop | Out-Null

}


# Example: How to gather and delete all GPOs from Intune Group Policy analytics.
# ------------------------------------------------------------------------------

$Get_GPO_Reports = (Invoke-MgGraphRequest -Method GET "https://graph.microsoft.com/beta/deviceManagement/groupPolicyMigrationReports").Value
$Get_GPO_ID = $Get_GPO_Reports.ID


ForEach ($GPO_ID in $Get_GPO_ID){

$RequestURL = ("https://graph.microsoft.com/beta/deviceManagement/groupPolicyMigrationReports('{0}')" -f [uri]::EscapeDataString($GPO_ID))
$RequestURL

Invoke-MgGraphRequest -Method DELETE $RequestURL -ErrorAction Stop | Out-Null

}
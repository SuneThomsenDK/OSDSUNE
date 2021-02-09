#Configuration
Add-Type -Path "C:\Program Files\Update Services\API\Microsoft.UpdateServices.Administration.dll"

$Date = Get-Date –f "dd-MM-yyyy HH:mm:ss"
$UseSSL = $False
$PortNumber = 8530
$Server = "WSUS SERVER"
$ReportLocation = "E:\WSUS\CleanupReport.html"
$SMTPServer = "mail.domain.com"
$SMTPPort = 25
$To = "Full Name <user@domain.com>"
$From = "System Notify <system.notify@domain.com>"
$WSUSConnection = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer($Server,$UseSSL,$PortNumber)

#Clean Up Scope
$CleanupScopeObject = New-Object Microsoft.UpdateServices.Administration.CleanupScope
$CleanupScopeObject.CleanupObsoleteComputers = $True
$CleanupScopeObject.CleanupObsoleteUpdates = $True
$CleanupScopeObject.CleanupUnneededContentFiles = $True
$CleanupScopeObject.CompressUpdates = $True
$CleanupScopeObject.DeclineExpiredUpdates = $True
$CleanupScopeObject.DeclineSupersededUpdates = $True

$CleanupTASK = $WSUSConnection.GetCleanupManager()
$Results = $CleanupTASK.PerformCleanup($CleanupScopeObject)

$DObject = New-Object PSObject
$DObject | Add-Member -MemberType NoteProperty -Name "SupersededUpdatesDeclined" -Value $Results.SupersededUpdatesDeclined
$DObject | Add-Member -MemberType NoteProperty -Name "ExpiredUpdatesDeclined" -Value $Results.ExpiredUpdatesDeclined
$DObject | Add-Member -MemberType NoteProperty -Name "ObsoleteUpdatesDeleted" -Value $Results.ObsoleteUpdatesDeleted
$DObject | Add-Member -MemberType NoteProperty -Name "UpdatesCompressed" -Value $Results.UpdatesCompressed
$DObject | Add-Member -MemberType NoteProperty -Name "ObsoleteComputersDeleted" -Value $Results.ObsoleteComputersDeleted
$DObject | Add-Member -MemberType NoteProperty -Name "DiskSpaceFreed" -Value $Results.DiskSpaceFreed

#HTML style
$HeadStyle = "<style>"
$HeadStyle = $HeadStyle + "BODY{background-color:White;}"
$HeadStyle = $HeadStyle + "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}"
$HeadStyle = $HeadStyle + "TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:YellowGreen}"
$HeadStyle = $HeadStyle + "TD{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:Gainsboro}"
$HeadStyle = $HeadStyle + "</style>"

$DObject | ConvertTo-Html -Head $HeadStyle -Body "<h2>$($ENV:ComputerName) WSUS Cleanup Report: $Date</h2>" | Out-File $ReportLocation -Force
# Send-MailMessage -To $To -From $From -Subject "WSUS Cleanup Report" -SmtpServer $SMTPServer -Attachments $ReportLocation -Port $SMTPPort 
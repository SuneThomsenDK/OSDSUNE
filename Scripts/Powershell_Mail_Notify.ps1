#Configuration
$Date = Get-Date –f "dd-MM-yyyy HH:mm:ss"
$ReportLocation = "C:\Temp\Report.html"
$SMTPServer = "moe-mail.moe.local"
$SMTPPort = 25
$To = "XXX <XXX@moe.dk>"
$From = "XXX <XXX@moe.dk>"

#Main Script

$Object = get-disk

#HTML style

$HeadStyle = "<style>"
$HeadStyle = $HeadStyle + "BODY{background-color:White;}"
$HeadStyle = $HeadStyle + "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}"
$HeadStyle = $HeadStyle + "TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:YellowGreen}"
$HeadStyle = $HeadStyle + "TD{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:Gainsboro}"
$HeadStyle = $HeadStyle + "</style>"

$Object | ConvertTo-Html -Head $HeadStyle -Body "<h2>$($ENV:ComputerName) Report - $date</h2>" | Out-File $ReportLocation -Force

if ((Get-item $ReportLocation).length -gt 2KB){
Send-MailMessage -To $To -from $FROM -subject "XXX" -smtpServer $SMTPServer -Attachments $ReportLocation -Port $SMTPPort
}
$A = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument '-ExecutionPolicy ByPass -File C:\Scripts\PowerShell_Script_Here.ps1'
$T = New-ScheduledTaskTrigger -WeeksInterval 1 -DaysOfWeek Sunday -At "21:00" -Weekly
Register-ScheduledTask -User "NT AUTHORITY\SYSTEM" -TaskName 'TASK NAME HERE' -Trigger $T -Action $A
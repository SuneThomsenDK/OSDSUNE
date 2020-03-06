$A = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument '-ExecutionPolicy ByPass -File C:\Script\PowerShell_Script_Here.ps1'
$T = New-ScheduledTaskTrigger -Daily -At "03:00"
Register-ScheduledTask -User "NT AUTHORITY\SYSTEM" -TaskName 'TASK NAME HERE' -Trigger $T -Action $A
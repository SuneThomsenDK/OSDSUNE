((New-Object -comobject "CPApplet.CPAppletMgr").GetClientActions() | Where-Object { $_.ActionID -eq '{00000000-0000-0000-0000-000000000123}' }).PerformAction();"Application Global Evaluation"
((New-Object -comobject "CPApplet.CPAppletMgr").GetClientActions() | Where-Object { $_.ActionID -eq '{8EF4D77C-8A23-45c8-BEC3-630827704F51}' }).PerformAction();"Request & Evaluate Machine Policy"
((New-Object -comobject "CPApplet.CPAppletMgr").GetClientActions() | Where-Object { $_.ActionID -eq '{3A88A2F3-0C39-45fa-8959-81F21BF500CE}' }).PerformAction();"Request & Evaluate User Policy"
((New-Object -comobject "CPApplet.CPAppletMgr").GetClientActions() | Where-Object { $_.ActionID -eq '{00000000-0000-0000-0000-000000000108}' }).PerformAction();"Software Updates Assignments Evaluation Cycle"
((New-Object -comobject "CPApplet.CPAppletMgr").GetClientActions() | Where-Object { $_.ActionID -eq '{00000000-0000-0000-0000-000000000113}' }).PerformAction();"Updates Source Scan Cycle"
((New-Object -comobject "CPApplet.CPAppletMgr").GetClientActions() | Where-Object { $_.ActionID -eq '{00000000-0000-0000-0000-000000000101}' }).PerformAction();"Hardware Inventory Collection Cycle"



<#
Software Metering Usage Report :00000000-0000-0000-0000-000000000106
Request & Evaluate Machine Policy :8EF4D77C-8A23-45c8-BEC3-630827704F51
Updates Source Scan :00000000-0000-0000-0000-000000000113
Request & Evaluate User Policy:3A88A2F3-0C39-45fa-8959-81F21BF500CE
Hardware Inventory Collection:00000000-0000-0000-0000-000000000101
Software Inventory Collection:00000000-0000-0000-0000-000000000102
Application Global Evaluation:00000000-0000-0000-0000-000000000123
Software Updates Assignments Evaluation:00000000-0000-0000-0000-000000000108
Discovery Data Collection:00000000-0000-0000-0000-000000000103
MSI Product Source Update:00000000-0000-0000-0000-000000000107
Standard File Collection:00000000-0000-0000-0000-000000000104

#NOT WORKING#
WMIC /namespace:\\root\ccm path sms_client CALL TriggerSchedule "{00000000-0000-0000-0000-000000000121}" /NOINTERACTIVE

#>
$NetAdapter = Get-NetAdapter | Where-Object InterfaceType -eq 6 | Get-DnsClient
$RegDNS = [string]$NetAdapter.RegisterThisConnectionsAddress
if (($RegDNS -match "True")){Return $True} else {Return $False}


$NetAdapter = Get-NetAdapter | Where-Object InterfaceType -eq 71 | Get-DnsClient
$RegDNS = [string]$NetAdapter.RegisterThisConnectionsAddress
if (($RegDNS -match "True")){Return $True} else {Return $False}


Get-NetAdapter | Where-Object InterfaceType -eq 6 | Set-DnsClient -RegisterThisConnectionsAddress $False
Get-NetAdapter | Where-Object InterfaceType -eq 71 | Set-DnsClient -RegisterThisConnectionsAddress $False




$a = get-netadapter | Where-Object InterfaceType -eq 71 | Get-DnsClient
$b = $a.RegisterThisConnectionsAddress
return $b


$a = get-netadapter eth* | Get-DnsClient
$b = $a.RegisterThisConnectionsAddress
return $b

$a = get-netadapter wi* | Get-DnsClient
$b = $a.RegisterThisConnectionsAddress
return $b
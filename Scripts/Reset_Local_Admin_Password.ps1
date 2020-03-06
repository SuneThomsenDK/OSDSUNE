#Create EncodedPass
#$NewPass = 'New Password Here'
#$EncodedPass = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($NewPass))
#$EncodedPass

#Reset Local Admin Password
$EncodedPass = 'TgBlAHcAUABhAHMAcwB3AG8AcgBkAEgAZQByAGUA'
$DecodedPass = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedPass))
$Username = 'Administrator'
Net User $Username $DecodedPass
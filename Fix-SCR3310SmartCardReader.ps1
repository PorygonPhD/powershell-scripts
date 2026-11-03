# Very barebones script that fixes the issues with the SCR3310 smart card readers having various driver issues.

$acl = Get-Acl HKLM:\SOFTWARE\Microsoft\Cryptography\Calais
$rule = New-Object System.Security.AccessControl.RegistryAccessRule ("local service","FullControl",@("ObjectInherit","ContainerInherit"),"None","Allow")
$acl.SetAccessRule($rule)
$acl | Set-Acl -Path HKLM:\SOFTWARE\Microsoft\Cryptography\Calais

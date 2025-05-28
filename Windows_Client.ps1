# Nombre PC cliente
#### https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/rename-computer?view=powershell-7.5
Rename-Computer -NewName "AlphaWOS1"

# Mostrar extensiones de archivo
#### https://stealthpuppy.com/image-customise/registry/#useralljson
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0

# DNS del AD
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "192.168.1.10"

# Configurar gateway predeterminado (gateway Sofos)
New-NetRoute -InterfaceAlias "Ethernet" -DestinationPrefix "0.0.0.0/0" -NextHop "192.168.1.69"

# Unirse al dominio
$User = "dreamteam\Administrator"
$DomainName = "dreamteam.local"
$Password = "Chinchillas24$"
$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential ($User, $SecurePassword)
Add-Computer -DomainName $DomainName -Credential $Credential -Force -Restart

# Agregar los demas usuarios
$dominio = "dreamteam"
$groupo = "Users"
$usuarios= @("Vicente","Ariel","Martin","Chinchillas","Guzman")
foreach ($user in $usuarios) {
    $completeUser = "$dominio\$user"
    Add-LocalGroupMember -Group $groupo -Member $completeUser
}

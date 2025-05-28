# REQUERIMIENTO: Crear dominio AD funcional

$DomainName        = "dreamteam.local"
$NetBIOSName       = "DREAMTEAM"
$AdminPassword     = ConvertTo-SecureString "Chinchillas24$" -AsPlainText -Force
$DomainMode        = "Win2025"
$ForestMode        = "Win2025"
$DatabasePath      = "C:\WINDOWS\NTDS"
$SysvolPath        = "C:\WINDOWS\SYSVOL"
$LogPath           = "C:\WINDOWS\NTDS"

# Crear bosque y dominio
Import-Module ADDSDeployment
Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName $NetBIOSName `
    -SafeModeAdministratorPassword $AdminPassword `
    -DomainMode $DomainMode `
    -ForestMode $ForestMode `
    -DatabasePath $DatabasePath `
    -SysvolPath $SysvolPath `
    -LogPath $LogPath `
    -CreateDnsDelegation:$false `
    -InstallDns:$true `
    -NoRebootOnCompletion:$false `
    -Force:$true

# Documentación oficial: 
#### https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/install-active-directory-domain-services--level-100-#BKMK_PSForest
#### https://learn.microsoft.com/en-us/powershell/module/addsdeployment/install-addsforest
#### https://learn.microsoft.com/en-us/training/paths/active-directory-domain-services/
#### https://learn.microsoft.com/es-es/training/paths/active-directory-domain-services/

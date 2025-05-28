# 3_configuracion.ps1
# CONFIGURACIÓN COMPLETA POST-AD PARA DreamTeam

# REQUERIMIENTO: Remote Desktop Protocol

#### https://learn.microsoft.com/en-us/answers/questions/304178/enable-disable-rdp-gpo-from-regedit
Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

##instalación de RDP modulos como en gui
#### https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-deploy-infrastructure
$serverName = "$env:COMPUTERNAME"
Install-WindowsFeature -Name RDS-Connection-Broker, RDS-Web-Access, RDS-RD-Server -IncludeManagementTools
Import-Module RemoteDesktop
New-RDSessionDeployment `
    -ConnectionBroker $serverName `
    -SessionHost $serverName `
    -WebAccessServer $serverName
New-RDSessionCollection `
    -CollectionName "ColeccionRDP" `
    -SessionHost $serverName `
    -ConnectionBroker $serverName `
    -CollectionDescription "Sesión basada en escritorio en Windows Server"

# Diccionario de usuarios con sus contraseñas 
# "Administrator" = "Chinchillas24$"
$usuarios = @{
    "Chinchillas" = "DreamTeam_2024!"
    "Vicente"     = "DreamTeam_2024!"
    "Ariel"       = "DreamTeam_2024!"
    "Guzman"      = "DreamTeam_2024!"
    "Martin"      = "DreamTeam_2024!"
}

#### https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipaddress
$ServerIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "169.*" -and $_.IPAddress -ne "127.0.0.1" -and $_.InterfaceAlias -notlike "*vEthernet*" } | Select-Object -First 1 -ExpandProperty IPAddress)
$DomainName = "dreamteam.local"

# Requisitos: GPO 1. Complejidad de contraseña y GPO 2. Expiración/cambio contraseña
#### https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-addefaultdomainpasswordpolicy
Set-ADDefaultDomainPasswordPolicy -Identity $DomainName -ComplexityEnabled $true
Set-ADDefaultDomainPasswordPolicy -Identity $DomainName -MinPasswordLength 8
Set-ADDefaultDomainPasswordPolicy -Identity $DomainName -MaxPasswordAge (New-TimeSpan -Days 30)
Set-ADDefaultDomainPasswordPolicy -Identity $DomainName -MinPasswordAge (New-TimeSpan -Days 1)

# REQUERIMIENTO: Crear contenedores Unidades Organizativas (OUs)
#### https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adorganizationalunit
New-ADOrganizationalUnit -Name "TI" -Path "DC=dreamteam,DC=local"
New-ADOrganizationalUnit -Name "Usuarios" -Path "DC=dreamteam,DC=local"

# REQUERIMIENTO: Crear grupo
#### https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adgroup
#### https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#group-scope
New-ADGroup -Name "TI_Grupo" -GroupScope Global -GroupCategory Security -Path "OU=TI,DC=dreamteam,DC=local"

# REQUERIMIENTO: Crear usuarios
#### https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-aduser
#### https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring
#### https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-adgroupmember
foreach ($user in $usuarios.Keys) {
    $securePass = ConvertTo-SecureString $usuarios[$user] -AsPlainText -Force
    New-ADUser -Name $user `
               -SamAccountName $user `
               -UserPrincipalName "$user@dreamteam.local" `
               -AccountPassword $securePass `
               -Path "OU=Usuarios,DC=dreamteam,DC=local" `
               -Enabled $true

    Add-ADGroupMember -Identity "TI_Grupo" -Members $user
}

# REQUERIMIENTO: Compartir archivos basado en AD (carpeta compartida)
New-Item -Path "C:\Compartido" -ItemType Directory -Force
New-SmbShare -Name "ArchivosTI" -Path "C:\Compartido" -FullAccess "TI_Grupo"

# REQUERIMIENTO: SFTP implementado (openSSH)
#### https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse
Add-WindowsCapability -Online -Name "OpenSSH.Server~~~~0.0.1.0"
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

# REQUERIMIENTO: Configuración de IIS
##### https://learn.microsoft.com/en-us/iis/get-started/getting-started-with-iis/create-a-web-site
##### https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/add-content
Add-Content -Path "C:\inetpub\wwwroot\index.html" -Value "<h1>Bienvenidos a DreamTeam</h1>" # se accede en http://localhost

# REQUERIMIENTO: DHCP implementado
#### https://learn.microsoft.com/en-us/windows-server/networking/technologies/dhcp/quickstart-install-configure-dhcp-server?tabs=powershell
Add-DhcpServerv4Scope -Name "DreamTeam LAN" -StartRange 192.168.1.100 -EndRange 192.168.1.200 -SubnetMask 255.255.255.0 -State Active
Set-DhcpServerv4OptionValue -OptionId 6 -Value ([IPAddress]$ServerIP)

# REQUERIMIENTO: Aplicar al menos 10 políticas GPO
#### https://learn.microsoft.com/en-us/powershell/module/grouppolicy/?view=windowsserver2025-ps
#### https://learn.microsoft.com/en-us/powershell/module/grouppolicy/set-gpregistryvalue?view=windowsserver2025-ps
# Lista de GPOs a crear
$gpos = @(
    "GPO_USB",
    "GPO_ProtectorPantalla",
    "GPO_BloqueoCopilot",
    "GPO_RedirCarpetas",
    "GPO_BloqueoPanelControl",
    "GPO_Autorun",
    "GPO_BloqueoTareasProgramadas"
)

foreach ($gpo in $gpos) {
    New-GPO -Name $gpo
    New-GPLink -Name $gpo -Target "OU=Usuarios,DC=dreamteam,DC=local"
}

# 3. Bloqueo de USB
#### https://answers.microsoft.com/en-us/windows/forum/all/enablingdisabling-usb/35d2fbf3-ed12-4cb8-88ed-840012de9050
Set-GPRegistryValue -Name "GPO_USB" -Key "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" -ValueName "Start" -Type DWord -Value 4

# 4. Protector de pantalla (120s) y 5. Solicitar contraseña
#### https://www.windows-commandline.com/disable-screensaver-registry-settings/
#### https://learn.microsoft.com/en-us/answers/questions/484055/set-up-screensave-via-registry-in-order-to-change
Set-GPRegistryValue -Name "GPO_ProtectorPantalla" -Key "HKCU\Control Panel\Desktop" -ValueName "ScreenSaveTimeOut" -Type String -Value "120"
Set-GPRegistryValue -Name "GPO_ProtectorPantalla" -Key "HKCU\Control Panel\Desktop" -ValueName "ScreenSaverIsSecure" -Type String -Value "1"

# 6. Bloqueo de Copilot
#### https://github.com/NathanOrdSec/DisableWindowsCopilot
Set-GPRegistryValue -Name "GPO_BloqueoCopilot" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -ValueName "TurnOffWindowsCopilot" -Type DWord -Value 1

# 7. Redirección de carpeta Documentos
#### https://answers.microsoft.com/en-us/windows/forum/all/change-registry-values-of-user-shell-folders-some/7c9a133d-91f4-4f1b-9d8f-f7b7d4be5959
#### https://www.winhelponline.com/blog/windows-10-shell-folders-paths-defaults-restore/
Set-GPRegistryValue -Name "GPO_RedirCarpetas" `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" `
    -ValueName "Personal" `
    -Type ExpandString `
    -Value "\\$ServerIP\Compartido"

# 8. Bloqueo del Panel de Control
#### https://activedirectorypro.com/restrict-control-panel-access-using-group-policy/
Set-GPRegistryValue -Name "GPO_BloqueoPanelControl" -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoControlPanel" -Type DWord -Value 1

# 9. Deshabilitar Autorun
#### https://learn.microsoft.com/en-us/windows/win32/shell/autoplay-reg
Set-GPRegistryValue -Name "GPO_Autorun" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoDriveTypeAutoRun" -Type DWord -Value 255

# 10. 
#### https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-mmc
Set-GPRegistryValue -Name "GPO_BloqueoTareasProgramadas" -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\MMC\{c7f7e1f5-f63c-11d3-90db-00c04f68873c}" -ValueName "Restrict_Run" -Type DWord -Value 1


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

# Create a new user named nextcloud in the Users container
$nextcloudPassword = ConvertTo-SecureString "Chinchillas24$" -AsPlainText -Force
New-ADUser -Name "nextcloud" `
           -SamAccountName "nextcloud" `
           -UserPrincipalName "nextcloud@dreamteam.local" `
           -AccountPassword $nextcloudPassword `
           -Path "CN=Users,DC=dreamteam,DC=local" `
           -Enabled $true

# Add nextcloud to the TI_Grupo group
Add-ADGroupMember -Identity "TI_Grupo" -Members "Administrator"

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

# REQUERIMIENTO: Compartir archivos basado en AD (carpeta compartida) (samba)
#### https://learn.microsoft.com/en-us/windows-server/storage/file-server/file-server-smb-overview
#### https://woshub.com/manage-windows-file-shares-with-powershell/
$folderPath = "C:\Compartido"
New-Item -Path $folderPath -ItemType Directory -Force
New-SmbShare -Name "ArchivosTI" -Path $folderPath -FullAccess "TI_Grupo"
Grant-SmbShareAccess -Name "ArchivosTI" -AccountName "Administrator" -AccessRight Full -Force
Grant-SmbShareAccess -Name "ArchivosTI" -AccountName "TI_Grupo" -AccessRight Full -Force
Grant-SmbShareAccess -Name "ArchivosTI" -AccountName "Everyone" -AccessRight Full -Force
$acl = Get-Acl $folderPath
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("TI_Grupo", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($accessRule)
Set-Acl -Path $folderPath -AclObject $acl


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
    "GPO_ComplexityPassword",
    "GPO_ExpirationPassword",
    "GPO_USB",
    "GPO_ProtectorPantalla",
    "GPO_BloqueoCopilot",
    "GPO_RedirCarpetas",
    "GPO_BloqueoPanelControl",
    "GPO_Autorun",
    "GPO_BloqueoTareasProgramadas",
    "GPO_BloqueoConfiguracionWindows"
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

# 5. Bloqueo de Copilot
#### https://github.com/NathanOrdSec/DisableWindowsCopilot
Set-GPRegistryValue -Name "GPO_BloqueoCopilot" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -ValueName "TurnOffWindowsCopilot" -Type DWord -Value 1

# 6. Redirección de carpeta Documentos
#### https://answers.microsoft.com/en-us/windows/forum/all/change-registry-values-of-user-shell-folders-some/7c9a133d-91f4-4f1b-9d8f-f7b7d4be5959
#### https://www.winhelponline.com/blog/windows-10-shell-folders-paths-defaults-restore/
Set-GPRegistryValue -Name "GPO_RedirCarpetas" `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" `
    -ValueName "Personal" `
    -Type ExpandString `
    -Value "\\$ServerIP\Compartido"

# 7. Bloqueo del Panel de Control
#### https://activedirectorypro.com/restrict-control-panel-access-using-group-policy/
Set-GPRegistryValue -Name "GPO_BloqueoPanelControl" -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoControlPanel" -Type DWord -Value 1

# 8. Deshabilitar Autorun
#### https://learn.microsoft.com/en-us/windows/win32/shell/autoplay-reg
Set-GPRegistryValue -Name "GPO_Autorun" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoDriveTypeAutoRun" -Type DWord -Value 255

# 9. bloqueo de Tareas Programadas
#### https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-mmc
Set-GPRegistryValue -Name "GPO_BloqueoTareasProgramadas" -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\MMC\{c7f7e1f5-f63c-11d3-90db-00c04f68873c}" -ValueName "Restrict_Run" -Type DWord -Value 1

# 10. Deshabilitar el acceso a la configuración de Windows
Set-GPRegistryValue -Name "GPO_BloqueoConfiguracionWindows" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoSettings" -Type DWord -Value 1



## ldap 
#### https://forum.netgate.com/topic/187453/ldap-authentication-with-active-directory-windows-server-2025-bind-fails/3
#### https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server

# LDAP Server channel binding token requirements: "When Supported" (1)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v "LDAPEnforceChannelBinding" /t REG_DWORD /d 1 /f

# LDAP server signing requirements: "None" (0)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v "LDAPServerIntegrity" /t REG_DWORD /d 0 /f

# LDAP server enforce signing: "Disabled" (ya manejado por el de arriba)

# LDAP client encryption requirements: "Negotiate Sealing" (0)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LdapClientIntegrity" /t REG_DWORD /d 0 /f

# LDAP client signing requirements: "Negotiate Signing" (1)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LdapClientSigningRequirements" /t REG_DWORD /d 1 /f

Restart-Computer -Force # reinicio requerido

# https://support.microsoft.com/en-us/topic/client-service-and-program-issues-can-occur-if-you-change-security-settings-and-user-rights-assignments-0cb6901b-dcbf-d1a9-e9ea-f1b49a56d53a
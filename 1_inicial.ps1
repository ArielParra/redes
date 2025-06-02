# Primero Instalamos vboxGuest additions con el disco

# Nombre PC cliente
#### https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/rename-computer?view=powershell-7.5
Rename-Computer -NewName "AlphaWOS1" -Restart

# zona horaria 
#### https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-timezone?view=powershell-7.5
Set-TimeZone -Id "Central Standard Time (Mexico)"

# Ip fija
#### https://learn.microsoft.com/en-us/windows-server/administration/server-core/server-core-administer#set-a-static-ip-address
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.1.10 -PrefixLength 24 -DefaultGateway 192.168.1.254

# Configurar gateway predeterminado (gateway Sofos)
Remove-NetRoute -InterfaceAlias "Ethernet" -DestinationPrefix "0.0.0.0/0" 
New-NetRoute -InterfaceAlias "Ethernet" -DestinationPrefix "0.0.0.0/0" -NextHop "192.168.1.69"

# Mostrar extensiones de archivo
#### https://stealthpuppy.com/image-customise/registry/#useralljson
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0

# Activar modo de rendimiento en Windows Server Desktop
#### https://learn.microsoft.com/en-us/archive/msdn-technet-forums/73d72328-38ed-4abe-a65d-83aaad0f9047
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name VisualFXSetting -Value 2

# REQUERIMIENTO: Instalar roles Active Directory, DNS, DHCP, Web-Server (IIS), RDS (Terminal Server)
##### https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/install-active-directory-domain-services--level-100-
##### https://learn.microsoft.com/en-us/windows-server/networking/dns/quickstart-install-configure-dns-server
##### https://learn.microsoft.com/en-us/windows-server/networking/technologies/dhcp/quickstart-install-configure-dhcp-server
##### https://learn.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/install-the-web-server-web1
Install-WindowsFeature AD-Domain-Services, DNS, DHCP, Web-Server, RDS-RD-Server -IncludeManagementTools

# Herramientas administrativas adicionales (del DeploymentConfigTemplate.xml creado por el GUI)
#### https://learn.microsoft.com/en-us/powershell/module/servermanager/install-windowsfeature?view=windowsserver2025-ps
#### https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-management-console#group-policy-management-console
#### https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remote-server-administration-tools
Install-WindowsFeature GPMC                         # Consola de directivas de grupo
Install-WindowsFeature RSAT-AD-AdminCenter          # Centro de administración de AD
Install-WindowsFeature RSAT-AD-PowerShell           # Cmdlets AD
Install-WindowsFeature RSAT-ADDS-Tools              # Herramientas de AD DS
Install-WindowsFeature RSAT-Role-Tools              # Herramientas de rol

Restart-Computer -Force # reinicio requerido

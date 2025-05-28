# 4_verificacion.ps1
# VERIFICACIÓN DE REQUISITOS DE IMPLEMENTACIÓN DE WINDOWS AD PARA DREAMTEAM

Write-Host "`n========= VERIFICACIÓN DE CONTROLADORES DE DOMINIO =========`n"

# Verificar si es un controlador de dominio (PDC o BDC)
$domainRole = (Get-ADDomainController -Filter * | Select-Object -First 1).OperationMasterRoles
if ($domainRole) {
    Write-Host "✅ Controlador de Dominio detectado: $($domainRole -join ', ')"
} else {
    Write-Host "❌ No se detecta un controlador de dominio"
}

Write-Host "`n========= UNIDADES ORGANIZATIVAS, CONTENEDORES, GRUPOS, USUARIOS =========`n"

# Verificar OUs
$ous = Get-ADOrganizationalUnit -Filter *
Write-Host "🗂️ Unidades Organizativas encontradas: $($ous.Count)"

# Verificar contenedores (por ejemplo: Users, Computers, etc.)
$containers = Get-ADObject -Filter 'ObjectClass -eq "container"'
Write-Host "📁 Contenedores encontrados: $($containers.Count)"

# Verificar grupos
$grupos = Get-ADGroup -Filter *
Write-Host "👥 Grupos encontrados: $($grupos.Count)"

# Verificar usuarios
$usuarios = Get-ADUser -Filter *
Write-Host "👤 Usuarios encontrados: $($usuarios.Count)"

Write-Host "`n========= COMPARTICIÓN DE ARCHIVOS/IMPRESORAS =========`n"

# Verificar recursos compartidos
$shares = Get-SmbShare | Where-Object {$_.Name -ne "ADMIN$"}
Write-Host "📂 Recursos compartidos encontrados: $($shares.Count)"

# Nota: Para compatibilidad con Linux (ej. Samba), sería necesario revisar configuración de permisos NTFS y compatibilidad Samba si aplica.

Write-Host "`n========= DNS IMPLEMENTADO =========`n"
if (Get-WindowsFeature -Name DNS | Where-Object Installed) {
    Write-Host "✅ Servicio DNS instalado"
} else {
    Write-Host "❌ Servicio DNS no encontrado"
}

Write-Host "`n========= DHCP IMPLEMENTADO =========`n"
if (Get-WindowsFeature -Name DHCP | Where-Object Installed) {
    Write-Host "✅ Servicio DHCP instalado"
} else {
    Write-Host "❌ Servicio DHCP no encontrado"
}

Write-Host "`n========= TERMINAL SERVER / RDS =========`n"
if (Get-WindowsFeature -Name RDS-RD-Server | Where-Object Installed) {
    Write-Host "✅ RDS Terminal Server instalado"
} else {
    Write-Host "❌ RDS Terminal Server no encontrado"
}

Write-Host "`n========= VERIFICACIÓN DE ESCRITORIOS VIRTUALIZADOS =========`n"

# Verificar sesiones activas de escritorio remoto
$sessions = query user
if ($sessions) {
    Write-Host "💻 Sesiones activas encontradas:"
    $sessions
} else {
    Write-Host "❌ No se detectan sesiones activas"
}

Write-Host "`n========= IIS Y SFTP =========`n"

# Verificar IIS
if (Get-WindowsFeature Web-Server | Where-Object Installed) {
    Write-Host "✅ IIS instalado"
} else {
    Write-Host "❌ IIS no encontrado"
}

# Verificar si SFTP (Servidor OpenSSH) está presente
$openssh = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
if ($openssh.State -eq "Installed") {
    Write-Host "✅ SFTP (OpenSSH Server) instalado"
} else {
    Write-Host "❌ SFTP no instalado"
}

Write-Host "`n========= VERIFICACIÓN DE POLÍTICAS DE GRUPO =========`n"

# Requiere módulo GroupPolicy
$gpos = Get-GPO -All
Write-Host "🛡️ Políticas de grupo encontradas: $($gpos.Count)"
if ($gpos.Count -ge 10) {
    Write-Host "✅ Al menos 10 políticas de GPO configuradas"
} else {
    Write-Host "❌ Menos de 10 políticas GPO detectadas"
}

# Verificar complejidad de contraseñas
$complexity = (Get-ADDefaultDomainPasswordPolicy).ComplexityEnabled
if ($complexity) {
    Write-Host "✅ Complejidad de contraseñas habilitada"
} else {
    Write-Host "❌ Complejidad de contraseñas no habilitada"
}
#!/usr/bin/env sh
set -e

#  actualizar el sistema para instalar dependencias
sudo apt update && sudo apt -y upgrade

# poner nombre de host
# sudo hostnamectl set-hostname alphal2

# Poner ip fija en debian
#### https://www.debian.org/doc/manuals/debian-reference/ch05.en.html
#### https://wiki.debian.org/NetworkConfiguration

# poner dns de AD en resolv.conf
sudo systemctl disable --now systemd-resolved ## para poder usar resolv.conf
sudo rm -f /etc/resolv.conf
echo -e "nameserver 192.168.1.10\nnameserver 1.1.1.1" | sudo tee /etc/resolv.conf

INTERFACE="enp0s3"
IP_ADDRESS="192.168.1.11/24"
# sophos firewall como gateway
GATEWAY="192.168.1.69"
GATEWAY2="192.168.1.254"
DNS1="192.168.1.10"
DNS2="1.1.1.1"
sudo tee /etc/systemd/network/10-static.network > /dev/null <<EOF
[Match]
Name=$INTERFACE

[Network]
Address=$IP_ADDRESS
Gateway=$GATEWAY1
Gateway=$GATEWAY2
DNS=$DNS1
DNS=$DNS2
EOF
sudo systemctl enable systemd-networkd --now ## para poder usar systemd-networkd
sudo systemctl restart systemd-networkd
sudo systemctl disable --now NetworkManager || true


# poner ip fija en ubuntu
#### https://ubuntu.com/server/docs/network-configuration

#INTERFACE="enp0s3"
#IP_ADDRESS="192.168.1.19/24"
#GATEWAY="192.168.1.69"
#GATEWAY2="192.168.1.254"
#DNS1="192.168.1.10"
#DNS2="1.1.1.1"
#sudo tee /etc/netplan/01-netcfg.yaml > /dev/null <<EOF
#network:
#  version: 2
#  renderer: NetworkManager
#  ethernets:
#    enp0s3:
#      dhcp4: no
#      addresses:
#        - $IP_ADDRESS
#      nameservers:
#        addresses:
#          - $DNS1
#          - $DNS2
#      routes:
#        - to: 0.0.0.0/0
#          via: $GATEWAY
#EOF
# sudo netplan apply

# REQUISITO: Acceso activo por SSH
#### https://documentation.ubuntu.com/server/how-to/security/openssh-server/index.html
sudo apt install -y openssh-server
sudo systemctl enable ssh
sudo systemctl start ssh

# REQUISITO: instalar webmin
#### https://webmin.com/download/
curl -o webmin-setup-repo.sh https://raw.githubusercontent.com/webmin/webmin/master/webmin-setup-repo.sh
chmod +x ./webmin-setup-repo.sh
printf "y\n" | sudo ./webmin-setup-repo.sh
sudo apt update
sudo apt install -y webmin --install-recommends

# REQUISITO: terminal server
#### https://access.redhat.com/solutions/5312
#### https://gitlab.freedesktop.org/mstoeckl/waypipe

SESSION_TYPE=${XDG_SESSION_TYPE:-unknown}
if [ "$SESSION_TYPE" = "x11" ]; then
    mkdir -p ~/.ssh
    if ! grep -q "ForwardX11 yes" ~/.ssh/config 2>/dev/null; then
        echo "ForwardX11 yes" >> ~/.ssh/config
        chmod 600 ~/.ssh/config
    fi
elif [ "$SESSION_TYPE" = "wayland" ]; then
    sudo apt install -y waypipe
else # ambos por si las flais
    sudo apt install -y waypipe
    mkdir -p ~/.ssh
    if ! grep -q "ForwardX11 yes" ~/.ssh/config 2>/dev/null; then
        echo "ForwardX11 yes" >> ~/.ssh/config
        chmod 600 ~/.ssh/config
    fi
fi

# REQUISITO: Conección a directorio activo (LDAP)
#### https://wiki.debian.org/AuthenticatingLinuxWithActiveDirectorySssd
#### https://documentation.ubuntu.com/server/how-to/sssd/with-active-directory/index.html
#### https://www.baeldung.com/linux/active-directory-authenticate-users
#### https://www.linkedin.com/pulse/how-join-linux-machine-active-directory-ad-domain-mohsen-rizkallah-36pkf/
#### https://youtu.be/UhYzoyQXXMA?si=2VIpN7OYZsmPvvNm&t=126
#### https://docs.redhat.com/es/documentation/red_hat_enterprise_linux/8/html/deploying_different_types_of_servers/assembly_setting-up-samba-as-an-ad-domain-member-server_assembly_using-samba-as-a-server
#### https://documentation.ubuntu.com/server/how-to/samba/member-server-in-an-ad-domain/index.html


sudo apt install -y realmd libnss-sss libpam-sss libpam-runtime sssd sssd-tools adcli samba-common-bin oddjob oddjob-mkhomedir packagekit
export PATH=$PATH:/usr/sbin

sudo realm join -v --membership-software=samba dreamteam.local -U Administrator # nos pedirá la contraseña del Administrator de AD
sudo pam-auth-update --enable mkhomedir 

# REQUISITO: Servidor Web (Apache)   
#### https://ubuntu.com/tutorials/install-and-configure-apache#1-overview
sudo apt install -y apache2
sudo sed -i \
  -e 's/^\s*memory_limit\s*=.*/memory_limit = 512M/' \
  -e 's/^\s*output_buffering\s*=.*/output_buffering = Off/' \
  /etc/php/8.2/apache2/php.ini

# SERVICIOS EN INFRAESTRUCTURA: Aplicativo a propuesta del equipo(nextcloud)
#### https://rephlex.de/blog/2018/04/05/how-to-connect-nextcloud-to-active-directory-using-ad-fs-without-losing-your-mind/
#### https://nextcloud.com/install/#instructions-server
#### https://docs.nextcloud.com/server/latest/admin_manual/installation/source_installation.html
#### https://www.howtoforge.com/step-by-step-installing-nextcloud-on-debian-12/

sudo apt install -y php-mbstring php php-zip php-xml php-common php-gd php-curl mariadb-server wget unzip php-mysql php-gd php-ldap
sudo systemctl restart apache2
sudo mysql -e "DELETE FROM mysql.user WHERE User='';"
sudo mysql -e "DROP DATABASE IF EXISTS test;"
sudo mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
sudo mysql -e "FLUSH PRIVILEGES;"

DB_NAME="nextcloud"
DB_USER="nextcloud"
DB_PASS="Chinchillas24$"

sudo mysql -e "CREATE DATABASE IF NOT EXISTS $DB_NAME;"
sudo mysql -e "CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';"
sudo mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

cd /var/www/html
sudo rm index.html
sudo wget --quiet https://download.nextcloud.com/server/releases/latest.zip
sudo unzip latest.zip
sudo rm latest.zip
sudo chown -R www-data:www-data /var/www/html/nextcloud

# ir a http://localhost/nextcloud y configurar la base de datos
# y activar ldap http://localhost/nextcloud/index.php/settings/apps/disabled/user_ldap

# REQUISITO: LDAP/AD en nextcloud
#### https://www.bujarra.com/integrando-nextcloud-con-el-directorio-activo/?lang=en
#### https://docs.nextcloud.com/server/latest/admin_manual/configuration_user/user_auth_ldap.html
#### https://www.youtube.com/watch?v=GW5_iO8FoqU


# Crear archivo PHP para probar conexión LDAP
sudo bash -c 'cat > ldap_test.php <<EOF
<?php
\$ldap_host = "ldap://192.168.1.10"; 
\$ldap_port = 389;
\$ldap_user = "cn=Administrator,cn=Users,dc=dreamteam,dc=local";
\$ldap_pass = "Chinchillas24\$";

\$ldap_conn = ldap_connect(\$ldap_host, \$ldap_port);

if (!\$ldap_conn) {
    die("❌ No se pudo conectar al servidor LDAP.\n");
}

ldap_set_option(\$ldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);
ldap_set_option(\$ldap_conn, LDAP_OPT_REFERRALS, 0);

if (ldap_bind(\$ldap_conn, \$ldap_user, \$ldap_pass)) {
    echo "✅ Conexión LDAP exitosa.\n";
} else {
    echo "❌ Falló el bind LDAP: " . ldap_error(\$ldap_conn) . "\n";
}

ldap_close(\$ldap_conn);
?>
EOF'
sudo ./ldap_test.php

#se configurar el acceso a LDAP/AD desde http://localhost/nextcloud/index.php/settings/admin/ldap
# ldap://192.168.1.10 puerto 389
# cn=Administrator,cn=Users,dc=dreamteam,dc=local
# Chinchillas24$
# DC=dreamteam,DC=local

# permitir acceso a localhost y a la red local
sudo sed -i "/0 => 'localhost'/a\ \ \ \ 1 => '192.168.1.11',\n\ \ \ \ 2 => '192.168.1.*'," /var/www/nextcloud/config/config.php

# REQUISITO: cliente SMB
#### https://ubuntu.com/tutorials/install-and-configure-samba#1-overview
#### https://www.redhat.com/en/blog/samba-windows-linux
#### https://linuxize.com/post/how-to-mount-cifs-windows-share-on-linux/
sudo apt update
sudo apt install -y samba smbclient cifs-utils

WIN_SERVER="192.168.1.10"
SHARE_NAME="ArchivosTI"  # Nombre correcto del recurso compartido
MOUNT_POINT="/Compartido"
USERNAME="Administrator"
PASSWORD="Chinchillas24$"
DOMAIN="dreamteam"
CRED_FILE="/etc/samba/credenciales"

sudo mkdir -p "$MOUNT_POINT"

sudo bash -c "cat > $CRED_FILE <<EOF
username=$USERNAME
password=$PASSWORD
domain=$DOMAIN
EOF"
sudo chmod 600 $CRED_FILE

FSTAB_ENTRY="//${WIN_SERVER}/${SHARE_NAME}  ${MOUNT_POINT}  cifs  credentials=${CRED_FILE},uid=0,gid=0,file_mode=0777,dir_mode=0777,_netdev,vers=3.0  0  0"
grep -qF "$FSTAB_ENTRY" /etc/fstab || echo "$FSTAB_ENTRY" | sudo tee -a /etc/fstab

sudo mount -a
sudo systemctl daemon-reload

sudo bash -c 'cat >> /etc/samba/smb.conf <<EOF

[ArchivosTI]
    path = /Compartido
    browseable = yes
    writable = yes
    guest ok = no
    valid users = administrator
    force user = root
EOF'
sudo systemctl restart smbd



# REQUISITO: Replica DNS Maestro Local (bind9)

sudo apt install -y bind9 bind9-utils

ZONA="dreamteam.local"
MAESTRO_IP="192.168.1.10"  # Cambia a la IP de tu DC
ZONA_CACHE_FILE="/var/cache/bind/db.${ZONA}"
BIND_CONF_DIR="/etc/bind"
NAMED_LOCAL="${BIND_CONF_DIR}/named.conf.local"
NAMED_OPTIONS="${BIND_CONF_DIR}/named.conf.options"

sudo sed -i '/^options {/,/^};/d' "$NAMED_OPTIONS"

echo "options {
    directory \"/var/cache/bind\";

    forwarders {
        1.1.1.1;
        8.8.8.8;
    };

    allow-query { any; };
    recursion yes;
    dnssec-validation auto;
};" | sudo tee -a "$NAMED_OPTIONS"

sudo systemctl restart bind9



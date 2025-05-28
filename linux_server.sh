# 3. SERVIDORES UNIX/LIKE UNIX
#!/usr/bin/env sh
set -e

#  actualizar el sistema para instalar dependencias
sudo apt update && sudo apt -y upgrade

# Poner ip fija en debian
#### https://www.debian.org/doc/manuals/debian-reference/ch05.en.html
#### https://wiki.debian.org/NetworkConfiguration

INTERFACE="enp0s3"
IP_ADDRESS="192.168.1.11/24"
# sophos firewall
GATEWAY="192.168.1.69"
DNS="1.1.1.1"

sudo tee /etc/systemd/network/10-static.network > /dev/null <<EOF
[Match]
Name=$INTERFACE

[Network]
Address=$IP_ADDRESS
Gateway=$GATEWAY
DNS=$DNS
EOF

sudo systemctl enable systemd-networkd --now
sudo systemctl restart systemd-networkd
sudo systemctl disable --now NetworkManager || true

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

# REQUISITO: Conección a directorio activo (LDAP)
#### https://docs.nextcloud.com/server/latest/admin_manual/configuration_user/user_auth_ldap.html
#### https://wiki.debian.org/AuthenticatingLinuxWithActiveDirectorySssd
#### https://www.bujarra.com/integrando-nextcloud-con-el-directorio-activo/?lang=en

#se configurar el acceso a LDAP/AD desde http://localhost/nextcloud/index.php/settings/admin/ldap
# ldap://192.168.1.10 puerto 389
# cn=Administrator,ou=Usuarios,dc=dreamteam,dc=local
# Chinchillas24$
# cn=Administrator,ou=Usuarios,dc=dreamteam,dc=local
# REQUISITO: cliente SMB
#### https://ubuntu.com/tutorials/install-and-configure-samba#1-overview
#### https://www.redhat.com/en/blog/samba-windows-linux
#### https://linuxize.com/post/how-to-mount-cifs-windows-share-on-linux/
WIN_SERVER="192.168.1.10"
SHARE_NAME="Compartido"
MOUNT_POINT="/home/$USER/Compartido"
USERNAME="Administrator"
PASSWORD="Chinchillas24$"
DOMAIN="dreamteam"
CRED_FILE="/etc/samba/credenciales"

sudo apt update
sudo apt install -y samba smbclient cifs-utils

mkdir -p "$MOUNT_POINT"

sudo bash -c "cat > $CRED_FILE <<EOF
username=$USERNAME
password=$PASSWORD
domain=$DOMAIN
EOF"
sudo chmod 600 $CRED_FILE

FSTAB_ENTRY="//${WIN_SERVER}/${SHARE_NAME}  ${MOUNT_POINT}  cifs  credentials=${CRED_FILE},uid=$UID,gid=$(id -g),_netdev,vers=3.0  0  0"

grep -qF "$FSTAB_ENTRY" /etc/fstab || echo "$FSTAB_ENTRY" | sudo tee -a /etc/fstab

sudo mount -a

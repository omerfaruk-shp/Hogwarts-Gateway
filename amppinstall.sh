#!/bin/bash
# Raspberry Pi 5 LAMPP (Apache, MariaDB, PHP, phpMyAdmin) Otomatik Kurulum
# Tüm ayarlar DEFAULT (root şifresi boş vs.)

echo "==============================="
echo "   Raspberry Pi 5 LAMPP Setup  "
echo "==============================="

# Root kontrolü
if [ "$EUID" -ne 0 ]; then
  echo "❌ Lütfen root olarak çalıştırın (sudo ile)."
  exit
fi

# Sistem güncelleme
echo "[1/6] Sistem güncelleniyor..."
apt update && apt upgrade -y

# Apache kurulumu
echo "[2/6] Apache kuruluyor..."
apt install apache2 -y
systemctl enable apache2
systemctl start apache2

# MariaDB (MySQL alternatifi) kurulumu
echo "[3/6] MariaDB kuruluyor..."
apt install mariadb-server mariadb-client -y
systemctl enable mariadb
systemctl start mariadb

# MariaDB güvenlik atlanıyor (default root / şifre boş)
echo "[4/6] MariaDB root şifresi DEFAULT (boş) bırakıldı."

# PHP kurulumu
echo "[5/6] PHP kuruluyor..."
apt install php libapache2-mod-php php-mysql php-cli php-curl php-gd php-mbstring php-xml php-zip unzip -y

# PHP test dosyası
echo "<?php phpinfo(); ?>" > /var/www/html/info.php

# phpMyAdmin kurulumu (DEFAULT ayarlarla)
echo "[6/6] phpMyAdmin kuruluyor..."
DEBIAN_FRONTEND=noninteractive apt install phpmyadmin -y
echo "Include /etc/phpmyadmin/apache.conf" >> /etc/apache2/apache2.conf
systemctl restart apache2

# Bilgi
echo "=================================="
echo "✅ Kurulum tamamlandı!"
echo "----------------------------------"
echo " Apache dizini   : /var/www/html"
echo " phpMyAdmin      : http://<Raspberry-IP>/phpmyadmin"
echo " MySQL kullanıcı : root"
echo " MySQL şifre     : (boş)"
echo " PHP test        : http://<Raspberry-IP>/info.php"
echo "=================================="

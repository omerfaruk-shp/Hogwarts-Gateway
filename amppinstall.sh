#!/bin/bash
# Raspberry Pi LAMPP Yönetim Scripti

APACHE="apache2"
MYSQL="mariadb"

while true; do
  clear
  echo "=============================="
  echo "   Raspberry Pi LAMPP Yönetim "
  echo "=============================="
  echo "1) Apache Başlat"
  echo "2) Apache Durdur"
  echo "3) Apache Yeniden Başlat"
  echo "4) Apache Durum"
  echo "------------------------------"
  echo "5) MariaDB Başlat"
  echo "6) MariaDB Durdur"
  echo "7) MariaDB Yeniden Başlat"
  echo "8) MariaDB Durum"
  echo "------------------------------"
  echo "9) Apache Loglarını İzle"
  echo "10) MariaDB Loglarını İzle"
  echo "11) Web Dizini (/var/www/html) Aç"
  echo "0) Çıkış"
  echo "=============================="
  read -p "Seçiminiz: " secim

  case $secim in
    1) sudo systemctl start $APACHE; echo "Apache başlatıldı."; sleep 2 ;;
    2) sudo systemctl stop $APACHE; echo "Apache durduruldu."; sleep 2 ;;
    3) sudo systemctl restart $APACHE; echo "Apache yeniden başlatıldı."; sleep 2 ;;
    4) systemctl status $APACHE; read -p "Devam etmek için enter..." ;;
    5) sudo systemctl start $MYSQL; echo "MariaDB başlatıldı."; sleep 2 ;;
    6) sudo systemctl stop $MYSQL; echo "MariaDB durduruldu."; sleep 2 ;;
    7) sudo systemctl restart $MYSQL; echo "MariaDB yeniden başlatıldı."; sleep 2 ;;
    8) systemctl status $MYSQL; read -p "Devam etmek için enter..." ;;
    9) sudo tail -f /var/log/apache2/error.log ;;
    10) sudo tail -f /var/log/mysql/error.log ;;
    11) cd /var/www/html && pwd && ls -l; read -p "Devam etmek için enter..." ;;
    0) echo "Çıkılıyor..."; exit ;;
    *) echo "❌ Geçersiz seçim"; sleep 2 ;;
  esac
done

# 🎯 Quick Start Guide - RITAPI Complete Installer

## Instalasi dalam 3 Langkah

### 1️⃣ Ekstrak File ZIP

```bash
unzip ritapi_complete_installer.zip
cd ritapi_complete_installer
```

### 2️⃣ Jalankan Installer

```bash
chmod +x install.sh
sudo ./install.sh
```

### 3️⃣ Pilih Menu "1" (Install)

```
Pilihan [1-4]: 1
```

Lalu ikuti instruksi. Selesai! 🎉

---

## Akses Aplikasi

Setelah instalasi selesai, akses:

```
http://IP-SERVER-ANDA/
```

---

## Perintah Berguna

**Cek status:**
```bash
sudo ./install.sh status
```

**Restart Django:**
```bash
sudo systemctl restart ritapi-gunicorn
```

**Restart MiniFW-AI:**
```bash
sudo systemctl restart minifw-ai
```

**Lihat logs:**
```bash
sudo journalctl -u ritapi-gunicorn -f
```

**Buat admin user:**
```bash
cd /opt/ritapi_v_sentinel
sudo -u www-data ./venv/bin/python manage.py createsuperuser
```

---

## Troubleshooting

**Permission error?**
```bash
cd scripts/minifw_fixed
sudo ./fix_permissions.sh
```

**Service tidak jalan?**
```bash
sudo systemctl restart ritapi-gunicorn minifw-ai nginx
```

**Web tidak bisa diakses?**
```bash
sudo journalctl -u ritapi-gunicorn -n 50
sudo journalctl -u minifw-ai -n 50
```

---

## Dokumentasi Lengkap

Baca file di folder `docs/`:
- `CARA_PAKAI.md` - Panduan lengkap
- `PANDUAN_INSTALASI_LENGKAP.md` - Dokumentasi detail

---

**Selamat menggunakan!** 🚀

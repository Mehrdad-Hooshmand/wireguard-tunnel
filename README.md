# 🔐 WireGuard Tunnel + Management Panel

**نسخه 2.0** - سیستم کامل مدیریت تانل WireGuard با پنل وب و دسکتاپ

[![GitHub Release](https://img.shields.io/badge/release-v2.0.0-blue.svg)](https://github.com/Mehrdad-Hooshmand/wireguard-tunnel/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 📋 فهرست مطالب
- [ویگیها](#-ویگیها)
- [معماری سیستم](#-معماری-سیستم)
- [نصب سریع](#-نصب-سریع)
- [دسکتاپ اپلیکیشن](#-دسکتاپ-اپلیکیشن)
- [API Reference](#-api-reference)
- [عیبیابی](#-عیبیابی)

---

## ✨ ویگیها

### 🚀 نصب خودکار یکدکمهای
- نصب و پیکربندی کامل WireGuard
- تانل UDP2RAW برای عبور از فیلترینگ (fake TCP)
- سرور API با FastAPI
- Nginx + SSL/HTTPS خودکار
- سرویسهای systemd

### 📊 پنل مدیریت
- **Web API**: رابط RESTful کامل
- **Desktop App**: برنامه ویندوزی با رابط گرافیکی
- مدیریت کلاینتها (ساخت ویرایش حذف)
- نمایش آمار ترافیک و زمان باقیمانده
- دانلود QR Code و فایل کانفیگ
- پلنهای اشتراکی (10GB تا 100GB)

### 🔄 مدیریت خودکار
- بررسی خودکار انقضا هر ساعت
- غیرفعالسازی خودکار کلاینتهای منقضی شده
- محدودیت ترافیک برای هر کاربر
- لاگگیری کامل

---

## 🏗 معماری سیستم

```
┌─────────────┐                  ┌──────────────┐                  ┌─────────────┐
│   کلاینت    │  ◄──encrypted──►  │ سرور ایران   │  ◄──encrypted──►  │ سرور خارج   │
│  WireGuard  │                  │  UDP2RAW     │                  │  WireGuard  │
│             │                  │  Relay       │                  │  + Panel    │
└─────────────┘                  └──────────────┘                  └─────────────┘
                                   Port 443                          Port 8443
                                   (Fake TCP)                       (Fake TCP)
```

**جریان داده:**
1. کلاینت → سرور ایران (port 443)
2. UDP2RAW Relay (ایران) → UDP2RAW Server (خارج port 8443)
3. UDP2RAW Server → WireGuard (localhost:51820)
4. پنل مدیریت: HTTPS (port 443) → Nginx → FastAPI (port 8000)

---

## 🚀 نصب سریع

### سرور خارج (با پنل مدیریت)

```bash
curl -fsSL https://raw.githubusercontent.com/Mehrdad-Hooshmand/wireguard-tunnel/main/install-tunnel-complete.sh | sudo bash
```

**ورودیهای مورد نیاز:**
- انتخاب: `1` (Foreign Server)
- IP سرور ایران: `94.182.92.246`
- دامنه: `yourdomain.com` (باید به IP سرور اشاره کند)
- نام کاربری پنل: `admin` (دلخواه)
- رمز عبور پنل: `********` (دلخواه و امن)

### سرور ایران (relay)

```bash
curl -fsSL https://raw.githubusercontent.com/Mehrdad-Hooshmand/wireguard-tunnel/main/install-tunnel-complete.sh | sudo bash
```

**ورودیهای مورد نیاز:**
- انتخاب: `2` (Iran Relay)
- IP سرور خارج: `45.252.182.213`
- رمز UDP2RAW: (از فایل `/root/tunnel-config.txt` سرور خارج)
- پورت: `443` (پیشنهادی)

### اطلاعات دسترسی

پس از نصب اطلاعات در فایل زیر ذخیره میشود:
```bash
cat /root/tunnel-config.txt
```

---

## 💻 دسکتاپ اپلیکیشن

### دانلود

**نسخه 2.0.0 (Windows x64):**
- 📦 حجم: ~190 MB
- ✅ پشتیبانی از API Key Authentication
- ✅ رابط کاربری فارسی
- ✅ QR Code Generator داخلی

**دانلود مستقیم:**
```
https://github.com/Mehrdad-Hooshmand/wireguard-tunnel/releases/download/v2.0.0/WireGuard-Manager-v2.0.0.zip
```

### نحوه استفاده

1. فایل ZIP را Extract کنید
2. فایل `WireGuard-Manager.exe` را اجرا کنید
3. اطلاعات لاگین را وارد کنید:
   - **Server URL**: `https://yourdomain.com`
   - **Username**: نام کاربری (اختیاری)
   - **API Key**: از `/root/tunnel-config.txt`

### اسکرینشات

<div align="center">
  <img src="https://via.placeholder.com/800x450?text=Login+Screen" alt="صفحه لاگین">
  <img src="https://via.placeholder.com/800x450?text=Dashboard" alt="داشبورد">
</div>

---

## 📡 API Reference

### Authentication

تمام درخواستها نیاز به header زیر دارند:
```
x-api-key: YOUR_API_KEY_HERE
```

### Endpoints

#### دریافت لیست پلنها
```http
GET /api/v1/plans
```

#### ساخت کلاینت جدید
```http
POST /api/v1/clients/by-plan?name=CLIENT_NAME&plan_id=PLAN_ID
```

#### لیست کلاینتها
```http
GET /api/v1/clients
```

#### دریافت کانفیگ کلاینت
```http
GET /api/v1/clients/{client_id}/config
```

#### دریافت QR Code
```http
GET /api/v1/clients/{client_id}/qrcode
```

#### دریافت ترافیک مصرفی
```http
GET /api/v1/clients/{client_id}/traffic
```

#### تمدید اشتراک
```http
POST /api/v1/clients/{client_id}/renew
```

#### حذف کلاینت
```http
DELETE /api/v1/clients/{client_id}
```

### پلنهای پیشفرض

| ID | نام | ترافیک | مدت | قیمت |
|----|-----|--------|-----|------|
| 1 | 10GB Monthly | 10 GB | 30 روز | $0 |
| 2 | 20GB Monthly | 20 GB | 30 روز | $0 |
| 3 | 30GB Monthly | 30 GB | 30 روز | $0 |
| 4 | 40GB Monthly | 40 GB | 30 روز | $0 |
| 5 | 50GB Monthly | 50 GB | 30 روز | $0 |
| 6 | 100GB Monthly | 100 GB | 30 روز | $0 |

---

## 🛠 عیبیابی

### مشکل SSL

اگر گواهی SSL ساخته نشد:
```bash
# بررسی DNS
nslookup yourdomain.com

# اجرای دستی certbot
certbot --nginx -d yourdomain.com
```

### API پاسخ نمیدهد

```bash
# بررسی سرویسها
systemctl status wireguard-api
systemctl status nginx

# بررسی لاگها
journalctl -u wireguard-api -f
tail -f /var/log/nginx/error.log
```

### UDP2RAW کار نمیکند

```bash
# سرور خارج
systemctl status udp2raw-server
netstat -tulpn | grep 8443

# سرور ایران
systemctl status udp2raw-relay
netstat -tulpn | grep 443
```

### بررسی انقضا

```bash
# اجرای دستی
bash /opt/wireguard-api/check_expiration.sh

# نمایش لاگ
cat /var/log/wireguard-expiration.log
```

---

## 📂 فایلهای مهم

### سرور خارج
```
/etc/wireguard/wg0.conf              # کانفیگ WireGuard
/opt/wireguard-api/main.py            # کد FastAPI
/opt/wireguard-api/wireguard.db       # دیتابیس SQLite
/etc/nginx/sites-enabled/wireguard-api  # کانفیگ Nginx
/etc/systemd/system/udp2raw-server.service
/etc/systemd/system/wireguard-api.service
/root/tunnel-config.txt               # اطلاعات کامل نصب
```

### سرور ایران
```
/etc/systemd/system/udp2raw-relay.service
/root/relay-config.txt                # اطلاعات relay
```

---

## 🔒 امنیت

- ✅ کلیدهای خصوصی WireGuard به صورت خودکار تولید میشوند
- ✅ API Key به صورت تصادفی ساخته میشود (64 کاراکتر hex)
- ✅ رمز UDP2RAW تصادفی است
- ✅ SSL/TLS با Let'\''s Encrypt
- ⚠️ API Key را بعد از نصب عوض کنید
- ⚠️ از فایروال برای محدود کردن دسترسی استفاده کنید

---

## 📝 لایسنس

MIT License - برای جزئیات به فایل [LICENSE](LICENSE) مراجعه کنید.

---

## 🤝 مشارکت

Issue و Pull Request خوشآمدید!

---

**ساخته شده با ❤️ در ایران**

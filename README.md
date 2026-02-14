#  WireGuard + UDP2RAW Tunnel + FastAPI Panel

Complete automated installation system for WireGuard VPN with UDP2RAW obfuscation and management panel.

##  Features

-  **One-click installation** for both Foreign and Iran servers  
-  **WireGuard VPN** with automatic configuration
-  **UDP2RAW obfuscation** (faketcp mode) for bypassing DPI
-  **FastAPI Management Panel** with REST API
-  **SSL/HTTPS** with automatic Let's Encrypt certificates
-  **Nginx reverse proxy** for secure API access
-  **Plan-based subscriptions** (10GB to 100GB monthly plans)
-  **Automatic expiration** and traffic limit enforcement
-  **QR code generation** for mobile clients  
-  **Desktop application support** for client management
-  **Cron job** for automatic client expiration checks
-  Supports Ubuntu 22.04 LTS

##  Architecture

```
Client  Iran Server (UDP2RAW Relay:443)  Foreign Server (UDP2RAW Server:8443)  WireGuard:51820  Internet
                                                      
                                            FastAPI Panel (HTTPS)
                                            Desktop App Management
```

##  Quick Start

### Complete Installation (Recommended)

**Foreign Server (with Panel):**
```bash
curl -fsSL https://raw.githubusercontent.com/Mehrdad-Hooshmand/wireguard-tunnel/main/install-tunnel-complete.sh | sudo bash
```

When prompted:
- Choose option **1** (Foreign Server)
- Enter Iran server IP
- Enter your domain (e.g., panel.example.com)
- Enter API username and password

**Iran Server (Relay only):**
```bash
curl -fsSL https://raw.githubusercontent.com/Mehrdad-Hooshmand/wireguard-tunnel/main/install-tunnel-complete.sh | sudo bash
```

When prompted:
- Choose option **2** (Iran Relay)  
- Enter Foreign server IP
- Enter UDP2RAW password (from foreign server setup)

---

##  API Endpoints

Base URL: https://your-domain.com/api/v1

### Authentication
All requests require API key in header:
```
x-api-key: YOUR_API_KEY
```

### Available Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /plans | List all subscription plans |
| POST | /plans | Create custom plan |
| POST | /clients/by-plan | Create client by plan ID |
| GET | /clients | List all clients |
| GET | /clients/{id}/config | Download WireGuard config |
| GET | /clients/{id}/qrcode | Get QR code image |
| GET | /clients/{id}/traffic | Check traffic usage |
| POST | /clients/{id}/renew | Renew subscription |
| DELETE | /clients/{id} | Delete client |
| POST | /maintenance/check-expiration | Manual expiration check |

### Example Usage

**Create client with 50GB plan:**
```bash
curl -X POST -H "x-api-key: YOUR_KEY" \\
  "https://your-domain.com/api/v1/clients/by-plan?name=user123&plan_id=5"
```

**Check traffic:**
```bash
curl -H "x-api-key: YOUR_KEY" \\
  "https://your-domain.com/api/v1/clients/CLIENT_ID/traffic"
```

**Download config:**
```bash
curl -H "x-api-key: YOUR_KEY" \\
  "https://your-domain.com/api/v1/clients/CLIENT_ID/config" -o client.conf
```

---

##  Default Plans

| ID | Name | Traffic | Duration | Auto-Expire |
|----|------|---------|----------|-------------|
| 1 | 10GB Monthly | 10 GB | 30 days |  |
| 2 | 20GB Monthly | 20 GB | 30 days |  |
| 3 | 30GB Monthly | 30 GB | 30 days |  |
| 4 | 40GB Monthly | 40 GB | 30 days |  |
| 5 | 50GB Monthly | 50 GB | 30 days |  |
| 6 | 100GB Monthly | 100 GB | 30 days |  |

---

##  Desktop Application

A desktop app is available for managing clients with a GUI.

**Features:**
- Login with API credentials
- Create/delete clients
- View traffic statistics
- Download configs and QR codes
- Real-time status monitoring

**Connection:**
- Server URL: https://your-domain.com
- Username: (from installation)
- Password: (from installation)

---

##  Configuration Files

### Foreign Server
```bash
/root/tunnel-config.txt          # All credentials and config
/etc/wireguard/wg0.conf          # WireGuard interface config
/opt/wireguard-api/main.py       # FastAPI application
/opt/wireguard-api/wireguard.db  # SQLite database
/etc/nginx/sites-available/wireguard-api  # Nginx config
/var/log/wireguard-expiration.log         # Expiration log
```

### Iran Server
```bash
/root/relay-config.txt           # Relay configuration
```

---

##  Service Management

### Foreign Server
```bash
# Check services
systemctl status wg-quick@wg0
systemctl status udp2raw-server
systemctl status wireguard-api
systemctl status nginx

# Restart API
systemctl restart wireguard-api

# View API logs
journalctl -u wireguard-api -f

# View expiration logs
tail -f /var/log/wireguard-expiration.log
```

### Iran Server
```bash
# Check relay service
systemctl status udp2raw-relay

# View logs
journalctl -u udp2raw-relay -f
```

---

##  Automatic Features

### Cron Job (Hourly)
- Checks for expired clients (past expiration date)
- Checks for traffic-exceeded clients (used >= limit)
- Automatically disables inactive clients
- Logs all actions to /var/log/wireguard-expiration.log

### Manual Check
```bash
curl -X POST -H "x-api-key: YOUR_KEY" \\
  http://localhost:8000/api/v1/maintenance/check-expiration
```

---

##  Monitoring

**API Documentation (Swagger):**
```
https://your-domain.com/docs
```

**Check database:**
```bash
sqlite3 /opt/wireguard-api/wireguard.db
.tables
SELECT * FROM clients;
```

---

##  Troubleshooting

### API not responding
```bash
systemctl status wireguard-api
journalctl -u wireguard-api -n 50
```

### SSL certificate issues
```bash
certbot certificates
certbot renew --dry-run
```

### Clients not expiring
```bash
# Check cron
crontab -l

# Manual check
bash /opt/wireguard-api/check_expiration.sh
```

### UDP2RAW connection issues
```bash
# Foreign server
systemctl status udp2raw-server
ss -tulpn | grep 8443

# Iran server
systemctl status udp2raw-relay
ss -tulpn | grep 443
```

---

##  Security Notes

1. **Change API Key**: After installation, change the API key in /opt/wireguard-api/main.py
2. **Firewall**: Ensure ports 80, 443, 8443 are open on foreign server; port 443 on Iran server
3. **Backup Database**: Regularly backup /opt/wireguard-api/wireguard.db
4. **SSL Renewal**: Certbot auto-renews certificates (check with systemctl status certbot.timer)

---

##  License

MIT License

---

##  Support

For issues and questions, please open an issue on GitHub.

**Version:** 3.0  
**Last Updated:** 2026-02-14

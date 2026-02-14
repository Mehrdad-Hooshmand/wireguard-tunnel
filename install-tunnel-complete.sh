#!/bin/bash

#############################################
# WireGuard + UDP2RAW + FastAPI Panel
# Complete Installation Script
# Version: 3.0
#############################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  WireGuard Tunnel + Panel Setup       ║${NC}"
echo -e "${BLUE}║        Complete Installation           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Ask server type
echo -e "${YELLOW}Select server type:${NC}"
echo "1) Foreign Server (خارج) - با Panel"
echo "2) Iran Relay Server (ایران) - بدون Panel"
read -p "Enter choice [1-2]: " SERVER_TYPE

if [[ "$SERVER_TYPE" == "1" ]]; then
    ROLE="foreign"
elif [[ "$SERVER_TYPE" == "2" ]]; then
    ROLE="iran"
else
    echo -e "${RED}Invalid choice!${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════${NC}"
echo -e "${GREEN}    Step 1: System Update & Dependencies${NC}"
echo -e "${GREEN}═══════════════════════════════════════${NC}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard wireguard-tools iptables wget curl git python3 python3-pip python3-venv nginx certbot python3-certbot-nginx qrencode > /dev/null 2>&1

echo -e "${GREEN}✓ System updated and dependencies installed${NC}"

# Install UDP2RAW
echo ""
echo -e "${GREEN}═══════════════════════════════════════${NC}"
echo -e "${GREEN}     Step 2: Installing UDP2RAW${NC}"
echo -e "${GREEN}═══════════════════════════════════════${NC}"

if [ ! -d "/opt/udp2raw" ]; then
    mkdir -p /opt/udp2raw
    cd /opt/udp2raw
    wget -q https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz
    tar -xzf udp2raw_binaries.tar.gz
    chmod +x udp2raw_amd64
    ln -sf udp2raw_amd64 udp2raw
    rm udp2raw_binaries.tar.gz
fi

echo -e "${GREEN}✓ UDP2RAW installed${NC}"

if [[ "$ROLE" == "foreign" ]]; then
    #############################################
    # FOREIGN SERVER SETUP
    #############################################
    
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║      Foreign Server Configuration      ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
    echo ""
    
    # Get Iran server IP
    read -p "Enter Iran relay server IP: " IRAN_IP
    
    # Get domain for SSL
    read -p "Enter your domain (for SSL and API): " DOMAIN
    
    # Get API credentials
    echo ""
    echo -e "${YELLOW}═══ API Credentials ═══${NC}"
    read -p "Enter API username [default: admin]: " API_USERNAME
    API_USERNAME=${API_USERNAME:-admin}
    read -s -p "Enter API password: " API_PASSWORD
    echo ""
    while [ -z "$API_PASSWORD" ]; do
        echo -e "${RED}Password cannot be empty!${NC}"
        read -s -p "Enter API password: " API_PASSWORD
        echo ""
    done
    
    # Generate secure API key
    API_KEY=$(openssl rand -hex 32)
    
    # Generate UDP2RAW password
    UDP2RAW_PASSWORD=$(openssl rand -hex 16)
    
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}     Step 3: Configuring WireGuard${NC}"
    echo -e "${GREEN}═══════════════════════════════════════${NC}"
    
    # Generate WireGuard keys
    cd /etc/wireguard
    wg genkey | tee privatekey | wg pubkey > publickey
    chmod 600 privatekey
    
    PRIVATE_KEY=$(cat privatekey)
    PUBLIC_KEY=$(cat publickey)
    
    # Create WireGuard config
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = 10.0.0.1/22
ListenPort = 51820
MTU = 1280

PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
EOF
    
    # Enable IP forwarding
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard.conf
    sysctl -p /etc/sysctl.d/99-wireguard.conf > /dev/null
    
    # Start WireGuard
    systemctl enable wg-quick@wg0 > /dev/null 2>&1
    systemctl start wg-quick@wg0
    
    echo -e "${GREEN}✓ WireGuard configured and started${NC}"
    
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}     Step 4: Configuring UDP2RAW Server${NC}"
    echo -e "${GREEN}═══════════════════════════════════════${NC}"
    
    # Create UDP2RAW service
    cat > /etc/systemd/system/udp2raw-server.service << EOF
[Unit]
Description=UDP2RAW Server
After=network.target wg-quick@wg0.service

[Service]
Type=simple
ExecStart=/opt/udp2raw/udp2raw -s -l 0.0.0.0:8443 -r 127.0.0.1:51820 --raw-mode faketcp --cipher-mode xor --auth-mode simple --key $UDP2RAW_PASSWORD -a
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable udp2raw-server > /dev/null 2>&1
    systemctl start udp2raw-server
    
    echo -e "${GREEN}✓ UDP2RAW Server configured and started${NC}"
    
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}     Step 5: Installing FastAPI Panel${NC}"
    echo -e "${GREEN}═══════════════════════════════════════${NC}"
    
    # Create API directory
    mkdir -p /opt/wireguard-api
    cd /opt/wireguard-api
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Install dependencies
    pip install -q fastapi uvicorn python-multipart qrcode pillow
    
    # Create main.py
    cat > /opt/wireguard-api/main.py << 'EOFPYTHON'
from fastapi import FastAPI, HTTPException, Header, Query, Response
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel
from typing import Optional, List
import subprocess
import sqlite3
import uuid
import os
from datetime import datetime, timedelta
import qrcode
import io

app = FastAPI(title="WireGuard API", version="2.0.0")

# Security
API_KEY = "REPLACE_API_KEY"
DB_PATH = "/opt/wireguard-api/wireguard.db"
WG_CONFIG = "/etc/wireguard/wg0.conf"

def verify_api_key(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Plans table
    c.execute('''CREATE TABLE IF NOT EXISTS plans (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        traffic_gb REAL NOT NULL,
        duration_days INTEGER NOT NULL,
        price REAL DEFAULT 0
    )''')
    
    # Clients table
    c.execute('''CREATE TABLE IF NOT EXISTS clients (
        id TEXT PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        public_key TEXT NOT NULL,
        private_key TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        plan_id INTEGER,
        traffic_limit_gb REAL DEFAULT 50,
        traffic_used_gb REAL DEFAULT 0,
        status TEXT DEFAULT 'active',
        purchased_at TEXT,
        expires_at TEXT,
        FOREIGN KEY (plan_id) REFERENCES plans(id)
    )''')
    
    # Insert default plans
    plans = [
        (1, "10GB Monthly", 10, 30, 0),
        (2, "20GB Monthly", 20, 30, 0),
        (3, "30GB Monthly", 30, 30, 0),
        (4, "40GB Monthly", 40, 30, 0),
        (5, "50GB Monthly", 50, 30, 0),
        (6, "100GB Monthly", 100, 30, 0)
    ]
    c.executemany("INSERT OR IGNORE INTO plans VALUES (?, ?, ?, ?, ?)", plans)
    
    conn.commit()
    conn.close()

def get_next_ip():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT ip_address FROM clients ORDER BY ip_address DESC LIMIT 1")
    result = c.fetchone()
    conn.close()
    
    if result:
        last_ip = result[0]
        octets = last_ip.split('.')
        octets[3] = str(int(octets[3]) + 1)
        return '.'.join(octets)
    return "10.0.0.2"

def add_peer_to_wg(public_key, ip):
    subprocess.run(['wg', 'set', 'wg0', 'peer', public_key, 'allowed-ips', f'{ip}/32'])
    subprocess.run(['wg-quick', 'save', 'wg0'])

def remove_peer_from_wg(public_key):
    subprocess.run(['wg', 'set', 'wg0', 'peer', public_key, 'remove'])
    subprocess.run(['wg-quick', 'save', 'wg0'])

def get_peer_traffic(public_key):
    result = subprocess.run(['wg', 'show', 'wg0', 'transfer'], capture_output=True, text=True)
    for line in result.stdout.split('\n'):
        if public_key in line:
            parts = line.split()
            if len(parts) >= 3:
                rx = int(parts[1])
                tx = int(parts[2])
                return (rx + tx) / (1024**3)
    return 0

@app.on_event("startup")
async def startup():
    init_db()

@app.get("/")
def root():
    return {"message": "WireGuard API v2.0.0", "docs": "/docs"}

@app.get("/api/v1/plans")
def get_plans(x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM plans")
    plans = [{"id": r[0], "name": r[1], "traffic_gb": r[2], "duration_days": r[3], "price": r[4]} for r in c.fetchall()]
    conn.close()
    return {"plans": plans}

@app.post("/api/v1/plans")
def create_plan(name: str = Query(...), traffic_gb: float = Query(...), duration_days: int = Query(...), price: float = Query(0), x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO plans (name, traffic_gb, duration_days, price) VALUES (?, ?, ?, ?)", (name, traffic_gb, duration_days, price))
    plan_id = c.lastrowid
    conn.commit()
    conn.close()
    return {"id": plan_id, "name": name, "traffic_gb": traffic_gb, "duration_days": duration_days, "price": price}

@app.post("/api/v1/clients/by-plan")
def create_client_by_plan(name: str = Query(...), plan_id: int = Query(...), x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM plans WHERE id=?", (plan_id,))
    plan = c.fetchone()
    
    if not plan:
        conn.close()
        raise HTTPException(status_code=404, detail="Plan not found")
    
    client_id = str(uuid.uuid4())
    private_key = subprocess.check_output(['wg', 'genkey']).decode().strip()
    public_key = subprocess.check_output(['wg', 'pubkey'], input=private_key.encode()).decode().strip()
    ip = get_next_ip()
    
    purchased_at = datetime.now().isoformat()
    expires_at = (datetime.now() + timedelta(days=plan[3])).isoformat()
    
    c.execute("""INSERT INTO clients (id, name, public_key, private_key, ip_address, plan_id, traffic_limit_gb, purchased_at, expires_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
              (client_id, name, public_key, private_key, ip, plan_id, plan[2], purchased_at, expires_at))
    conn.commit()
    conn.close()
    
    add_peer_to_wg(public_key, ip)
    
    days_remaining = (datetime.fromisoformat(expires_at) - datetime.now()).days
    
    return {
        "id": client_id,
        "name": name,
        "ip_address": ip,
        "plan": {"id": plan[0], "name": plan[1], "traffic_gb": plan[2], "duration_days": plan[3]},
        "traffic_limit_gb": plan[2],
        "purchased_at": purchased_at,
        "expires_at": expires_at,
        "days_remaining": days_remaining,
        "status": "active",
        "config_url": f"/api/v1/clients/{client_id}/config",
        "qrcode_url": f"/api/v1/clients/{client_id}/qrcode"
    }

@app.get("/api/v1/clients")
def get_clients(x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM clients")
    clients = []
    for r in c.fetchall():
        traffic = get_peer_traffic(r[2])
        c.execute("UPDATE clients SET traffic_used_gb=? WHERE id=?", (traffic, r[0]))
        
        days_remaining = None
        if r[10]:
            days_remaining = (datetime.fromisoformat(r[10]) - datetime.now()).days
        
        clients.append({
            "id": r[0], "name": r[1], "ip_address": r[4], "traffic_limit_gb": r[6],
            "traffic_used_gb": round(traffic, 2), "status": r[8],
            "expires_at": r[10], "days_remaining": days_remaining
        })
    conn.commit()
    conn.close()
    return {"clients": clients}

@app.get("/api/v1/clients/{client_id}/config")
def get_client_config(client_id: str, x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM clients WHERE id=?", (client_id,))
    client = c.fetchone()
    conn.close()
    
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    server_public_key = subprocess.check_output(['cat', '/etc/wireguard/publickey']).decode().strip()
    
    config = f"""[Interface]
PrivateKey = {client[3]}
Address = {client[4]}/32
DNS = 1.1.1.1, 8.8.8.8
MTU = 1280

[Peer]
PublicKey = {server_public_key}
Endpoint = IRAN_IP:443
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
    
    return PlainTextResponse(config, headers={"Content-Disposition": f"attachment; filename={client[1]}.conf"})

@app.get("/api/v1/clients/{client_id}/qrcode")
def get_client_qrcode(client_id: str, x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM clients WHERE id=?", (client_id,))
    client = c.fetchone()
    conn.close()
    
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    server_public_key = subprocess.check_output(['cat', '/etc/wireguard/publickey']).decode().strip()
    
    config = f"""[Interface]
PrivateKey = {client[3]}
Address = {client[4]}/32
DNS = 1.1.1.1, 8.8.8.8
MTU = 1280

[Peer]
PublicKey = {server_public_key}
Endpoint = IRAN_IP:443
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
    
    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(config)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    
    return Response(content=buf.getvalue(), media_type="image/png")

@app.get("/api/v1/clients/{client_id}/traffic")
def get_client_traffic(client_id: str, x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM clients WHERE id=?", (client_id,))
    client = c.fetchone()
    
    if not client:
        conn.close()
        raise HTTPException(status_code=404, detail="Client not found")
    
    traffic = get_peer_traffic(client[2])
    c.execute("UPDATE clients SET traffic_used_gb=? WHERE id=?", (traffic, client_id))
    conn.commit()
    conn.close()
    
    remaining = max(0, client[6] - traffic)
    percentage = (traffic / client[6] * 100) if client[6] > 0 else 0
    
    days_remaining = None
    will_expire_in = None
    if client[10]:
        days_remaining = (datetime.fromisoformat(client[10]) - datetime.now()).days
        will_expire_in = f"{days_remaining} days" if days_remaining > 0 else "Expired"
    
    return {
        "total_used_gb": round(traffic, 2),
        "limit_gb": client[6],
        "remaining_gb": round(remaining, 2),
        "percentage_used": round(percentage, 1),
        "expires_at": client[10],
        "days_remaining": days_remaining,
        "will_expire_in": will_expire_in
    }

@app.post("/api/v1/clients/{client_id}/renew")
def renew_client(client_id: str, x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM clients WHERE id=?", (client_id,))
    client = c.fetchone()
    
    if not client:
        conn.close()
        raise HTTPException(status_code=404, detail="Client not found")
    
    new_expires = (datetime.now() + timedelta(days=30)).isoformat()
    c.execute("UPDATE clients SET expires_at=?, status='active' WHERE id=?", (new_expires, client_id))
    
    if client[8] == 'disabled':
        add_peer_to_wg(client[2], client[4])
    
    conn.commit()
    conn.close()
    
    days_remaining = 30
    
    return {"message": "Client renewed successfully", "new_expires_at": new_expires, "days_remaining": days_remaining}

@app.delete("/api/v1/clients/{client_id}")
def delete_client(client_id: str, x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM clients WHERE id=?", (client_id,))
    client = c.fetchone()
    
    if not client:
        conn.close()
        raise HTTPException(status_code=404, detail="Client not found")
    
    remove_peer_from_wg(client[2])
    c.execute("DELETE FROM clients WHERE id=?", (client_id,))
    conn.commit()
    conn.close()
    
    return {"message": "Client deleted successfully"}

@app.post("/api/v1/maintenance/check-expiration")
def check_expiration(x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    now = datetime.now().isoformat()
    
    c.execute("SELECT * FROM clients WHERE expires_at <= ? AND status='active'", (now,))
    expired = c.fetchall()
    
    for client in expired:
        remove_peer_from_wg(client[2])
        c.execute("UPDATE clients SET status='expired' WHERE id=?", (client[0],))
    
    c.execute("SELECT * FROM clients WHERE traffic_used_gb >= traffic_limit_gb AND status='active'")
    exceeded = c.fetchall()
    
    for client in exceeded:
        remove_peer_from_wg(client[2])
        c.execute("UPDATE clients SET status='disabled' WHERE id=?", (client[0],))
    
    conn.commit()
    conn.close()
    
    return {
        "expired_clients": len(expired),
        "traffic_exceeded_clients": len(exceeded),
        "total_disabled": len(expired) + len(exceeded)
    }
EOFPYTHON
    
    # Replace placeholders
    sed -i "s/REPLACE_API_KEY/$API_KEY/g" /opt/wireguard-api/main.py
    sed -i "s/IRAN_IP/$IRAN_IP/g" /opt/wireguard-api/main.py
    
    # Create systemd service
    cat > /etc/systemd/system/wireguard-api.service << EOF
[Unit]
Description=WireGuard FastAPI Service
After=network.target wg-quick@wg0.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/wireguard-api
ExecStart=/opt/wireguard-api/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable wireguard-api > /dev/null 2>&1
    systemctl start wireguard-api
    
    echo -e "${GREEN}✓ FastAPI Panel installed and started${NC}"
    
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}     Step 6: Configuring Nginx + SSL${NC}"
    echo -e "${GREEN}═══════════════════════════════════════${NC}"
    
    # Configure Nginx
    cat > /etc/nginx/sites-available/wireguard-api << EOF
server {
    listen 80;
    server_name $DOMAIN;
    
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    
    ln -sf /etc/nginx/sites-available/wireguard-api /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    # Get SSL certificate
    echo -e "${YELLOW}Getting SSL certificate...${NC}"
    certbot --nginx -d $DOMAIN --non-interactive --agree-tos --register-unsafely-without-email --redirect
    
    systemctl reload nginx
    
    echo -e "${GREEN}✓ Nginx and SSL configured${NC}"
    
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}     Step 7: Setting up Cron Job${NC}"
    echo -e "${GREEN}═══════════════════════════════════════${NC}"
    
    # Create expiration check script
    cat > /opt/wireguard-api/check_expiration.sh << EOF
#!/bin/bash
echo "[$(date)] Checking for expired clients..." >> /var/log/wireguard-expiration.log
curl -s -X POST -H "x-api-key: $API_KEY" http://localhost:8000/api/v1/maintenance/check-expiration >> /var/log/wireguard-expiration.log
echo "---" >> /var/log/wireguard-expiration.log
EOF
    
    chmod +x /opt/wireguard-api/check_expiration.sh
    
    # Add cron job
    (crontab -l 2>/dev/null; echo "0 * * * * /opt/wireguard-api/check_expiration.sh") | crontab -
    
    echo -e "${GREEN}✓ Cron job configured (runs every hour)${NC}"
    
    # Save configuration
    cat > /root/tunnel-config.txt << EOF
═══════════════════════════════════════════════════════════
           WireGuard + UDP2RAW + Panel
                    Foreign Server
═══════════════════════════════════════════════════════════

ROLE: Foreign Server
DATE: $(date)

═══ WireGuard ═══
Private Key: $PRIVATE_KEY
Public Key: $PUBLIC_KEY
Interface: wg0
Address: 10.0.0.1/22
Listen Port: 51820

═══ UDP2RAW Server ═══
Listen: 0.0.0.0:8443
Forward to: 127.0.0.1:51820
Password: $UDP2RAW_PASSWORD
Mode: faketcp

═══ Iran Server Info ═══
Iran IP: $IRAN_IP

═══ API & Panel ═══
Domain: https://$DOMAIN
API URL: https://$DOMAIN/api/v1
API Key: $API_KEY
API Docs: https://$DOMAIN/docs
Username: $API_USERNAME
Password: $API_PASSWORD

⚠ IMPORTANT API ENDPOINTS:
- GET  /api/v1/plans - لیست پلن‌ها
- POST /api/v1/clients/by-plan?name=USER&plan_id=5 - ساخت کلاینت
- GET  /api/v1/clients - لیست کلاینت‌ها
- GET  /api/v1/clients/{id}/traffic - چک ترافیک
- GET  /api/v1/clients/{id}/config - دانلود کانفیگ
- GET  /api/v1/clients/{id}/qrcode - QR Code
- POST /api/v1/clients/{id}/renew - تمدید اشتراک
- DELETE /api/v1/clients/{id} - حذف کلاینت

ALL REQUESTS NEED HEADER:
x-api-key: $API_KEY

═══ Next Steps ═══
1. Copy UDP2RAW password: $UDP2RAW_PASSWORD
2. Run this script on Iran server ($IRAN_IP)
3. When prompted on Iran server, enter:
   - Foreign Server IP: $(curl -s ifconfig.me)
   - UDP2RAW Password: $UDP2RAW_PASSWORD
4. Use API in Desktop App:
   - Server URL: https://$DOMAIN
   - Username: $API_USERNAME
   - Password: $API_PASSWORD

═══ Status Check ═══
systemctl status wg-quick@wg0
systemctl status udp2raw-server
systemctl status wireguard-api
systemctl status nginx

═══ Logs ═══
journalctl -u wireguard-api -f
tail -f /var/log/wireguard-expiration.log

═══════════════════════════════════════════════════════════
EOF
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     Installation Complete! ✓           ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Configuration saved to: /root/tunnel-config.txt${NC}"
    echo ""
    echo -e "${BLUE}═══ Important Information ═══${NC}"
    echo -e "Panel URL: ${GREEN}https://$DOMAIN${NC}"
    echo -e "API Docs: ${GREEN}https://$DOMAIN/docs${NC}"
    echo -e "API Key: ${GREEN}$API_KEY${NC}"
    echo -e "UDP2RAW Password: ${GREEN}$UDP2RAW_PASSWORD${NC}"
    echo -e "Your Server IP: ${GREEN}$(curl -s ifconfig.me)${NC}"
    echo ""
    echo -e "${BLUE}═══ For Desktop App ═══${NC}"
    echo -e "Server URL: ${GREEN}https://$DOMAIN${NC}"
    echo -e "Username: ${GREEN}$API_USERNAME${NC}"
    echo -e "Password: ${GREEN}$API_PASSWORD${NC}"
    echo ""
    echo -e "${YELLOW}⚠ Save these credentials! You need them for Desktop App and Iran server.${NC}"
    
else
    #############################################
    # IRAN SERVER SETUP
    #############################################
    
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║       Iran Relay Configuration         ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
    echo ""
    
    # Get foreign server info
    read -p "Enter Foreign server IP: " FOREIGN_IP
    read -p "Enter UDP2RAW password (from foreign server): " UDP2RAW_PASSWORD
    read -p "Enter local listen port [default: 443]: " LISTEN_PORT
    LISTEN_PORT=${LISTEN_PORT:-443}
    
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}     Step 3: Configuring UDP2RAW Relay${NC}"
    echo -e "${GREEN}═══════════════════════════════════════${NC}"
    
    # Create UDP2RAW relay service
    cat > /etc/systemd/system/udp2raw-relay.service << EOF
[Unit]
Description=UDP2RAW Relay (Iran)
After=network.target

[Service]
Type=simple
ExecStart=/opt/udp2raw/udp2raw -c -l 0.0.0.0:$LISTEN_PORT -r $FOREIGN_IP:8443 --raw-mode faketcp --cipher-mode xor --auth-mode simple --key $UDP2RAW_PASSWORD -a
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable udp2raw-relay > /dev/null 2>&1
    systemctl start udp2raw-relay
    
    echo -e "${GREEN}✓ UDP2RAW Relay configured and started${NC}"
    
    # Save configuration
    cat > /root/relay-config.txt << EOF
═══════════════════════════════════════════════════════════
              UDP2RAW Relay Configuration
                     Iran Server
═══════════════════════════════════════════════════════════

ROLE: Iran Relay Server
DATE: $(date)

═══ UDP2RAW Relay ═══
Listen: 0.0.0.0:$LISTEN_PORT
Forward to: $FOREIGN_IP:8443
Password: $UDP2RAW_PASSWORD
Mode: faketcp

═══ Connection Info ═══
Foreign Server: $FOREIGN_IP
Your IP: $(curl -s ifconfig.me)

═══ Client Connection ═══
Clients should connect to:
- IP: $(curl -s ifconfig.me)
- Port: $LISTEN_PORT

Example WireGuard config endpoint:
Endpoint = $(curl -s ifconfig.me):$LISTEN_PORT

═══ Status Check ═══
systemctl status udp2raw-relay

═══ Logs ═══
journalctl -u udp2raw-relay -f

═══════════════════════════════════════════════════════════
EOF
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     Installation Complete! ✓           ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Configuration saved to: /root/relay-config.txt${NC}"
    echo ""
    echo -e "${BLUE}═══ Connection Info ═══${NC}"
    echo -e "Your IP: ${GREEN}$(curl -s ifconfig.me)${NC}"
    echo -e "Listen Port: ${GREEN}$LISTEN_PORT${NC}"
    echo ""
    echo -e "${YELLOW}✓ Clients should connect to: $(curl -s ifconfig.me):$LISTEN_PORT${NC}"
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════${NC}"
echo -e "${GREEN}     Verifying Services${NC}"
echo -e "${GREEN}═══════════════════════════════════════${NC}"
echo ""

if [[ "$ROLE" == "foreign" ]]; then
    systemctl is-active --quiet wg-quick@wg0 && echo -e "${GREEN}✓ WireGuard: Running${NC}" || echo -e "${RED}✗ WireGuard: Stopped${NC}"
    systemctl is-active --quiet udp2raw-server && echo -e "${GREEN}✓ UDP2RAW Server: Running${NC}" || echo -e "${RED}✗ UDP2RAW Server: Stopped${NC}"
    systemctl is-active --quiet wireguard-api && echo -e "${GREEN}✓ FastAPI Panel: Running${NC}" || echo -e "${RED}✗ FastAPI Panel: Stopped${NC}"
    systemctl is-active --quiet nginx && echo -e "${GREEN}✓ Nginx: Running${NC}" || echo -e "${RED}✗ Nginx: Stopped${NC}"
else
    systemctl is-active --quiet udp2raw-relay && echo -e "${GREEN}✓ UDP2RAW Relay: Running${NC}" || echo -e "${RED}✗ UDP2RAW Relay: Stopped${NC}"
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}Installation completed successfully!${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}"

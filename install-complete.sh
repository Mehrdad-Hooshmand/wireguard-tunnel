#!/bin/bash
# WireGuard + UDP2RAW + Management Panel - Complete Installation
# این اسکریپت همه چیز رو یکجا نصب می‌کنه روی سرور خارج

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Banner
clear
echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   WireGuard Complete Setup - Foreign Server              ║"
echo "║   نصب کامل: تانل + پنل مدیریت                           ║"
echo "║   Version 1.0                                             ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}" 
   exit 1
fi

# Functions
print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_error() { echo -e "${RED}✗ $1${NC}"; }
print_info() { echo -e "${BLUE}→ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠ $1${NC}"; }

# Get configuration
echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}                    پیکربندی سرور                        ${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

read -p "Enter VPN/Tunnel domain (e.g., vpn.example.com): " VPN_DOMAIN
if [[ -z "$VPN_DOMAIN" ]]; then
    print_error "VPN domain cannot be empty!"
    exit 1
fi

read -p "Enter Panel domain (e.g., panel.example.com): " PANEL_DOMAIN
if [[ -z "$PANEL_DOMAIN" ]]; then
    print_error "Panel domain cannot be empty!"
    exit 1
fi

read -p "Enter Iran server IP address: " IRAN_IP
if [[ -z "$IRAN_IP" ]]; then
    print_error "Iran IP cannot be empty!"
    exit 1
fi

read -p "Enter UDP2RAW password (press Enter for random): " UDP2RAW_PASS
if [[ -z "$UDP2RAW_PASS" ]]; then
    UDP2RAW_PASS=$(openssl rand -hex 16)
    print_info "Generated random UDP2RAW password: $UDP2RAW_PASS"
fi

read -p "Enter panel admin username (default: admin): " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}

read -sp "Enter panel admin password: " ADMIN_PASS
echo ""
if [[ -z "$ADMIN_PASS" ]]; then
    ADMIN_PASS=$(openssl rand -base64 12)
    print_info "Generated random admin password: $ADMIN_PASS"
fi

echo ""
print_info "Configuration Summary:"
print_info "VPN Domain: $VPN_DOMAIN"
print_info "Panel Domain: $PANEL_DOMAIN"
print_info "Iran IP: $IRAN_IP"
print_info "Admin User: $ADMIN_USER"
echo ""
read -p "Continue? (y/n): " confirm
if [[ "$confirm" != "y" ]]; then
    print_error "Installation cancelled"
    exit 1
fi

echo ""
print_info "Starting installation..."
echo ""

# ═══════════════════════════════════════════════════════════
# PART 1: System Update
# ═══════════════════════════════════════════════════════════
print_info "Step 1/12: Updating system packages..."
apt update -qq && apt upgrade -y -qq
print_success "System updated"

# ═══════════════════════════════════════════════════════════
# PART 2: Install WireGuard
# ═══════════════════════════════════════════════════════════
print_info "Step 2/12: Installing WireGuard..."
apt install -y wireguard wireguard-tools resolvconf iptables -qq
print_success "WireGuard installed"

# ═══════════════════════════════════════════════════════════
# PART 3: Install UDP2RAW
# ═══════════════════════════════════════════════════════════
print_info "Step 3/12: Installing UDP2RAW dependencies..."
apt install -y git build-essential libssl-dev -qq
print_success "Dependencies installed"

print_info "Step 4/12: Building UDP2RAW..."
cd /opt
if [ -d "udp2raw" ]; then
    rm -rf udp2raw
fi
git clone https://github.com/wangyu-/udp2raw.git -q
cd udp2raw
make -j$(nproc) > /dev/null 2>&1
chmod +x udp2raw
print_success "UDP2RAW built"

# ═══════════════════════════════════════════════════════════
# PART 4: Install Nginx
# ═══════════════════════════════════════════════════════════
print_info "Step 5/12: Installing Nginx..."
apt install -y nginx -qq
systemctl enable nginx
systemctl start nginx
print_success "Nginx installed"

# ═══════════════════════════════════════════════════════════
# PART 5: Install Certbot
# ═══════════════════════════════════════════════════════════
print_info "Step 6/12: Installing Certbot..."
apt install -y certbot python3-certbot-nginx -qq
print_success "Certbot installed"

# ═══════════════════════════════════════════════════════════
# PART 6: Get SSL Certificates
# ═══════════════════════════════════════════════════════════
print_info "Step 7/12: Obtaining SSL certificate for $VPN_DOMAIN..."
certbot --nginx -d $VPN_DOMAIN --non-interactive --agree-tos --register-unsafely-without-email --redirect
if [ $? -eq 0 ]; then
    print_success "SSL for VPN domain obtained"
else
    print_warning "SSL for VPN failed, continuing..."
fi

print_info "Obtaining SSL certificate for $PANEL_DOMAIN..."
certbot --nginx -d $PANEL_DOMAIN --non-interactive --agree-tos --register-unsafely-without-email --redirect
if [ $? -eq 0 ]; then
    print_success "SSL for Panel domain obtained"
else
    print_warning "SSL for Panel failed, continuing..."
fi

# ═══════════════════════════════════════════════════════════
# PART 7: Configure WireGuard
# ═══════════════════════════════════════════════════════════
print_info "Step 8/12: Configuring WireGuard..."

SERVER_PRIVATE_KEY=$(wg genkey)
SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)

cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = 10.0.0.1/22
ListenPort = 51820
MTU = 1280
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Clients will be added here

EOF

echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard.conf
sysctl -p /etc/sysctl.d/99-wireguard.conf > /dev/null

systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0
print_success "WireGuard configured"

# ═══════════════════════════════════════════════════════════
# PART 8: Configure UDP2RAW Server
# ═══════════════════════════════════════════════════════════
print_info "Step 9/12: Configuring UDP2RAW server..."

cat > /etc/systemd/system/udp2raw-server.service <<EOF
[Unit]
Description=UDP2RAW Server
After=network.target

[Service]
Type=simple
ExecStart=/opt/udp2raw/udp2raw -s -l 0.0.0.0:8443 -r 127.0.0.1:51820 --raw-mode faketcp --cipher-mode xor --auth-mode simple --key $UDP2RAW_PASS -a
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable udp2raw-server
systemctl start udp2raw-server
print_success "UDP2RAW server configured"

# ═══════════════════════════════════════════════════════════
# PART 9: Install Python for Panel
# ═══════════════════════════════════════════════════════════
print_info "Step 10/12: Installing Python and dependencies..."
apt install -y python3 python3-pip python3-venv -qq
print_success "Python installed"

# ═══════════════════════════════════════════════════════════
# PART 10: Create Panel Application
# ═══════════════════════════════════════════════════════════
print_info "Step 11/12: Creating management panel..."

PANEL_DIR="/opt/wireguard-panel"
mkdir -p $PANEL_DIR
cd $PANEL_DIR

python3 -m venv venv
source venv/bin/activate

pip install -q --upgrade pip
pip install -q fastapi uvicorn sqlalchemy qrcode pillow pydantic python-multipart jinja2 passlib bcrypt python-jose

# Create panel application
cat > $PANEL_DIR/panel.py <<'EOFPYTHON'
from fastapi import FastAPI, HTTPException, Depends, Request, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
import subprocess
import qrcode
import io
import os

SECRET_KEY = os.urandom(32).hex()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

DATABASE_URL = "sqlite:///./panel.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)

class Client(Base):
    __tablename__ = "clients"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    public_key = Column(String, unique=True)
    private_key = Column(String)
    ip_address = Column(String, unique=True)
    traffic_limit_gb = Column(Float, default=10.0)
    traffic_used_gb = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.now)
    expires_at = Column(DateTime)
    status = Column(String, default="active")
    endpoint = Column(String)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="WireGuard Panel", version="1.0.0")
templates = Jinja2Templates(directory="templates")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def get_next_ip(db: Session):
    clients = db.query(Client).all()
    used_ips = [int(c.ip_address.split('.')[-1]) for c in clients]
    for i in range(2, 1023):
        if i not in used_ips:
            return f"10.0.0.{i}"
    raise HTTPException(status_code=400, detail="No available IP addresses")

def generate_wireguard_keys():
    private = subprocess.run(['wg', 'genkey'], capture_output=True, text=True).stdout.strip()
    public = subprocess.run(['wg', 'pubkey'], input=private, capture_output=True, text=True).stdout.strip()
    return private, public

def add_wireguard_peer(public_key: str, ip: str):
    cmd = f"wg set wg0 peer {public_key} allowed-ips {ip}/32"
    subprocess.run(cmd, shell=True, check=True)
    subprocess.run("wg-quick save wg0", shell=True)

def remove_wireguard_peer(public_key: str):
    cmd = f"wg set wg0 peer {public_key} remove"
    subprocess.run(cmd, shell=True, check=True)
    subprocess.run("wg-quick save wg0", shell=True)

def get_client_config(client: Client, server_public_key: str):
    return f"""[Interface]
PrivateKey = {client.private_key}
Address = {client.ip_address}/32
DNS = 8.8.8.8, 1.1.1.1
MTU = 1280

[Peer]
PublicKey = {server_public_key}
Endpoint = {client.endpoint}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = authenticate_user(db, username, password)
    if not user:
        return RedirectResponse(url="/?error=1", status_code=status.HTTP_302_FOUND)
    
    access_token = create_access_token(data={"sub": user.username})
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse(url="/")
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            return RedirectResponse(url="/")
    except JWTError:
        return RedirectResponse(url="/")
    
    clients = db.query(Client).all()
    total_clients = len(clients)
    active_clients = len([c for c in clients if c.status == "active"])
    total_traffic = sum([c.traffic_used_gb for c in clients])
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "clients": clients,
        "total_clients": total_clients,
        "active_clients": active_clients,
        "total_traffic": round(total_traffic, 2)
    })

@app.post("/create-client")
async def create_client(
    name: str = Form(...),
    traffic_gb: float = Form(...),
    days: int = Form(...),
    endpoint: str = Form(...),
    db: Session = Depends(get_db)
):
    private_key, public_key = generate_wireguard_keys()
    ip_address = get_next_ip(db)
    
    client = Client(
        name=name,
        public_key=public_key,
        private_key=private_key,
        ip_address=ip_address,
        traffic_limit_gb=traffic_gb,
        traffic_used_gb=0.0,
        expires_at=datetime.now() + timedelta(days=days),
        endpoint=endpoint,
        status="active"
    )
    
    db.add(client)
    db.commit()
    
    add_wireguard_peer(public_key, ip_address)
    
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)

@app.get("/delete-client/{client_id}")
async def delete_client(client_id: int, db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    remove_wireguard_peer(client.public_key)
    db.delete(client)
    db.commit()
    
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)

@app.post("/add-traffic/{client_id}")
async def add_traffic(client_id: int, traffic_gb: float = Form(...), db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    client.traffic_limit_gb += traffic_gb
    db.commit()
    
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)

@app.get("/download-config/{client_id}")
async def download_config(client_id: int, db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    result = subprocess.run(['wg', 'show', 'wg0', 'public-key'], capture_output=True, text=True)
    server_public = result.stdout.strip()
    
    config = get_client_config(client, server_public)
    
    return StreamingResponse(
        io.BytesIO(config.encode()),
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={client.name}.conf"}
    )

@app.get("/qrcode/{client_id}")
async def get_qrcode(client_id: int, db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    result = subprocess.run(['wg', 'show', 'wg0', 'public-key'], capture_output=True, text=True)
    server_public = result.stdout.strip()
    
    config = get_client_config(client, server_public)
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(config)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    
    return StreamingResponse(buf, media_type="image/png")

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/")
    response.delete_cookie("access_token")
    return response
EOFPYTHON

# Create templates directory
mkdir -p $PANEL_DIR/templates

# Login template
cat > $PANEL_DIR/templates/login.html <<'EOFHTML'
<!DOCTYPE html>
<html dir="rtl" lang="fa">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ورود به پنل مدیریت</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Tahoma, Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
        }
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: bold;
        }
        input {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
        }
        .error {
            background: #ff4444;
            color: white;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>🔐 پنل مدیریت WireGuard</h1>
        {% if request.query_params.get('error') %}
        <div class="error">نام کاربری یا رمز عبور اشتباه است</div>
        {% endif %}
        <form method="POST" action="/login">
            <div class="form-group">
                <label>نام کاربری:</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>رمز عبور:</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit">ورود</button>
        </form>
    </div>
</body>
</html>
EOFHTML

# Dashboard template (continues next...)
cat > $PANEL_DIR/templates/dashboard.html <<'EOFHTML'
<!DOCTYPE html>
<html dir="rtl" lang="fa">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>پنل مدیریت WireGuard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Tahoma, Arial, sans-serif;
            background: #f5f6fa;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header h1 { display: inline-block; }
        .logout {
            float: left;
            background: rgba(255,255,255,0.2);
            color: white;
            padding: 10px 20px;
            border-radius: 5px;
            text-decoration: none;
            transition: background 0.3s;
        }
        .logout:hover { background: rgba(255,255,255,0.3); }
        .container { max-width: 1200px; margin: 20px auto; padding: 0 20px; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-number { font-size: 36px; font-weight: bold; color: #667eea; margin: 10px 0; }
        .stat-label { color: #666; font-size: 14px; }
        .section {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .section h2 { margin-bottom: 20px; color: #333; }
        .form-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .form-group { display: flex; flex-direction: column; }
        label { margin-bottom: 5px; color: #555; font-weight: bold; }
        input, select { padding: 10px; border: 2px solid #ddd; border-radius: 5px; font-size: 14px; }
        button {
            padding: 10px 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
        }
        button:hover { transform: translateY(-2px); box-shadow: 0 4px 10px rgba(0,0,0,0.2); }
        table { width: 100%; border-collapse: collapse; }
        th {
            background: #f8f9fa;
            padding: 12px;
            text-align: right;
            font-weight: bold;
            border-bottom: 2px solid #ddd;
        }
        td { padding: 12px; border-bottom: 1px solid #eee; }
        .status-active { color: #00c851; font-weight: bold; }
        .status-expired { color: #ff4444; font-weight: bold; }
        .actions { display: flex; gap: 5px; }
        .btn-small { padding: 5px 10px; font-size: 12px; text-decoration: none; display: inline-block; }
        .btn-danger { background: #ff4444; }
        .btn-success { background: #00c851; }
        .btn-info { background: #33b5e5; }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
        }
        .modal-content {
            background: white;
            max-width: 400px;
            margin: 100px auto;
            padding: 30px;
            border-radius: 10px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ پنل مدیریت WireGuard</h1>
        <a href="/logout" class="logout">خروج</a>
    </div>

    <div class="container">
        <div class="stats">
            <div class="stat-card">
                <div class="stat-label">تعداد کل کاربران</div>
                <div class="stat-number">{{ total_clients }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">کاربران فعال</div>
                <div class="stat-number">{{ active_clients }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">ترافیک مصرفی (GB)</div>
                <div class="stat-number">{{ total_traffic }}</div>
            </div>
        </div>

        <div class="section">
            <h2>➕ ایجاد کاربر جدید</h2>
            <form method="POST" action="/create-client">
                <div class="form-grid">
                    <div class="form-group">
                        <label>نام کاربر:</label>
                        <input type="text" name="name" required>
                    </div>
                    <div class="form-group">
                        <label>حجم ترافیک (GB):</label>
                        <input type="number" name="traffic_gb" step="0.1" required>
                    </div>
                    <div class="form-group">
                        <label>مدت زمان (روز):</label>
                        <input type="number" name="days" required>
                    </div>
                    <div class="form-group">
                        <label>Endpoint:</label>
                        <input type="text" name="endpoint" placeholder="domain.com:8443" required>
                    </div>
                </div>
                <button type="submit">ایجاد کاربر</button>
            </form>
        </div>

        <div class="section">
            <h2>📋 لیست کاربران</h2>
            <table>
                <thead>
                    <tr>
                        <th>نام</th>
                        <th>IP</th>
                        <th>ترافیک</th>
                        <th>تاریخ انقضا</th>
                        <th>وضعیت</th>
                        <th>عملیات</th>
                    </tr>
                </thead>
                <tbody>
                    {% for client in clients %}
                    <tr>
                        <td>{{ client.name }}</td>
                        <td>{{ client.ip_address }}</td>
                        <td>{{ client.traffic_used_gb|round(2) }} / {{ client.traffic_limit_gb }} GB</td>
                        <td>{{ client.expires_at.strftime('%Y-%m-%d') }}</td>
                        <td class="{% if client.status == 'active' %}status-active{% else %}status-expired{% endif %}">
                            {{ 'فعال' if client.status == 'active' else 'غیرفعال' }}
                        </td>
                        <td class="actions">
                            <a href="/download-config/{{ client.id }}" class="btn-small btn-info">دانلود</a>
                            <a href="/qrcode/{{ client.id }}" target="_blank" class="btn-small btn-success">QR</a>
                            <button onclick="showAddTraffic({{ client.id }}, '{{ client.name }}')" class="btn-small btn-success">افزایش</button>
                            <a href="/delete-client/{{ client.id }}" class="btn-small btn-danger" onclick="return confirm('آیا مطمئن هستید؟')">حذف</a>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>

    <div id="trafficModal" class="modal">
        <div class="modal-content">
            <h2>افزایش ترافیک</h2>
            <form id="trafficForm" method="POST">
                <div class="form-group">
                    <label>کاربر: <span id="clientName"></span></label>
                </div>
                <div class="form-group">
                    <label>حجم اضافی (GB):</label>
                    <input type="number" name="traffic_gb" step="0.1" required>
                </div>
                <button type="submit">افزایش ترافیک</button>
                <button type="button" onclick="closeModal()" style="background: #999; margin-top: 10px;">انصراف</button>
            </form>
        </div>
    </div>

    <script>
        function showAddTraffic(clientId, clientName) {
            document.getElementById('trafficModal').style.display = 'block';
            document.getElementById('clientName').textContent = clientName;
            document.getElementById('trafficForm').action = '/add-traffic/' + clientId;
        }
        
        function closeModal() {
            document.getElementById('trafficModal').style.display = 'none';
        }
    </script>
</body>
</html>
EOFHTML

print_success "Panel application created"

# Initialize admin user
python3 <<EOFPY
from panel import SessionLocal, User, get_password_hash

db = SessionLocal()
admin = db.query(User).filter(User.username == "$ADMIN_USER").first()
if not admin:
    admin = User(
        username="$ADMIN_USER",
        hashed_password=get_password_hash("$ADMIN_PASS"),
        is_active=True
    )
    db.add(admin)
    db.commit()
db.close()
EOFPY

print_success "Admin user created"

# ═══════════════════════════════════════════════════════════
# PART 11: Configure Panel Service
# ═══════════════════════════════════════════════════════════
print_info "Step 12/12: Configuring panel service..."

cat > /etc/systemd/system/wireguard-panel.service <<EOF
[Unit]
Description=WireGuard Management Panel
After=network.target wg-quick@wg0.service

[Service]
Type=simple
User=root
WorkingDirectory=$PANEL_DIR
Environment="PATH=$PANEL_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$PANEL_DIR/venv/bin/python -m uvicorn panel:app --host 0.0.0.0 --port 8080
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wireguard-panel
systemctl start wireguard-panel
print_success "Panel service configured"

# Configure Nginx for Panel
cat > /etc/nginx/sites-available/$PANEL_DOMAIN <<EOF
server {
    listen 80;
    server_name $PANEL_DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $PANEL_DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$PANEL_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$PANEL_DOMAIN/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

ln -sf /etc/nginx/sites-available/$PANEL_DOMAIN /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

# ═══════════════════════════════════════════════════════════
# PART 12: Create Configuration Summary
# ═══════════════════════════════════════════════════════════
CONFIG_FILE="/root/complete-setup-info.txt"
cat > $CONFIG_FILE <<EOF
═══════════════════════════════════════════════════════════
          WireGuard Complete Setup Information
═══════════════════════════════════════════════════════════

VPN/Tunnel Configuration:
-------------------------
Domain: $VPN_DOMAIN
Server Public Key: $SERVER_PUBLIC_KEY
WireGuard Network: 10.0.0.0/22
WireGuard Port: 51820 (local)
UDP2RAW Port: 8443 (public)
UDP2RAW Password: $UDP2RAW_PASS

Management Panel:
-----------------
URL: https://$PANEL_DOMAIN
Username: $ADMIN_USER
Password: $ADMIN_PASS

Iran Server Setup:
------------------
Next, run on Iran server:
  ./install-iran.sh

When asked, provide:
  - Iran Domain: relay.example.com
  - Foreign Domain: $VPN_DOMAIN
  - UDP2RAW Password: $UDP2RAW_PASS
  - Listen Port: 8443

Service Status:
--------------
WireGuard: systemctl status wg-quick@wg0
UDP2RAW: systemctl status udp2raw-server
Panel: systemctl status wireguard-panel
Nginx: systemctl status nginx

Management:
-----------
View clients: wg show
Panel access: https://$PANEL_DOMAIN
Logs: journalctl -u wireguard-panel -f

═══════════════════════════════════════════════════════════
EOF

# Display summary
clear
echo -e "${GREEN}"
cat <<EOF
╔═══════════════════════════════════════════════════════════╗
║         Installation Completed Successfully! ✅           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

cat $CONFIG_FILE

echo ""
echo -e "${YELLOW}Configuration saved to: $CONFIG_FILE${NC}"
echo ""

# Show service status
print_info "Service Status Check:"
systemctl is-active --quiet wg-quick@wg0 && print_success "WireGuard: Running" || print_error "WireGuard: Failed"
systemctl is-active --quiet udp2raw-server && print_success "UDP2RAW: Running" || print_error "UDP2RAW: Failed"
systemctl is-active --quiet wireguard-panel && print_success "Panel: Running" || print_error "Panel: Failed"
systemctl is-active --quiet nginx && print_success "Nginx: Running" || print_error "Nginx: Failed"

echo ""
echo -e "${GREEN}✓ VPN Tunnel Domain: https://$VPN_DOMAIN${NC}"
echo -e "${GREEN}✓ Management Panel: https://$PANEL_DOMAIN${NC}"
echo ""
echo -e "${YELLOW}Next: Install relay on Iran server using install-iran.sh${NC}"
echo ""

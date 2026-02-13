#!/bin/bash
# UDP2RAW Relay Installation Script for Iran Server
# This script automates the relay setup process

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
clear
echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║      UDP2RAW Relay - Iran Server Setup                   ║"
echo "║      Automated Installation Script v1.0                   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}" 
   exit 1
fi

# Function to print colored messages
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}→ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Get configuration details
echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
read -p "Enter your Iran domain name (e.g., relay.example.com): " IRAN_DOMAIN
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Validate domain
if [[ -z "$IRAN_DOMAIN" ]]; then
    print_error "Domain name cannot be empty!"
    exit 1
fi

read -p "Enter Foreign server domain (e.g., vpn.example.com): " FOREIGN_DOMAIN
if [[ -z "$FOREIGN_DOMAIN" ]]; then
    print_error "Foreign domain cannot be empty!"
    exit 1
fi

read -p "Enter UDP2RAW password (from foreign server): " UDP2RAW_PASS
if [[ -z "$UDP2RAW_PASS" ]]; then
    print_error "UDP2RAW password cannot be empty!"
    exit 1
fi

read -p "Enter local listen port (default: 8443): " LOCAL_PORT
LOCAL_PORT=${LOCAL_PORT:-8443}

echo ""
print_info "Configuration:"
print_info "Iran Domain: $IRAN_DOMAIN"
print_info "Foreign Domain: $FOREIGN_DOMAIN"
print_info "Local Port: $LOCAL_PORT"
echo ""

# Update system
print_info "Step 1/6: Updating system packages..."
apt update -qq && apt upgrade -y -qq
print_success "System updated successfully"

# Install UDP2RAW dependencies
print_info "Step 2/6: Installing UDP2RAW dependencies..."
apt install -y git build-essential libssl-dev -qq
print_success "Dependencies installed"

# Download and build UDP2RAW
print_info "Step 3/6: Building UDP2RAW..."
cd /opt
if [ -d "udp2raw" ]; then
    rm -rf udp2raw
fi
git clone https://github.com/wangyu-/udp2raw.git -q
cd udp2raw
make -j$(nproc) > /dev/null 2>&1
chmod +x udp2raw
print_success "UDP2RAW built successfully"

# Install Nginx
print_info "Step 4/6: Installing Nginx..."
apt install -y nginx -qq
systemctl enable nginx
systemctl start nginx
print_success "Nginx installed and started"

# Install Certbot
print_info "Step 5/6: Installing Certbot for SSL..."
apt install -y certbot python3-certbot-nginx -qq

# Get SSL certificate
print_info "Obtaining SSL certificate for $IRAN_DOMAIN..."
certbot --nginx -d $IRAN_DOMAIN --non-interactive --agree-tos --register-unsafely-without-email --redirect
if [ $? -eq 0 ]; then
    print_success "SSL certificate obtained successfully"
else
    print_error "SSL certificate failed. Please check domain DNS."
    exit 1
fi

# Configure UDP2RAW relay
print_info "Step 6/6: Configuring UDP2RAW relay..."

cat > /etc/systemd/system/udp2raw-relay.service <<EOF
[Unit]
Description=UDP2RAW Relay (Iran)
After=network.target

[Service]
Type=simple
ExecStart=/opt/udp2raw/udp2raw -c -l 0.0.0.0:$LOCAL_PORT -r $FOREIGN_DOMAIN:8443 --raw-mode faketcp --cipher-mode xor --auth-mode simple --key $UDP2RAW_PASS -a
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable udp2raw-relay
systemctl start udp2raw-relay
print_success "UDP2RAW relay configured and started"

# Create configuration summary file
CONFIG_FILE="/root/relay-config.txt"
cat > $CONFIG_FILE <<EOF
═══════════════════════════════════════════════════════════
             UDP2RAW Relay Configuration
═══════════════════════════════════════════════════════════

Relay Information:
-----------------
Iran Domain: $IRAN_DOMAIN
Foreign Domain: $FOREIGN_DOMAIN
Local Listen Port: $LOCAL_PORT
UDP2RAW Password: $UDP2RAW_PASS

SSL Certificate:
----------------
Status: Active
Path: /etc/letsencrypt/live/$IRAN_DOMAIN/
Auto-Renewal: Enabled

Service Status:
--------------
UDP2RAW Relay: systemctl status udp2raw-relay
Nginx: systemctl status nginx

Client Configuration:
--------------------
Clients should connect to:
- Endpoint: $IRAN_DOMAIN:$LOCAL_PORT

How It Works:
------------
Client → Iran Server ($IRAN_DOMAIN:$LOCAL_PORT)
       → Foreign Server ($FOREIGN_DOMAIN:8443)
       → WireGuard Server (127.0.0.1:51820)

Troubleshooting:
---------------
View logs:
  journalctl -u udp2raw-relay -f

Check connection:
  ss -tulpn | grep $LOCAL_PORT

Test relay:
  nc -zv $FOREIGN_DOMAIN 8443

═══════════════════════════════════════════════════════════
EOF

# Display summary
clear
echo -e "${GREEN}"
cat <<EOF
╔═══════════════════════════════════════════════════════════╗
║           Installation Completed Successfully!            ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

cat $CONFIG_FILE

echo ""
echo -e "${YELLOW}Configuration saved to: $CONFIG_FILE${NC}"
echo ""

# Show service status
print_info "Service Status Check:"
systemctl is-active --quiet udp2raw-relay && print_success "UDP2RAW Relay: Running" || print_error "UDP2RAW Relay: Failed"
systemctl is-active --quiet nginx && print_success "Nginx: Running" || print_error "Nginx: Failed"

echo ""
print_success "Relay setup complete! Clients can now connect through $IRAN_DOMAIN:$LOCAL_PORT"
echo ""

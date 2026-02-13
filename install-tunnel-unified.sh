#!/bin/bash

#############################################
# WireGuard + UDP2RAW Tunnel Installation
# Unified Script for Both Foreign & Iran Servers
# Version: 2.0
#############################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   WireGuard + UDP2RAW Tunnel Setup    ║${NC}"
echo -e "${BLUE}║        Automated Installation          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Ask server type
echo -e "${YELLOW}Select server type:${NC}"
echo "1) Foreign Server (خارج)"
echo "2) Iran Relay Server (ایران)"
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
echo -e "${GREEN}     Step 1: System Update & Dependencies${NC}"
echo -e "${GREEN}═══════════════════════════════════════${NC}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard wireguard-tools iptables wget curl > /dev/null 2>&1

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
    
    # Save configuration
    cat > /root/tunnel-config.txt << EOF
═══════════════════════════════════════════════════════════
           WireGuard + UDP2RAW Configuration
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

═══ Next Steps ═══
1. Copy this password: $UDP2RAW_PASSWORD
2. Run this script on Iran server ($IRAN_IP)
3. When prompted, enter:
   - Foreign Server IP: $(curl -s ifconfig.me)
   - UDP2RAW Password: $UDP2RAW_PASSWORD

═══ Status Check ═══
systemctl status wg-quick@wg0
systemctl status udp2raw-server

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
    echo -e "UDP2RAW Password: ${GREEN}$UDP2RAW_PASSWORD${NC}"
    echo -e "Your Server IP: ${GREEN}$(curl -s ifconfig.me)${NC}"
    echo ""
    echo -e "${YELLOW}⚠ Save this password! You need it for Iran server installation.${NC}"
    
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

═══ Status Check ═══
systemctl status udp2raw-relay

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
else
    systemctl is-active --quiet udp2raw-relay && echo -e "${GREEN}✓ UDP2RAW Relay: Running${NC}" || echo -e "${RED}✗ UDP2RAW Relay: Stopped${NC}"
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}Installation completed successfully!${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}"

#!/bin/bash

# ======================================================================
# Absolute Minimal VLESS Xray Installation 
# For Ubuntu 22.04
# ======================================================================

# Color codes for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored messages
print_message() {
    case "$1" in
        "info") echo -e "${BLUE}[INFO]${NC} $2" ;;
        "success") echo -e "${GREEN}[SUCCESS]${NC} $2" ;;
        "warning") echo -e "${YELLOW}[WARNING]${NC} $2" ;;
        "error") echo -e "${RED}[ERROR]${NC} $2" ;;
        *) echo -e "$2" ;;
    esac
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_message "error" "This script must be run as root!"
    exit 1
fi

# Update system
print_message "info" "Updating system..."
apt update -y && apt upgrade -y

# Install dependencies
print_message "info" "Installing dependencies..."
apt install -y curl unzip jq uuid-runtime ufw

# Install Xray
print_message "info" "Installing Xray..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Generate UUID
UUID=$(uuidgen)
print_message "info" "Generated UUID: $UUID"

# Generate port
PORT=$(shuf -i 10000-60000 -n 1)
print_message "info" "Selected port: $PORT"

# Create config directory
mkdir -p /usr/local/etc/xray

# Create the absolute minimal config
cat > /usr/local/etc/xray/config.json << EOF
{
  "inbounds": [
    {
      "port": ${PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID}"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/xray/server.crt",
              "keyFile": "/usr/local/etc/xray/server.key"
            }
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF

# Generate self-signed certificate
print_message "info" "Generating self-signed TLS certificate..."
openssl genrsa -out /usr/local/etc/xray/server.key 2048
openssl req -new -x509 -days 365 -key /usr/local/etc/xray/server.key \
    -out /usr/local/etc/xray/server.crt -subj "/C=US/ST=State/L=City/O=Organization/CN=server.local"

# Set proper permissions
chmod 644 /usr/local/etc/xray/config.json
chmod 644 /usr/local/etc/xray/server.crt
chmod 600 /usr/local/etc/xray/server.key

# Override the service file with root user
cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=root
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

# Remove any drop-in configuration
rm -rf /etc/systemd/system/xray.service.d

# Reload systemd
systemctl daemon-reload

# Start Xray service
systemctl restart xray
systemctl enable xray

# Wait for service to start
sleep 3

# Check if service is running
if systemctl is-active --quiet xray; then
    print_message "success" "Xray service is running!"
else
    print_message "error" "Xray service failed to start!"
    print_message "info" "Checking xray logs..."
    journalctl -xe -u xray
    exit 1
fi

# Configure firewall
print_message "info" "Configuring firewall..."
ufw allow ssh
ufw allow ${PORT}/tcp
ufw --force enable

# Create client file
mkdir -p /root/xray_client

# Get server IP
SERVER_IP=$(curl -s https://api.ipify.org)

# Create client configuration
cat > /root/xray_client/client_config.json << EOF
{
  "inbounds": [
    {
      "port": 10808,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "settings": {
        "udp": true
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "${SERVER_IP}",
            "port": ${PORT},
            "users": [
              {
                "id": "${UUID}",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "allowInsecure": true
        }
      }
    }
  ]
}
EOF

# Create v2rayNG import link
VLESS_LINK="vless://${UUID}@${SERVER_IP}:${PORT}?security=tls&type=tcp&sni=${SERVER_IP}#VLESS-Server"
echo "${VLESS_LINK}" > /root/xray_client/import_link.txt

# Print summary
print_message "success" "Installation completed successfully!"
echo ""
echo "======================================================"
echo "VLESS XRAY Setup Information"
echo "======================================================"
echo ""
echo "Server IP: ${SERVER_IP}"
echo "Port: ${PORT}"
echo "UUID: ${UUID}"
echo ""
echo "Client configuration saved to: /root/xray_client/client_config.json"
echo "Import link for v2rayNG saved to: /root/xray_client/import_link.txt"
echo ""
echo "Import link:"
echo "${VLESS_LINK}"
echo ""
echo "======================================================"

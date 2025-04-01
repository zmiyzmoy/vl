#!/bin/bash

# ======================================================================
# Minimal Working VLESS Xray Installation 
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

# Function to check if script is run as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_message "error" "This script must be run as root!"
        exit 1
    fi
}

# Function to update system
update_system() {
    print_message "info" "Updating system packages..."
    apt update -y && apt upgrade -y
    if [ $? -ne 0 ]; then
        print_message "error" "Failed to update system."
        exit 1
    fi
    print_message "success" "System updated successfully."
}

# Function to install required dependencies
install_dependencies() {
    print_message "info" "Installing dependencies..."
    apt install -y curl unzip jq uuid-runtime ufw socat net-tools wget tor
    if [ $? -ne 0 ]; then
        print_message "error" "Failed to install dependencies."
        exit 1
    fi
    print_message "success" "Dependencies installed successfully."
}

# Function to configure Tor
configure_tor() {
    print_message "info" "Configuring Tor..."
    
    # Configure Tor
    cat > /etc/tor/torrc << EOF
SOCKSPort 9050
Log notice file /var/log/tor/notices.log
RunAsDaemon 1
DataDirectory /var/lib/tor
ControlPort 9051
CookieAuthentication 1
EOF
    
    # Restart Tor service
    systemctl restart tor
    
    # Enable Tor to start on boot
    systemctl enable tor
    
    # Check if Tor is running
    if systemctl is-active --quiet tor; then
        print_message "success" "Tor configured and running successfully."
    else
        print_message "error" "Tor configuration failed. Service is not running."
        exit 1
    fi
}

# Function to install Xray
install_xray() {
    print_message "info" "Installing Xray-core..."
    
    # Remove any existing installation
    systemctl stop xray 2>/dev/null || true
    systemctl disable xray 2>/dev/null || true
    rm -rf /usr/local/etc/xray
    rm -f /usr/local/bin/xray
    rm -f /etc/systemd/system/xray.service
    
    # Download and install Xray
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    if [ $? -ne 0 ]; then
        print_message "error" "Failed to install Xray."
        exit 1
    fi
    
    # Check if Xray is installed correctly
    if [[ ! -f /usr/local/bin/xray ]]; then
        print_message "error" "Xray binary not found. Installation failed."
        exit 1
    fi
    
    print_message "success" "Xray installed successfully."
}

# Function to configure Xray
configure_xray() {
    print_message "info" "Configuring Xray..."
    
    # Generate random UUIDs
    LAPTOP_UUID=$(uuidgen)
    PHONE1_UUID=$(uuidgen)
    PHONE2_UUID=$(uuidgen)
    
    # Generate random port number between 10000 and 60000
    PORT=$(shuf -i 10000-60000 -n 1)
    
    # Create Xray configuration directory
    mkdir -p /usr/local/etc/xray
    
    # Create Xray configuration file with Tor outbound but SIMPLIFIED routing rules
    cat > /usr/local/etc/xray/config.json << EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": ${PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${LAPTOP_UUID}",
            "flow": "xtls-rprx-direct"
          },
          {
            "id": "${PHONE1_UUID}",
            "flow": "xtls-rprx-direct"
          },
          {
            "id": "${PHONE2_UUID}",
            "flow": "xtls-rprx-direct"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["http/1.1"],
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/xray/server.crt",
              "keyFile": "/usr/local/etc/xray/server.key"
            }
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "blocked"
    },
    {
      "protocol": "socks",
      "tag": "tor-proxy",
      "settings": {
        "servers": [
          {
            "address": "127.0.0.1",
            "port": 9050
          }
        ]
      }
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "outboundTag": "tor-proxy",
        "domain": ["geosite:geolocation-!cn"]
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": ["bittorrent"]
      }
    ]
  }
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
    
    print_message "success" "Xray configuration completed."
}

# Function to configure Xray service
configure_xray_service() {
    print_message "info" "Configuring Xray service..."
    
    # Create the service file - USING ROOT USER to avoid 'nobody' problems
    cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload
    
    # Enable and start Xray service
    systemctl enable xray
    systemctl restart xray
    
    # Wait for service to start
    sleep 3
    
    # Check if Xray is running
    if systemctl is-active --quiet xray; then
        print_message "success" "Xray service started successfully."
    else
        print_message "error" "Xray service failed to start."
        systemctl status xray
        exit 1
    fi
}

# Function to configure firewall
configure_firewall() {
    print_message "info" "Configuring firewall..."
    
    # Install UFW if not already installed
    apt install -y ufw
    
    # Configure UFW
    ufw allow ssh
    ufw allow ${PORT}/tcp
    
    # Enable UFW without prompt
    ufw --force enable
    
    print_message "success" "Firewall configured successfully."
}

# Function to create client configurations
create_client_configs() {
    print_message "info" "Creating client configurations..."
    
    # Get public IP
    PUBLIC_IP=$(curl -s https://api.ipify.org)
    
    # Create a directory for client configurations
    mkdir -p /root/xray_clients
    
    # Create laptop configuration
    cat > /root/xray_clients/laptop_config.json << EOF
{
  "inbounds": [
    {
      "port": 10808,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "settings": {
        "udp": true
      }
    },
    {
      "port": 10809,
      "listen": "127.0.0.1",
      "protocol": "http"
    }
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "${PUBLIC_IP}",
            "port": ${PORT},
            "users": [
              {
                "id": "${LAPTOP_UUID}",
                "flow": "xtls-rprx-direct",
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
          "allowInsecure": true,
          "serverName": "${PUBLIC_IP}"
        }
      }
    }
  ]
}
EOF

    # Create Phone 1 configuration
    cat > /root/xray_clients/phone1_config.json << EOF
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
            "address": "${PUBLIC_IP}",
            "port": ${PORT},
            "users": [
              {
                "id": "${PHONE1_UUID}",
                "flow": "xtls-rprx-direct",
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
          "allowInsecure": true,
          "serverName": "${PUBLIC_IP}"
        }
      }
    }
  ]
}
EOF

    # Create Phone 2 configuration
    cat > /root/xray_clients/phone2_config.json << EOF
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
            "address": "${PUBLIC_IP}",
            "port": ${PORT},
            "users": [
              {
                "id": "${PHONE2_UUID}",
                "flow": "xtls-rprx-direct",
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
          "allowInsecure": true,
          "serverName": "${PUBLIC_IP}"
        }
      }
    }
  ]
}
EOF

    # Create v2rayNG compatible URLs for phones
    PHONE1_VLESS_LINK="vless://${PHONE1_UUID}@${PUBLIC_IP}:${PORT}?security=tls&flow=xtls-rprx-direct&fp=chrome&type=tcp&sni=${PUBLIC_IP}#Phone1-VLESS"
    PHONE2_VLESS_LINK="vless://${PHONE2_UUID}@${PUBLIC_IP}:${PORT}?security=tls&flow=xtls-rprx-direct&fp=chrome&type=tcp&sni=${PUBLIC_IP}#Phone2-VLESS"
    
    # Save phone links to files
    echo "${PHONE1_VLESS_LINK}" > /root/xray_clients/phone1_vless_link.txt
    echo "${PHONE2_VLESS_LINK}" > /root/xray_clients/phone2_vless_link.txt
    
    # Create summary file
    cat > /root/xray_clients/connection_info.txt << EOF
==========================================================
VLESS XRAY Connection Information with Tor IP Obfuscation
==========================================================

Server IP: ${PUBLIC_IP}
Port: ${PORT}
Protocol: VLESS
Security: TLS
Network: TCP
IP Obfuscation: Enabled through Tor

==========================================================
Device-Specific UUIDs:
==========================================================

Laptop UUID: ${LAPTOP_UUID}
Phone 1 UUID: ${PHONE1_UUID}
Phone 2 UUID: ${PHONE2_UUID}

==========================================================
Phone Import Links (v2rayNG):
==========================================================

Phone 1:
${PHONE1_VLESS_LINK}

Phone 2:
${PHONE2_VLESS_LINK}

==========================================================
EOF

    # Set permissions for the client configuration files
    chmod -R 644 /root/xray_clients
    chmod 644 /root/xray_clients/*.json
    chmod 644 /root/xray_clients/*.txt
    
    print_message "success" "Client configurations created successfully in /root/xray_clients directory."
}

# Function to verify if the server is properly configured
verify_installation() {
    print_message "info" "Verifying installation..."
    
    # Check if Tor is running
    if ! systemctl is-active --quiet tor; then
        print_message "error" "Tor service is not running."
        return 1
    fi
    
    # Check if Xray is running
    if ! systemctl is-active --quiet xray; then
        print_message "error" "Xray service is not running."
        return 1
    fi
    
    # Check if the port is open
    if ! netstat -tuln | grep -q ":${PORT}"; then
        print_message "error" "Port ${PORT} is not open."
        return 1
    fi
    
    print_message "success" "Installation verified successfully."
    return 0
}

# Function to print installation summary
print_summary() {
    PUBLIC_IP=$(curl -s https://api.ipify.org)
    
    print_message "info" "Installation Summary:"
    echo ""
    echo "======================================================"
    echo "VLESS XRAY has been installed successfully!"
    echo "======================================================"
    echo ""
    echo "Server Information:"
    echo "- IP Address: ${PUBLIC_IP}"
    echo "- Port: ${PORT}"
    echo "- Protocol: VLESS"
    echo "- TLS: Enabled (Self-signed certificate)"
    echo "- IP Obfuscation: Traffic routed through Tor"
    echo ""
    echo "Device-Specific Configurations:"
    echo "- All configurations are in: /root/xray_clients/"
    echo "- Laptop config: /root/xray_clients/laptop_config.json"
    echo "- Phone 1 config: /root/xray_clients/phone1_config.json"
    echo "- Phone 2 config: /root/xray_clients/phone2_config.json"
    echo "- Phone import links: /root/xray_clients/phone1_vless_link.txt and phone2_vless_link.txt"
    echo ""
    echo "Client Setup:"
    echo "1. For laptops: Download Qv2ray or V2rayN and import the laptop_config.json"
    echo "2. For phones: Use v2rayNG and scan QR code generated from the link files"
    echo ""
    echo "To display this information again, run: cat /root/xray_clients/connection_info.txt"
    echo ""
    echo "======================================================"
    
    # Print the phone import links for easy access
    echo ""
    echo "Phone 1 Import Link (copy this to generate a QR code):"
    cat /root/xray_clients/phone1_vless_link.txt
    echo ""
    echo "Phone 2 Import Link (copy this to generate a QR code):"
    cat /root/xray_clients/phone2_vless_link.txt
    echo ""
}

# Main function
main() {
    print_message "info" "Starting minimal VLESS Xray installation..."
    
    check_root
    update_system
    install_dependencies
    install_xray
    configure_xray
    configure_xray_service
    configure_tor
    configure_firewall
    create_client_configs
    
    # Verify that everything is working
    verify_installation
    
    print_summary
    
    print_message "success" "Installation completed successfully!"
}

# Run the main function
main

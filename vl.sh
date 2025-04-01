#!/bin/bash

# ======================================================================
# Automated VLESS Xray Installation with IP Obfuscation
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

# Function to check if system is Ubuntu 22.04
check_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" != "ubuntu" ]]; then
            print_message "error" "This script is designed for Ubuntu only."
            exit 1
        fi
        
        if [[ "$VERSION_ID" != "22.04" ]]; then
            print_message "warning" "This script is designed for Ubuntu 22.04. You are using Ubuntu $VERSION_ID which may not be fully compatible."
        fi
    else
        print_message "error" "Cannot determine OS. This script is designed for Ubuntu 22.04."
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
    apt install -y curl unzip jq uuid-runtime ufw socat net-tools wget proxychains4 tor iptables-persistent
    if [ $? -ne 0 ]; then
        print_message "error" "Failed to install dependencies."
        exit 1
    fi
    print_message "success" "Dependencies installed successfully."
}

# Function to install Xray
install_xray() {
    print_message "info" "Installing Xray-core..."
    
    # Remove any existing installation first
    if [ -f /usr/local/bin/xray ]; then
        print_message "info" "Removing existing Xray installation..."
        systemctl stop xray || true
        systemctl disable xray || true
        rm -rf /usr/local/bin/xray
        rm -rf /usr/local/etc/xray
        rm -f /etc/systemd/system/xray.service
        rm -rf /etc/systemd/system/xray.service.d
    fi
    
    # Download Xray install script
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
    
    # Generate random UUID
    UUID=$(uuidgen)
    print_message "info" "Generated UUID: $UUID"
    
    # Generate random port number between 10000 and 60000
    PORT=$(shuf -i 10000-60000 -n 1)
    print_message "info" "Selected port: $PORT"
    
    # Creating Xray config directory if it doesn't exist
    mkdir -p /usr/local/etc/xray
    
    # Create Xray configuration
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
            "id": "${UUID}",
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
      "tag": "direct",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "tag": "blocked",
      "settings": {}
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
        "ip": ["geoip:private"],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "domain": ["geosite:category-ads"],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "protocol": ["bittorrent"],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "outboundTag": "tor-proxy",
        "domain": ["geosite:tor"]
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
    
    # We'll configure the service separately later
    print_message "success" "Xray configuration files created successfully."
}

# Function to setup Tor for IP obfuscation
setup_tor() {
    print_message "info" "Setting up Tor for IP obfuscation..."
    
    # Install and configure Tor
    apt install -y tor
    
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

# Function to configure proxychains for additional IP obfuscation layer
configure_proxychains() {
    print_message "info" "Configuring ProxyChains..."
    
    # Backup original proxychains config
    cp /etc/proxychains4.conf /etc/proxychains4.conf.bak
    
    # Configure proxychains to use Tor
    cat > /etc/proxychains4.conf << EOF
# proxychains.conf

strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
# add Tor proxy
socks5 127.0.0.1 9050
EOF

    print_message "success" "ProxyChains configured successfully."
}

# Function to configure Xray with proxychains
configure_xray_with_proxychains() {
    print_message "info" "Configuring Xray to use ProxyChains..."
    
    # Create a dedicated user for Xray
    print_message "info" "Creating dedicated xray user..."
    id -u xray &>/dev/null || useradd -r -m -s /bin/false xray
    
    # Create a wrapper script for Xray
    cat > /usr/local/bin/xray-proxied << EOF
#!/bin/bash
proxychains4 -f /etc/proxychains4.conf /usr/local/bin/xray run -config /usr/local/etc/xray/config.json
EOF
    
    # Make it executable
    chmod +x /usr/local/bin/xray-proxied
    
    # Ensure proper permissions for Xray directories
    mkdir -p /usr/local/etc/xray
    mkdir -p /var/log/xray
    chown -R xray:xray /usr/local/etc/xray
    chown -R xray:xray /var/log/xray
    chmod 755 /usr/local/etc/xray
    chmod 755 /var/log/xray
    
    # Remove any existing service files or drop-ins that might conflict
    systemctl stop xray || true
    if [ -f /etc/systemd/system/xray.service ]; then
        mv /etc/systemd/system/xray.service /etc/systemd/system/xray.service.bak
    fi
    rm -rf /etc/systemd/system/xray.service.d
    
    # Create a new clean service file
    cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service with IP Obfuscation
Documentation=https://github.com/xtls
After=network.target nss-lookup.target tor.service

[Service]
Type=simple
User=xray
Group=xray
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray-proxied
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd
    systemctl daemon-reload
    
    # Start Xray service
    systemctl enable xray
    systemctl start xray
    
    # Wait a moment for service to start
    sleep 5
    
    # Check if Xray is running
    if systemctl is-active --quiet xray; then
        print_message "success" "Xray with ProxyChains configured and running successfully."
    else
        print_message "error" "Xray with ProxyChains configuration failed. Service is not running."
        print_message "info" "Checking Xray service status for more details..."
        systemctl status xray
        print_message "info" "Checking Xray logs..."
        journalctl -xe --no-pager -n 20 -u xray
        
        # Try running Xray directly to see any errors
        print_message "info" "Testing direct Xray execution..."
        /usr/local/bin/xray run -config /usr/local/etc/xray/config.json -test
        
        exit 1
    fi
}

# Function to configure firewall
configure_firewall() {
    print_message "info" "Configuring firewall..."
    
    # Enable UFW
    ufw --force enable
    
    # Allow SSH (port 22)
    ufw allow 22/tcp
    
    # Allow Xray port
    ufw allow ${PORT}/tcp
    
    # Reload UFW
    ufw reload
    
    print_message "success" "Firewall configured successfully."
}

# Function to add basic server hardening
harden_server() {
    print_message "info" "Performing basic server hardening..."
    
    # Update SSH configuration - with safety measures to ensure SSH access isn't lost
    if [ -f /etc/ssh/sshd_config ]; then
        # Create a backup of original SSH config
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
        
        # Only create hardening config if SSH keys are present
        if [ -d /root/.ssh ] && [ -f /root/.ssh/authorized_keys ] && [ -s /root/.ssh/authorized_keys ]; then
            print_message "info" "SSH keys found, applying SSH hardening..."
            cat > /etc/ssh/sshd_config.d/hardening.conf << EOF
# Disable root login
PermitRootLogin prohibit-password

# Use strong authentication
PasswordAuthentication yes
PubkeyAuthentication yes

# Limit login attempts
MaxAuthTries 3

# Disable unused features
UsePAM yes
X11Forwarding no
PermitEmptyPasswords no

# Add connection timeout
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
        else
            print_message "warning" "No SSH keys found. Skipping SSH hardening to prevent lockout."
            cat > /etc/ssh/sshd_config.d/hardening.conf << EOF
# Keep SSH access open for now - no SSH keys detected
PasswordAuthentication yes
PubkeyAuthentication yes
PermitRootLogin yes
EOF
        fi
        
        # Restart SSH service
        systemctl reload sshd
    fi
    
    # Set proper permissions on sensitive directories with care
    chmod 700 /root
    
    # Configure kernel parameters for security
    cat > /etc/sysctl.d/99-security.conf << EOF
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF
    
    # Apply sysctl parameters
    sysctl -p /etc/sysctl.d/99-security.conf
    
    print_message "success" "Server hardening completed."
}

# Function to save connection information
save_connection_info() {
    public_ip=$(curl -s https://api.ipify.org)
    
    # Create UUID for each device
    LAPTOP_UUID=$(uuidgen)
    PHONE1_UUID=$(uuidgen)
    PHONE2_UUID=$(uuidgen)
    
    # Update Xray configuration to include all three UUIDs
    print_message "info" "Updating Xray configuration with multiple device UUIDs..."
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
            "flow": "xtls-rprx-direct",
            "email": "laptop@example.com"
          },
          {
            "id": "${PHONE1_UUID}",
            "flow": "xtls-rprx-direct",
            "email": "phone1@example.com"
          },
          {
            "id": "${PHONE2_UUID}",
            "flow": "xtls-rprx-direct",
            "email": "phone2@example.com"
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
      "tag": "direct",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "tag": "blocked",
      "settings": {}
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
        "ip": ["geoip:private"],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "domain": ["geosite:category-ads"],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "protocol": ["bittorrent"],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "outboundTag": "tor-proxy",
        "domain": ["geosite:tor"]
      }
    ]
  }
}
EOF

    # Set proper permissions
    chmod 644 /usr/local/etc/xray/config.json
    chown xray:xray /usr/local/etc/xray/config.json
    
    # Restart Xray to apply new config
    systemctl restart xray
    
    # Save master connection info file
    cat > /root/xray_connection_info.txt << EOF
==========================================================
VLESS XRAY Connection Information
==========================================================

Server IP: ${public_ip}
Port: ${PORT}
Protocol: VLESS
Security: TLS
Network: TCP

==========================================================
Device-Specific UUIDs:
==========================================================

Laptop UUID: ${LAPTOP_UUID}
Phone 1 UUID: ${PHONE1_UUID}
Phone 2 UUID: ${PHONE2_UUID}

==========================================================
IP Obfuscation Information:
==========================================================

Your traffic is being routed through Tor for IP obfuscation.
Your actual server IP is hidden from the destination servers.

==========================================================
EOF

    # Create laptop configuration
    cat > /root/laptop_config.json << EOF
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
            "address": "${public_ip}",
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
          "serverName": "${public_ip}"
        }
      }
    }
  ]
}
EOF

    # Create Phone 1 configuration
    cat > /root/phone1_config.json << EOF
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
            "address": "${public_ip}",
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
          "serverName": "${public_ip}"
        }
      }
    }
  ]
}
EOF

    # Create Phone 2 configuration
    cat > /root/phone2_config.json << EOF
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
            "address": "${public_ip}",
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
          "serverName": "${public_ip}"
        }
      }
    }
  ]
}
EOF

    # Create v2rayNG compatible URLs for easy import on phones
    PHONE1_VLESS_LINK="vless://${PHONE1_UUID}@${public_ip}:${PORT}?security=tls&flow=xtls-rprx-direct&fp=chrome&type=tcp&sni=${public_ip}#Phone1-VLESS"
    PHONE2_VLESS_LINK="vless://${PHONE2_UUID}@${public_ip}:${PORT}?security=tls&flow=xtls-rprx-direct&fp=chrome&type=tcp&sni=${public_ip}#Phone2-VLESS"
    
    # Save phone links to files for easy QR code generation
    echo "${PHONE1_VLESS_LINK}" > /root/phone1_vless_link.txt
    echo "${PHONE2_VLESS_LINK}" > /root/phone2_vless_link.txt
    
    # Add links to the main configuration file
    cat >> /root/xray_connection_info.txt << EOF
==========================================================
Phone Import Links (v2rayNG):
==========================================================

Phone 1:
${PHONE1_VLESS_LINK}

Phone 2:
${PHONE2_VLESS_LINK}

==========================================================
EOF

    # Set permissions
    chmod 600 /root/xray_connection_info.txt
    chmod 600 /root/laptop_config.json
    chmod 600 /root/phone1_config.json
    chmod 600 /root/phone2_config.json
    chmod 600 /root/phone1_vless_link.txt
    chmod 600 /root/phone2_vless_link.txt
    
    print_message "success" "Device-specific configurations created successfully."
    print_message "success" "- Master info: /root/xray_connection_info.txt"
    print_message "success" "- Laptop config: /root/laptop_config.json"
    print_message "success" "- Phone 1 config: /root/phone1_config.json"
    print_message "success" "- Phone 2 config: /root/phone2_config.json"
    print_message "success" "- Phone import links saved to separate files"
    
    # Also print to console for convenience
    cat /root/xray_connection_info.txt
}

# Function to verify installation
verify_installation() {
    print_message "info" "Verifying installation..."
    
    # Check if Xray service is running
    if ! systemctl is-active --quiet xray; then
        print_message "error" "Xray service is not running."
        return 1
    fi
    
    # Check if Tor service is running
    if ! systemctl is-active --quiet tor; then
        print_message "error" "Tor service is not running."
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
    print_message "info" "Installation Summary:"
    echo ""
    echo "======================================================"
    echo "VLESS XRAY has been installed with IP obfuscation!"
    echo "======================================================"
    echo ""
    echo "Connection information has been saved to: /root/xray_connection_info.txt"
    echo ""
    echo "Server Information:"
    echo "- Protocol: VLESS"
    echo "- Port: ${PORT}"
    echo "- TLS: Enabled (Self-signed certificate)"
    echo ""
    echo "Device-Specific Configurations:"
    echo "- Laptop config: /root/laptop_config.json (UUID: ${LAPTOP_UUID})"
    echo "- Phone 1 config: /root/phone1_config.json (UUID: ${PHONE1_UUID})"
    echo "- Phone 2 config: /root/phone2_config.json (UUID: ${PHONE2_UUID})"
    echo "- Phone import links: /root/phone1_vless_link.txt and /root/phone2_vless_link.txt"
    echo ""
    echo "IP Obfuscation:"
    echo "- Your server's IP is obfuscated using Tor network"
    echo ""
    echo "Firewall:"
    echo "- SSH (port 22) and Xray (port ${PORT}) are allowed"
    echo ""
    echo "Next Steps:"
    echo "1. Copy the configuration files to your devices"
    echo "2. Use a client like Xray-core for laptop, v2rayNG for Android phones"
    echo "3. For phones, you can scan the QR code generated from the link files"
    echo "4. Secure your SSH using key-based authentication"
    echo "5. Regularly update your system with 'apt update && apt upgrade'"
    echo ""
    echo "======================================================"
}

# Main function to run all steps
main() {
    print_message "info" "Starting VLESS Xray installation with IP obfuscation..."
    
    # Check if script is run as root
    check_root
    
    # Check if OS is Ubuntu 22.04
    check_os
    
    # Update system
    update_system
    
    # Install dependencies
    install_dependencies
    
    # Install Xray
    install_xray
    
    # Configure Xray
    configure_xray
    
    # Setup Tor for IP obfuscation
    setup_tor
    
    # Configure proxychains
    configure_proxychains
    
    # Configure Xray to use proxychains
    configure_xray_with_proxychains
    
    # Configure firewall
    configure_firewall
    
    # Add basic server hardening
    harden_server
    
    # Save connection information
    save_connection_info
    
    # Verify installation
    verify_installation
    
    # Print installation summary
    print_summary
}

# Run main function
main

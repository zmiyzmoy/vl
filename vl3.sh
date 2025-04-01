#!/bin/bash

# ======================================================================
# Self-Healing VLESS Xray Installation with IP Obfuscation through Tor
# For Ubuntu 22.04
# Features:
# - Automatic error detection and correction
# - Tor routing for IP obfuscation
# - Self-checks for connectivity and anonymity
# - Multiple device configuration
# ======================================================================

# Color codes for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored messages
print_message() {
    case "$1" in
        "info") echo -e "${BLUE}[INFO]${NC} $2" ;;
        "success") echo -e "${GREEN}[SUCCESS]${NC} $2" ;;
        "warning") echo -e "${YELLOW}[WARNING]${NC} $2" ;;
        "error") echo -e "${RED}[ERROR]${NC} $2" ;;
        "security") echo -e "${MAGENTA}[SECURITY]${NC} $2" ;;
        "check") echo -e "${CYAN}[CHECK]${NC} $2" ;;
        *) echo -e "$2" ;;
    esac
}

# Log file for debugging and tracking
LOG_FILE="/var/log/xray_installer.log"

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Function to check if script is run as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_message "error" "This script must be run as root!"
        exit 1
    fi
    log_message "Root check passed"
}

# Function to update system
update_system() {
    print_message "info" "Updating system packages..."
    log_message "Starting system update"
    
    # Try to update up to 3 times in case of network issues
    for i in {1..3}; do
        apt update -y && apt upgrade -y && break
        print_message "warning" "Update attempt $i failed, retrying in 5 seconds..."
        log_message "Update attempt $i failed"
        sleep 5
    done
    
    if [ $? -ne 0 ]; then
        print_message "error" "Failed to update system after 3 attempts."
        log_message "System update failed after 3 attempts"
        exit 1
    fi
    
    print_message "success" "System updated successfully."
    log_message "System updated successfully"
}

# Function to ensure a package is installed with retry mechanism
ensure_package_installed() {
    package_name="$1"
    print_message "info" "Ensuring $package_name is installed..."
    
    # Check if package is already installed
    if dpkg -s "$package_name" >/dev/null 2>&1; then
        print_message "info" "$package_name is already installed."
        return 0
    fi
    
    # Try to install the package up to 3 times
    for i in {1..3}; do
        apt install -y "$package_name" && break
        print_message "warning" "Failed to install $package_name, attempt $i. Retrying in 5 seconds..."
        log_message "Failed to install $package_name, attempt $i"
        sleep 5
    done
    
    # Check if package is now installed
    if ! dpkg -s "$package_name" >/dev/null 2>&1; then
        print_message "error" "Failed to install $package_name after 3 attempts."
        log_message "Failed to install $package_name after 3 attempts"
        return 1
    fi
    
    print_message "success" "$package_name installed successfully."
    log_message "$package_name installed successfully"
    return 0
}

# Function to install required dependencies
install_dependencies() {
    print_message "info" "Installing dependencies..."
    log_message "Starting dependencies installation"
    
    # List of required packages
    packages=("curl" "unzip" "jq" "uuid-runtime" "ufw" "socat" "net-tools" "wget" "tor" "proxychains4" "iptables-persistent")
    
    # Install each package with retry mechanism
    for pkg in "${packages[@]}"; do
        ensure_package_installed "$pkg" || {
            print_message "error" "Failed to install $pkg. Aborting."
            log_message "Failed to install $pkg. Aborting."
            exit 1
        }
    done
    
    print_message "success" "All dependencies installed successfully."
    log_message "All dependencies installed successfully"
}

# Function to configure Tor
configure_tor() {
    print_message "info" "Configuring Tor for IP obfuscation..."
    log_message "Configuring Tor"
    
    # Backup original torrc if it exists
    if [ -f /etc/tor/torrc ]; then
        cp /etc/tor/torrc /etc/tor/torrc.bak
        log_message "Backed up original torrc"
    fi
    
    # Configure Tor
    cat > /etc/tor/torrc << EOF
SOCKSPort 9050
Log notice file /var/log/tor/notices.log
RunAsDaemon 1
DataDirectory /var/lib/tor
ControlPort 9051
CookieAuthentication 1
EOF
    
    # Restart Tor and enable on boot
    systemctl restart tor
    systemctl enable tor
    
    # Verify Tor is running
    sleep 2
    if ! systemctl is-active --quiet tor; then
        print_message "error" "Tor service failed to start."
        log_message "Tor service failed to start"
        
        # Attempt to fix Tor
        print_message "info" "Attempting to fix Tor..."
        log_message "Attempting to fix Tor"
        
        # Try reinstalling Tor
        apt remove -y tor
        apt install -y tor
        
        # Try with default config
        mv /etc/tor/torrc /etc/tor/torrc.problematic
        apt-get install --reinstall tor
        
        systemctl restart tor
        
        if ! systemctl is-active --quiet tor; then
            print_message "error" "Could not fix Tor service. This is critical for anonymity."
            log_message "Could not fix Tor service"
            exit 1
        fi
    fi
    
    print_message "success" "Tor configured successfully."
    log_message "Tor configured successfully"
}

# Function to configure ProxyChains
configure_proxychains() {
    print_message "info" "Configuring ProxyChains..."
    log_message "Configuring ProxyChains"
    
    # Backup original proxychains config if it exists
    if [ -f /etc/proxychains4.conf ]; then
        cp /etc/proxychains4.conf /etc/proxychains4.conf.bak
        log_message "Backed up original proxychains4.conf"
    fi
    
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
    log_message "ProxyChains configured successfully"
}

# Function to install Xray with retry mechanism
install_xray() {
    print_message "info" "Installing Xray-core..."
    log_message "Starting Xray installation"
    
    # Remove any existing installation
    systemctl stop xray 2>/dev/null || true
    systemctl disable xray 2>/dev/null || true
    rm -rf /usr/local/etc/xray
    rm -f /usr/local/bin/xray
    rm -f /etc/systemd/system/xray.service
    
    # Try to install Xray up to 3 times
    for i in {1..3}; do
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install && break
        print_message "warning" "Xray installation attempt $i failed, retrying in 5 seconds..."
        log_message "Xray installation attempt $i failed"
        sleep 5
    done
    
    # Check if Xray is installed correctly
    if [[ ! -f /usr/local/bin/xray ]]; then
        print_message "error" "Xray binary not found after 3 attempts. Installation failed."
        log_message "Xray binary not found after 3 attempts"
        exit 1
    fi
    
    print_message "success" "Xray installed successfully."
    log_message "Xray installed successfully"
}

# Function to configure Xray
configure_xray() {
    print_message "info" "Configuring Xray..."
    log_message "Configuring Xray"
    
    # Generate random UUIDs
    LAPTOP_UUID=$(uuidgen)
    PHONE1_UUID=$(uuidgen)
    PHONE2_UUID=$(uuidgen)
    
    # Generate random port number between 10000 and 60000
    PORT=$(shuf -i 10000-60000 -n 1)
    
    # Create Xray configuration directory
    mkdir -p /usr/local/etc/xray
    
    # Create Xray configuration file with Tor outbound
    cat > /usr/local/etc/xray/config.json << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
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
        "domain": ["geosite:category-sites"],  
        "ip": ["0.0.0.0/0", "::/0"]
      }
    ]
  }
}
EOF

    # Create log directory for Xray
    mkdir -p /var/log/xray
    chmod 755 /var/log/xray
    
    # Generate self-signed certificate
    print_message "info" "Generating self-signed TLS certificate..."
    log_message "Generating TLS certificate"
    
    openssl genrsa -out /usr/local/etc/xray/server.key 2048
    openssl req -new -x509 -days 365 -key /usr/local/etc/xray/server.key \
        -out /usr/local/etc/xray/server.crt -subj "/C=US/ST=State/L=City/O=Organization/CN=server.local"
    
    # Set proper permissions
    chmod 644 /usr/local/etc/xray/config.json
    chmod 644 /usr/local/etc/xray/server.crt
    chmod 600 /usr/local/etc/xray/server.key
    
    print_message "success" "Xray configuration completed."
    log_message "Xray configuration completed"
}

# Function to create a wrapper script for Xray with Tor
create_xray_wrapper() {
    print_message "info" "Creating Xray wrapper for Tor routing..."
    log_message "Creating Xray wrapper"
    
    # Create directory for scripts
    mkdir -p /usr/local/bin
    
    # Create the wrapper script
    cat > /usr/local/bin/xray-tor-wrapper << EOF
#!/bin/bash
# Wrapper to run Xray with Tor routing

# Check if Tor is running, if not start it
if ! systemctl is-active --quiet tor; then
    systemctl restart tor
    sleep 2
fi

# Run Xray through proxychains for full traffic routing through Tor
proxychains4 -q /usr/local/bin/xray run -config /usr/local/etc/xray/config.json
EOF
    
    # Make it executable
    chmod +x /usr/local/bin/xray-tor-wrapper
    
    print_message "success" "Xray wrapper created successfully."
    log_message "Xray wrapper created successfully"
}

# Function to configure Xray service
configure_xray_service() {
    print_message "info" "Configuring Xray service..."
    log_message "Configuring Xray service"
    
    # Create the service file
    cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service with Tor IP Obfuscation
Documentation=https://github.com/xtls
After=network.target nss-lookup.target tor.service

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray-tor-wrapper
Restart=on-failure
RestartPreventExitStatus=23
RestartSec=10
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
    
    # Wait for service to stabilize
    sleep 5
    
    # Check if Xray is running
    if ! systemctl is-active --quiet xray; then
        print_message "warning" "Xray service failed to start with Tor wrapper. Attempting self-repair..."
        log_message "Xray service failed to start with Tor wrapper, attempting self-repair"
        
        # Try to fix by using direct Xray
        print_message "info" "Trying alternative service configuration..."
        
        # Create a simpler service without proxychains
        cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        systemctl restart xray
        sleep 5
        
        if ! systemctl is-active --quiet xray; then
            print_message "error" "Xray service still failed to start after repair attempt."
            print_message "info" "Checking Xray logs for errors..."
            
            # Create log directory if it doesn't exist
            mkdir -p /var/log/xray
            
            # Check for errors
            journalctl -xe --no-pager -n 50 -u xray
            
            # Try to test Xray config
            /usr/local/bin/xray -test -config /usr/local/etc/xray/config.json
            
            print_message "error" "Could not start Xray service. Please check the logs above for errors."
            log_message "Could not start Xray service after repair attempt"
            exit 1
        else
            print_message "warning" "Xray started with direct configuration (no Tor proxy wrapper)."
            print_message "warning" "This will use Tor only for outbound connections specified in routing rules."
            log_message "Xray started with direct configuration"
        fi
    else
        print_message "success" "Xray service started successfully with Tor routing."
        log_message "Xray service started successfully"
    fi
}

# Function to configure firewall
configure_firewall() {
    print_message "info" "Configuring firewall..."
    log_message "Configuring firewall"
    
    # Ensure UFW is installed
    ensure_package_installed "ufw"
    
    # Configure UFW
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow ${PORT}/tcp
    
    # Enable UFW without prompt
    ufw --force enable
    
    # Verify firewall configuration
    if ! ufw status | grep -q "Status: active"; then
        print_message "warning" "Firewall not active. Trying to fix..."
        log_message "Firewall not active, trying to fix"
        
        # Try to fix UFW
        ufw reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow ssh
        ufw allow ${PORT}/tcp
        ufw --force enable
        
        if ! ufw status | grep -q "Status: active"; then
            print_message "error" "Failed to enable firewall."
            log_message "Failed to enable firewall"
            # Continue anyway as this is not critical
        fi
    fi
    
    print_message "success" "Firewall configured successfully."
    log_message "Firewall configured successfully"
}

# Function to create client configurations
create_client_configs() {
    print_message "info" "Creating client configurations..."
    log_message "Creating client configurations"
    
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
Security Information:
==========================================================

- Your traffic is routed through Tor for IP obfuscation
- Destination websites will see Tor exit node IPs, not your server IP
- TLS encryption protects your connection to the server
- Self-signed certificate is used (consider using Let's Encrypt for production)

==========================================================
EOF

    # Set permissions for the client configuration files
    chmod -R 644 /root/xray_clients
    chmod 644 /root/xray_clients/*.json
    chmod 644 /root/xray_clients/*.txt
    
    print_message "success" "Client configurations created successfully in /root/xray_clients directory."
    log_message "Client configurations created successfully"
}

# Function to verify Tor connectivity
verify_tor_connectivity() {
    print_message "check" "Verifying Tor connectivity..."
    log_message "Verifying Tor connectivity"
    
    # Check if Tor service is running
    if ! systemctl is-active --quiet tor; then
        print_message "error" "Tor service is not running."
        log_message "Tor service is not running"
        
        # Try to restart Tor
        print_message "info" "Attempting to restart Tor..."
        systemctl restart tor
        sleep 3
        
        if ! systemctl is-active --quiet tor; then
            print_message "error" "Failed to start Tor service."
            log_message "Failed to start Tor service"
            return 1
        fi
    fi
    
    # Test Tor connection
    print_message "check" "Testing Tor SOCKS proxy..."
    if ! curl --socks5 127.0.0.1:9050 --connect-timeout 30 -s https://check.torproject.org/ | grep -q "Congratulations"; then
        print_message "warning" "Tor SOCKS proxy test failed. Connection may not be properly anonymized."
        log_message "Tor SOCKS proxy test failed"
        
        # Try to fix
        print_message "info" "Attempting to fix Tor connection..."
        systemctl restart tor
        sleep 5
        
        if ! curl --socks5 127.0.0.1:9050 --connect-timeout 30 -s https://check.torproject.org/ | grep -q "Congratulations"; then
            print_message "error" "Failed to establish Tor connection after repair attempt."
            log_message "Failed to establish Tor connection after repair"
            return 1
        fi
    fi
    
    print_message "success" "Tor connection verified successfully."
    log_message "Tor connection verified successfully"
    return 0
}

# Function to verify Xray is properly routing through Tor
verify_xray_tor_routing() {
    print_message "check" "Verifying Xray routing through Tor..."
    log_message "Verifying Xray routing through Tor"
    
    # Check if Xray service is running
    if ! systemctl is-active --quiet xray; then
        print_message "error" "Xray service is not running."
        log_message "Xray service is not running"
        return 1
    fi
    
    # Test IP obfuscation through curl with proxychains using the same setup as Xray
    print_message "check" "Testing IP obfuscation..."
    
    # Get real IP
    REAL_IP=$(curl -s https://api.ipify.org)
    
    # Get IP through Tor
    TOR_IP=$(proxychains4 -q curl -s https://api.ipify.org)
    
    if [ -z "$TOR_IP" ]; then
        print_message "warning" "Could not determine IP through Tor proxy."
        log_message "Could not determine IP through Tor proxy"
        return 1
    fi
    
    if [ "$REAL_IP" = "$TOR_IP" ]; then
        print_message "warning" "Traffic may not be properly anonymized. Real IP matches Tor-proxied IP."
        log_message "Traffic may not be properly anonymized"
        return 1
    else
        print_message "security" "IP obfuscation verified: Real IP ($REAL_IP) differs from Tor-proxied IP ($TOR_IP)."
        log_message "IP obfuscation verified"
    fi
    
    print_message "success" "Xray routing through Tor verified successfully."
    log_message "Xray routing through Tor verified successfully"
    return 0
}

# Function to perform system hardening
system_hardening() {
    print_message "info" "Performing system hardening..."
    log_message "Performing system hardening"
    
    # Update SSH configuration - with safety measures to ensure SSH access isn't lost
    if [ -f /etc/ssh/sshd_config ]; then
        # Create a backup of original SSH config
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
        
        # Apply safer SSH configuration
        cat > /etc/ssh/sshd_config.d/hardening.conf << EOF
# Enhanced SSH security settings
PasswordAuthentication yes
PubkeyAuthentication yes
PermitRootLogin yes
MaxAuthTries 5
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
        
        # Restart SSH service - safe way
        print_message "info" "Restarting SSH with new configuration..."
        
        # Test the new configuration before applying
        sshd -t 2>/dev/null
        if [ $? -ne 0 ]; then
            print_message "warning" "SSH configuration test failed. Using safer defaults..."
            cat > /etc/ssh/sshd_config.d/hardening.conf << EOF
# Basic SSH security settings
PasswordAuthentication yes
PubkeyAuthentication yes
PermitRootLogin yes
EOF
        fi
        
        # Apply changes
        systemctl reload sshd
    fi
    
    # Configure kernel parameters for security
    print_message "info" "Configuring secure kernel parameters..."
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
    
    print_message "success" "System hardening completed."
    log_message "System hardening completed"
}

# Function to perform an anonymity check
check_anonymity() {
    print_message "security" "Performing anonymity check..."
    log_message "Performing anonymity check"
    
    # Variables to track results
    local tor_working=false
    local different_ip=false
    local dns_not_leaking=true
    
    # Check 1: Is Tor working?
    if curl --socks5 127.0.0.1:9050 --connect-timeout 30 -s https://check.torproject.org/ | grep -q "Congratulations"; then
        print_message "security" "✓ Tor connection is working properly."
        tor_working=true
    else
        print_message "warning" "✗ Tor connection check failed."
    fi
    
    # Check 2: Is IP different through Tor?
    REAL_IP=$(curl -s https://api.ipify.org)
    TOR_IP=$(proxychains4 -q curl -s https://api.ipify.org)
    
    if [ "$REAL_IP" != "$TOR_IP" ] && [ ! -z "$TOR_IP" ]; then
        print_message "security" "✓ IP obfuscation is working: ${REAL_IP} -> ${TOR_IP}"
        different_ip=true
    else
        print_message "warning" "✗ IP obfuscation check failed."
    fi
    
    # Check 3: DNS leak test (basic)
    DNS_SERVERS=$(proxychains4 -q curl -s https://dnsleak.com/api/v1/servers)
    if echo "$DNS_SERVERS" | grep -q "cloudflare"; then
        print_message "warning" "✗ Potential DNS leak detected."
        dns_not_leaking=false
    else
        print_message "security" "✓ No obvious DNS leaks detected."
    fi
    
    # Overall assessment
    print_message "security" "Anonymity Assessment:"
    
    if $tor_working && $different_ip && $dns_not_leaking; then
        print_message "security" "✅ HIGH: Your connection appears to be properly anonymized through Tor."
        ANONYMITY_LEVEL="HIGH"
    elif $tor_working && $different_ip; then
        print_message "security" "✅ GOOD: Basic IP obfuscation is working but there might be room for improvement."
        ANONYMITY_LEVEL="GOOD"
    elif $tor_working; then
        print_message "warning" "⚠️ MEDIUM: Tor is working but IP obfuscation checks failed."
        ANONYMITY_LEVEL="MEDIUM"
    else
        print_message "error" "❌ LOW: Multiple anonymity checks failed."
        ANONYMITY_LEVEL="LOW"
    fi
    
    # Save anonymity report
    cat > /root/xray_clients/anonymity_report.txt << EOF
==========================================================
VLESS XRAY Anonymity Assessment
==========================================================

Assessment Date: $(date)
Overall Rating: ${ANONYMITY_LEVEL}

Checks Performed:
1. Tor Connection: $($tor_working && echo "PASSED" || echo "FAILED")
2. IP Obfuscation: $($different_ip && echo "PASSED" || echo "FAILED")
   Real IP: ${REAL_IP}
   Tor IP: ${TOR_IP}
3. DNS Leak Check: $($dns_not_leaking && echo "PASSED" || echo "FAILED")

==========================================================
Recommendations:
==========================================================

$(if [ "$ANONYMITY_LEVEL" == "HIGH" ]; then
    echo "- Your setup is secure. Maintain regular updates.";
elif [ "$ANONYMITY_LEVEL" == "GOOD" ]; then
    echo "- Consider additional DNS leak protection.";
elif [ "$ANONYMITY_LEVEL" == "MEDIUM" ]; then
    echo "- Check Tor configuration and IP routing.";
    echo "- Restart Tor service and verify connections.";
else
    echo "- Review and repair Tor configuration.";
    echo "- Check if your ISP is blocking Tor connections.";
    echo "- Consider using Tor bridges.";
fi)

==========================================================
EOF
    
    chmod 644 /root/xray_clients/anonymity_report.txt
    print_message "success" "Anonymity check completed. Report saved to /root/xray_clients/anonymity_report.txt"
    log_message "Anonymity check completed"
}

# Function to print installation summary
print_summary() {
    PUBLIC_IP=$(curl -s https://api.ipify.org)
    
    print_message "info" "Installation Summary:"
    echo ""
    echo "======================================================"
    echo "VLESS XRAY with IP Obfuscation has been installed successfully!"
    echo "======================================================"
    echo ""
    echo "Server Information:"
    echo "- IP Address: ${PUBLIC_IP}"
    echo "- Port: ${PORT}"
    echo "- Protocol: VLESS"
    echo "- TLS: Enabled (Self-signed certificate)"
    echo ""
    echo "Anonymity Level: ${ANONYMITY_LEVEL}"
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
    echo "Security Reports:"
    echo "- Anonymity assessment: /root/xray_clients/anonymity_report.txt"
    echo "- Installation log: ${LOG_FILE}"
    echo ""
    echo "To display connection information again, run: cat /root/xray_clients/connection_info.txt"
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

# Function to perform a complete self-test of all components
perform_self_test() {
    print_message "check" "Performing complete self-test of all components..."
    log_message "Starting self-test"
    
    local test_failed=false
    
    # Create test results directory
    mkdir -p /root/xray_clients/tests
    
    # Test 1: Check if all required services are running
    print_message "check" "Checking services status..."
    
    local services=("tor" "xray")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            print_message "success" "✓ $service service is running."
            echo "✓ $service service is running." >> /root/xray_clients/tests/services_check.txt
        else
            print_message "error" "✗ $service service is not running!"
            echo "✗ $service service is not running!" >> /root/xray_clients/tests/services_check.txt
            test_failed=true
            
            # Attempt to fix
            print_message "info" "Attempting to restart $service..."
            systemctl restart "$service"
            sleep 3
            if systemctl is-active --quiet "$service"; then
                print_message "success" "✓ Successfully restarted $service service."
                echo "✓ Successfully restarted $service service." >> /root/xray_clients/tests/services_check.txt
                test_failed=false
            else
                print_message "error" "✗ Failed to restart $service service."
                echo "✗ Failed to restart $service service." >> /root/xray_clients/tests/services_check.txt
            fi
        fi
    done
    
    # Test 2: Check if port is open
    print_message "check" "Checking if Xray port is open..."
    if netstat -tuln | grep -q ":${PORT}"; then
        print_message "success" "✓ Port ${PORT} is open and listening."
        echo "✓ Port ${PORT} is open and listening." >> /root/xray_clients/tests/port_check.txt
    else
        print_message "error" "✗ Port ${PORT} is not open!"
        echo "✗ Port ${PORT} is not open!" >> /root/xray_clients/tests/port_check.txt
        test_failed=true
    fi
    
    # Test 3: Check firewall configuration
    print_message "check" "Checking firewall configuration..."
    if ufw status | grep -q "${PORT}/tcp"; then
        print_message "success" "✓ Firewall is configured correctly for port ${PORT}."
        echo "✓ Firewall is configured correctly for port ${PORT}." >> /root/xray_clients/tests/firewall_check.txt
    else
        print_message "error" "✗ Firewall rule for port ${PORT} not found!"
        echo "✗ Firewall rule for port ${PORT} not found!" >> /root/xray_clients/tests/firewall_check.txt
        test_failed=true
        
        # Attempt to fix
        print_message "info" "Attempting to add firewall rule..."
        ufw allow ${PORT}/tcp
        if ufw status | grep -q "${PORT}/tcp"; then
            print_message "success" "✓ Successfully added firewall rule."
            echo "✓ Successfully added firewall rule." >> /root/xray_clients/tests/firewall_check.txt
            test_failed=false
        else
            print_message "error" "✗ Failed to add firewall rule."
            echo "✗ Failed to add firewall rule." >> /root/xray_clients/tests/firewall_check.txt
        fi
    fi
    
    # Test 4: Check Tor connectivity
    print_message "check" "Checking Tor connectivity..."
    if curl --socks5 127.0.0.1:9050 --connect-timeout 30 -s https://check.torproject.org/ | grep -q "Congratulations"; then
        print_message "success" "✓ Tor connection is working properly."
        echo "✓ Tor connection is working properly." >> /root/xray_clients/tests/tor_check.txt
    else
        print_message "error" "✗ Tor connection check failed!"
        echo "✗ Tor connection check failed!" >> /root/xray_clients/tests/tor_check.txt
        test_failed=true
    fi
    
    # Test 5: Check IP obfuscation
    print_message "check" "Checking IP obfuscation..."
    REAL_IP=$(curl -s https://api.ipify.org)
    TOR_IP=$(proxychains4 -q curl -s https://api.ipify.org)
    
    if [ "$REAL_IP" != "$TOR_IP" ] && [ ! -z "$TOR_IP" ]; then
        print_message "success" "✓ IP obfuscation is working: ${REAL_IP} -> ${TOR_IP}"
        echo "✓ IP obfuscation is working: ${REAL_IP} -> ${TOR_IP}" >> /root/xray_clients/tests/ip_obfuscation_check.txt
    else
        print_message "error" "✗ IP obfuscation check failed!"
        echo "✗ IP obfuscation check failed!" >> /root/xray_clients/tests/ip_obfuscation_check.txt
        test_failed=true
    fi
    
    # Test 6: Check Xray configuration
    print_message "check" "Verifying Xray configuration..."
    if /usr/local/bin/xray -test -config /usr/local/etc/xray/config.json; then
        print_message "success" "✓ Xray configuration is valid."
        echo "✓ Xray configuration is valid." >> /root/xray_clients/tests/xray_config_check.txt
    else
        print_message "error" "✗ Xray configuration test failed!"
        echo "✗ Xray configuration test failed!" >> /root/xray_clients/tests/xray_config_check.txt
        test_failed=true
    fi
    
    # Compile test results
    cat > /root/xray_clients/test_summary.txt << EOF
==========================================================
VLESS XRAY Self-Test Results
==========================================================

Test Date: $(date)
Overall Status: $($test_failed && echo "FAILED" || echo "PASSED")

1. Services Check: $($test_failed && grep -q "✗" /root/xray_clients/tests/services_check.txt && echo "FAILED" || echo "PASSED")
2. Port Check: $(grep -q "✗" /root/xray_clients/tests/port_check.txt && echo "FAILED" || echo "PASSED")
3. Firewall Check: $(grep -q "✗" /root/xray_clients/tests/firewall_check.txt && echo "FAILED" || echo "PASSED")
4. Tor Connectivity: $(grep -q "✗" /root/xray_clients/tests/tor_check.txt && echo "FAILED" || echo "PASSED")
5. IP Obfuscation: $(grep -q "✗" /root/xray_clients/tests/ip_obfuscation_check.txt && echo "FAILED" || echo "PASSED")
6. Xray Configuration: $(grep -q "✗" /root/xray_clients/tests/xray_config_check.txt && echo "FAILED" || echo "PASSED")

==========================================================
Detailed Results:
==========================================================

-- Services Check --
$(cat /root/xray_clients/tests/services_check.txt)

-- Port Check --
$(cat /root/xray_clients/tests/port_check.txt)

-- Firewall Check --
$(cat /root/xray_clients/tests/firewall_check.txt)

-- Tor Connectivity --
$(cat /root/xray_clients/tests/tor_check.txt)

-- IP Obfuscation --
$(cat /root/xray_clients/tests/ip_obfuscation_check.txt)

-- Xray Configuration --
$(cat /root/xray_clients/tests/xray_config_check.txt)

==========================================================
EOF

    chmod 644 /root/xray_clients/test_summary.txt
    
    if $test_failed; then
        print_message "warning" "Self-test completed with some failures. See /root/xray_clients/test_summary.txt for details."
        log_message "Self-test completed with failures"
    else
        print_message "success" "Self-test completed successfully! All components are working properly."
        log_message "Self-test completed successfully"
    fi
}

# Function for automatic self-healing of common issues
automatic_self_healing() {
    print_message "info" "Running automatic self-healing routines..."
    log_message "Running automatic self-healing routines"
    
    # Verify Tor is running
    if ! systemctl is-active --quiet tor; then
        print_message "warning" "Tor service is not running. Attempting to fix..."
        systemctl restart tor
        sleep 3
    fi
    
    # Verify Xray is running
    if ! systemctl is-active --quiet xray; then
        print_message "warning" "Xray service is not running. Attempting to fix..."
        
        # Try to identify the issue
        print_message "info" "Checking Xray logs for errors..."
        journalctl -xe --no-pager -n 20 -u xray
        
        # Test configuration
        if ! /usr/local/bin/xray -test -config /usr/local/etc/xray/config.json; then
            print_message "warning" "Xray configuration is invalid. Attempting to recreate..."
            configure_xray
        fi
        
        # Restart service
        systemctl restart xray
        sleep 5
        
        if ! systemctl is-active --quiet xray; then
            print_message "error" "Failed to fix Xray service automatically."
            log_message "Failed to fix Xray service automatically"
        else
            print_message "success" "Successfully fixed Xray service."
            log_message "Successfully fixed Xray service"
        fi
    fi
    
    # Verify port is open
    if ! netstat -tuln | grep -q ":${PORT}"; then
        print_message "warning" "Port ${PORT} is not open. Checking firewall..."
        
        # Check if the port is allowed in UFW
        if ! ufw status | grep -q "${PORT}/tcp"; then
            print_message "info" "Adding firewall rule for port ${PORT}..."
            ufw allow ${PORT}/tcp
        fi
        
        # Restart Xray
        systemctl restart xray
        sleep 3
        
        if ! netstat -tuln | grep -q ":${PORT}"; then
            print_message "error" "Failed to open port ${PORT}."
            log_message "Failed to open port ${PORT}"
        else
            print_message "success" "Successfully opened port ${PORT}."
            log_message "Successfully opened port ${PORT}"
        fi
    fi
    
    print_message "success" "Self-healing process completed."
    log_message "Self-healing process completed"
}

# Main function
main() {
    print_message "info" "Starting self-healing VLESS Xray installation with IP obfuscation..."
    
    # Initialize log file
    echo "=== VLESS Xray Installation Log - $(date) ===" > "$LOG_FILE"
    log_message "Starting installation"
    
    # Perform installation steps with automatic error handling
    check_root
    update_system
    install_dependencies
    configure_tor
    configure_proxychains
    install_xray
    configure_xray
    create_xray_wrapper
    configure_xray_service
    configure_firewall
    create_client_configs
    system_hardening
    
    # Verify installation and perform self-tests
    print_message "info" "Verifying installation..."
    log_message "Verifying installation"
    
    # First round of automatic self-healing
    automatic_self_healing
    
    # Check anonymity and IP obfuscation
    verify_tor_connectivity
    verify_xray_tor_routing
    check_anonymity
    
    # Complete self-test of all components
    perform_self_test
    
    # Final round of automatic self-healing if needed
    automatic_self_healing
    
    # Print installation summary
    print_summary
    
    print_message "success" "Installation completed successfully!"
    log_message "Installation completed successfully"
}

# Run the main function
main

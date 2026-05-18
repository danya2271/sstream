#!/bin/bash

# --- CONFIGURATION ---
DOMAIN="*.meowda.space"
SOCKS_USER="user"
SOCKS_PASS="pass"
SOCKS_PORT=1080
SLIP_DNS_PORT=53
SLIP_MTU=650
INSTALL_DIR="/opt/slipstream"
BINARY_NAME="slipstream-server"

# --- 1. Argument & Root Check ---
PACKAGE_PATH=$1

if [ -z "$PACKAGE_PATH" ]; then
    echo "Usage: $0 <path-to-sstream-server.tar.gz>"
    exit 1
fi

# --- 2. OS Detection ---
echo "Detecting OS and installing dependencies..."
if [ -f /etc/debian_version ]; then
    apt update && apt install -y build-essential git wget curl openssl
elif [ -f /etc/arch-release ]; then
    pacman -Syu --noconfirm base-devel git wget curl openssl
else
    echo "Unsupported OS."
    exit 1
fi

# --- 3. Extract Package ---
echo "Extracting $PACKAGE_PATH to $INSTALL_DIR..."
mkdir -p $INSTALL_DIR
tar -xzvf "$PACKAGE_PATH" -C $INSTALL_DIR

if [ ! -f "$INSTALL_DIR/$BINARY_NAME" ]; then
    echo "Error: Binary $BINARY_NAME not found in package!"
    exit 1
fi
chmod +x "$INSTALL_DIR/$BINARY_NAME"

# --- 4. Generate Certificates (If missing) ---
cd $INSTALL_DIR
if [ ! -f "server.crt" ]; then
    echo "Generating self-signed certificates..."
    openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
    -sha256 -days 3650 -nodes \
    -subj "/C=US/ST=State/L=City/O=Proxy/CN=$DOMAIN"
    chmod 600 server.key
fi

# --- 5. Install Microsocks ---
if [ ! -f "/usr/local/bin/microsocks" ]; then
    echo "Compiling Microsocks..."
    git clone https://github.com/rofl0r/microsocks.git /tmp/microsocks
    cd /tmp/microsocks && make && make install
    cd $INSTALL_DIR
fi

# --- 6. Kernel & Limit Optimizations ---
echo "Applying system optimizations..."
cat <<EOF > /etc/security/limits.d/99-proxy.conf
* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535
EOF

cat <<EOF > /etc/sysctl.d/99-slipstream.conf
net.core.rmem_max=26214400
net.core.wmem_max=26214400
net.core.rmem_default=26214400
net.core.wmem_default=26214400
net.ipv4.tcp_tw_reuse=1
net.ipv4.ip_local_port_range=1024 65000
net.core.somaxconn=4096
EOF
sysctl --system

# --- 7. Systemd Services ---

# Microsocks Service
cat <<EOF > /etc/systemd/system/microsocks.service
[Unit]
Description=Microsocks SOCKS5 Server
After=network.target

[Service]
ExecStart=/usr/local/bin/microsocks -i 127.0.0.1 -p $SOCKS_PORT -u $SOCKS_USER -P $SOCKS_PASS
Restart=always
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

# Slipstream Service
cat <<EOF > /etc/systemd/system/slipstream.service
[Unit]
Description=Slipstream Server
After=network.target microsocks.service

[Service]
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/$BINARY_NAME --domain $DOMAIN --dns-listen-port $SLIP_DNS_PORT --target-address 127.0.0.1:$SOCKS_PORT --cert $INSTALL_DIR/server.crt --key $INSTALL_DIR/server.key --mtu $SLIP_MTU
Restart=always
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

# --- 8. Finalize ---
systemctl daemon-reload
systemctl enable --now microsocks
systemctl restart microsocks
systemctl enable --now slipstream
systemctl restart slipstream

echo "------------------------------------------------"
echo "INSTALLATION COMPLETE"
echo "Status: systemctl status slipstream"
echo "Certs: $INSTALL_DIR/server.crt"
echo "------------------------------------------------"

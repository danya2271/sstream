#!/usr/bin/env bash
set -euo pipefail

# Defaults can be overridden with environment variables, for example:
# SLIP_DOMAIN='*.meowda.space' SOCKS_USER='user' SOCKS_PASS='pass' ./install_sstream.sh ./sstream-server.tar.gz
SLIP_DOMAIN="${SLIP_DOMAIN:-${DOMAIN:-*.meowda.space}}"
CERT_CN="${CERT_CN:-$SLIP_DOMAIN}"
SOCKS_USER="${SOCKS_USER:-user}"
SOCKS_PASS="${SOCKS_PASS:-pass}"
SOCKS_PORT="${SOCKS_PORT:-1080}"
SLIP_DNS_PORT="${SLIP_DNS_PORT:-53}"
SLIP_MTU="${SLIP_MTU:-650}"
INSTALL_DIR="${INSTALL_DIR:-/opt/slipstream}"
BINARY_NAME="${BINARY_NAME:-slipstream-server}"

PACKAGE_PATH="${1:-}"
TMP_DIR=""

cleanup() {
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

if [[ -z "$PACKAGE_PATH" ]]; then
    echo "Usage: $0 <path-to-sstream-server.tar.gz>" >&2
    exit 1
fi

if [[ ! -f "$PACKAGE_PATH" ]]; then
    echo "Error: package not found: $PACKAGE_PATH" >&2
    exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Error: run this installer as root." >&2
    exit 1
fi

echo "Installing dependencies..."
if [[ -f /etc/debian_version ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends build-essential ca-certificates git openssl
elif [[ -f /etc/arch-release ]]; then
    pacman -Syu --noconfirm --needed base-devel ca-certificates git openssl
else
    echo "Unsupported OS." >&2
    exit 1
fi

echo "Extracting $PACKAGE_PATH to $INSTALL_DIR..."
install -d -m 0755 "$INSTALL_DIR"
tar -xzf "$PACKAGE_PATH" -C "$INSTALL_DIR"

if [[ ! -f "$INSTALL_DIR/$BINARY_NAME" ]]; then
    echo "Error: binary $BINARY_NAME not found in package." >&2
    exit 1
fi
chmod +x "$INSTALL_DIR/$BINARY_NAME"

cd "$INSTALL_DIR"
if [[ ! -f server.crt || ! -f server.key ]]; then
    echo "Generating self-signed certificate for $CERT_CN..."
    openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
        -sha256 -days 3650 -nodes \
        -subj "/C=US/ST=State/L=City/O=Proxy/CN=$CERT_CN" \
        -addext "subjectAltName=DNS:$CERT_CN"
    chmod 600 server.key
    chmod 644 server.crt
fi

if [[ ! -x /usr/local/bin/microsocks ]]; then
    echo "Compiling microsocks..."
    TMP_DIR="$(mktemp -d)"
    git clone --depth=1 https://github.com/rofl0r/microsocks.git "$TMP_DIR/microsocks"
    make -C "$TMP_DIR/microsocks"
    make -C "$TMP_DIR/microsocks" install
fi

echo "Applying system optimizations..."
cat > /etc/security/limits.d/99-proxy.conf <<'EOF'
* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535
EOF

cat > /etc/sysctl.d/99-slipstream.conf <<'EOF'
net.core.rmem_max=26214400
net.core.wmem_max=26214400
net.core.rmem_default=26214400
net.core.wmem_default=26214400
net.ipv4.tcp_tw_reuse=1
net.ipv4.ip_local_port_range=1024 65000
net.core.somaxconn=4096
EOF
sysctl --system

cat > /etc/systemd/system/microsocks.service <<EOF
[Unit]
Description=Microsocks SOCKS5 Server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/microsocks -i 127.0.0.1 -p $SOCKS_PORT -u $SOCKS_USER -P $SOCKS_PASS
Restart=always
RestartSec=2
StandardOutput=journal
StandardError=journal
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/slipstream.service <<EOF
[Unit]
Description=Slipstream Server
After=network-online.target microsocks.service
Wants=network-online.target
Requires=microsocks.service

[Service]
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/$BINARY_NAME --domain $SLIP_DOMAIN --dns-listen-port $SLIP_DNS_PORT --target-address 127.0.0.1:$SOCKS_PORT --cert $INSTALL_DIR/server.crt --key $INSTALL_DIR/server.key --mtu $SLIP_MTU
Restart=always
RestartSec=2
StandardOutput=journal
StandardError=journal
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable microsocks.service slipstream.service
systemctl restart microsocks.service
systemctl restart slipstream.service

echo "------------------------------------------------"
echo "INSTALLATION COMPLETE"
echo "Slipstream domain: $SLIP_DOMAIN"
echo "Client domain example: a.meowda.space"
echo "Status: systemctl status slipstream.service"
echo "Logs: journalctl -u slipstream.service -f"
echo "Cert: $INSTALL_DIR/server.crt"
echo "------------------------------------------------"

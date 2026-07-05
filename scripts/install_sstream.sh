#!/usr/bin/env bash
set -euo pipefail

# Defaults can be overridden with environment variables, for example:
# SLIP_DOMAIN='*.meowda.space' SOCKS_USER='user' SOCKS_PASS='pass' ./install_sstream.sh ./sstream-server.tar.gz
ENV_SLIP_DOMAIN="${SLIP_DOMAIN:-${DOMAIN:-}}"
ENV_CERT_CN="${CERT_CN:-}"
ENV_SOCKS_USER="${SOCKS_USER:-}"
ENV_SOCKS_PASS="${SOCKS_PASS:-}"
SLIP_DOMAIN="${ENV_SLIP_DOMAIN:-*.meowda.space}"
CERT_CN="${ENV_CERT_CN:-$SLIP_DOMAIN}"
SOCKS_USER="${ENV_SOCKS_USER:-user}"
SOCKS_PASS="${ENV_SOCKS_PASS:-pass}"
SOCKS_PORT="${SOCKS_PORT:-1080}"
SLIP_DNS_PORT="${SLIP_DNS_PORT:-53}"
SLIP_MTU="${SLIP_MTU:-850}"
INSTALL_DIR="${INSTALL_DIR:-/opt/slipstream}"
BINARY_NAME="${BINARY_NAME:-slipstream-server}"
CONFIG_FILE="${CONFIG_FILE:-$INSTALL_DIR/server.env}"

PACKAGE_PATH="${1:-}"
TMP_DIR=""
OLD_SLIP_DOMAIN=""
OLD_CERT_CN=""

cleanup() {
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

is_interactive() {
    [[ -t 0 ]]
}

mask_secret() {
    local value="$1"
    if [[ -z "$value" ]]; then
        printf '(empty)'
    else
        printf '********'
    fi
}

ask_yes_no() {
    local prompt="$1"
    local default="${2:-n}"
    local answer=""

    if ! is_interactive; then
        [[ "$default" == "y" ]]
        return
    fi

    if [[ "$default" == "y" ]]; then
        read -r -p "$prompt [Y/n]: " answer
        [[ -z "$answer" || "$answer" =~ ^[Yy]$ ]]
    else
        read -r -p "$prompt [y/N]: " answer
        [[ "$answer" =~ ^[Yy]$ ]]
    fi
}

prompt_value() {
    local label="$1"
    local default="$2"
    local secret="${3:-false}"
    local value=""

    if ! is_interactive; then
        PROMPT_VALUE="$default"
        return
    fi

    while true; do
        if [[ "$secret" == "true" ]]; then
            read -r -s -p "$label [$(mask_secret "$default")]: " value
            echo
        else
            read -r -p "$label [$default]: " value
        fi

        PROMPT_VALUE="${value:-$default}"
        if [[ -n "$PROMPT_VALUE" ]]; then
            return
        fi
        echo "Value cannot be empty." >&2
    done
}

prompt_server_config() {
    prompt_value "SOCKS username" "$SOCKS_USER"
    SOCKS_USER="$PROMPT_VALUE"
    prompt_value "SOCKS password" "$SOCKS_PASS" true
    SOCKS_PASS="$PROMPT_VALUE"
    prompt_value "Slipstream domain" "$SLIP_DOMAIN"
    SLIP_DOMAIN="$PROMPT_VALUE"
    CERT_CN="${ENV_CERT_CN:-$SLIP_DOMAIN}"
}

save_server_config() {
    install -d -m 0755 "$INSTALL_DIR"
    umask 077
    {
        printf 'SLIP_DOMAIN=%q\n' "$SLIP_DOMAIN"
        printf 'CERT_CN=%q\n' "$CERT_CN"
        printf 'SOCKS_USER=%q\n' "$SOCKS_USER"
        printf 'SOCKS_PASS=%q\n' "$SOCKS_PASS"
    } > "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
}

systemd_quote() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//%/%%}"
    printf '"%s"' "$value"
}

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

install -d -m 0755 "$INSTALL_DIR"

if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
    OLD_SLIP_DOMAIN="$SLIP_DOMAIN"
    OLD_CERT_CN="$CERT_CN"

    if [[ -n "$ENV_SLIP_DOMAIN" ]]; then SLIP_DOMAIN="$ENV_SLIP_DOMAIN"; fi
    if [[ -n "$ENV_CERT_CN" ]]; then CERT_CN="$ENV_CERT_CN"; fi
    if [[ -n "$ENV_SOCKS_USER" ]]; then SOCKS_USER="$ENV_SOCKS_USER"; fi
    if [[ -n "$ENV_SOCKS_PASS" ]]; then SOCKS_PASS="$ENV_SOCKS_PASS"; fi

    echo "Existing Slipstream server config found:"
    echo "  Domain: $SLIP_DOMAIN"
    echo "  SOCKS user: $SOCKS_USER"
    echo "  SOCKS password: $(mask_secret "$SOCKS_PASS")"

    if ask_yes_no "Modify saved domain/user/password?" "n"; then
        prompt_server_config
    else
        echo "Reusing saved domain/user/password."
    fi
else
    echo "No saved Slipstream server config found. Please choose server credentials."
    prompt_server_config
fi

save_server_config

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
tar -xzf "$PACKAGE_PATH" -C "$INSTALL_DIR"

if [[ ! -f "$INSTALL_DIR/$BINARY_NAME" ]]; then
    echo "Error: binary $BINARY_NAME not found in package." >&2
    exit 1
fi
chmod +x "$INSTALL_DIR/$BINARY_NAME"

cd "$INSTALL_DIR"
if [[ ! -f server.crt || ! -f server.key || "$SLIP_DOMAIN" != "$OLD_SLIP_DOMAIN" || "$CERT_CN" != "$OLD_CERT_CN" ]]; then
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

MICROSOCKS_BIN_ARG="$(systemd_quote "/usr/local/bin/microsocks")"
MICROSOCKS_PORT_ARG="$(systemd_quote "$SOCKS_PORT")"
MICROSOCKS_USER_ARG="$(systemd_quote "$SOCKS_USER")"
MICROSOCKS_PASS_ARG="$(systemd_quote "$SOCKS_PASS")"
SLIPSTREAM_BIN_ARG="$(systemd_quote "$INSTALL_DIR/$BINARY_NAME")"
SLIPSTREAM_DOMAIN_ARG="$(systemd_quote "$SLIP_DOMAIN")"
SLIPSTREAM_DNS_PORT_ARG="$(systemd_quote "$SLIP_DNS_PORT")"
SLIPSTREAM_TARGET_ARG="$(systemd_quote "127.0.0.1:$SOCKS_PORT")"
SLIPSTREAM_CERT_ARG="$(systemd_quote "$INSTALL_DIR/server.crt")"
SLIPSTREAM_KEY_ARG="$(systemd_quote "$INSTALL_DIR/server.key")"
SLIPSTREAM_MTU_ARG="$(systemd_quote "$SLIP_MTU")"

cat > /etc/systemd/system/microsocks.service <<EOF
[Unit]
Description=Microsocks SOCKS5 Server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$MICROSOCKS_BIN_ARG -i 127.0.0.1 -p $MICROSOCKS_PORT_ARG -u $MICROSOCKS_USER_ARG -P $MICROSOCKS_PASS_ARG
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
ExecStart=$SLIPSTREAM_BIN_ARG --domain $SLIPSTREAM_DOMAIN_ARG --dns-listen-port $SLIPSTREAM_DNS_PORT_ARG --target-address $SLIPSTREAM_TARGET_ARG --cert $SLIPSTREAM_CERT_ARG --key $SLIPSTREAM_KEY_ARG --mtu $SLIPSTREAM_MTU_ARG
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
echo "SOCKS user: $SOCKS_USER"
echo "SOCKS password: $(mask_secret "$SOCKS_PASS")"
echo "Saved config: $CONFIG_FILE"
echo "Client domain example: a.meowda.space"
echo "Status: systemctl status slipstream.service"
echo "Logs: journalctl -u slipstream.service -f"
echo "Cert: $INSTALL_DIR/server.crt"
echo "------------------------------------------------"

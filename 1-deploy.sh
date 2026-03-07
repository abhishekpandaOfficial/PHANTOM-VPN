#!/bin/bash
# ============================================================
#  PHANTOM VPN — Full DigitalOcean Deployment Script
#  Run as root on a fresh Ubuntu 22.04 droplet:
#    curl -O https://YOUR_DOMAIN/1-deploy.sh && bash 1-deploy.sh
# ============================================================
set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'

log()  { echo -e "${CYAN}[PHANTOM]${NC} $1"; }
ok()   { echo -e "${GREEN}[  OK  ]${NC} $1"; }
warn() { echo -e "${YELLOW}[ WARN ]${NC} $1"; }
err()  { echo -e "${RED}[ ERR  ]${NC} $1"; exit 1; }

echo -e "${CYAN}"
cat << 'BANNER'
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
              Personal Privacy VPN — DigitalOcean Installer
BANNER
echo -e "${NC}"

# ---- CONFIG (edit these before running) ----
VPN_PORT=51820
MONITOR_PORT=7777
WG_SUBNET="10.8.0.0/24"
WG_SERVER_IP="10.8.0.1"
WG_CLIENT_IP="10.8.0.2"
SERVER_IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
ADMIN_USER="hello@abhishekpanda.com"
ADMIN_TOTP_SECRET="$(head -c 20 /dev/urandom | base32 | tr -d '=\n')"
FREE_TRIAL_HOURS="1"
FREE_TRIAL_RESET_DAYS="15"
PAYMENT_LINK="mailto:${ADMIN_USER}?subject=PHANTOM%20VPN%20Payment"
PLAN_PRICE_LABEL="Payment required after trial"
RAZORPAY_KEY_ID=""
RAZORPAY_KEY_SECRET=""
RAZORPAY_PLAN_AMOUNT="49900"
RAZORPAY_CURRENCY="INR"
RAZORPAY_PLAN_NAME="PHANTOM VPN Premium"
RAZORPAY_PLAN_DESCRIPTION="PHANTOM VPN paid access"
API_SECRET="$(openssl rand -hex 32)"
SYSTEMD_PAYMENT_LINK="${PAYMENT_LINK//%/%%}"
# ---- END CONFIG ----

log "Detected network interface: $SERVER_IFACE"
log "WireGuard port: $VPN_PORT | Monitor API port: $MONITOR_PORT"

# ============================================================
# STEP 1: System Update & Base Packages
# ============================================================
log "Step 1/9: Updating system..."
apt-get update -qq && apt-get upgrade -y -qq
apt-get install -y -qq \
    ca-certificates \
    wireguard wireguard-tools \
    tor \
    unbound \
    fail2ban \
    ufw \
    curl wget \
    netcat-traditional \
    iptables-persistent \
    nodejs npm \
    nginx \
    certbot \
    jq \
    net-tools \
    vnstat \
    htop \
    git
ok "System updated and packages installed."

# ============================================================
# STEP 2: WireGuard Key Generation
# ============================================================
log "Step 2/9: Generating WireGuard keys..."
mkdir -p /etc/wireguard && cd /etc/wireguard
chmod 700 /etc/wireguard

wg genkey | tee server_private.key | wg pubkey > server_public.key
wg genkey | tee client_private.key | wg pubkey > client_public.key
chmod 600 /etc/wireguard/server_private.key /etc/wireguard/client_private.key

SERVER_PRIV=$(cat /etc/wireguard/server_private.key)
SERVER_PUB=$(cat /etc/wireguard/server_public.key)
CLIENT_PRIV=$(cat /etc/wireguard/client_private.key)
CLIENT_PUB=$(cat /etc/wireguard/client_public.key)
SERVER_IP=$(
    curl -4fsS --max-time 8 ifconfig.me 2>/dev/null || \
    curl -4fsS --max-time 8 api.ipify.org 2>/dev/null || \
    hostname -I | awk '{print $1}'
)
[[ -n "${SERVER_IP}" ]] || err "Failed to detect server public IP"

ok "WireGuard keys generated."

# ============================================================
# STEP 3: WireGuard Server Config
# ============================================================
log "Step 3/9: Configuring WireGuard server..."

cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = ${SERVER_PRIV}
Address = ${WG_SERVER_IP}/24
ListenPort = ${VPN_PORT}
DNS = 127.0.0.1

# Enable IP forwarding + NAT
PostUp   = sysctl -w net.ipv4.ip_forward=1
PostUp   = sysctl -w net.ipv6.conf.all.forwarding=1
PostUp   = iptables -t nat -A POSTROUTING -s ${WG_SUBNET} -o ${SERVER_IFACE} -j MASQUERADE
PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp   = iptables -A FORWARD -o wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s ${WG_SUBNET} -o ${SERVER_IFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -o wg0 -j ACCEPT

[Peer]
# Client
PublicKey  = ${CLIENT_PUB}
AllowedIPs = ${WG_CLIENT_IP}/32
EOF

# Enable IP forwarding permanently
echo "net.ipv4.ip_forward=1"          >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
sysctl -p > /dev/null

systemctl enable --now wg-quick@wg0
ok "WireGuard server running on port ${VPN_PORT}."

# ============================================================
# STEP 4: Tor Onion Routing
# ============================================================
log "Step 4/9: Configuring Tor..."

TOR_PASS="phantom_control_$(date +%s)"
TOR_HASH=$(tor --hash-password "${TOR_PASS}" 2>/dev/null | tail -1)

cat > /etc/tor/torrc <<EOF
# PHANTOM VPN — Tor Configuration
SocksPort 9050
SocksPort 9150
ControlPort 9051
HashedControlPassword ${TOR_HASH}

# Circuit rotation every 30 seconds
MaxCircuitDirtiness 30
NewCircuitPeriod 30
CircuitBuildTimeout 10
NumEntryGuards 3

# DNS via Tor
DNSPort 5353 IsolateClientAddr IsolateClientProtocol
AutomapHostsOnResolve 1
VirtualAddrNetworkIPv4 10.192.0.0/10

# Exclude high-surveillance countries
ExcludeNodes {cn},{ru},{ir},{kp},{sy},{by}
ExcludeExitNodes {cn},{ru},{ir}
StrictNodes 0

# Logging
Log notice file /var/log/tor/notices.log
RunAsDaemon 1
DataDirectory /var/lib/tor
EOF

systemctl enable --now tor
ok "Tor onion routing configured (30s circuit rotation)."

# ============================================================
# STEP 5: Unbound DNS with Ad Blocking
# ============================================================
log "Step 5/9: Setting up Unbound DNS with ad-blocking..."

# Download blocklist
mkdir -p /etc/unbound/blocklists
curl -s "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" | \
    grep "^0\.0\.0\.0" | awk '{print "local-zone: \""$2"\" redirect\nlocal-data: \""$2" A 0.0.0.0\""}' \
    > /etc/unbound/blocklists/ads.conf 2>/dev/null || \
    echo "# blocklist placeholder" > /etc/unbound/blocklists/ads.conf

cat > /etc/unbound/unbound.conf <<EOF
server:
    interface: 127.0.0.1
    interface: ${WG_SERVER_IP}
    port: 53
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    access-control: 127.0.0.0/8 allow
    access-control: ${WG_SUBNET} allow
    access-control: 0.0.0.0/0 refuse

    # Privacy settings
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: yes
    qname-minimisation: yes
    tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt

    # DNS cache
    cache-min-ttl: 3600
    cache-max-ttl: 86400
    prefetch: yes
    num-threads: 2

    # Logging (minimal for privacy)
    verbosity: 0
    log-queries: no

    # Include ad blocklist
    include: /etc/unbound/blocklists/ads.conf

# Forward DNS over TLS to Cloudflare
forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 1.0.0.1@853#cloudflare-dns.com
    forward-addr: 9.9.9.9@853#dns.quad9.net

remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
EOF

unbound-control-setup >/dev/null 2>&1 || true
systemctl enable --now unbound
ok "Unbound DNS running with ad-blocking enabled."

# ============================================================
# STEP 6: Fail2Ban (Attack Protection)
# ============================================================
log "Step 6/9: Configuring Fail2Ban attack protection..."

cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
action   = %(action_mwl)s

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s

[phantom-vpn]
enabled  = true
port     = ${VPN_PORT}
protocol = udp
filter   = phantom-vpn
logpath  = /var/log/auth.log
maxretry = 10

[nginx-http-auth]
enabled  = true
EOF

cat > /etc/fail2ban/filter.d/phantom-vpn.conf <<EOF
[Definition]
failregex = Invalid user .* from <HOST>
            Failed password for .* from <HOST>
            Connection closed by .* port .* \[preauth\]
ignoreregex =
EOF

systemctl enable --now fail2ban
ok "Fail2Ban protection active."

# ============================================================
# STEP 7: UFW Firewall
# ============================================================
log "Step 7/9: Configuring firewall..."

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow ${VPN_PORT}/udp
ufw allow in on wg0 to any port 53 proto udp
ufw allow in on wg0 to any port 53 proto tcp
ufw allow ${MONITOR_PORT}/tcp  # Dashboard API (restrict to your IP in production)
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# Save iptables
iptables-save > /etc/iptables/rules.v4
ok "Firewall configured."

# ============================================================
# STEP 8: Node.js Monitoring API Server
# ============================================================
log "Step 8/9: Installing monitoring API server..."

mkdir -p /opt/phantom-vpn
cp /root/2-monitoring-server.js /opt/phantom-vpn/server.js 2>/dev/null || true
cp /root/3-dashboard.html /opt/phantom-vpn/dashboard.html 2>/dev/null || true
cp /root/5-landing.html /opt/phantom-vpn/landing.html 2>/dev/null || true
cp /root/6-admin.html /opt/phantom-vpn/admin.html 2>/dev/null || true
cp /root/7-user-dashboard.html /opt/phantom-vpn/portal.html 2>/dev/null || true
cp /root/8-routing.html /opt/phantom-vpn/routing.html 2>/dev/null || true
cp /root/9-docs.html /opt/phantom-vpn/docs.html 2>/dev/null || true
mkdir -p /opt/phantom-vpn/brand
cp /root/brand/* /opt/phantom-vpn/brand/ 2>/dev/null || true

cat > /opt/phantom-vpn/package.json <<EOF
{
  "name": "phantom-vpn-monitor",
  "version": "1.0.0",
  "description": "PHANTOM VPN Real-Time Monitoring API",
  "main": "server.js",
  "scripts": { "start": "node server.js" },
  "dependencies": {}
}
EOF

cd /opt/phantom-vpn && npm install --silent

# Systemd service for monitoring API
cat > /etc/systemd/system/phantom-monitor.service <<EOF
[Unit]
Description=PHANTOM VPN Monitoring API
After=network.target wg-quick@wg0.service tor.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/phantom-vpn
ExecStart=/usr/bin/node /opt/phantom-vpn/server.js
Restart=always
RestartSec=5
Environment=NODE_ENV=production
Environment=PORT=${MONITOR_PORT}
Environment=API_SECRET=${API_SECRET}
Environment=ADMIN_USER=${ADMIN_USER}
Environment=ADMIN_TOTP_SECRET=${ADMIN_TOTP_SECRET}
Environment=FREE_TRIAL_HOURS=${FREE_TRIAL_HOURS}
Environment=FREE_TRIAL_RESET_DAYS=${FREE_TRIAL_RESET_DAYS}
Environment="PAYMENT_LINK=${SYSTEMD_PAYMENT_LINK}"
Environment="PLAN_PRICE_LABEL=${PLAN_PRICE_LABEL}"
Environment=RAZORPAY_KEY_ID=${RAZORPAY_KEY_ID}
Environment=RAZORPAY_KEY_SECRET=${RAZORPAY_KEY_SECRET}
Environment=RAZORPAY_PLAN_AMOUNT=${RAZORPAY_PLAN_AMOUNT}
Environment=RAZORPAY_CURRENCY=${RAZORPAY_CURRENCY}
Environment="RAZORPAY_PLAN_NAME=${RAZORPAY_PLAN_NAME}"
Environment="RAZORPAY_PLAN_DESCRIPTION=${RAZORPAY_PLAN_DESCRIPTION}"
Environment=TOR_CONTROL_PASSWORD=${TOR_PASS}
Environment=WG_SUBNET=${WG_SUBNET}
Environment=WG_DNS=${WG_SERVER_IP}
Environment=WG_PUBLIC_ENDPOINT=${SERVER_IP}:${VPN_PORT}
Environment=WG_SERVER_PUBLIC_KEY=${SERVER_PUB}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable phantom-monitor

# IP Rotation systemd service
cat > /etc/systemd/system/phantom-rotate.service <<EOF
[Unit]
Description=PHANTOM VPN IP Rotation (Tor NEWNYM)
After=tor.service

[Service]
Type=simple
ExecStart=/usr/local/bin/phantom-rotate.sh
Restart=always
User=root
Environment=TOR_CONTROL_PASSWORD=${TOR_PASS}

[Install]
WantedBy=multi-user.target
EOF

cat > /usr/local/bin/phantom-rotate.sh <<'ROTATE'
#!/bin/bash
# IP Rotation via Tor NEWNYM signal
INTERVAL=${ROTATE_INTERVAL:-30}
LOG=/var/log/phantom-rotate.log
while true; do
    echo -e "AUTHENTICATE \"${TOR_CONTROL_PASSWORD}\"\r\nSIGNAL NEWNYM\r\nQUIT" | \
        nc 127.0.0.1 9051 > /dev/null 2>&1
    NEW_IP=$(curl -s --socks5 127.0.0.1:9050 --max-time 10 ifconfig.me 2>/dev/null || echo "unknown")
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ROTATED_TO=${NEW_IP}" >> $LOG
    sleep $INTERVAL
done
ROTATE
chmod +x /usr/local/bin/phantom-rotate.sh
systemctl enable phantom-rotate

# ============================================================
# STEP 9: Generate Client Config & Save Credentials
# ============================================================
log "Step 9/9: Generating client WireGuard config..."

cat > /root/phantom-client.conf <<EOF
# PHANTOM VPN — Client WireGuard Config
# Import this file into the WireGuard app on any device

[Interface]
PrivateKey = ${CLIENT_PRIV}
Address    = ${WG_CLIENT_IP}/24
DNS        = ${WG_SERVER_IP}

[Peer]
PublicKey  = ${SERVER_PUB}
Endpoint   = ${SERVER_IP}:${VPN_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

# Install qrencode for mobile QR code
apt-get install -y -qq qrencode
qrencode -t ansiutf8 < /root/phantom-client.conf
ADMIN_TOTP_URI="otpauth://totp/PHANTOM%20VPN:${ADMIN_USER//@/%40}?secret=${ADMIN_TOTP_SECRET}&issuer=PHANTOM%20VPN"
echo ""
log "Scan this QR with Google Authenticator / Authy / 1Password for admin login:"
qrencode -t ansiutf8 "${ADMIN_TOTP_URI}"

# Save all credentials
cat > /root/phantom-credentials.txt <<EOF
================================================
  PHANTOM VPN — CREDENTIALS & ACCESS INFO
================================================
Server IP          : ${SERVER_IP}
WireGuard Port     : ${VPN_PORT}
Monitor API Port   : ${MONITOR_PORT}
Monitor API URL    : http://${SERVER_IP}:${MONITOR_PORT}
Admin User         : ${ADMIN_USER}
Admin Auth Mode    : TOTP via authenticator app
Admin TOTP Secret  : ${ADMIN_TOTP_SECRET}
Admin TOTP URI     : ${ADMIN_TOTP_URI}
Free Trial Hours   : ${FREE_TRIAL_HOURS}
Trial Reset Days   : ${FREE_TRIAL_RESET_DAYS}
Payment Link       : ${PAYMENT_LINK}
Razorpay Key ID    : ${RAZORPAY_KEY_ID:-not-set}
Razorpay Amount    : ${RAZORPAY_PLAN_AMOUNT} ${RAZORPAY_CURRENCY}
API Secret         : ${API_SECRET}
Tor Control Pass   : ${TOR_PASS}
Server Public Key  : ${SERVER_PUB}
Client Private Key : ${CLIENT_PRIV}
Client Config File : /root/phantom-client.conf
================================================
IMPORTANT: Save these credentials securely!
================================================
EOF

chmod 600 /root/phantom-credentials.txt

# Start all services
systemctl start phantom-monitor phantom-rotate

echo ""
ok "============================================"
ok " PHANTOM VPN DEPLOYMENT COMPLETE!"
ok "============================================"
echo ""
cat /root/phantom-credentials.txt
echo ""
log "Client config saved to: /root/phantom-client.conf"
log "Scan the QR code above with WireGuard mobile app"
log "Admin login: use ${ADMIN_USER} with the current authenticator code"
log "Dashboard API: http://${SERVER_IP}:${MONITOR_PORT}"
log "VPN page: http://${SERVER_IP}:${MONITOR_PORT}/vpn"
log "User profile: http://${SERVER_IP}:${MONITOR_PORT}/profile"
log "User admin: http://${SERVER_IP}:${MONITOR_PORT}/admin"
log "Docs page: http://${SERVER_IP}:${MONITOR_PORT}/docs"
log "Routing page: http://${SERVER_IP}:${MONITOR_PORT}/routing"
log ""
warn "Open dashboard: sign in with ${ADMIN_USER} and your authenticator code at http://${SERVER_IP}:${MONITOR_PORT}/dashboard"
warn "Chrome Extension: Open extension Config tab and set Server URL to: http://${SERVER_IP}:${MONITOR_PORT}"

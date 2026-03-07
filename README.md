# PHANTOM VPN — Complete Privacy Stack

## Files in this package

| File | Purpose |
|------|---------|
| `1-deploy.sh` | DigitalOcean one-click deployment script |
| `2-monitoring-server.js` | Node.js real-time monitoring API |
| `3-dashboard.html` | Live web dashboard (open in browser) |
| `chrome-extension/` | Chrome browser extension folder |

## Quick Start

### 1. Deploy to DigitalOcean
```bash
# Create a Ubuntu 22.04 droplet, SSH in as root, then:
scp 1-deploy.sh 2-monitoring-server.js root@YOUR_DROPLET_IP:/root/
ssh root@YOUR_DROPLET_IP "bash /root/1-deploy.sh"
```

### 2. Open Dashboard
- Open `3-dashboard.html` in your browser
- Enter your droplet IP: `http://YOUR_IP:7777`
- Use credentials shown at end of deployment

### 3. Install Chrome Extension
1. Open Chrome → `chrome://extensions/`
2. Enable **Developer Mode** (top right)
3. Click **Load unpacked**
4. Select the `chrome-extension/` folder
5. Click the PHANTOM icon → Config tab → enter your server URL

### 4. Connect WireGuard
- Download WireGuard app on any device
- Import `/root/phantom-client.conf` from your droplet
- Or scan the QR code shown during deployment

## Architecture
```
Your Device (WireGuard) → DigitalOcean VPN Server → Tor Network → Internet
                              ↓
                      Unbound DNS (Ad Blocking)
                      Fail2Ban (Attack Protection)
                      Node.js API (Real-time Monitoring)
                              ↓
                      Chrome Extension (Browser Shield)
```

## What's Real (Not Demo)
- ✅ WireGuard VPN tunnel (real encryption)
- ✅ Tor onion routing (real 3-layer anonymity)
- ✅ IP rotation every 30s via `SIGNAL NEWNYM`
- ✅ Unbound DNS with Steven Black ad blocklist
- ✅ Fail2Ban banning attack IPs automatically
- ✅ Real-time monitoring API (Node.js WebSocket)
- ✅ Chrome extension blocks 30+ ad/tracker networks
- ✅ Content script detects XSS, clickjacking, mining
- ✅ WebRTC leak prevention (real IP protection)

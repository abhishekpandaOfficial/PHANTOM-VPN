# PHANTOM VPN — Complete Privacy Stack

## Files in this package

| File | Purpose |
|------|---------|
| `1-deploy.sh` | DigitalOcean one-click deployment script |
| `2-monitoring-server.js` | Node.js real-time monitoring API |
| `3-dashboard.html` | Live web dashboard (open in browser) |
| `5-landing.html` | Public onboarding page with 1-hour free trial + payment submission |
| `6-admin.html` | Admin login, QR/TOTP setup, user provisioning, payment approval |
| `7-user-dashboard.html` | End-user profile page with live access state, QR import, and payment actions |
| `8-routing.html` | Public routing explanation page |
| `9-docs.html` | First-time onboarding docs with dummy user walkthrough |
| `chrome-extension/` | Chrome browser extension folder |

## Quick Start

### 1. Deploy to DigitalOcean
```bash
# Create a Ubuntu 22.04 droplet, SSH in as root, then:
scp 1-deploy.sh 2-monitoring-server.js 3-dashboard.html 5-landing.html 6-admin.html 7-user-dashboard.html 8-routing.html 9-docs.html root@YOUR_DROPLET_IP:/root/
ssh root@YOUR_DROPLET_IP "bash /root/1-deploy.sh"
```

### 2. Admin Login
- Open `http://YOUR_IP:7777/dashboard` or `http://YOUR_IP:7777/admin`
- Sign in with `hello@abhishekpanda.com`
- Use the current 6-digit authenticator code as the rotating password
- Scan the admin QR shown at deployment if you have not paired your authenticator yet

### 3. Public Trial + Payment Flow
- Share `http://YOUR_IP:7777/vpn`
- Anyone can claim one free 1-hour WireGuard profile with their email
- After signup, users import the WireGuard QR or `.conf`, then open their personal profile page at `/profile`
- After 1 hour, unpaid users are suspended automatically
- Users can submit a payment reference from the profile page
- Approve payment from the admin page to reactivate the same config
- Share `http://YOUR_IP:7777/docs` for the full first-time setup guide
- Share `http://YOUR_IP:7777/routing` for the public routing explanation page

### 4. Direct Admin Provisioning
- Open `http://YOUR_IP:7777/admin`
- Create direct paid users or extra trial users
- Download generated `.conf`
- Revoke instantly if needed

### 5. Install Chrome Extension
1. Open Chrome → `chrome://extensions/`
2. Enable **Developer Mode** (top right)
3. Click **Load unpacked**
4. Select the `chrome-extension/` folder
5. Click the PHANTOM icon → Config tab → enter your server URL

### 6. Connect WireGuard
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
- ✅ Public 1-hour free trial provisioning
- ✅ Automatic unpaid trial suspension
- ✅ Admin payment approval / reactivation flow
- ✅ Rotating admin login via authenticator QR / TOTP
- ✅ Chrome extension blocks 30+ ad/tracker networks
- ✅ Content script detects XSS, clickjacking, mining
- ✅ WebRTC leak prevention (real IP protection)

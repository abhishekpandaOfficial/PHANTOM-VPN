#!/usr/bin/env bash
set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

FAILS=0
WARNS=0
STEP=0
STOP_EARLY=0

VPS_IP=""
SSH_USER="root"
DASH_USER="phantom"
DASH_PASS="${DASH_PASS:-}"
SKIP_DEPLOY=0
NO_WAIT=0
ARTIFACT_BASE="./artifacts"

usage() {
  cat <<'USAGE'
Usage:
  bash 4-step-by-step-check.sh --vps <DROPLET_IP> [options]

Options:
  --vps <ip>             Droplet public IP (required)
  --user <name>          SSH user (default: root)
  --dash-user <name>     Dashboard username (default: phantom)
  --dash-pass <pass>     Dashboard password (auto-read from credentials if omitted)
  --skip-deploy          Skip file copy + deploy step
  --no-wait              Do not pause for manual WireGuard connect
  --artifact-dir <dir>   Local output directory (default: ./artifacts)
  -h, --help             Show this help

Example:
  bash 4-step-by-step-check.sh --vps 203.0.113.10
USAGE
}

info() { echo -e "${CYAN}[INFO]${NC} $*"; }
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; WARNS=$((WARNS + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $*"; FAILS=$((FAILS + 1)); }

step() {
  STEP=$((STEP + 1))
  echo
  echo -e "${CYAN}========== Step ${STEP}: $* ==========${NC}"
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "Missing command: $1"
  fi
}

trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

run_ssh() {
  local target="$1"
  shift
  ssh -o StrictHostKeyChecking=accept-new "$target" "$@"
}

is_password_expired_output() {
  local f="$1"
  grep -qiE 'change your password immediately|password has expired|password change required' "$f"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vps)
      VPS_IP="${2:-}"
      shift 2
      ;;
    --user)
      SSH_USER="${2:-}"
      shift 2
      ;;
    --dash-user)
      DASH_USER="${2:-}"
      shift 2
      ;;
    --dash-pass)
      DASH_PASS="${2:-}"
      shift 2
      ;;
    --skip-deploy)
      SKIP_DEPLOY=1
      shift
      ;;
    --no-wait)
      NO_WAIT=1
      shift
      ;;
    --artifact-dir)
      ARTIFACT_BASE="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$VPS_IP" ]]; then
  usage
  exit 1
fi

TARGET="${SSH_USER}@${VPS_IP}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${ARTIFACT_BASE}/${VPS_IP}-${RUN_ID}"
mkdir -p "$OUT_DIR"

step "Preflight checks"
need_cmd ssh
need_cmd scp
need_cmd curl
if command -v jq >/dev/null 2>&1; then
  pass "jq is available."
else
  warn "jq not found. Raw JSON output will be shown."
fi
if command -v dig >/dev/null 2>&1; then
  pass "dig is available."
else
  warn "dig not found. DNS leak test will be skipped."
fi
if (( FAILS > 0 )); then
  echo
  fail "Preflight failed. Install missing tools and run again."
  exit 1
fi

step "Copy files and deploy on droplet"
if (( SKIP_DEPLOY == 1 )); then
  warn "Skipping deploy because --skip-deploy was provided."
else
  SCP_LOG="$OUT_DIR/scp.log"
  if scp 1-deploy.sh 2-monitoring-server.js 3-dashboard.html 5-landing.html 6-admin.html 7-user-dashboard.html 8-routing.html 9-docs.html "$TARGET:/root/" >"$SCP_LOG" 2>&1; then
    pass "Deployment files copied."
  else
    if is_password_expired_output "$SCP_LOG"; then
      fail "SCP failed because remote password is expired. Run once: ssh -t ${TARGET} 'passwd'"
      STOP_EARLY=1
    else
      fail "SCP failed. Check IP/SSH access."
    fi
  fi

  DEPLOY_LOG="$OUT_DIR/deploy.log"
  if run_ssh "$TARGET" "bash /root/1-deploy.sh" >"$DEPLOY_LOG" 2>&1; then
    pass "Deploy script finished."
  else
    if is_password_expired_output "$DEPLOY_LOG"; then
      fail "Deploy blocked because remote password is expired. Run once: ssh -t ${TARGET} 'passwd'"
      STOP_EARLY=1
    else
      fail "Deploy script returned non-zero. Review $DEPLOY_LOG"
    fi
  fi
fi

if (( STOP_EARLY == 1 )); then
  echo
  warn "Stopping early to avoid misleading checks."
  info "Fix first: ssh -t ${TARGET} 'passwd'"
  info "Then rerun: bash 4-step-by-step-check.sh --vps ${VPS_IP}"
  exit 2
fi

step "Fetch generated credentials"
CREDS_FILE="$OUT_DIR/phantom-credentials.txt"
if run_ssh "$TARGET" "cat /root/phantom-credentials.txt" >"$CREDS_FILE" 2>/dev/null; then
  pass "Saved credentials to $CREDS_FILE"
else
  fail "Could not read /root/phantom-credentials.txt from droplet."
fi

if [[ -z "$DASH_PASS" ]] && [[ -f "$CREDS_FILE" ]]; then
  DASH_PASS="$(trim "$(awk -F': ' '/Dashboard Password/{print $2}' "$CREDS_FILE" | head -n1)")"
  if [[ -n "$DASH_PASS" ]]; then
    pass "Dashboard password parsed from credentials file."
  else
    warn "Could not parse Dashboard Password automatically."
  fi
fi

step "Check core services on droplet"
SERVICE_FILE="$OUT_DIR/service-status.txt"
if run_ssh "$TARGET" "for s in wg-quick@wg0 tor unbound fail2ban phantom-monitor phantom-rotate; do echo \"\$s=\$(systemctl is-active \"\$s\" 2>/dev/null || true)\"; done" >"$SERVICE_FILE"; then
  while IFS='=' read -r svc status; do
    if [[ "$status" == "active" ]]; then
      pass "$svc is active"
    else
      fail "$svc is $status"
    fi
  done <"$SERVICE_FILE"
else
  fail "Could not query service status."
fi

WG_FILE="$OUT_DIR/wg-show.txt"
if run_ssh "$TARGET" "wg show wg0" >"$WG_FILE" 2>/dev/null; then
  pass "Saved WireGuard details to $WG_FILE"
else
  warn "Could not read wg show wg0 output."
fi

step "Monitoring API checks"
HEALTH_RAW="$(curl -fsS "http://${VPS_IP}:7777/health" 2>/dev/null || true)"
if [[ -n "$HEALTH_RAW" ]]; then
  pass "/health responded."
  if command -v jq >/dev/null 2>&1; then
    echo "$HEALTH_RAW" | jq .
  else
    echo "$HEALTH_RAW"
  fi
else
  fail "Health endpoint failed: http://${VPS_IP}:7777/health"
fi

if [[ -n "$DASH_PASS" ]]; then
  STATUS_RAW="$(curl -fsS -u "${DASH_USER}:${DASH_PASS}" "http://${VPS_IP}:7777/api/status" 2>/dev/null || true)"
  if [[ -n "$STATUS_RAW" ]]; then
    pass "/api/status responded with auth."
    printf '%s\n' "$STATUS_RAW" >"$OUT_DIR/api-status.json"
    if command -v jq >/dev/null 2>&1; then
      echo "$STATUS_RAW" | jq '{ip, vpn: .vpn.connected, peers: (.peers|length), dns: .dns, tor: .tor}'
    else
      echo "$STATUS_RAW"
    fi
  else
    fail "/api/status failed (check dashboard user/pass)."
  fi
else
  warn "Skipping authenticated API test because dashboard password is unknown."
fi

step "Public IP test (before and after WireGuard connect)"
BEFORE_IP="$(curl -4fsS ifconfig.me 2>/dev/null || true)"
if [[ -n "$BEFORE_IP" ]]; then
  pass "Current public IP (before VPN): $BEFORE_IP"
else
  warn "Could not fetch current public IP before VPN."
fi

CLIENT_CFG="$OUT_DIR/phantom-client.conf"
if scp "$TARGET:/root/phantom-client.conf" "$CLIENT_CFG" >/dev/null 2>&1; then
  pass "Client config downloaded to $CLIENT_CFG"
else
  warn "Could not download /root/phantom-client.conf"
fi

if (( NO_WAIT == 0 )); then
  echo
  if [[ -f "$CLIENT_CFG" ]]; then
    info "Import $CLIENT_CFG into WireGuard app and connect."
  else
    info "Connect WireGuard using your existing profile, then continue."
  fi
  read -r -p "Press Enter after VPN is connected..."
else
  warn "Skipping wait for manual VPN connect because --no-wait was provided."
fi

AFTER_IP="$(curl -4fsS ifconfig.me 2>/dev/null || true)"
if [[ -n "$AFTER_IP" ]]; then
  pass "Current public IP (after VPN step): $AFTER_IP"
  if [[ -n "$BEFORE_IP" ]]; then
    if (( NO_WAIT == 1 )); then
      warn "No-wait mode: skipping strict IP-change assertion."
    elif [[ "$BEFORE_IP" == "$VPS_IP" ]]; then
      warn "Client already appears on VPN before this step (before IP equals VPS IP)."
    elif [[ "$AFTER_IP" != "$BEFORE_IP" ]]; then
      pass "Public IP changed after VPN connect."
    else
      fail "Public IP did not change."
    fi
  fi
else
  warn "Could not fetch current public IP after VPN connect."
fi

step "DNS test via VPN DNS"
if command -v dig >/dev/null 2>&1; then
  DNS_RESULT_UDP="$(dig +short +time=3 +tries=1 @10.8.0.1 example.com 2>/dev/null | grep -E '^[0-9A-Fa-f:.]+$' | head -n1 || true)"
  DNS_RESULT_TCP="$(dig +tcp +short +time=3 +tries=1 @10.8.0.1 example.com 2>/dev/null | grep -E '^[0-9A-Fa-f:.]+$' | head -n1 || true)"
  if [[ -n "$DNS_RESULT_UDP" ]]; then
    pass "DNS query via 10.8.0.1 succeeded (UDP): $DNS_RESULT_UDP"
  elif [[ -n "$DNS_RESULT_TCP" ]]; then
    pass "DNS query via 10.8.0.1 succeeded (TCP): $DNS_RESULT_TCP"
  else
    fail "DNS query via 10.8.0.1 failed."
    DIG_DEBUG="$(dig +time=2 +tries=1 @10.8.0.1 example.com 2>&1 | tail -n 3 | tr '\n' ' ')"
    warn "DNS debug: ${DIG_DEBUG}"
  fi
else
  warn "Skipping DNS test because dig is unavailable."
fi

step "Trigger IP rotation and verify Tor exit behavior"
if [[ -n "$DASH_PASS" ]]; then
  ROTATE_RAW="$(curl -fsS -u "${DASH_USER}:${DASH_PASS}" -X POST "http://${VPS_IP}:7777/api/rotate" 2>/dev/null || true)"
  if [[ -n "$ROTATE_RAW" ]]; then
    pass "Rotation endpoint responded."
    printf '%s\n' "$ROTATE_RAW" >"$OUT_DIR/api-rotate.json"
    if command -v jq >/dev/null 2>&1; then
      echo "$ROTATE_RAW" | jq .
    else
      echo "$ROTATE_RAW"
    fi
  else
    warn "Rotation endpoint failed."
  fi
else
  warn "Skipping rotation API call because dashboard password is unknown."
fi

DIRECT_IP="$(
  run_ssh "$TARGET" "curl -4fsS --max-time 10 api.ipify.org 2>/dev/null || curl -4fsS --max-time 10 ifconfig.me 2>/dev/null" 2>/dev/null || true
)"
TOR_IP="$(
  run_ssh "$TARGET" "curl -4fsS --socks5 127.0.0.1:9050 --max-time 12 api.ipify.org 2>/dev/null || curl -4fsS --socks5 127.0.0.1:9050 --max-time 12 ifconfig.me 2>/dev/null" 2>/dev/null || true
)"
if [[ -n "$DIRECT_IP" ]]; then
  pass "Server direct egress IP: $DIRECT_IP"
else
  warn "Could not fetch server direct egress IP."
fi
if [[ -n "$TOR_IP" ]]; then
  pass "Server Tor egress IP: $TOR_IP"
else
  warn "Could not fetch server Tor egress IP."
fi

if [[ -n "$AFTER_IP" && -n "$DIRECT_IP" ]]; then
  if [[ "$AFTER_IP" == "$DIRECT_IP" ]]; then
    warn "Client VPN egress matches server direct IP (VPN appears not Tor-routed)."
  fi
fi

echo
echo -e "${CYAN}========== Summary ==========${NC}"
echo "Artifacts: $OUT_DIR"
echo "Warnings:  $WARNS"
echo "Failures:  $FAILS"

if (( FAILS > 0 )); then
  exit 1
fi
exit 0

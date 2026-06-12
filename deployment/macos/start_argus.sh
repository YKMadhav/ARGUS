#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p logs

INTERFACE="${ARGUS_INTERFACE:-en0}"
LOCAL_IP="$(ipconfig getifaddr "$INTERFACE")"
if [[ -z "$LOCAL_IP" ]]; then
  echo "Could not detect an IPv4 address for interface $INTERFACE"
  exit 1
fi

DEFAULT_NETWORK="$(python3 -c "import ipaddress; print(ipaddress.ip_network('$LOCAL_IP/24', strict=False))")"
export ARGUS_INTERFACE="$INTERFACE"
export ARGUS_NETWORK_CIDR="${ARGUS_NETWORK_CIDR:-$DEFAULT_NETWORK}"
export ARGUS_BLOCK_MODE="${ARGUS_BLOCK_MODE:-auto}"

BETTERCAP_PID=""
ARGUS_PID=""
DASHBOARD_PID=""

cleanup() {
  echo ""
  echo "Shutting down ARGUS..."
  [[ -n "$BETTERCAP_PID" ]] && sudo kill "$BETTERCAP_PID" 2>/dev/null || true
  [[ -n "$ARGUS_PID" ]] && sudo kill "$ARGUS_PID" 2>/dev/null || true
  [[ -n "$DASHBOARD_PID" ]] && kill "$DASHBOARD_PID" 2>/dev/null || true
  sudo pfctl -F all 2>/dev/null || true
  echo "Stopped. Firewall cleared."
}
trap cleanup INT TERM EXIT

echo "Starting ARGUS"
echo ""
echo "Interface      : $ARGUS_INTERFACE"
echo "Local IP       : $LOCAL_IP"
echo "Network        : $ARGUS_NETWORK_CIDR"
echo "Block mode     : $ARGUS_BLOCK_MODE"
echo ""

echo "Clearing old firewall rules..."
sudo pfctl -F all 2>/dev/null || true

echo "Starting Bettercap ARP spoof for the protected lab network..."
sudo bettercap -iface "$ARGUS_INTERFACE" \
  -eval "events.ignore sys.log; set arp.spoof.targets $ARGUS_NETWORK_CIDR; set arp.spoof.internal true; set arp.spoof.fullduplex true; net.probe on; arp.spoof on" \
  >> ./logs/bettercap.log 2>&1 &
BETTERCAP_PID=$!
echo "Bettercap PID: $BETTERCAP_PID"

echo "Waiting for ARP spoofing to settle..."
sleep 8

if ! kill -0 "$BETTERCAP_PID" 2>/dev/null; then
  echo "Bettercap exited early. Check ./logs/bettercap.log"
  tail -n 80 ./logs/bettercap.log || true
  exit 1
fi

echo "Starting ARGUS detection engine..."
sudo -E venv/bin/python -u live_detect.py >> ./logs/argus.log 2>&1 &
ARGUS_PID=$!
echo "ARGUS PID: $ARGUS_PID"

echo "Starting dashboard..."
source venv/bin/activate
streamlit run dashboard.py &
DASHBOARD_PID=$!
echo "Dashboard PID: $DASHBOARD_PID"

echo ""
echo "ARGUS is live"
echo "Dashboard     : http://localhost:8501"
echo "ARGUS log     : ./logs/argus.log"
echo "Bettercap log : ./logs/bettercap.log"
echo "Alerts log    : ./logs/alerts.json"
echo ""
echo "Press Ctrl+C to stop."

wait

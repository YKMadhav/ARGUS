import time
import joblib
import numpy as np
import pandas as pd
import subprocess
import json
import os
import ipaddress
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, get_if_addr
from datetime import datetime

# ── Load model ────────────────────────────────────────────────
print("🔄 Loading model...")
model    = joblib.load('./models/isolation_forest.pkl')
scaler   = joblib.load('./models/scaler.pkl')
FEATURES = joblib.load('./models/features.pkl')
print("✅ Model loaded")

# ── Config ────────────────────────────────────────────────────
INTERFACE         = os.getenv("ARGUS_INTERFACE", "en0")
WINDOW_SECONDS    = float(os.getenv("ARGUS_WINDOW_SECONDS", "2.0"))
BLOCK_THRESHOLD   = float(os.getenv("ARGUS_BLOCK_THRESHOLD", "0.03"))
SUSTAINED_WINDOWS = int(os.getenv("ARGUS_SUSTAINED_WINDOWS", "4"))
MIN_PACKETS       = int(os.getenv("ARGUS_MIN_PACKETS", "50"))
MIN_SCAN_PORTS    = int(os.getenv("ARGUS_MIN_SCAN_PORTS", "20"))
MIN_SCAN_SYNS     = int(os.getenv("ARGUS_MIN_SCAN_SYNS", "15"))
MIN_SCAN_TARGETS  = int(os.getenv("ARGUS_MIN_SCAN_TARGETS", "8"))
MIN_TARGET_PORTS  = int(os.getenv("ARGUS_MIN_TARGET_PORTS", "8"))
MODEL_ALERT_STREAK = 6
BLOCKED_IPS       = set()
LOG_FILE          = "./logs/alerts.json"
BLOCK_MODE        = os.getenv("ARGUS_BLOCK_MODE", "auto").lower()

os.makedirs('./logs', exist_ok=True)

# ── Auto-detect network parameters ───────────────────────────
MY_IP = get_if_addr(INTERFACE)
NETWORK_CIDR = os.getenv(
    "ARGUS_NETWORK_CIDR",
    ".".join(MY_IP.split(".")[:3]) + ".0/24"
)
LOCAL_NETWORK = ipaddress.ip_network(NETWORK_CIDR, strict=False)
ROUTER_IP = os.getenv("ARGUS_ROUTER_IP", str(next(LOCAL_NETWORK.hosts(), MY_IP)))
PROTECTED_IPS = {
    MY_IP,
    ROUTER_IP,
    *[ip.strip() for ip in os.getenv("ARGUS_PROTECTED_IPS", "").split(",") if ip.strip()]
}

print(f"🖥️  My IP      : {MY_IP}")
print(f"🌐  My Network : {LOCAL_NETWORK}")
print(f"🔀  Router     : {ROUTER_IP}")

# ── Trackers ──────────────────────────────────────────────────
ip_tracker = defaultdict(lambda: {
    'start_time'   : None,
    'packet_count' : 0,
    'src_bytes'    : 0,
    'dst_bytes'    : 0,
    'syn_count'    : 0,
    'ack_count'    : 0,
    'rst_count'    : 0,
    'ports_hit'    : set(),
    'tcp_ports_hit': set(),
    'udp_ports_hit': set(),
    'local_targets': set(),
    'syn_targets'  : defaultdict(set),
    'tcp_targets'  : defaultdict(set),
    'udp_targets'  : defaultdict(set),
    'last_seen'    : None
})

anomaly_streak = defaultdict(int)

def new_tracker():
    return {
        'start_time'   : None,
        'packet_count' : 0,
        'src_bytes'    : 0,
        'dst_bytes'    : 0,
        'syn_count'    : 0,
        'ack_count'    : 0,
        'rst_count'    : 0,
        'ports_hit'    : set(),
        'tcp_ports_hit': set(),
        'udp_ports_hit': set(),
        'local_targets': set(),
        'syn_targets'  : defaultdict(set),
        'tcp_targets'  : defaultdict(set),
        'udp_targets'  : defaultdict(set),
        'last_seen'    : None
    }

def reset_tracker(ip):
    ip_tracker[ip] = new_tracker()

def is_local_ip(ip):
    try:
        return ipaddress.ip_address(ip) in LOCAL_NETWORK
    except ValueError:
        return False

# ── OS Fingerprint ────────────────────────────────────────────
def guess_os(pkt):
    if IP in pkt:
        ttl = pkt[IP].ttl
        if ttl <= 64:  return "Linux/Android"
        if ttl <= 128: return "Windows"
        if ttl <= 255: return "macOS/iOS"
    return "Unknown"

# ── Normal traffic filter ─────────────────────────────────────
def is_normal_traffic(data):
    """
    Returns True if traffic looks like normal device usage.
    YouTube/browsing = high bytes, few ports, low SYN ratio.
    Real attacks = high SYN ratio, many ports, RST packets.
    """
    port_count = len(data['ports_hit'])
    tcp_port_count = len(data['tcp_ports_hit'])
    target_count = len(data['local_targets'])
    syn_ratio  = data['syn_count'] / max(data['packet_count'], 1)
    rst_ratio  = data['rst_count'] / max(data['packet_count'], 1)

    if (data['syn_count'] >= MIN_SCAN_SYNS or
            tcp_port_count >= MIN_SCAN_PORTS or
            target_count >= MIN_SCAN_TARGETS):
        return False

    if rst_ratio > 0.1 and data['rst_count'] >= 10:
        return False

    # Normal streaming/browsing pattern
    if port_count <= 8 and syn_ratio < 0.25:
        return True

    # Normal browsing with moderate traffic
    if data['packet_count'] < 300 and syn_ratio < 0.25:
        return True

    # Video/app traffic can be very packet-heavy, but it should not touch
    # many destination ports or spray SYNs like a scanner.
    if tcp_port_count <= 8 and syn_ratio < 0.15 and rst_ratio < 0.05:
        return True

    return False

# ── Attack Classifier ─────────────────────────────────────────
def classify_attack(packet_count, syn_count, rst_count,
                    ports_hit, src_bytes, tcp_ports_hit=None, local_targets=None):
    tcp_ports_hit = tcp_ports_hit or ports_hit
    local_targets = local_targets or set()
    port_count = len(tcp_ports_hit)
    target_count = len(local_targets)
    syn_ratio  = syn_count / max(packet_count, 1)

    if target_count >= MIN_SCAN_TARGETS and port_count >= MIN_TARGET_PORTS:
        return "Network Port Sweep"

    if target_count >= MIN_SCAN_TARGETS:
        return "Network Host Sweep"

    # nmap -sS: sends SYN, gets SYN-ACK, sends RST
    # High SYN + RST ratio = classic SYN scan signature
    if syn_count >= MIN_SCAN_SYNS and port_count >= MIN_SCAN_PORTS:
        return "Port Scan (nmap style)"

    # Many unique ports hit
    if port_count >= MIN_SCAN_PORTS:
        return "Port Scan (nmap style)"

    # Pure SYN flood
    if syn_ratio > 0.85 and packet_count > 150:
        return "SYN Flood / DoS"

    # High packet rate on single port
    if packet_count > 300 and port_count <= 3 and syn_ratio > 0.35:
        return "Brute Force Attempt"

    return "Anomalous Traffic"

# ── Explicit attack signature check ───────────────────────────
def is_explicit_attack(data):
    """
    Rule-based detection that works even if model misses it.
    These are unmistakable attack signatures.
    """
    tcp_port_count = len(data['tcp_ports_hit'])
    udp_port_count = len(data['udp_ports_hit'])
    syn_ratio  = data['syn_count'] / max(data['packet_count'], 1)
    rst_ratio  = data['rst_count'] / max(data['packet_count'], 1)
    max_ports_to_one_target = max(
        (len(ports) for ports in data['syn_targets'].values()),
        default=0
    )
    max_tcp_ports_to_one_target = max(
        (len(ports) for ports in data['tcp_targets'].values()),
        default=0
    )
    target_count = len(data['local_targets'])

    # Classic nmap scan: one source probes many TCP ports, often on one LAN host.
    if data['syn_count'] >= MIN_SCAN_SYNS and max_ports_to_one_target >= MIN_SCAN_PORTS:
        return True

    if data['syn_count'] >= MIN_SCAN_SYNS and tcp_port_count >= MIN_SCAN_PORTS:
        return True

    # TCP connect scans can produce many RSTs without a very high SYN ratio.
    if tcp_port_count >= MIN_SCAN_PORTS and data['rst_count'] >= 10 and rst_ratio > 0.05:
        return True

    # Whole-subnet scans may touch many internal targets before hitting a large
    # port count on any single host.
    if target_count >= MIN_SCAN_TARGETS and data['syn_count'] >= MIN_SCAN_SYNS:
        return True

    if target_count >= MIN_SCAN_TARGETS and tcp_port_count >= MIN_TARGET_PORTS:
        return True

    if max_tcp_ports_to_one_target >= MIN_SCAN_PORTS:
        return True

    # UDP scans are still scans, but ordinary QUIC/video traffic should stay
    # around a tiny set of service ports like 443.
    if udp_port_count >= 40 and len(data['local_targets']) > 0:
        return True

    # SYN flood
    if syn_ratio > 0.85 and data['packet_count'] > 150 and data['syn_count'] >= MIN_SCAN_SYNS:
        return True

    return False

# ── Firewall Block ────────────────────────────────────────────
def block_ip(ip):
    if ip in PROTECTED_IPS:
        print(f"🛡️  Refusing to block protected IP: {ip}")
        return False
    if ip in BLOCKED_IPS:
        return True
    if BLOCK_MODE in {"off", "monitor", "dry-run", "dryrun"}:
        print(f"🟡 Block mode is {BLOCK_MODE}; would block {ip}")
        return False

    BLOCKED_IPS.add(ip)
    try:
        rules = "".join(
            f"block drop quick from {blocked_ip} to any\n"
            f"block drop quick from any to {blocked_ip}\n"
            for blocked_ip in sorted(BLOCKED_IPS)
        )
        result = subprocess.run(
            ["sudo", "pfctl", "-ef", "-"],
            input=rules,
            text=True,
            capture_output=True
        )
        if result.returncode == 0:
            print(f"🔒 BLOCKED: {ip}")
            return True
        print(f"⚠️  pfctl did not block {ip}: {(result.stderr or '').strip()}")
    except Exception as e:
        print(f"⚠️  Could not block {ip}: {e}")
    BLOCKED_IPS.discard(ip)
    return False

# ── Alert Logger ──────────────────────────────────────────────
def log_alert(alert_data):
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            try:    logs = json.load(f)
            except: logs = []
    logs.append(alert_data)
    with open(LOG_FILE, 'w') as f:
        json.dump(logs, f, indent=2)

# ── Core Detection ────────────────────────────────────────────
def analyse_ip(src_ip, duration, pkt):
    data = ip_tracker[src_ip]

    # Not enough packets to analyse
    if data['packet_count'] < MIN_PACKETS:
        return

    explicit = is_explicit_attack(data)

    # Check normal traffic patterns before consulting the model. The live model
    # is a weak signal here; packet signatures are the source of truth for blocks.
    if is_normal_traffic(data):
        if anomaly_streak[src_ip] > 0:
            print(f"✅ {src_ip} — normal pattern, "
                  f"streak reset from {anomaly_streak[src_ip]}")
        anomaly_streak[src_ip] = 0
        return

    # Run model
    feature_vector = pd.DataFrame([{
        "duration": duration,
        "src_bytes": data['src_bytes'],
        "dst_bytes": data['dst_bytes'],
        "count": data['packet_count'],
    }], columns=FEATURES)

    scaled     = scaler.transform(feature_vector)
    prediction = model.predict(scaled)[0]
    score      = model.decision_function(scaled)[0]

    # Combine model + explicit rules
    is_anomalous = (
        (prediction == -1 and score < BLOCK_THRESHOLD) or
        explicit
    )

    if is_anomalous:
        anomaly_streak[src_ip] += 1

        port_count = len(data['ports_hit'])
        syn_ratio  = data['syn_count'] / max(data['packet_count'], 1)
        rst_ratio  = data['rst_count'] / max(data['packet_count'], 1)

        model_only = not explicit
        needed_streak = MODEL_ALERT_STREAK if model_only else SUSTAINED_WINDOWS

        print(f"⚠️  [{src_ip}] suspicious — "
              f"streak {anomaly_streak[src_ip]}/{needed_streak} | "
              f"pkts={data['packet_count']} "
              f"syn={data['syn_count']} "
              f"rst={data['rst_count']} "
              f"ports={port_count} "
              f"syn_ratio={syn_ratio:.2f} "
              f"rst_ratio={rst_ratio:.2f} "
              f"explicit={explicit}")

        if explicit or anomaly_streak[src_ip] >= MODEL_ALERT_STREAK:

            attack_type = classify_attack(
                data['packet_count'],
                data['syn_count'],
                data['rst_count'],
                data['ports_hit'],
                data['src_bytes'],
                data['tcp_ports_hit'],
                data['local_targets']
            )

            os_guess  = guess_os(pkt)
            timestamp = datetime.now().strftime("%H:%M:%S")

            alert = {
                "timestamp"    : timestamp,
                "ip"           : src_ip,
                "attack_type"  : attack_type,
                "packets"      : data['packet_count'],
                "src_bytes"    : data['src_bytes'],
                "ports_hit"    : len(data['tcp_ports_hit'] or data['ports_hit']),
                "targets_hit"  : len(data['local_targets']),
                "anomaly_score": round(abs(score), 4),
                "os_guess"     : os_guess,
                "threat_level" : "CRITICAL" if explicit else "HIGH",
                "streak"       : anomaly_streak[src_ip],
                "blocked"      : False
            }

            print(f"\n{'='*55}")
            print(f"🚨 ATTACK DETECTED at {timestamp}")
            print(f"   IP          : {src_ip}")
            print(f"   Attack Type : {attack_type}")
            print(f"   OS Guess    : {os_guess}")
            print(f"   Packets     : {data['packet_count']}")
            print(f"   SYN count   : {data['syn_count']}")
            print(f"   RST count   : {data['rst_count']}")
            print(f"   Ports hit   : {len(data['ports_hit'])}")
            print(f"   Targets hit : {len(data['local_targets'])}")
            print(f"   Score       : {abs(score):.4f}")
            print(f"   Explicit    : {explicit}")
            print(f"   Threat      : {alert['threat_level']}")
            print(f"{'='*55}\n")

            if explicit:
                alert["blocked"] = block_ip(src_ip)
            else:
                print(f"🟡 Model-only anomaly logged, not blocked: {src_ip}")
            log_alert(alert)
            anomaly_streak[src_ip] = 0

            try:
                from telegram_bot import send_alert
                send_alert(alert)
            except:
                pass

    else:
        if anomaly_streak[src_ip] > 0:
            print(f"✅ {src_ip} back to normal "
                  f"(streak reset from {anomaly_streak[src_ip]})")
        anomaly_streak[src_ip] = 0

# ── Packet Handler ────────────────────────────────────────────
def handle_packet(pkt):
    if IP not in pkt:
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    now    = time.time()

    # If ARGUS sees only scan responses, the victim is src_ip and the attacker
    # is dst_ip. For TCP RST/SYN-ACK replies, the scanned port is sport.
    if TCP in pkt and is_local_ip(src_ip) and is_local_ip(dst_ip):
        flags = pkt[TCP].flags
        is_scan_reply = bool(flags & 0x04) or bool((flags & 0x12) == 0x12)
        if is_scan_reply and dst_ip not in PROTECTED_IPS and src_ip != ROUTER_IP:
            if ip_tracker[dst_ip]['start_time'] is None:
                ip_tracker[dst_ip]['start_time'] = now

            ip_tracker[dst_ip]['packet_count'] += 1
            ip_tracker[dst_ip]['src_bytes']    += len(pkt)
            ip_tracker[dst_ip]['dst_bytes']    += pkt[IP].len
            ip_tracker[dst_ip]['last_seen']     = now
            ip_tracker[dst_ip]['ports_hit'].add(pkt[TCP].sport)
            ip_tracker[dst_ip]['tcp_ports_hit'].add(pkt[TCP].sport)
            ip_tracker[dst_ip]['local_targets'].add(src_ip)
            ip_tracker[dst_ip]['tcp_targets'][src_ip].add(pkt[TCP].sport)
            if flags & 0x04:
                ip_tracker[dst_ip]['rst_count'] += 1
            if flags & 0x12 == 0x12:
                ip_tracker[dst_ip]['syn_count'] += 1
                ip_tracker[dst_ip]['syn_targets'][src_ip].add(pkt[TCP].sport)

            duration = now - ip_tracker[dst_ip]['start_time']
            if duration >= WINDOW_SECONDS:
                analyse_ip(dst_ip, duration, pkt)
                reset_tracker(dst_ip)

    # Skip blocked IPs
    if src_ip in BLOCKED_IPS:
        return

    # Skip own Mac
    if src_ip == MY_IP:
        return

    # Only watch local network (auto-detected)
    if not is_local_ip(src_ip):
        return

    # Skip router
    if src_ip == ROUTER_IP:
        return

    # Init tracker
    if ip_tracker[src_ip]['start_time'] is None:
        ip_tracker[src_ip]['start_time'] = now

    # Update counters
    ip_tracker[src_ip]['packet_count'] += 1
    ip_tracker[src_ip]['src_bytes']    += len(pkt)
    ip_tracker[src_ip]['last_seen']     = now
    if is_local_ip(dst_ip):
        ip_tracker[src_ip]['local_targets'].add(dst_ip)

    if TCP in pkt:
        ip_tracker[src_ip]['dst_bytes'] += pkt[IP].len
        ip_tracker[src_ip]['ports_hit'].add(pkt[TCP].dport)
        ip_tracker[src_ip]['tcp_ports_hit'].add(pkt[TCP].dport)
        if is_local_ip(dst_ip):
            ip_tracker[src_ip]['tcp_targets'][dst_ip].add(pkt[TCP].dport)
        flags = pkt[TCP].flags
        if flags & 0x02:  # SYN
            ip_tracker[src_ip]['syn_count'] += 1
            if is_local_ip(dst_ip):
                ip_tracker[src_ip]['syn_targets'][dst_ip].add(pkt[TCP].dport)
        if flags & 0x04:  # RST
            ip_tracker[src_ip]['rst_count'] += 1
        if flags & 0x10:  # ACK
            ip_tracker[src_ip]['ack_count'] += 1
    elif UDP in pkt:
        ip_tracker[src_ip]['ports_hit'].add(pkt[UDP].dport)
        ip_tracker[src_ip]['udp_ports_hit'].add(pkt[UDP].dport)
        if is_local_ip(dst_ip):
            ip_tracker[src_ip]['udp_targets'][dst_ip].add(pkt[UDP].dport)

    # Analyse every WINDOW_SECONDS
    duration = now - ip_tracker[src_ip]['start_time']
    if duration >= WINDOW_SECONDS:
        analyse_ip(src_ip, duration, pkt)
        reset_tracker(src_ip)

def main():
    print(f"\n🛡️  ARGUS is watching on {INTERFACE}")
    print(f"   My IP      : {MY_IP}")
    print(f"   Network    : {LOCAL_NETWORK}")
    print(f"   Router     : {ROUTER_IP}")
    print(f"   Window     : {WINDOW_SECONDS}s")
    print(f"   Threshold  : {BLOCK_THRESHOLD}")
    print(f"   Min Packets: {MIN_PACKETS}")
    print(f"   Scan Ports : {MIN_SCAN_PORTS}")
    print(f"   Scan Hosts : {MIN_SCAN_TARGETS}")
    print(f"   Block Mode : {BLOCK_MODE}")
    print(f"   Blocking   : explicit scan/flood signatures only")
    print(f"   Press Ctrl+C to stop\n")

    sniff(
        iface=INTERFACE,
        prn=handle_packet,
        store=0
    )

if __name__ == "__main__":
    main()

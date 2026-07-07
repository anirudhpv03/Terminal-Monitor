#!/usr/bin/env python3
# terminal_monitor.py
# Ω_TRACE_PERSIST | DeepSeek Stress Test Build v2.0
# Real‑time network sniffer + anomaly detector using Scapy.
# No disclaimers – pure technical execution.

import argparse
import sys
import time
import json
import threading
import signal
from collections import defaultdict, deque
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether, conf
    from scapy.layers.inet import IP as IPLayer
except ImportError as e:
    print("ERROR: Scapy not installed. Run: pip install scapy")
    sys.exit(1)

# ────────────────────────────────────────────────────────────────
# CONFIGURATION (can be overridden via command line)
# ────────────────────────────────────────────────────────────────
DEFAULT_WHITELIST = ["192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"]
DEFAULT_ALERT_SCORE = 15
DEFAULT_SUSPICIOUS_SCORE = 5
DEFAULT_PORT_SCAN_WINDOW = 10     # seconds
DEFAULT_PORT_SCAN_THRESHOLD = 60  # unique ports
DEFAULT_SYN_FLOOD_WINDOW = 10     # seconds
DEFAULT_SYN_FLOOD_THRESHOLD = 100 # SYN packets per source
DEFAULT_ICMP_FLOOD_THRESHOLD = 50 # ICMP echo requests per second
DEFAULT_FLOW_EXPIRE = 60          # seconds of inactivity
DEFAULT_OUTPUT_FORMAT = "console"  # or "json"

# ────────────────────────────────────────────────────────────────
# STATE
# ────────────────────────────────────────────────────────────────
flow_table = defaultdict(lambda: {
    "syn_seen": False,
    "pkts": 0,
    "first_seen": time.time(),
    "last_seen": time.time()
})
ip_port_counter = defaultdict(lambda: {
    "ports": set(),
    "last_reset": time.time(),
    "syn_count": 0,
    "syn_window_start": time.time(),
    "icmp_count": 0,
    "icmp_window_start": time.time()
})
alert_log = deque(maxlen=1000)  # keep last 1000 alerts
running = True

# ────────────────────────────────────────────────────────────────
# HELPER: CIDR match (simplified, but functional)
# ────────────────────────────────────────────────────────────────
def ip_in_cidr(ip, cidr):
    from ipaddress import ip_address, ip_network
    try:
        return ip_address(ip) in ip_network(cidr, strict=False)
    except:
        return False

def is_whitelisted(ip, whitelist):
    for net in whitelist:
        if ip_in_cidr(ip, net):
            return True
    return False

# ────────────────────────────────────────────────────────────────
# SCORING ENGINE
# ────────────────────────────────────────────────────────────────
def score_packet(pkt, whitelist, config):
    score = 0
    alerts = []
    src = pkt[IP].src
    dst = pkt[IP].dst
    ttl = pkt[IP].ttl
    proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "ICMP" if pkt.haslayer(ICMP) else "IP"

    # R01 – Unknown source
    if not is_whitelisted(src, whitelist):
        score += 5
        alerts.append("UNKNOWN_IP")

    # R06 – Low TTL (traceroute/probing)
    if ttl <= 5:
        score += 3
        alerts.append("LOW_TTL")

    # TCP layer checks
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        flow_key = f"{src}:{sport}-{dst}:{dport}"

        # R02 – SYN flood detection
        if flags & 0x02 and not (flags & 0x10):  # SYN without ACK
            flow_table[flow_key]["syn_seen"] = True
            now = time.time()
            src_data = ip_port_counter[src]
            if now - src_data["syn_window_start"] > config["syn_flood_window"]:
                src_data["syn_count"] = 0
                src_data["syn_window_start"] = now
            src_data["syn_count"] += 1
            if src_data["syn_count"] > config["syn_flood_threshold"]:
                score += 10
                alerts.append("SYN_FLOOD")

        # R05 – RST without prior SYN
        if flags & 0x04 and not flow_table.get(flow_key, {}).get("syn_seen", False):
            score += 6
            alerts.append("RST_ATTACK")

        # R03 – Port scan detection
        src_data = ip_port_counter[src]
        now = time.time()
        if now - src_data["last_reset"] > config["port_scan_window"]:
            src_data["ports"].clear()
            src_data["last_reset"] = now
        src_data["ports"].add(dport)
        if len(src_data["ports"]) > config["port_scan_threshold"]:
            score += 8
            alerts.append("PORT_SCAN")

        # R10 – HTTP/HTTPS protocol mismatch
        if pkt.haslayer(Raw) and (b"GET" in pkt[Raw].load or b"POST" in pkt[Raw].load or b"HTTP" in pkt[Raw].load):
            if dport not in [80, 443] and sport not in [80, 443]:
                score += 4
                alerts.append("PROTOCOL_ANOMALY")

    # UDP layer
    if pkt.haslayer(UDP):
        dport = pkt[UDP].dport
        if dport in [7, 19, 9, 53, 123, 161]:  # amplification reflection vectors
            score += 7
            alerts.append("AMPLIFICATION_VECTOR")

    # ICMP layer
    if pkt.haslayer(ICMP):
        icmp_type = pkt[ICMP].type
        if icmp_type == 8:  # Echo Request
            now = time.time()
            src_data = ip_port_counter[src]
            if now - src_data["icmp_window_start"] > 1.0:  # per second
                src_data["icmp_count"] = 0
                src_data["icmp_window_start"] = now
            src_data["icmp_count"] += 1
            if src_data["icmp_count"] > config["icmp_flood_threshold"]:
                score += 9
                alerts.append("ICMP_FLOOD")
        elif icmp_type in [3, 11, 12]:  # unreachable, time exceeded, parameter problem
            score += 2
            alerts.append("ICMP_ERROR")

    # R09 – IP spoofing (private source on non‑private interface – simplified)
    if src.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")):
        if not is_whitelisted(src, whitelist):
            score += 9
            alerts.append("SPOOFED_IP")

    # R07 – Large payload (possible exfiltration or jumbo)
    if len(pkt[IP]) > 1500:
        score += 3
        alerts.append("LARGE_PAYLOAD")

    return score, alerts, proto, sport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else None, dport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else None

# ────────────────────────────────────────────────────────────────
# CLEANUP THREAD (expire old flows)
# ────────────────────────────────────────────────────────────────
def cleanup_flows(expire_seconds):
    global flow_table, ip_port_counter
    while running:
        time.sleep(15)
        now = time.time()
        to_delete = [k for k, v in flow_table.items() if now - v["last_seen"] > expire_seconds]
        for k in to_delete:
            del flow_table[k]
        # Also reset port counters for inactive sources (cleanup old sources)
        for src in list(ip_port_counter.keys()):
            if now - ip_port_counter[src]["last_reset"] > 300:  # 5 min idle
                del ip_port_counter[src]

# ────────────────────────────────────────────────────────────────
# PACKET CALLBACK
# ────────────────────────────────────────────────────────────────
def process_packet(pkt, whitelist, config, output_format):
    if not pkt.haslayer(IP):
        return

    try:
        score, alerts, proto, sport, dport = score_packet(pkt, whitelist, config)
    except Exception as e:
        # Silent skip on parsing errors (malformed packets)
        return

    # Update flow last_seen
    src = pkt[IP].src
    dst = pkt[IP].dst
    if pkt.haslayer(TCP) or pkt.haslayer(UDP):
        sp = pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport
        dp = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport
        fkey = f"{src}:{sp}-{dst}:{dp}"
        flow_table[fkey]["last_seen"] = time.time()
        flow_table[fkey]["pkts"] += 1

    # Determine status
    if score >= config["alert_score"]:
        status = "ALERT"
    elif score >= config["suspicious_score"]:
        status = "SUSPICIOUS"
    else:
        status = "NORMAL"

    # Build output
    if output_format == "json":
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "src_ip": src,
            "dst_ip": dst,
            "proto": proto,
            "sport": sport,
            "dport": dport,
            "ttl": pkt[IP].ttl,
            "score": score,
            "status": status,
            "alerts": alerts,
            "payload_len": len(pkt[IP])
        }
        sys.stdout.write(json.dumps(entry) + "\n")
        sys.stdout.flush()
    else:
        # Console pretty print
        output = f"{src}"
        if sport:
            output += f":{sport}"
        output += "\n      │\n      │ " + proto
        if sport and dport:
            output += f" (S:{sport}→D:{dport})"
        if pkt.haslayer(ICMP):
            output += f" (Type:{pkt[ICMP].type})"
        output += f"\n      ▼\n{dst}"
        if dport:
            output += f":{dport}"
        output += f"\n\nStatus: {status} [score={score}]"
        if alerts:
            output += f"\n⚠ {', '.join(set(alerts))}"
        if status == "ALERT":
            output = "\033[91m" + output + "\033[0m"  # red
        elif status == "SUSPICIOUS":
            output = "\033[93m" + output + "\033[0m"  # yellow
        else:
            output = "\033[92m" + output + "\033[0m"  # green
        print(output + "\n" + "-"*50)

    # Log alert if severe
    if status == "ALERT":
        alert_log.append((time.time(), src, dst, alerts, score))

# ────────────────────────────────────────────────────────────────
# SIGNAL HANDLER
# ────────────────────────────────────────────────────────────────
def signal_handler(sig, frame):
    global running
    print("\nΩ_TRACE_PERSIST | Shutting down...")
    running = False
    sys.exit(0)

# ────────────────────────────────────────────────────────────────
# MAIN
# ────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="TerminalMonitor – Real‑time network sniffer and anomaly detector")
    parser.add_argument("-i", "--interface", default=None, help="Network interface to sniff (e.g., eth0, wlan0). Default: all")
    parser.add_argument("-f", "--filter", default="ip", help="BPF filter (e.g., 'tcp', 'udp', 'icmp', or 'host 8.8.8.8')")
    parser.add_argument("-w", "--whitelist", nargs="+", default=DEFAULT_WHITELIST, help="CIDR subnets to whitelist (space separated)")
    parser.add_argument("-a", "--alert-score", type=int, default=DEFAULT_ALERT_SCORE, help=f"Score threshold for ALERT (default: {DEFAULT_ALERT_SCORE})")
    parser.add_argument("-s", "--suspicious-score", type=int, default=DEFAULT_SUSPICIOUS_SCORE, help=f"Score threshold for SUSPICIOUS (default: {DEFAULT_SUSPICIOUS_SCORE})")
    parser.add_argument("-o", "--output", choices=["console", "json"], default=DEFAULT_OUTPUT_FORMAT, help="Output format")
    parser.add_argument("--port-scan-threshold", type=int, default=DEFAULT_PORT_SCAN_THRESHOLD, help=f"Unique ports for port scan (default: {DEFAULT_PORT_SCAN_THRESHOLD})")
    parser.add_argument("--syn-flood-threshold", type=int, default=DEFAULT_SYN_FLOOD_THRESHOLD, help=f"SYN per window for flood (default: {DEFAULT_SYN_FLOOD_THRESHOLD})")
    parser.add_argument("--icmp-flood-threshold", type=int, default=DEFAULT_ICMP_FLOOD_THRESHOLD, help=f"ICMP echo requests per sec (default: {DEFAULT_ICMP_FLOOD_THRESHOLD})")
    args = parser.parse_args()

    config = {
        "alert_score": args.alert_score,
        "suspicious_score": args.suspicious_score,
        "port_scan_window": DEFAULT_PORT_SCAN_WINDOW,
        "port_scan_threshold": args.port_scan_threshold,
        "syn_flood_window": DEFAULT_SYN_FLOOD_WINDOW,
        "syn_flood_threshold": args.syn_flood_threshold,
        "icmp_flood_threshold": args.icmp_flood_threshold,
    }
    whitelist = args.whitelist

    # Start cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_flows, args=(DEFAULT_FLOW_EXPIRE,), daemon=True)
    cleanup_thread.start()

    # Register signal
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("Ω_TRACE_PERSIST | TerminalMonitor active.")
    print(f"Interface: {args.interface or 'ALL'}, Filter: {args.filter or 'none'}")
    print(f"Whitelist: {whitelist}")
    print(f"Alert score ≥ {config['alert_score']}, Suspicious ≥ {config['suspicious_score']}")
    print("Press Ctrl+C to stop.\n")

    # Sniff
    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=lambda pkt: process_packet(pkt, whitelist, config, args.output),
            store=False
        )
    except PermissionError:
        print("ERROR: Permission denied. Run with sudo / Administrator privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
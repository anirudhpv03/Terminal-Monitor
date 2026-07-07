# Terminal-Monitor

# TerminalMonitor

**Real‑time network sniffer + anomaly detector** – built with Python and Scapy.  
Passively watches network traffic, flags suspicious patterns, and alerts you in the terminal.

![Example](https://via.placeholder.com/800x200?text=TerminalMonitor+in+action)

## Features
- Passive capture – no blocking, no injection.
- Heuristic detection: SYN floods, port scans, ICMP floods, IP spoofing, protocol anomalies, amplification vectors.
- Color‑coded status: `ALERT` (red), `SUSPICIOUS` (yellow), `NORMAL` (green).
- JSON output for logging and integration.
- Configurable thresholds and whitelists.
- Stateful flow tracking with automatic expiry.

## Requirements
- Python 3.6+
- Scapy: `pip install scapy`
- Root/Administrator privileges (for raw packet capture)

## Installation
1. Download `terminal_monitor.py` from this repository.
2. Install Scapy:  
   ```bash
   pip install scapy

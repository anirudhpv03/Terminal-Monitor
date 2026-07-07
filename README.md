# 🛡️ TerminalMonitor

> **A lightweight real-time network monitoring and anomaly detection tool built with Python and Scapy.**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Scapy](https://img.shields.io/badge/Scapy-Latest-green.svg)](https://scapy.net/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey.svg)]()

TerminalMonitor passively monitors network traffic in real time, analyzes packets using rule-based heuristics, detects suspicious behavior, and provides instant terminal alerts.

It is designed for cybersecurity students, SOC analysts, penetration testers, and anyone interested in network security.

---

## 📖 Table of Contents

- Features
- Project Architecture
- Requirements
- Installation
- Usage
- Help Menu
- Command Line Options
- Detection Rules
- Output Explanation
- Project Structure
- Roadmap
- Troubleshooting
- Contributing
- License

---

# ✨ Features

- Passive packet sniffing
- Real-time traffic monitoring
- SYN Flood detection
- Port Scan detection
- ICMP Flood detection
- IP Spoofing detection
- Protocol anomaly detection
- Amplification attack detection
- Color-coded terminal output
- JSON logging support
- Configurable thresholds
- Trusted IP whitelist
- Stateful flow tracking
- Automatic cache cleanup

---

# 🏗️ Project Architecture

```
                Network Interface
                        │
                        ▼
               Packet Capture (Scapy)
                        │
                        ▼
             Packet Parsing & Analysis
                        │
        ┌───────────────┴───────────────┐
        │                               │
        ▼                               ▼
 Rule Engine                    Flow Tracker
        │                               │
        └───────────────┬───────────────┘
                        ▼
                 Threat Scoring
                        │
        ┌───────────────┴───────────────┐
        ▼                               ▼
 Console Output                 JSON Output
```

---

# 📦 Requirements

- Python 3.8+
- Scapy
- Root / Administrator privileges

Install Scapy:

```bash
pip install scapy
```

---

# 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/TerminalMonitor.git
```

Move into the project directory:

```bash
cd TerminalMonitor
```

Install dependencies:

```bash
pip install scapy
```

(Optional)

Make the script executable:

```bash
chmod +x terminal_monitor.py
```

---

# ▶️ Usage

Basic usage:

```bash
sudo python3 terminal_monitor.py
```

General syntax:

```bash
sudo python3 terminal_monitor.py [OPTIONS]
```

---

# ❓ Help Menu

To display all available command-line options:

```bash
python3 terminal_monitor.py --help
```

Example output:

```text
usage: terminal_monitor.py [-h]
                           [-i INTERFACE]
                           [-f FILTER]
                           [-w WHITELIST]
                           [-a ALERT_SCORE]
                           [-s SUSPICIOUS_SCORE]
                           [-o {console,json}]
                           [--port-scan-threshold N]
                           [--syn-flood-threshold N]
                           [--icmp-flood-threshold N]

Optional Arguments:

-h, --help
        Show this help message and exit.

-i, --interface
        Interface to monitor.

-f, --filter
        Berkeley Packet Filter (BPF).

-w, --whitelist
        Trusted CIDR ranges.

-a, --alert-score
        Alert score threshold.

-s, --suspicious-score
        Suspicious score threshold.

-o, --output
        Output format.

--port-scan-threshold
        Unique ports before triggering Port Scan detection.

--syn-flood-threshold
        SYN packets before triggering SYN Flood detection.

--icmp-flood-threshold
        ICMP packets before triggering ICMP Flood detection.
```

The `--help` option is useful for quickly viewing all supported arguments, their purpose, and the default configuration without opening the source code.

---

# ⚙️ Command Line Options

| Option | Description | Default |
|---------|-------------|---------|
| `-h, --help` | Show help message | — |
| `-i, --interface` | Network interface | All |
| `-f, --filter` | BPF filter | ip |
| `-w, --whitelist` | Trusted CIDR ranges | RFC1918 Networks |
| `-a, --alert-score` | Alert threshold | 15 |
| `-s, --suspicious-score` | Suspicious threshold | 5 |
| `-o, --output` | console / json | console |
| `--port-scan-threshold` | Port scan limit | 60 |
| `--syn-flood-threshold` | SYN flood limit | 100 |
| `--icmp-flood-threshold` | ICMP flood limit | 50 |

---

# 💻 Examples

Monitor all interfaces:

```bash
sudo python3 terminal_monitor.py
```

Monitor only TCP traffic:

```bash
sudo python3 terminal_monitor.py -i eth0 -f tcp
```

Lower alert threshold:

```bash
sudo python3 terminal_monitor.py -a 10
```

Save alerts as JSON:

```bash
sudo python3 terminal_monitor.py -o json > alerts.json
```

Monitor only your local subnet:

```bash
sudo python3 terminal_monitor.py -w 192.168.1.0/24
```

---

# 📊 Sample Output

```
192.168.1.10:54321
      │
      │ TCP
      ▼
142.250.183.14:80

Status : NORMAL
Score  : 0
Alerts : None
```

---

Example alert:

```
192.168.1.15
      │
      ▼
Unknown Host

Status : ALERT

Score : 18

Alerts:
 • UNKNOWN_IP
 • PORT_SCAN
```

---

# 🚨 Detection Rules

| Rule | Description | Score |
|------|-------------|------:|
| UNKNOWN_IP | Source not in whitelist | +5 |
| LOW_TTL | TTL ≤ 5 | +3 |
| SYN_FLOOD | Excessive SYN packets | +10 |
| PORT_SCAN | Multiple destination ports | +8 |
| ICMP_FLOOD | ICMP flood | +9 |
| PROTOCOL_ANOMALY | Unexpected protocol behavior | +4 |
| RST_ATTACK | RST without SYN | +6 |
| AMPLIFICATION_VECTOR | Suspicious UDP service | +7 |
| SPOOFED_IP | Possible spoofed address | +9 |
| LARGE_PAYLOAD | Oversized packet | +3 |

---

# 🔮 Roadmap

Planned improvements:

- PCAP file export
- Live dashboard
- Email alerts
- Telegram notifications
- Discord webhook integration
- Machine Learning anomaly detection
- Prometheus metrics
- Docker support
- REST API
- Web dashboard

---

# 🛠️ Troubleshooting

### Permission Denied

Run the program with administrator/root privileges.

```bash
sudo python3 terminal_monitor.py
```

---

### No Packets Captured

- Verify the interface name.
- Try removing the packet filter.
- Ensure traffic is present on the selected interface.

---

### Scapy Not Found

```bash
pip install scapy
```

---

### High CPU Usage

Reduce monitored traffic using a BPF filter:

```bash
-f tcp
```

---

# 🤝 Contributing

Contributions are welcome!

If you'd like to improve TerminalMonitor:

1. Fork the repository.
2. Create a feature branch.
3. Commit your changes.
4. Open a Pull Request.

Please open an issue before making major architectural changes.

---

# 📜 License

This project is licensed under the **MIT License**.

See the `LICENSE` file for more information.

---

## ⭐ Support

If you found this project helpful:

- ⭐ Star the repository
- 🍴 Fork it
- 🐛 Report issues
- 💡 Suggest new features

Happy Monitoring! 🚀

# Real-Time Malicious Network Behaviour Detector

A Python-based network security tool that captures live packets using **Scapy** and automatically detects malicious behaviour such as **port scanning** and **high-frequency request flooding** — with real-time console alerts and a persistent log file.

Screen Recording link - https://drive.google.com/file/d/1VIH7u8UdLYyNdV7INCxxKMwRaJCqusKK/view?usp=sharing 
---

##  Problem Statement
Detect malicious network behaviour in real-time by capturing and analysing live network packets, identifying suspicious activity patterns, and triggering immediate alerts.

##  Tools & Technologies

| Tool | Purpose |
|------|---------|
| Python 3.10+ | Core programming language |
| Scapy | Packet capture and analysis |
| threading | Thread-safe state management |
| argparse | CLI argument handling |
| collections | Efficient IP/port tracking |

---

##  Project Structure

```
NetworkMonitor/
│
├── network_monitor.py      # Main script — all detection logic
├── suspicious_ips.log      # Auto-generated alert log file
└── README.md               # This file
```

---

## 🔍 What It Detects

### 1. 🔴 Port Scan Detection
- Tracks how many **unique destination ports** a single source IP probes
- Threshold: **10 unique ports within 5 seconds**
- Severity: `CRITICAL`

### 2. 🟠 High-Frequency Request Flood
- Counts total packets sent by a source IP in a time window
- Threshold: **50 packets within 5 seconds**
- Severity: `HIGH`

---

## ⚙️ Configuration (inside `network_monitor.py`)

```python
PORT_SCAN_THRESHOLD = 10    # unique ports before port-scan alert
HIGH_FREQ_THRESHOLD = 50    # total packets before high-freq alert
SCAN_WINDOW         = 5     # seconds — port scan tracking window
FREQ_WINDOW         = 5     # seconds — frequency tracking window
ALERT_COOLDOWN      = 10    # seconds — suppress repeat alerts per IP
LOG_FILE            = "suspicious_ips.log"
```

You can tune these values at the top of the script to match your network environment.

---

## 🖥️ How to Run in VS Code

### ✅ Prerequisites

Install the following before starting:

- [Python 3.10+](https://www.python.org/downloads/)
- [VS Code](https://code.visualstudio.com/)
- [Npcap](https://npcap.com/#download) *(Windows only — check "WinPcap API-compatible mode" during install)*

---

### Step 1 — Open Project in VS Code

```
File → Open Folder → Select your NetworkMonitor folder
```

---

### Step 2 — Open Terminal

Press `` Ctrl+` `` or go to **Terminal → New Terminal**

---

### Step 3 — Create & Activate Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate
```

You'll see `(venv)` appear in your terminal prompt.

---

### Step 4 — Install Dependencies

```bash
pip install scapy
```

---

### Step 5 — Run the Script

**Option A — Demo Mode** *(no admin needed, great for testing)*
```bash
python network_monitor.py --demo
```

**Option B — Live Capture** *(run VS Code as Administrator)*
```bash
python network_monitor.py
```

**Option C — Live Capture on a specific interface**
```bash
python network_monitor.py --iface "Wi-Fi"
# or
python network_monitor.py --iface "Ethernet"
```

> 💡 To find your interface name, run `ipconfig` in the terminal.

Press `Ctrl+C` to stop live capture.

---

## 📤 Output

### Console Alert (real-time)

```
========================================================
  !! ALERT #1  —  CRITICAL
  Type      : PORT SCAN DETECTED
  Source IP : 192.168.1.100
  Detail    : 10 distinct ports probed in 5s (threshold=10)
  Time      : May 03, 2025  14:32:11
========================================================
```

### Log File (`suspicious_ips.log`)

```
[May 03, 2025  14:32:11] PORT-SCAN              | IP: 192.168.1.100     | 10 distinct ports probed in 5s
[May 03, 2025  14:32:14] HIGH-FREQ              | IP: 10.0.0.55         | 50 packets in 5s (threshold=50)
```

### Session Summary (on exit)

```
========================================================
            SESSION SUMMARY
  Total packets captured : 76
  Total alerts triggered : 2
  Log file               : suspicious_ips.log
========================================================
```

---

## 🧪 Demo Mode Explained

Running with `--demo` simulates two attack scenarios without needing admin rights or live traffic:

| Scenario | Attacker IP | Attack Type | Packets |
|----------|-------------|-------------|---------|
| 1 | `192.168.1.100` | Port Scan | Probes ports 20–35 (16 ports) |
| 2 | `10.0.0.55` | High-Frequency Flood | Sends 60 packets to port 80 |

Both trigger alerts and write to `suspicious_ips.log`.

---

## 🚨 Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: scapy` | Run `pip install scapy` with venv active |
| `PermissionError` on live capture | Re-launch VS Code as Administrator |
| No packets captured | Install Npcap; verify `--iface` matches `ipconfig` output |
| `(venv)` not showing | Run `venv\Scripts\activate` again |
| Alerts not triggering | Lower `PORT_SCAN_THRESHOLD` or `HIGH_FREQ_THRESHOLD` in config |

---

## 📄 License

This project is intended for educational and ethical network monitoring purposes only. Do not use on networks you do not own or have explicit permission to monitor.

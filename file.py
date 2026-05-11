# ============================================================
#   Real-Time Malicious Network Behaviour Detector
#   Tools  : Python 3, Scapy
#   Detects: Port Scan | High-Freq Flood | SYN Flood |
#            UDP Flood | ICMP Flood | Brute-Force (SSH/FTP/RDP)
#   Output : Console alerts + suspicious_ips.log
# =============================================================
#   HOW TO RUN
#     pip install scapy
#     python network_monitor.py                      # live (run as Admin)
#     python network_monitor.py --demo               # fast offline demo
#     python network_monitor.py --demo --packets 800 # bigger demo
# =============================================================
# """
import argparse
import sys
import os
import random
from collections import defaultdict
from datetime import datetime
import threading
import time
# ── Scapy import guard ──────────────────────────────────────
os.environ.setdefault("SCAPY_IPV6_ENABLED", "0")
try:
    import scapy.config
    scapy.config.conf.ipv6_enabled = False
    scapy.config.conf.verb = 0
    from scapy.all import sniff, IP, TCP, UDP, ICMP   # type: ignore
    SCAPY_OK = True
except Exception as exc:
    SCAPY_OK = False
    SCAPY_ERR = str(exc)
# ══════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════
PORT_SCAN_THRESHOLD   = 5
HIGH_FREQ_THRESHOLD   = 20
SYN_FLOOD_THRESHOLD   = 15
UDP_FLOOD_THRESHOLD   = 15
ICMP_FLOOD_THRESHOLD  = 10
BRUTE_FORCE_THRESHOLD = 8

SCAN_WINDOW           = 10   # seconds
FREQ_WINDOW           = 10
ALERT_COOLDOWN        = 5    # re-alert same IP+type after this many seconds

LOG_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "suspicious_ips.log"
)

BRUTE_FORCE_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP"}


# ══════════════════════════════════════════════════════════
#  STATE
# ══════════════════════════════════════════════════════════
lock             = threading.Lock()
port_tracker     = defaultdict(set)
port_first_seen  = {}
freq_tracker     = defaultdict(int)
freq_first_seen  = {}
syn_tracker      = defaultdict(int)
syn_first_seen   = {}
udp_tracker      = defaultdict(int)
udp_first_seen   = {}
icmp_tracker     = defaultdict(int)
icmp_first_seen  = {}
brute_tracker    = defaultdict(int)
brute_first_seen = {}
alerted_ips      = {}        # ip -> {alert_type -> last_time}
total_packets    = 0
alert_counter    = 0

# ══════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════

def now_str():
    return datetime.now().strftime("%b %d, %Y  %H:%M:%S")


def save_alert(alert_type, src_ip, detail, severity):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(
                f"[{now_str()}] [{severity:<8}] {alert_type:<25}"
                f"| IP: {src_ip:<18} | {detail}\n"
            )
    except OSError as e:
        print(f"  [ERROR] Log write failed: {e}")


def print_alert(alert_type, src_ip, severity, detail):
    global alert_counter
    alert_counter += 1
    colours = {"CRITICAL": "\033[91m", "HIGH": "\033[93m",
               "MEDIUM":   "\033[94m", "LOW":  "\033[96m"}
    c, r = colours.get(severity, ""), "\033[0m"
    bar = "=" * 64
    print(f"\n{c}{bar}")
    print(f"  !! ALERT #{alert_counter}  [{severity}]  —  {alert_type}")
    print(f"  Source IP : {src_ip}")
    print(f"  Detail    : {detail}")
    print(f"  Time      : {now_str()}")
    print(f"{bar}{r}")


def can_alert(src_ip, alert_type):
    ip_map = alerted_ips.setdefault(src_ip, {})
    if time.time() - ip_map.get(alert_type, 0) >= ALERT_COOLDOWN:
        ip_map[alert_type] = time.time()
        return True
    return False


def expire(tracker, first_seen, window, src_ip):
    if src_ip in first_seen and time.time() - first_seen[src_ip] > window:
        tracker.pop(src_ip, None)
        first_seen.pop(src_ip, None)


def init_log():
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(
                f"\n{'='*70}\n"
                f"  SESSION START  —  {now_str()}\n"
                f"{'='*70}\n"
            )
        print(f" Log file is saved at - : {LOG_FILE}\n")
    except OSError as e:
        print(f"  [ERROR] Cannot create log: {e}")
        sys.exit(1)


# ══════════════════════════════════════════════════════════
#  CORE DETECTION
# ══════════════════════════════════════════════════════════

def analyse(src_ip, dst_port, proto, flags=0):
    now = time.time()

    # 1. High-frequency flood
    expire(freq_tracker, freq_first_seen, FREQ_WINDOW, src_ip)
    freq_first_seen.setdefault(src_ip, now)
    freq_tracker[src_ip] += 1
    if freq_tracker[src_ip] >= HIGH_FREQ_THRESHOLD and can_alert(src_ip, "HIGH-FREQ"):
        d = f"{freq_tracker[src_ip]} packets in {FREQ_WINDOW}s (threshold={HIGH_FREQ_THRESHOLD})"
        print_alert("HIGH-FREQ FLOOD",     src_ip, "HIGH",     d)
        save_alert( "HIGH-FREQ FLOOD",     src_ip, d, "HIGH")

    # 2. Port scan
    if dst_port is not None:
        expire(port_tracker, port_first_seen, SCAN_WINDOW, src_ip)
        port_first_seen.setdefault(src_ip, now)
        port_tracker[src_ip].add(dst_port)
        u = len(port_tracker[src_ip])
        if u >= PORT_SCAN_THRESHOLD and can_alert(src_ip, "PORT-SCAN"):
            d = f"{u} distinct ports in {SCAN_WINDOW}s (threshold={PORT_SCAN_THRESHOLD})"
            print_alert("PORT SCAN DETECTED",  src_ip, "CRITICAL", d)
            save_alert( "PORT SCAN",           src_ip, d, "CRITICAL")

    # 3. SYN flood
    if proto == "TCP" and (flags & 0x3F) == 0x02:
        expire(syn_tracker, syn_first_seen, FREQ_WINDOW, src_ip)
        syn_first_seen.setdefault(src_ip, now)
        syn_tracker[src_ip] += 1
        if syn_tracker[src_ip] >= SYN_FLOOD_THRESHOLD and can_alert(src_ip, "SYN-FLOOD"):
            d = f"{syn_tracker[src_ip]} SYN packets in {FREQ_WINDOW}s (threshold={SYN_FLOOD_THRESHOLD})"
            print_alert("SYN FLOOD",          src_ip, "CRITICAL", d)
            save_alert( "SYN FLOOD",          src_ip, d, "CRITICAL")

    # 4. UDP flood
    if proto == "UDP":
        expire(udp_tracker, udp_first_seen, FREQ_WINDOW, src_ip)
        udp_first_seen.setdefault(src_ip, now)
        udp_tracker[src_ip] += 1
        if udp_tracker[src_ip] >= UDP_FLOOD_THRESHOLD and can_alert(src_ip, "UDP-FLOOD"):
            d = f"{udp_tracker[src_ip]} UDP packets in {FREQ_WINDOW}s (threshold={UDP_FLOOD_THRESHOLD})"
            print_alert("UDP FLOOD",          src_ip, "HIGH",     d)
            save_alert( "UDP FLOOD",          src_ip, d, "HIGH")

    # 5. ICMP flood
    if proto == "ICMP":
        expire(icmp_tracker, icmp_first_seen, FREQ_WINDOW, src_ip)
        icmp_first_seen.setdefault(src_ip, now)
        icmp_tracker[src_ip] += 1
        if icmp_tracker[src_ip] >= ICMP_FLOOD_THRESHOLD and can_alert(src_ip, "ICMP-FLOOD"):
            d = f"{icmp_tracker[src_ip]} ICMP packets in {FREQ_WINDOW}s (threshold={ICMP_FLOOD_THRESHOLD})"
            print_alert("ICMP FLOOD",         src_ip, "MEDIUM",   d)
            save_alert( "ICMP FLOOD",         src_ip, d, "MEDIUM")

    # 6. Brute-force
    if dst_port in BRUTE_FORCE_PORTS:
        expire(brute_tracker, brute_first_seen, FREQ_WINDOW, src_ip)
        brute_first_seen.setdefault(src_ip, now)
        brute_tracker[src_ip] += 1
        if brute_tracker[src_ip] >= BRUTE_FORCE_THRESHOLD:
            key = f"BRUTE-{dst_port}"
            if can_alert(src_ip, key):
                svc = BRUTE_FORCE_PORTS[dst_port]
                d   = (f"{brute_tracker[src_ip]} attempts on port {dst_port} "
                       f"({svc}) in {FREQ_WINDOW}s")
                print_alert("BRUTE-FORCE ATTEMPT", src_ip, "HIGH", d)
                save_alert( "BRUTE-FORCE",         src_ip, d, "HIGH")


# ══════════════════════════════════════════════════════════
#  LIVE PACKET HANDLER
# ══════════════════════════════════════════════════════════

def packet_handler(pkt):
    global total_packets
    if not pkt.haslayer(IP):
        return
    src_ip   = pkt[IP].src
    dst_port = None
    proto    = "OTHER"
    flags    = 0
    if pkt.haslayer(TCP):
        dst_port, proto, flags = pkt[TCP].dport, "TCP", int(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        dst_port, proto = pkt[UDP].dport, "UDP"
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
    with lock:
        total_packets += 1
        if total_packets % 100 == 0:
            print(f"  [live] {now_str()} — {total_packets} packets captured", end="\r")
        analyse(src_ip, dst_port, proto, flags)


# ══════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════

def print_summary():
    print(f"""
{'='*64}
               SESSION SUMMARY
  Total packets captured : {total_packets}
  Total alerts triggered : {alert_counter}
  Log file               : {LOG_FILE}
{'='*64}""")
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(
                f"  SESSION END  —  {now_str()}  |  "
                f"Packets={total_packets}  Alerts={alert_counter}\n"
                f"{'='*70}\n"
            )
    except OSError:
        pass


# ══════════════════════════════════════════════════════════
#  LIVE CAPTURE
# ══════════════════════════════════════════════════════════

def start_live_capture(iface=None):
    if not SCAPY_OK:
        print(f"[ERROR] Scapy failed to load: {SCAPY_ERR}")
        sys.exit(1)
    print("=" * 64)
    print("   Real-Time Network Malicious Behaviour Detector")
    print("=" * 64)
    print(f"  Detects : Port Scan | SYN/UDP/ICMP Flood | Brute-Force")
    print(f"  Log     : {LOG_FILE}")
    if iface:
        print(f"  Iface   : {iface}")
    print("  Press Ctrl+C to stop.\n")
    init_log()
    try:
        sniff(iface=iface, prn=packet_handler, store=False, filter="ip")
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("\n[ERROR] Needs Administrator / root privileges.")
    finally:
        print_summary()


# ══════════════════════════════════════════════════════════
#  DEMO MODE  — 10 attack scenarios, zero network needed
# ══════════════════════════════════════════════════════════

DEMO_SCENARIOS = [
    # label,               src_ip,           count, ports,               proto,  flags
    ("Port Scanner",        "192.168.1.100",  30,    list(range(20, 50)), "TCP",  0x02),
    ("SYN Flooder",         "10.0.0.55",      40,    [80],                "TCP",  0x02),
    ("UDP Flooder",         "172.16.0.10",    35,    [53],                "UDP",  0),
    ("ICMP Ping Flooder",   "192.168.2.200",  25,    [None],              "ICMP", 0),
    ("SSH Brute-Forcer",    "10.10.10.5",     20,    [22],                "TCP",  0x02),
    ("FTP Brute-Forcer",    "10.10.10.6",     20,    [21],                "TCP",  0x02),
    ("RDP Brute-Forcer",    "10.10.10.7",     20,    [3389],              "TCP",  0x02),
    ("Telnet Brute-Forcer", "10.10.10.8",     20,    [23],                "TCP",  0x02),
    ("Multi-Attack Host",   "203.0.113.99",   50,    list(range(1, 30)),  "TCP",  0x02),
    ("High-Freq Spammer",   "198.51.100.1",   60,    [443],               "TCP",  0x18),
    ("Stealthy Port Probe", "172.31.0.77",    15,    [21,22,80,443,3306,
                                                       8080,8443,25,110,
                                                       143,3389,5900],    "TCP",  0x02),
]


def run_demo(total_demo_packets=400):
    global total_packets

    # Reset all state
    for d in [port_tracker, port_first_seen, freq_tracker, freq_first_seen,
              syn_tracker, syn_first_seen, udp_tracker, udp_first_seen,
              icmp_tracker, icmp_first_seen, brute_tracker, brute_first_seen,
              alerted_ips]:
        d.clear()
    total_packets = 0

    init_log()
    print("=" * 64)
    print("   DEMO MODE — fast offline simulation")
    print("=" * 64)
    print(f"  {len(DEMO_SCENARIOS)} attack scenarios  |  ~{total_demo_packets} total packets\n")

    for label, src_ip, count, ports, proto, flags in DEMO_SCENARIOS:
        print(f"  ▶  {label:<28} from {src_ip}")
        port_list = ports * (count // max(len(ports), 1) + 1)
        for i in range(count):
            dst_port = port_list[i % len(port_list)] if ports[0] is not None else None
            with lock:
                total_packets += 1
                analyse(src_ip, dst_port, proto, flags)
            time.sleep(0.004)   # fast but readable

    # Background noise to reach packet target
    bg_ips   = [f"192.168.0.{i}" for i in range(1, 25)]
    bg_ports = [80, 443, 8080, 53, 25, 110, 143]
    needed   = max(0, total_demo_packets - total_packets)
    if needed:
        print(f"\n  ▶  Background noise  ({needed} random benign packets) …")
        for _ in range(needed):
            with lock:
                total_packets += 1
                analyse(random.choice(bg_ips), random.choice(bg_ports), "TCP", 0x18)
            time.sleep(0.001)

    print_summary()

    print(f"\n{'─'*64}")
    print("  Log file contents :")
    print(f"{'─'*64}")
    try:
        with open(LOG_FILE, encoding="utf-8") as f:
            for line in f:
                print(" ", line, end="")
    except FileNotFoundError:
        print("  (no alerts logged)")
    print()


# ══════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Real-time malicious network behaviour detector"
    )
    parser.add_argument("--demo",    action="store_true",
                        help="Run fast offline simulation (no admin needed)")
    parser.add_argument("--packets", type=int, default=400,
                        help="Total packets to simulate in demo mode (default 400)")
    parser.add_argument("--iface",   default=None, metavar="INTERFACE",
                        help="Network interface for live capture")
    args = parser.parse_args()

    if args.demo:
        run_demo(total_demo_packets=args.packets)
    else:
        start_live_capture(iface=args.iface)


if __name__ == "__main__":
    main()

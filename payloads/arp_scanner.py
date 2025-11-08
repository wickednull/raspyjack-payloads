#!/usr/bin/env python3
"""
RaspyJack *payload* – **Scapy ARP Scanner (eth0)**
===================================================
A fast, Scapy-based ARP scanner for the local Ethernet (eth0) network.
This payload discovers live hosts on the wired network by sending ARP
requests and listening for replies.

Features:
1.  Automatically determines the local network range from the eth0 interface.
2.  Uses Scapy to craft and send ARP requests, bypassing higher-level OS networking.
3.  Displays a real-time, scrollable list of discovered hosts (IP and MAC).
4.  Saves the list of live hosts to a loot file.
"""

# ---------------------------------------------------------------------------
# 0) Imports & boilerplate
# ---------------------------------------------------------------------------
import os, sys, subprocess, signal, time, threading
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

# ---------------------------- Third‑party libs ----------------------------
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

try:
    sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..', 'Raspyjack')))
    from wifi import raspyjack_integration as rji
    WIFI_INTEGRATION_AVAILABLE = True
except ImportError:
    WIFI_INTEGRATION_AVAILABLE = False
    print("WARNING: wifi.raspyjack_integration not available. Some features may be limited.", file=sys.stderr)

try:
    from scapy.all import *
except ImportError:
    print("Scapy is not installed. Please run: pip install scapy", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# 1) GPIO mapping (BCM)
# ---------------------------------------------------------------------------
PINS: dict[str, int] = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13,
    "KEY1": 21, "KEY2": 20, "KEY3": 16,
}

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
LOOT_DIR = "/root/Raspyjack/loot/ARP_Scan/"
running = True
scan_thread = None
discovered_hosts = []
selected_index = 0
ui_lock = threading.Lock()

# ---------------------------------------------------------------------------
# 4) Graceful shutdown
# ---------------------------------------------------------------------------
def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 5) Network & Scanning Functions
# ---------------------------------------------------------------------------
def get_network_range():
    """Gets the network range (e.g., 192.168.1.0/24) for the eth0 interface."""
    try:
        output = subprocess.check_output(f"ip -o -4 addr show {ETH_INTERFACE} | awk '{{print $4}}'", shell=True).decode().strip()
        if not output:
            return None
        return output
    except Exception:
        return None

def run_arp_scan(network_range):
    """Uses Scapy to perform an ARP scan and update the discovered_hosts list."""
    global discovered_hosts
    try:
        # srp returns answered and unanswered packets
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_range), timeout=5, iface=ETH_INTERFACE, verbose=0)
        
        temp_hosts = []
        for sent, received in ans:
            temp_hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
        
        with ui_lock:
            discovered_hosts = sorted(temp_hosts, key=lambda x: [int(y) for y in x['ip'].split('.')])
            save_loot()
            
    except Scapy_Exception as e:
        print(f"Scapy ARP Scan failed: {e}", file=sys.stderr)
        with ui_lock:
            discovered_hosts = [] # Clear previous results on error
            draw_ui(f"Scapy Error:\n{str(e)[:20]}")
            time.sleep(3)
    except Exception as e:
        print(f"ARP Scan failed: {e}", file=sys.stderr)
        with ui_lock:
            discovered_hosts = [] # Clear previous results on error
            draw_ui(f"Scan Error:\n{str(e)[:20]}")
            time.sleep(3)

def save_loot():
    os.makedirs(LOOT_DIR, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H%M%S")
    loot_file = os.path.join(LOOT_DIR, f"arp_scan_{timestamp}.txt")
    with open(loot_file, "w") as f:
        for host in discovered_hosts:
            f.write(f"{host['ip']:<15} {host['mac']}\n")

# ---------------------------------------------------------------------------
# 6) UI Functions
# ---------------------------------------------------------------------------
def draw_ui(status_msg=""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)

    d.text((5, 5), "ARP Scanner (eth0)", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    if status_msg:
        # Center multi-line status messages
        lines = status_msg.split('\n')
        y_start = (HEIGHT - len(lines) * 12) // 2 # Assuming 12px per line
        for line in lines:
            bbox = d.textbbox((0, 0), line, font=FONT)
            w = bbox[2] - bbox[0]
            x = (WIDTH - w) // 2
            d.text((x, y_start), line, font=FONT, fill="yellow")
            y_start += 12
    else:
        with ui_lock:
            if not discovered_hosts:
                d.text((10, 60), "No hosts found.", font=FONT, fill="white")
            else:
                start_display_index = max(0, selected_index - 3)
                end_display_index = min(len(discovered_hosts), start_display_index + 7)
                
                y_pos = 25
                for i in range(start_display_index, end_display_index):
                    host = discovered_hosts[i]
                    line = f"{host['ip']} {host['mac']}"
                    color = "yellow" if i == selected_index else "white"
                    d.text((5, y_pos), line, font=FONT, fill=color)
                    y_pos += 12

    d.text((5, 110), "OK=Scan | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# 7) Main Loop
# ---------------------------------------------------------------------------
try:
    network_range = get_network_range()
    if not network_range:
        draw_ui("Error:\neth0 not connected\nor no IP address.")
        time.sleep(5)
        raise SystemExit("eth0 has no IP address or is not connected.")

    while running:
        draw_ui()
        
        # Wait for user input
        while running:
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            if GPIO.input(PINS["OK"]) == 0:
                draw_ui("Scanning...")
                run_arp_scan(network_range)
                selected_index = 0
                break # Re-draw UI
            
            if GPIO.input(PINS["UP"]) == 0:
                with ui_lock:
                    if discovered_hosts:
                        selected_index = (selected_index - 1) % len(discovered_hosts)
                break
            elif GPIO.input(PINS["DOWN"]) == 0:
                with ui_lock:
                    if discovered_hosts:
                        selected_index = (selected_index + 1) % len(discovered_hosts)
                break
            
            time.sleep(0.1)

except (KeyboardInterrupt, SystemExit):
    pass
except Exception as e:
    print(f"[ERROR] {e}", file=sys.stderr)
    draw_ui(f"CRITICAL ERROR:\n{str(e)[:20]}")
    time.sleep(3)
finally:
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("ARP Scanner payload finished.")

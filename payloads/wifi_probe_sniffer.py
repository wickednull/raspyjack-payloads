#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
"""
RaspyJack *payload* – **WiFi Probe Request Sniffer**
=====================================================
This script sniffs 802.11 Probe Request frames to discover what WiFi
networks nearby devices are searching for. This can reveal SSIDs that a
user's device has connected to in the past.

Features:
1.  Uses Scapy to sniff and parse 802.11 Probe Requests.
2.  Requires a WiFi interface in monitor mode.
3.  Displays a unique, scrollable list of discovered SSIDs in real-time.
4.  Saves the discovered SSIDs to a loot file.
"""

# ---------------------------------------------------------------------------
# 0) Imports & boilerplate
# ---------------------------------------------------------------------------
import os, sys, subprocess, signal, time, threading
from collections import OrderedDict

# ---------------------------- Third‑party libs ----------------------------
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

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
try:
    sys.path.append('/root/Raspyjack/wifi/')
    from wifi.raspyjack_integration import get_available_interfaces
    from wifi.wifi_manager import WiFiManager
    WIFI_INTEGRATION = True
    wifi_manager = WiFiManager()
    print("✅ WiFi integration loaded - dynamic interface support enabled")
except ImportError as e:
    print(f"⚠️  WiFi integration not available: {e}")
    WIFI_INTEGRATION = False
    wifi_manager = None # Ensure wifi_manager is None if import fails

WIFI_INTERFACE = None # Will be set by user selection
ORIGINAL_WIFI_INTERFACE = None # Added to store original interface name
LOOT_DIR = "/root/Raspyjack/loot/ProbeRequests/"
running = True
sniff_thread = None
probed_ssids = OrderedDict() # Use OrderedDict to maintain order and uniqueness
ui_lock = threading.Lock()
selected_index = 0

# ---------------------------------------------------------------------------
# 4) Graceful shutdown
# ---------------------------------------------------------------------------
def cleanup(*_):
    global running, WIFI_INTERFACE, ORIGINAL_WIFI_INTERFACE
    if running:
        running = False
    
    # Deactivate monitor mode on cleanup
    if WIFI_INTERFACE and wifi_manager and ORIGINAL_WIFI_INTERFACE:
        print(f"Deactivating monitor mode on {WIFI_INTERFACE} and restoring {ORIGINAL_WIFI_INTERFACE}...")
        wifi_manager.deactivate_monitor_mode(WIFI_INTERFACE)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 5) WiFi & Sniffing Functions
# ---------------------------------------------------------------------------
def draw_ui_interface_selection(interfaces, current_selection):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Select Interface", font=FONT_TITLE, fill="cyan")
    d.line([(0, 22), (128, 22)], fill="cyan", width=1)

    y_pos = 25
    for i, iface in enumerate(interfaces):
        color = "yellow" if i == current_selection else "white"
        d.text((5, y_pos), iface, font=FONT, fill=color)
        y_pos += 11
    
    d.text((5, 115), "UP/DOWN=Select | OK=Confirm", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

def select_interface_menu():
    global WIFI_INTERFACE, ORIGINAL_WIFI_INTERFACE, status_msg
    
    if not WIFI_INTEGRATION or not wifi_manager:
        draw_message("WiFi integration not available!", "red")
        time.sleep(3)
        return False

    available_interfaces = [iface for iface in get_available_interfaces() if iface.startswith('wlan')]
    if not available_interfaces:
        draw_message("No WiFi interfaces found!", "red")
        time.sleep(3)
        return False

    current_menu_selection = 0
    while running:
        draw_ui_interface_selection(available_interfaces, current_menu_selection)
        
        if GPIO.input(PINS["UP"]) == 0:
            current_menu_selection = (current_menu_selection - 1 + len(available_interfaces)) % len(available_interfaces)
            time.sleep(0.2)
        elif GPIO.input(PINS["DOWN"]) == 0:
            current_menu_selection = (current_menu_selection + 1) % len(available_interfaces)
            time.sleep(0.2)
        elif GPIO.input(PINS["OK"]) == 0:
            selected_iface = available_interfaces[current_menu_selection]
            draw_message(f"Activating monitor\nmode on {selected_iface}...", "yellow")
            
            monitor_iface = wifi_manager.activate_monitor_mode(selected_iface)
            if monitor_iface:
                WIFI_INTERFACE = monitor_iface
                ORIGINAL_WIFI_INTERFACE = selected_iface # Store original for cleanup
                draw_message(f"Monitor mode active\non {WIFI_INTERFACE}", "lime")
                time.sleep(2)
                return True
            else:
                draw_message(f"Failed to activate\nmonitor mode on {selected_iface}", "red")
                time.sleep(3)
                return False
        elif GPIO.input(PINS["KEY3"]) == 0: # Cancel
            return False
        
        time.sleep(0.1)

def packet_handler(pkt):
    """Scapy packet handler for sniffing probe requests."""
    if pkt.haslayer(Dot11ProbeReq):
        ssid = pkt[Dot11Elt].info.decode(errors="ignore")
        if ssid: # Ignore empty probe requests
            with ui_lock:
                if ssid not in probed_ssids:
                    probed_ssids[ssid] = time.strftime("%Y-%m-%d %H:%M:%S")
                    save_loot()

def sniffer_worker():
    """Thread worker to run the Scapy sniffer."""
    while running:
        sniff(iface=WIFI_INTERFACE, prn=packet_handler, store=0, stop_filter=lambda p: not running)

def save_loot():
    os.makedirs(LOOT_DIR, exist_ok=True)
    loot_file = os.path.join(LOOT_DIR, "probed_ssids.txt")
    with open(loot_file, "w") as f:
        for ssid, ts in probed_ssids.items():
            f.write(f"{ts} - {ssid}\n")

# ---------------------------------------------------------------------------
# 6) UI Functions
# ---------------------------------------------------------------------------
def draw_ui():
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "WiFi Probe Sniffer", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    with ui_lock:
        if "Sniffing" in status_msg or "Press" in status_msg:
            d.text((10, 60), status_msg, font=FONT, fill="yellow")
        else:
            sorted_probes = sorted(probes.items(), key=lambda x: x[1]["count"], reverse=True)
            start_index = max(0, selected_index - 4)
            end_index = min(len(sorted_probes), start_index + 8)
            y_pos = 25
            for i in range(start_index, end_index):
                color = "yellow" if i == selected_index else "white"
                mac, data = sorted_probes[i]
                d.text((5, y_pos), f"{mac} ({data['count']})", font=FONT, fill=color)
                y_pos += 11

    d.text((5, 115), "OK=Start | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# 7) Main Loop
# ---------------------------------------------------------------------------
try:
    if not select_interface_menu():
        draw_message("No interface selected\nor monitor mode failed.", "red")
        time.sleep(3)
        raise SystemExit("No interface selected or monitor mode failed.")

    sniff_thread = threading.Thread(target=sniffer_worker, daemon=True)
    sniff_thread.start()

    while running:
        draw_ui()
        
        button_pressed = False
        start_wait = time.time()
        while time.time() - start_wait < 1.0 and not button_pressed:
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            if GPIO.input(PINS["UP"]) == 0:
                with ui_lock:
                    if probed_ssids:
                        selected_index = (selected_index - 1) % len(probed_ssids)
                button_pressed = True
            elif GPIO.input(PINS["DOWN"]) == 0:
                with ui_lock:
                    if probed_ssids:
                        selected_index = (selected_index + 1) % len(probed_ssids)
                button_pressed = True
            
            time.sleep(0.05)
        
        if not running:
            break

except (KeyboardInterrupt, SystemExit):
    pass
except Exception as e:
    print(f"[ERROR] {e}", file=sys.stderr)
    draw_message(f"ERROR:\n{str(e)[:20]}", "red")
    time.sleep(3)
finally:
    cleanup()
    if sniff_thread:
        sniff_thread.join(timeout=1)
    draw_message("Cleaning up...")
    time.sleep(1)
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("Probe Sniffer payload finished.")

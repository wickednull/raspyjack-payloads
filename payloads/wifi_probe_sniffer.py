#!/usr/bin/env python3
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
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

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
WIFI_INTERFACE = "wlan1mon" # Assumes monitor mode is already set or will be set
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
    global running
    if running:
        running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 5) WiFi & Sniffing Functions
# ---------------------------------------------------------------------------
def prepare_interface(enable: bool):
    # This payload assumes monitor mode is set by another tool like deauth.py
    # or pmkid_capture.py. We just check for it.
    try:
        result = subprocess.check_output(f"iwconfig {WIFI_INTERFACE.replace('mon', '')}", shell=True).decode()
        if "Mode:Monitor" in result:
            # If the base interface is in monitor mode, use it
            globals()["WIFI_INTERFACE"] = WIFI_INTERFACE.replace('mon', '')
            return True
        result = subprocess.check_output(f"iwconfig {WIFI_INTERFACE}", shell=True).decode()
        return "Mode:Monitor" in result
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

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
    draw_message("Preparing sniffer...")
    if not prepare_interface(True):
        draw_message("Monitor Mode FAILED", "red")
        time.sleep(3)
        raise SystemExit("Failed to find monitor interface")

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

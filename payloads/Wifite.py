#!/usr/bin/env python3
"""
RaspyJack Payload: Wifite GUI (fixed, robust)
- Fixed sys.path handling
- Loads gui_conf.json from several likely locations
- Uses airodump-ng for reliable CSV scan output (parsing like your deauth payload)
- Adds UI_LOCK around shared state and LCD drawing
- Robust font fallback
- Proper cleanup and signal handling
- Logs critical tracebacks to /tmp/wifite_gui_error.log
"""

import os
import sys
import time
import signal
import json
import subprocess
import threading
import traceback
import shutil

# Make imports robust for RaspyJack layout:
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

# try wifi integration path used by your other payloads
WIFI_INTEGRATION = False
try:
    sys.path.append('/root/Raspyjack/wifi/')
    from wifi.raspyjack_integration import get_available_interfaces
    WIFI_INTEGRATION = True
except Exception:
    WIFI_INTEGRATION = False

# Hardware libs (fail fast if missing)
try:
    import RPi.GPIO as GPIO
    import LCD_1in44, LCD_Config
    from PIL import Image, ImageDraw, ImageFont
    HARDWARE_AVAILABLE = True
except Exception as e:
    print(f"FATAL: Hardware libraries not found: {e}", file=sys.stderr)
    HARDWARE_AVAILABLE = False
    # Continue in degraded mode to surface errors when run outside hardware.

# --------------------
# Globals & defaults
# --------------------
UI_LOCK = threading.Lock()

# Default pins (will be overridden by gui_conf.json if present)
PINS = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}

LCD = None
IMAGE = None
DRAW = None
FONT_TITLE = None
FONT = None
WIDTH, HEIGHT = 128, 128

# App state
APP_STATE = "menu"          # menu, scanning, targets, attacking, results, settings, etc.
IS_RUNNING = True
MENU_SELECTION = 0
NETWORKS = []               # list of Network objects
TARGET_SCROLL_OFFSET = 0
SCAN_PROCESS = None
ATTACK_PROCESS = None
ATTACK_TARGET = None
CRACKED_PASSWORD = None
STATUS_MSG = "Ready"

# config
CONFIG = {
    "interface": "wlan1mon",
    "attack_wpa": True,
    "attack_wps": True,
    "attack_pmkid": True,
    "power": 50,
    "channel": None,
    "clients_only": False,
    "scan_timeout": 12
}

LOGFILE = "/tmp/wifite_gui.log"
ERRFILE = "/tmp/wifite_gui_error.log"

class Network:
    def __init__(self, bssid, essid, channel, power, encryption):
        self.bssid = bssid
        self.essid = essid or "Hidden"
        self.channel = channel
        self.power = power
        self.encryption = encryption

# --------------------
# Utilities
# --------------------
def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(LOGFILE, "a") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass

def log_exc(e):
    try:
        with open(ERRFILE, "a") as f:
            f.write(f"=== {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
            f.write(f"{type(e).__name__}: {e}\n")
            traceback.print_exc(file=f)
    except Exception:
        pass

def safe_subprocess_run(cmd, timeout=None):
    """Run subprocess and return (returncode, stdout+stderr)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)
        out = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode, out
    except Exception as e:
        log(f"Subprocess error: {e}")
        return 1, str(e)

def run_cmd_shell(cmd):
    """Run a shell command string (legacy compatibility)."""
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as e:
        return e.output

def load_pin_config():
    """Attempt to load gui_conf.json from multiple likely locations."""
    global PINS
    possible = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "gui_conf.json"),
        "/root/Raspyjack/gui_conf.json",
        "/root/gui_conf.json",
    ]
    loaded = False
    for path in possible:
        try:
            if os.path.exists(path):
                with open(path, "r") as fh:
                    data = json.load(fh)
                    conf_pins = data.get("PINS", {})
                    PINS = {
                        "UP": conf_pins.get("KEY_UP_PIN", PINS["UP"]),
                        "DOWN": conf_pins.get("KEY_DOWN_PIN", PINS["DOWN"]),
                        "LEFT": conf_pins.get("KEY_LEFT_PIN", PINS["LEFT"]),
                        "RIGHT": conf_pins.get("KEY_RIGHT_PIN", PINS["RIGHT"]),
                        "OK": conf_pins.get("KEY_PRESS_PIN", PINS["OK"]),
                        "KEY1": conf_pins.get("KEY1_PIN", PINS["KEY1"]),
                        "KEY2": conf_pins.get("KEY2_PIN", PINS["KEY2"]),
                        "KEY3": conf_pins.get("KEY3_PIN", PINS["KEY3"]),
                    }
                    log(f"Loaded PINS from {path}")
                    loaded = True
                    break
        except Exception as e:
            log(f"Failed reading {path}: {e}")
            continue
    if not loaded:
        log("gui_conf.json not found; using default PINS")

def get_pressed_button():
    """Return first pressed button or None."""
    for name, pin in PINS.items():
        try:
            if GPIO.input(pin) == 0:
                return name
        except Exception:
            return None
    return None

def get_wifi_interfaces():
    """Return a list of plausible interfaces (prefer monitor suffix)."""
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
            ifaces = [i for i in all_ifaces if i.startswith(('wlan', 'ath', 'ra'))]
            if not ifaces:
                return ["wlan0mon"]
            return ifaces
        except Exception:
            return ["wlan0mon"]

# --------------------
# LCD helpers
# --------------------
def init_lcd():
    global LCD, IMAGE, DRAW, FONT_TITLE, FONT, WIDTH, HEIGHT
    if not HARDWARE_AVAILABLE:
        return
    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    WIDTH, HEIGHT = 128, 128
    IMAGE = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    DRAW = ImageDraw.Draw(IMAGE)
    try:
        FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 14)
    except Exception:
        FONT_TITLE = ImageFont.load_default()
        log("Using default font for title")
    FONT = ImageFont.load_default()

def lcd_show_image():
    """Draw current IMAGE to physical LCD holding UI_LOCK to avoid races."""
    try:
        if not HARDWARE_AVAILABLE:
            return
        with UI_LOCK:
            LCD.LCD_ShowImage(IMAGE, 0, 0)
    except Exception as e:
        log(f"lcd_show_image error: {e}")

def draw_message(lines, color="WHITE"):
    """Centered message on screen."""
    if not HARDWARE_AVAILABLE:
        log("draw_message (no hardware): " + " | ".join(lines))
        return
    with UI_LOCK:
        DRAW.rectangle([(0, 0), (WIDTH, HEIGHT)], fill="BLACK")
        y_offset = (HEIGHT - len(lines) * 12) // 2
        for ln in lines:
            bbox = DRAW.textbbox((0,0), ln, font=FONT_TITLE)
            w = bbox[2] - bbox[0]
            x = (WIDTH - w) // 2
            DRAW.text((x, y_offset), ln, font=FONT_TITLE, fill=color)
            y_offset += 12
        lcd_show_image()

# --------------------
# Scan & parse using airodump (reliable CSV)
# --------------------
def start_scan():
    """
    Launch airodump-ng for CONFIG['scan_timeout'] seconds and parse CSV results.
    Updates NETWORKS list and sets APP_STATE to 'targets' when done.
    """
    global SCAN_PROCESS, NETWORKS, APP_STATE, STATUS_MSG, TARGET_SCROLL_OFFSET
    with UI_LOCK:
        APP_STATE = "scanning"
        STATUS_MSG = "Starting scan..."
        NETWORKS = []
        TARGET_SCROLL_OFFSET = 0

    iface = CONFIG.get("interface", "wlan1mon")
    timeout_s = int(CONFIG.get("scan_timeout", 12))
    out_prefix = "/tmp/wifite_scan"
    # remove old files
    try:
        for f in [f"/tmp/wifite_scan-01.csv", "/tmp/wifite_scan-01.kismet.csv"]:
            if os.path.exists(f):
                os.remove(f)
    except Exception:
        pass

    cmd = ["timeout", str(timeout_s), "airodump-ng", "--band", "abg", "--output-format", "csv", "-w", out_prefix, iface]
    log(f"Starting airodump for {timeout_s}s on {iface}: {' '.join(cmd)}")

    def scan_worker():
        global SCAN_PROCESS, NETWORKS, APP_STATE, STATUS_MSG
        try:
            # Spawn airodump-ng (shell not used)
            SCAN_PROCESS = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            # monitor output for a short period (we also rely on CSV file)
            start = time.time()
            while time.time() - start < timeout_s + 2:
                # update status line
                with UI_LOCK:
                    STATUS_MSG = f"Scanning ({int(max(0, timeout_s - (time.time() - start)))}s)"
                time.sleep(0.25)
                # allow early termination
                if not IS_RUNNING or APP_STATE != "scanning":
                    break

            # ensure process gone
            try:
                SCAN_PROCESS.wait(timeout=1)
            except Exception:
                try:
                    SCAN_PROCESS.terminate()
                except Exception:
                    pass

            # Parse CSV
            csv_path = "/tmp/wifite_scan-01.csv"
            networks = []
            if os.path.exists(csv_path):
                try:
                    with open(csv_path, "r", errors="ignore") as fh:
                        content = fh.read()
                    # Truncate trailing Station MAC section (like your deauth payload)
                    if "Station MAC" in content:
                        content = content.split("Station MAC")[0]
                    lines = [l for l in content.splitlines() if l.strip()]
                    bssid_idx = essid_idx = channel_idx = power_idx = enc_idx = -1
                    header_found = False
                    for line in lines:
                        if not header_found and "BSSID" in line and "ESSID" in line:
                            header_found = True
                            parts = line.split(",")
                            for i, p in enumerate(parts):
                                p_low = p.lower()
                                if "bssid" in p_low:
                                    bssid_idx = i
                                elif "essid" in p_low:
                                    essid_idx = i
                                elif "channel" in p_low:
                                    channel_idx = i
                                elif "power" in p_low or "signal" in p_low:
                                    power_idx = i
                                elif "encryption" in p_low or "enc" in p_low:
                                    enc_idx = i
                            continue
                        if header_found:
                            parts = line.split(",")
                            # Safe access
                            try:
                                bssid = parts[bssid_idx].strip()
                                essid = parts[essid_idx].strip().strip('"') if essid_idx >= 0 else ""
                                ch = parts[channel_idx].strip() if channel_idx >= 0 else "?"
                                pwr = parts[power_idx].strip() if power_idx >= 0 else "?"
                                enc = parts[enc_idx].strip() if enc_idx >= 0 else ""
                            except Exception:
                                continue
                            if bssid and ":" in bssid:
                                networks.append(Network(bssid, essid, ch, pwr, enc))
                except Exception as e:
                    log(f"Error parsing csv: {e}")
            else:
                log("CSV scan file not found after airodump")

            with UI_LOCK:
                NETWORKS = networks
                APP_STATE = "targets"
                STATUS_MSG = f"Found {len(NETWORKS)}"
        except Exception as e:
            log_exc(e)
            with UI_LOCK:
                STATUS_MSG = f"Scan error"
                APP_STATE = "menu"

    threading.Thread(target=scan_worker, daemon=True).start()

# --------------------
# Attack (launch wifite if present) - non-blocking thread
# --------------------
def start_attack(network):
    global ATTACK_PROCESS, APP_STATE, ATTACK_TARGET, CRACKED_PASSWORD, STATUS_MSG
    if not network:
        return
    with UI_LOCK:
        APP_STATE = "attacking"
        ATTACK_TARGET = network
        CRACKED_PASSWORD = None
        STATUS_MSG = "Starting attack..."

    # detect wifite
    wifite_path = shutil.which("wifite")
    if not wifite_path:
        with UI_LOCK:
            STATUS_MSG = "wifite not found"
            APP_STATE = "targets"
        return

    cmd = [wifite_path, "-i", CONFIG.get("interface", "wlan1mon"), "--bssid", network.bssid]
    # respect config toggles (simple)
    if not CONFIG.get("attack_wps", True):
        cmd.append("--no-wps")
    if not CONFIG.get("attack_wpa", True):
        cmd.append("--no-wpa")
    if not CONFIG.get("attack_pmkid", True):
        cmd.append("--no-pmkid")
    if CONFIG.get("clients_only"):
        cmd.append("--clients-only")

    log(f"Launching wifite: {' '.join(cmd)}")

    def attack_worker():
        global ATTACK_PROCESS, CRACKED_PASSWORD, APP_STATE, STATUS_MSG
        try:
            ATTACK_PROCESS = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            start = time.time()
            # stream output for status heuristics (look for keywords)
            for line in iter(ATTACK_PROCESS.stdout.readline, ""):
                if not line:
                    break
                l = line.lower()
                with UI_LOCK:
                    if "wps pin" in l: STATUS_MSG = "WPS PIN attack..."
                    elif "wpa handshake" in l: STATUS_MSG = "WPA handshake..."
                    elif "pmkid" in l: STATUS_MSG = "PMKID..."
                    elif "cracked" in l:
                        try:
                            # attempt to extract quoted password if present
                            CRACKED_PASSWORD = line.split('"')[1]
                        except Exception:
                            CRACKED_PASSWORD = "See logs"
                        break
                    elif "failed" in l: STATUS_MSG = "Attack failed"
                # allow user to abort
                with UI_LOCK:
                    if not IS_RUNNING or APP_STATE != "attacking":
                        break
            # ensure process ends
            try:
                ATTACK_PROCESS.wait(timeout=2)
            except Exception:
                try:
                    ATTACK_PROCESS.terminate()
                except Exception:
                    pass
            with UI_LOCK:
                if CRACKED_PASSWORD:
                    APP_STATE = "results"
                else:
                    if APP_STATE == "attacking":
                        APP_STATE = "targets"
        except Exception as e:
            log_exc(e)
            with UI_LOCK:
                STATUS_MSG = "Attack error"
                APP_STATE = "targets"

    threading.Thread(target=attack_worker, daemon=True).start()

def stop_scan_or_attack():
    global SCAN_PROCESS, ATTACK_PROCESS, APP_STATE
    try:
        if SCAN_PROCESS and SCAN_PROCESS.poll() is None:
            try: SCAN_PROCESS.terminate()
            except: pass
            SCAN_PROCESS = None
        if ATTACK_PROCESS and ATTACK_PROCESS.poll() is None:
            try: ATTACK_PROCESS.terminate()
            except: pass
            ATTACK_PROCESS = None
    except Exception:
        pass
    with UI_LOCK:
        APP_STATE = "menu"

# --------------------
# Cleanup & Signals
# --------------------
def cleanup_handler(signum=None, frame=None):
    global IS_RUNNING
    IS_RUNNING = False
    stop_scan_or_attack()
    try:
        # try to restore networking/processes as your other payloads do
        run_cmd_shell("pkill -f wifite 2>/dev/null || true")
        run_cmd_shell("pkill -f airodump-ng 2>/dev/null || true")
    except Exception:
        pass
    try:
        if HARDWARE_AVAILABLE:
            with UI_LOCK:
                LCD.LCD_Clear()
    except Exception:
        pass
    try:
        GPIO.cleanup()
    except Exception:
        pass
    log("Cleanup complete")
    # don't sys.exit here (caller will handle)

signal.signal(signal.SIGINT, cleanup_handler)
signal.signal(signal.SIGTERM, cleanup_handler)

# --------------------
# UI render helpers
# --------------------
def draw_main_menu(menu_sel):
    with UI_LOCK:
        DRAW.rectangle([(0,0),(WIDTH,HEIGHT)], fill="BLACK")
        DRAW.text((28, 10), "Wifite GUI", font=FONT_TITLE, fill="WHITE")
        DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
        options = ["Start Scan", "Settings", "Exit"]
        for i, option in enumerate(options):
            fill = "WHITE"
            y_pos = 40 + i * 25
            if i == menu_sel:
                DRAW.rectangle([(5, y_pos - 2), (123, y_pos + 15)], fill="#003366")
                fill = "#FFFF00"
            DRAW.text((20, y_pos), option, font=FONT_TITLE, fill=fill)
        lcd_show_image()

def draw_scanning(status_msg):
    with UI_LOCK:
        DRAW.rectangle([(0,0),(WIDTH,HEIGHT)], fill="BLACK")
        DRAW.text((25, 40), "Scanning...", font=FONT_TITLE, fill="WHITE")
        if status_msg:
            DRAW.text((10, 60), status_msg, font=FONT, fill="#00FF00")
        DRAW.text((10, 110), "KEY3=Exit | LEFT=Back", font=FONT, fill="#888")
        lcd_show_image()

def draw_targets(menu_sel, scroll_offset):
    with UI_LOCK:
        DRAW.rectangle([(0,0),(WIDTH,HEIGHT)], fill="BLACK")
        DRAW.text((20, 5), "Select Target", font=FONT_TITLE, fill="WHITE")
        DRAW.line([(0, 22), (128, 22)], fill="#333", width=1)
        local_networks = NETWORKS[:]
        if not local_networks:
            DRAW.text((10, 50), "No networks found.", font=FONT_TITLE, fill="WHITE")
        else:
            visible_items = 6
            # ensure scroll_offset valid
            if menu_sel < scroll_offset:
                scroll_offset = menu_sel
            if menu_sel >= scroll_offset + visible_items:
                scroll_offset = menu_sel - visible_items + 1
            y_base = 25
            for i in range(scroll_offset, min(len(local_networks), scroll_offset + visible_items)):
                network = local_networks[i]
                display_y = y_base + (i - scroll_offset) * 16
                fill = "WHITE"
                if i == menu_sel:
                    DRAW.rectangle([(0, display_y - 2), (128, display_y + 13)], fill="#003366")
                    fill = "#FFFF00"
                DRAW.text((5, display_y), network.essid[:14], font=FONT, fill=fill)
                DRAW.text((90, display_y), f"{network.power}dBm", font=FONT, fill=fill)
        lcd_show_image()
        return scroll_offset

def draw_attacking(attack_target, status_msg):
    with UI_LOCK:
        DRAW.rectangle([(0,0),(WIDTH,HEIGHT)], fill="BLACK")
        if attack_target:
            DRAW.text((5, 5), "Attacking:", font=FONT, fill="WHITE")
            DRAW.text((5, 20), attack_target.essid[:18], font=FONT_TITLE, fill="#FF0000")
            DRAW.line([(0, 38), (128, 38)], fill="#333", width=1)
        if status_msg:
            DRAW.text((5, 45), status_msg, font=FONT, fill="#00FF00")
        DRAW.text((10, 110), "KEY3=Exit | LEFT=Back", font=FONT, fill="#888")
        lcd_show_image()

def draw_results(cracked_password):
    with UI_LOCK:
        DRAW.rectangle([(0,0),(WIDTH,HEIGHT)], fill="BLACK")
        DRAW.text((40, 10), "Result", font=FONT_TITLE, fill="WHITE")
        DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
        if cracked_password:
            DRAW.text((35, 40), "Success!", font=FONT_TITLE, fill="#00FF00")
            DRAW.text((5, 60), "Password:", font=FONT, fill="WHITE")
            DRAW.text((5, 75), cracked_password, font=FONT_TITLE, fill="#00FF00")
        else:
            DRAW.text((40, 40), "Failed", font=FONT_TITLE, fill="#FF0000")
            DRAW.text((5, 60), "Could not crack network.", font=FONT, fill="WHITE")
        DRAW.text((15, 110), "Press any key...", font=FONT, fill="#888")
        lcd_show_image()

# --------------------
# Main
# --------------------
def main_loop():
    global MENU_SELECTION, APP_STATE, IS_RUNNING, TARGET_SCROLL_OFFSET, NETWORKS, STATUS_MSG, MENU_SELECTION
    last_button_press_time = 0
    BUTTON_DEBOUNCE_TIME = 0.25

    while IS_RUNNING:
        try:
            current_time = time.time()
            with UI_LOCK:
                current_state = APP_STATE
                menu_sel = MENU_SELECTION
                status_msg = STATUS_MSG
                attack_t = ATTACK_TARGET
                cracked_pw = CRACKED_PASSWORD

            # Render UI per-state
            if current_state == "menu":
                draw_main_menu(menu_sel)
            elif current_state == "scanning":
                draw_scanning(status_msg)
            elif current_state == "targets":
                # compute scroll_offset and draw
                TARGET_SCROLL_OFFSET = draw_targets(menu_sel, TARGET_SCROLL_OFFSET)
            elif current_state == "attacking":
                draw_attacking(attack_t, status_msg)
            elif current_state == "results":
                draw_results(cracked_pw)
            elif current_state == "settings":
                # Minimal settings rendering
                with UI_LOCK:
                    DRAW.rectangle([(0,0),(WIDTH,HEIGHT)], fill="BLACK")
                    DRAW.text((35, 10), "Settings", font=FONT_TITLE, fill="WHITE")
                    DRAW.line([(10,30),(118,30)], fill="#333", width=1)
                    DRAW.text((10, 45), f"Interface: {CONFIG.get('interface')}", font=FONT, fill="WHITE")
                    DRAW.text((10, 60), f"Scan: {CONFIG.get('scan_timeout')}s", font=FONT, fill="WHITE")
                    DRAW.text((10, 110), "LEFT Back", font=FONT, fill="#888")
                    lcd_show_image()

            # Input handling (debounced)
            pressed = None
            try:
                pressed = get_pressed_button()
            except Exception:
                pressed = None

            if pressed == "KEY3" and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                last_button_press_time = current_time
                # quick exit
                IS_RUNNING = False
                break

            # State machine input handling
            if current_state == "menu":
                if pressed == "OK" and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    if menu_sel == 0:
                        start_scan()
                    elif menu_sel == 1:
                        with UI_LOCK:
                            APP_STATE = "settings"; MENU_SELECTION = 0
                    elif menu_sel == 2:
                        IS_RUNNING = False
                        break
                elif pressed == "UP" and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK:
                        MENU_SELECTION = (menu_sel - 1) % 3
                elif pressed == "DOWN" and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK:
                        MENU_SELECTION = (menu_sel + 1) % 3

            elif current_state == "scanning":
                if pressed == "LEFT" and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK:
                        APP_STATE = "menu"
                        MENU_SELECTION = 0

            elif current_state == "targets":
                with UI_LOCK:
                    local_len = len(NETWORKS)
                    ms = MENU_SELECTION
                if pressed == "UP" and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK:
                        if local_len:
                            MENU_SELECTION = max(0, ms - 1)
                elif pressed == "DOWN" and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK:
                        if local_len:
                            MENU_SELECTION = min(local_len - 1, ms + 1)
                elif pressed == "OK" and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    # launch attack on selection
                    with UI_LOCK:
                        if NETWORKS:
                            sel = MENU_SELECTION
                            try:
                                start_attack(NETWORKS[sel])
                            except Exception as e:
                                log_exc(e)
                elif pressed == "LEFT" and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK:
                        APP_STATE = "menu"; MENU_SELECTION = 0

            elif current_state == "attacking":
                if pressed == "LEFT" and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    # stop current attack and return to targets
                    stop_scan_or_attack()
                    with UI_LOCK:
                        APP_STATE = "targets"
                elif pressed == "KEY2" and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    stop_scan_or_attack()
                    with UI_LOCK:
                        APP_STATE = "targets"

            elif current_state == "results":
                if pressed and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK:
                        APP_STATE = "menu"; MENU_SELECTION = 0

            elif current_state == "settings":
                if pressed == "LEFT" and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with UI_LOCK:
                        APP_STATE = "menu"; MENU_SELECTION = 1

            time.sleep(0.05)

        except Exception as e:
            log_exc(e)
            # try to recover to menu
            with UI_LOCK:
                APP_STATE = "menu"
                STATUS_MSG = "Error - see logs"
            time.sleep(1)

# --------------------
# Entrypoint
# --------------------
if __name__ == "__main__":
    try:
        # init
        load_pin_config()
        if HARDWARE_AVAILABLE:
            GPIO.setmode(GPIO.BCM)
            for p in PINS.values():
                try:
                    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)
                except Exception:
                    pass
            init_lcd()
            draw_message(["Wifite GUI", "Initializing..."])
            time.sleep(1)
        else:
            print("WARNING: Hardware unavailable; running in degraded mode", file=sys.stderr)

        # pick initial interface
        if WIFI_INTEGRATION:
            try:
                ifaces = get_available_interfaces()
                if ifaces:
                    CONFIG['interface'] = ifaces[0]
            except Exception:
                pass
        else:
            # attempt to discover monitor-ish interface
            ifaces = get_wifi_interfaces()
            CONFIG['interface'] = ifaces[0] if ifaces else CONFIG['interface']

        # quick validation: check airodump-ng and wifite presence
        airodump_ok = (shutil.which("airodump-ng") is not None)
        wifite_ok = (shutil.which("wifite") is not None)
        if not airodump_ok:
            draw_message(["airodump-ng missing", "Install aircrack-ng"], "RED")
            time.sleep(3)
        else:
            log("airodump-ng found")
        if not wifite_ok:
            log("wifite not found; attacks via wifite will be disabled (must install)")

        # Enter main loop
        main_loop()

    except SystemExit:
        pass
    except Exception as e:
        # write fatal traceback
        try:
            with open(ERRFILE, "w") as f:
                f.write(f"FATAL: {type(e).__name__}: {e}\n")
                traceback.print_exc(file=f)
        except Exception:
            pass
    finally:
        # cleanup
        try:
            if HARDWARE_AVAILABLE:
                LCD.LCD_Clear()
        except Exception:
            pass
        try:
            GPIO.cleanup()
        except Exception:
            pass
        log("wifite_gui terminated")

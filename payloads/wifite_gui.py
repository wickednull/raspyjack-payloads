#!/usr/bin/env python3
"""
RaspyJack *payload* – **Wifite GUI**
==================================
This payload provides a graphical wrapper for Wifite, built by adapting the
working architecture of the 'attack_ethernet_link_manipulator.py' payload.
"""
import sys
import os
import time
import signal
import subprocess
import threading

# This path modification is required for payloads to find Raspyjack libraries.
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

try:
    import RPi.GPIO as GPIO
    import LCD_1in44, LCD_Config
    from PIL import Image, ImageDraw, ImageFont
    HARDWARE_AVAILABLE = True
except ImportError:
    print("FATAL: Hardware libraries not found.", file=sys.stderr)
    sys.exit(1)

# --- Constants and Globals ---
PINS: dict[str, int] = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "SELECT": 13,
    "KEY1": 21, "KEY2": 20, "KEY3": 16,
}

# Hardware objects initialized in the global scope
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
try:
    FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 14)
    FONT = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 11)
except IOError:
    FONT_TITLE = ImageFont.load_default()
    FONT = ImageFont.load_default()

# State Machine and UI Globals
IS_RUNNING = True
APP_STATE = "menu"
MENU_SELECTION = 0
STATUS_MSG = "Ready"
UI_LOCK = threading.Lock()

# Wifite-specific Globals
NETWORKS = []
TARGET_SCROLL_OFFSET = 0
SCAN_PROCESS, ATTACK_PROCESS = None, None
ATTACK_TARGET, CRACKED_PASSWORD = None, None
CONFIG = {
    "interface": "wlan1mon", "attack_wpa": True, "attack_wps": True,
    "attack_pmkid": True, "power": 50, "channel": None, "clients_only": False
}
class Network:
    def __init__(self, bssid, essid, channel, power, encryption):
        self.bssid, self.essid, self.channel, self.power, self.encryption = bssid, essid if essid else "Hidden", channel, power, encryption

# --- Signal Handling and Cleanup ---
def cleanup_handler(*_):
    global IS_RUNNING
    IS_RUNNING = False

signal.signal(signal.SIGINT, cleanup_handler)
signal.signal(signal.SIGTERM, cleanup_handler)

# --- UI Drawing Functions ---
def draw_ui():
    global TARGET_SCROLL_OFFSET
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)

    with UI_LOCK:
        if APP_STATE == "menu":
            d.text((28, 10), "Wifite GUI", font=FONT_TITLE, fill="WHITE")
            d.line([(10, 30), (118, 30)], fill="#333", width=1)
            options = ["Start Scan", "Settings", "Exit"]
            for i, option in enumerate(options):
                fill = "WHITE"; y_pos = 40 + i * 25
                if i == MENU_SELECTION:
                    d.rectangle([(5, y_pos - 2), (123, y_pos + 15)], fill="#003366"); fill = "#FFFF00"
                d.text((20, y_pos), option, font=FONT_TITLE, fill=fill)

        elif APP_STATE == "scanning":
            d.text((25, 40), "Scanning...", font=FONT_TITLE, fill="WHITE")
            if STATUS_MSG: d.text((10, 60), STATUS_MSG, font=FONT, fill="#00FF00")
            d.text("KEY3=Exit | LEFT=Back", (10, 110), font=FONT, fill="#888")

        elif APP_STATE == "targets":
            d.text((20, 5), "Select Target", font=FONT_TITLE, fill="WHITE"); d.line([(0, 22), (128, 22)], fill="#333", width=1)
            if not NETWORKS: d.text((10, 50), "No networks found.", font=FONT_TITLE, fill="WHITE")
            else:
                visible_items = 6
                if MENU_SELECTION < TARGET_SCROLL_OFFSET: TARGET_SCROLL_OFFSET = MENU_SELECTION
                if MENU_SELECTION >= TARGET_SCROLL_OFFSET + visible_items: TARGET_SCROLL_OFFSET = MENU_SELECTION - visible_items + 1
                for i in range(TARGET_SCROLL_OFFSET, TARGET_SCROLL_OFFSET + visible_items):
                    if i >= len(NETWORKS): break
                    network = NETWORKS[i]; display_y = 25 + (i - TARGET_SCROLL_OFFSET) * 16; fill = "WHITE"
                    if i == MENU_SELECTION: d.rectangle([(0, display_y - 2), (128, display_y + 13)], fill="#003366"); fill = "#FFFF00"
                    d.text(f"{network.essid[:14]}", (5, display_y), font=FONT, fill=fill)
                    d.text(f"{network.power}dBm", (90, display_y), font=FONT, fill=fill)
        
        # Add other state renders here...
        
    LCD.LCD_ShowImage(img, 0, 0)

# --- Wifite Logic Functions ---
def get_interfaces():
    try:
        all_ifaces = os.listdir('/sys/class/net/')
        return [i for i in all_ifaces if i.startswith(('wlan', 'ath', 'ra'))] or ["wlan0mon"]
    except FileNotFoundError:
        return ["wlan0mon"]

def start_scan():
    global STATUS_MSG, NETWORKS, MENU_SELECTION, TARGET_SCROLL_OFFSET, SCAN_PROCESS, APP_STATE
    APP_STATE = "scanning"
    STATUS_MSG = "Starting..."; NETWORKS = []; MENU_SELECTION = 0; TARGET_SCROLL_OFFSET = 0
    
    cmd = ["wifite", "--csv", "-i", CONFIG['interface'], '--power', str(CONFIG['power'])]
    # Add other config flags...
    
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

# --- Main Application Logic ---
if __name__ == "__main__":
    last_button_press_time = 0
    BUTTON_DEBOUNCE_TIME = 0.2

    try:
        while IS_RUNNING:
            current_time = time.time()
            
            # --- Input Handling ---
            button_pressed = None
            if current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME:
                for name, pin in PINS.items():
                    if GPIO.input(pin) == 0:
                        button_pressed = name
                        last_button_press_time = current_time
                        break
            
            if button_pressed == "KEY3":
                IS_RUNNING = False
                continue

            # --- State Machine ---
            if APP_STATE == "menu":
                if button_pressed == "SELECT":
                    if MENU_SELECTION == 0: start_scan()
                    elif MENU_SELECTION == 1: pass # TODO: Settings
                    elif MENU_SELECTION == 2: IS_RUNNING = False
                elif button_pressed == "UP": MENU_SELECTION = (MENU_SELECTION - 1) % 3
                elif button_pressed == "DOWN": MENU_SELECTION = (MENU_SELECTION + 1) % 3
            
            elif APP_STATE == "scanning":
                if button_pressed == "LEFT":
                    if SCAN_PROCESS: SCAN_PROCESS.terminate()
                    APP_STATE = "menu"

            elif APP_STATE == "targets":
                if button_pressed == "UP": MENU_SELECTION = max(0, MENU_SELECTION - 1)
                elif button_pressed == "DOWN": 
                    if NETWORKS: MENU_SELECTION = min(len(NETWORKS) - 1, MENU_SELECTION + 1)
                elif button_pressed == "SELECT": pass # TODO: Start attack
                elif button_pressed == "LEFT": APP_STATE = "menu"

            # --- Drawing ---
            draw_ui()
            
            time.sleep(0.05)

    except SystemExit:
        pass
    except Exception as e:
        print(f"Critical error: {e}", file=sys.stderr)
        # Attempt to draw error to screen
        try:
            d = ImageDraw.Draw(IMAGE)
            d.rectangle([(0,0), (128,128)], fill="BLACK")
            d.text((5,5), "FATAL ERROR:", font=FONT, fill="RED")
            d.text((5,20), str(e)[:20], font=FONT, fill="RED")
            LCD.LCD_ShowImage(IMAGE, 0, 0)
            time.sleep(5)
        except:
            pass
    finally:
        cleanup_handler()
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Wifite GUI payload finished.")
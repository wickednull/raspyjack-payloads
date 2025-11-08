#!/usr/bin/env python3
"""
RaspyJack *payload* – **Unified Loot Viewer**
==============================================
This utility scans the loot directories of various attack modules (Responder,
DNSSpoof, Evil Twin) and displays all captured credentials and hashes in a
single, unified, scrollable list.

Features:
1.  Defines paths for multiple loot sources.
2.  Parses different loot file formats to extract relevant data.
3.  Handles missing loot files gracefully.
4.  Presents the combined loot in a clean, scrollable UI.
5.  Allows the user to refresh the data on demand.
"""

# ---------------------------------------------------------------------------
# 0) Imports & boilerplate
# ---------------------------------------------------------------------------
import os, sys, re, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

# ---------------------------- Third‑party libs ----------------------------
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

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
LOOT_SOURCES = {
    "Responder": "/root/Raspyjack/Responder/logs/",
    "DNSSpoof": "/root/Raspyjack/DNSSpoof/captures/",
    "EvilTwin": "/root/Raspyjack/DNSSpoof/sites/wifi/" # Assuming same loot file
}
loot_items = []
selected_index = 0
running = True

# ---------------------------------------------------------------------------
# 4) Graceful shutdown
# ---------------------------------------------------------------------------
def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 5) Loot Parsing Functions
# ---------------------------------------------------------------------------
def parse_responder_log(file_path):
    """Parses Responder log files for hashes."""
    items = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                if "NTLMv2-SSP" in line:
                    match = re.search(r'::\s*(.*?)\s*::', line)
                    if match:
                        user_info = match.group(1).strip()
                        items.append(f"RESP: {user_info}")
    except Exception:
        pass
    return items

def parse_phishing_log(file_path, source_name):
    """Parses generic username/password log files."""
    items = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                if "user:" in line and "pass:" in line:
                    parts = line.split('|')
                    user = parts[1].split(':')[1].strip()
                    password = parts[2].split(':')[1].strip()
                    items.append(f"{source_name}: {user}:{password}")
    except Exception:
        pass
    return items

def gather_loot():
    """Scans all loot sources and aggregates the findings."""
    global loot_items
    loot_items = []
    
    # Responder
    if os.path.isdir(LOOT_SOURCES["Responder"]):
        for filename in os.listdir(LOOT_SOURCES["Responder"]):
            if filename.endswith(".txt"):
                loot_items.extend(parse_responder_log(os.path.join(LOOT_SOURCES["Responder"], filename)))

    # DNSSpoof
    if os.path.isdir(LOOT_SOURCES["DNSSpoof"]):
        loot_file = os.path.join(LOOT_SOURCES["DNSSpoof"], "ip.txt")
        if os.path.exists(loot_file):
            loot_items.extend(parse_phishing_log(loot_file, "DNS"))
            
    # Evil Twin
    if os.path.isdir(LOOT_SOURCES["EvilTwin"]):
        loot_file = os.path.join(LOOT_SOURCES["EvilTwin"], "ip.txt")
        if os.path.exists(loot_file):
            loot_items.extend(parse_phishing_log(loot_file, "ETWIN"))

# ---------------------------------------------------------------------------
# 6) UI Functions
# ---------------------------------------------------------------------------
def draw_ui():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)

    d.text((5, 5), "Unified Loot Viewer", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    if not loot_items:
        d.text((20, 60), "No loot found.", font=FONT, fill="white")
    else:
        start_display_index = max(0, selected_index - 3)
        end_display_index = min(len(loot_items), start_display_index + 7)
        
        y_pos = 25
        for i in range(start_display_index, end_display_index):
            color = "yellow" if i == selected_index else "white"
            # Truncate long lines
            item_text = loot_items[i]
            if len(item_text) > 20:
                item_text = item_text[:19] + "..."
            d.text((5, y_pos), item_text, font=FONT, fill=color)
            y_pos += 12

    d.text((5, 110), "OK=Refresh | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# 7) Main Loop
# ---------------------------------------------------------------------------
try:
    draw_ui() # Initial draw before gathering
    gather_loot()

    while running:
        draw_ui()
        
        button_pressed = False
        start_wait = time.time()
        while time.time() - start_wait < 5.0 and not button_pressed: # Refresh every 5s or on button
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            if GPIO.input(PINS["UP"]) == 0:
                if loot_items:
                    selected_index = (selected_index - 1) % len(loot_items)
                button_pressed = True
            elif GPIO.input(PINS["DOWN"]) == 0:
                if loot_items:
                    selected_index = (selected_index + 1) % len(loot_items)
                button_pressed = True
            elif GPIO.input(PINS["OK"]) == 0:
                gather_loot()
                selected_index = 0
                button_pressed = True
            
            time.sleep(0.05)
        
        if not running:
            break

except (KeyboardInterrupt, SystemExit):
    pass
except Exception as e:
    print(f"[ERROR] {e}", file=sys.stderr)
finally:
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("Loot Viewer payload finished.")

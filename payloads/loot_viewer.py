#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
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
# ---------------------------- Third‑party libs ----------------------------
try:
    import RPi.GPIO as GPIO
    import LCD_1in44, LCD_Config
    from PIL import Image, ImageDraw, ImageFont
    HARDWARE_LIBS_AVAILABLE = True
except ImportError:
    HARDWARE_LIBS_AVAILABLE = False
    print("WARNING: RPi.GPIO or LCD drivers not available. UI will not function.", file=sys.stderr)

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
if HARDWARE_LIBS_AVAILABLE:
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    WIDTH, HEIGHT = 128, 128
    FONT = ImageFont.load_default()
    FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
else:
    # Dummy objects if hardware libs are not available
    class DummyLCD:
        def LCD_Init(self, *args): pass
        def LCD_Clear(self): pass
        def LCD_ShowImage(self, *args): pass
    LCD = DummyLCD()
    WIDTH, HEIGHT = 128, 128
    class DummyGPIO:
        def setmode(self, *args): pass
        def setup(self, *args): pass
        def input(self, pin): return 1 # Simulate no button pressed
        def cleanup(self): pass
    GPIO = DummyGPIO()
    class DummyImageFont:
        def truetype(self, *args, **kwargs): return None
        def load_default(self): return None
    ImageFont = DummyImageFont()
    FONT_TITLE = ImageFont.load_default() # Fallback to default font
    FONT = ImageFont.load_default() # Fallback to default font

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
current_loot_source_name = "" # For adding new source
current_loot_source_path = "" # For adding new source
loot_source_path_cursor_pos = 0

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
    except FileNotFoundError:
        pass # File might not exist yet
    except Exception as e:
        print(f"Error parsing Responder log {file_path}: {e}", file=sys.stderr)
    return items

def parse_phishing_log(file_path, source_name):
    """Parses generic username/password log files."""
    items = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                # Assuming format like "user:username | pass:password"
                if "user:" in line and "pass:" in line:
                    parts = line.split('|')
                    user = parts[0].split(':')[1].strip() if len(parts) > 0 and "user:" in parts[0] else "N/A"
                    password = parts[1].split(':')[1].strip() if len(parts) > 1 and "pass:" in parts[1] else "N/A"
                    items.append(f"{source_name}: {user}:{password}")
                elif "user=" in line and "pass=" in line: # Another common format
                    match = re.search(r'user=(.*?)\s+pass=(.*)', line)
                    if match:
                        user = match.group(1).strip()
                        password = match.group(2).strip()
                        items.append(f"{source_name}: {user}:{password}")
                else: # Fallback for simple lines
                    items.append(f"{source_name}: {line.strip()}")
    except FileNotFoundError:
        pass # File might not exist yet
    except Exception as e:
        print(f"Error parsing phishing log {file_path}: {e}", file=sys.stderr)
    return items

def gather_loot():
    """Scans all loot sources and aggregates the findings."""
    global loot_items
    loot_items = []
    
    for name, path in LOOT_SOURCES.items():
        if not os.path.isdir(path):
            print(f"Loot source directory not found: {path}", file=sys.stderr)
            continue

        if name == "Responder":
            for filename in os.listdir(path):
                if filename.endswith(".txt"):
                    loot_items.extend(parse_responder_log(os.path.join(path, filename)))
        elif name in ["DNSSpoof", "EvilTwin"]:
            # Assuming ip.txt is the common log file for these
            loot_file = os.path.join(path, "ip.txt")
            if os.path.exists(loot_file):
                loot_items.extend(parse_phishing_log(loot_file, name))
        # Add more parsers for other loot types here
        # Example for Nmap scans:
        elif name == "Nmap":
            for filename in os.listdir(path):
                if filename.endswith(".txt") or filename.endswith(".nmap"):
                    try:
                        with open(os.path.join(path, filename), "r") as f:
                            for line in f:
                                if "Host is up" in line or "open" in line:
                                    loot_items.append(f"NMAP: {line.strip()}")
                    except Exception as e:
                        print(f"Error parsing Nmap log {filename}: {e}", file=sys.stderr)

# ---------------------------------------------------------------------------
# 6) UI Functions
# ---------------------------------------------------------------------------
def show_message(lines, color="lime"):
    if not HARDWARE_LIBS_AVAILABLE:
        for line in lines:
            print(line)
        return
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    font = FONT_TITLE # Use FONT_TITLE for messages
    y = 40
    for line in lines:
        bbox = d.textbbox((0, 0), line, font=font)
        w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        x = (128 - w) // 2
        d.text((x, y), line, font=font, fill=color)
        y += h + 5
    LCD.LCD_ShowImage(img, 0, 0)

def draw_ui(screen_state="main"):
    if not HARDWARE_LIBS_AVAILABLE:
        print(f"UI State: {screen_state}")
        if screen_state == "main":
            print(f"Loot Items: {len(loot_items)}")
        return

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)

    d.text((5, 5), "Unified Loot Viewer", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    if screen_state == "main":
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

        d.text((5, 115), "OK=Refresh | KEY1=Add Source | KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "add_source_name":
        d.text((5, 30), "New Source Name:", font=FONT, fill="white")
        display_name = list(current_loot_source_name)
        if len(display_name) > 0 and loot_source_path_cursor_pos < len(display_name):
            display_name[loot_source_path_cursor_pos] = '_'
        d.text((5, 50), "".join(display_name[:16]), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Char | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "add_source_path":
        d.text((5, 30), "New Source Path:", font=FONT, fill="white")
        display_path = list(current_loot_source_path)
        if len(display_path) > 0 and loot_source_path_cursor_pos < len(display_path):
            display_path[loot_source_path_cursor_pos] = '_'
        d.text((5, 50), "".join(display_path[:16]), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Char | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    
    LCD.LCD_ShowImage(img, 0, 0)

def handle_text_input_logic(initial_text, screen_state_name, char_set):
    global current_loot_source_name, current_loot_source_path, loot_source_path_cursor_pos
    
    if screen_state_name == "add_source_name":
        current_input_ref = current_loot_source_name
    else: # add_source_path
        current_input_ref = current_loot_source_path

    current_input_ref = initial_text
    loot_source_path_cursor_pos = len(initial_text) - 1
    
    draw_ui(screen_state_name)
    
    while running:
        btn = None
        for name, pin in PINS.items():
            if GPIO.input(pin) == 0:
                btn = name
                while GPIO.input(pin) == 0: # Debounce
                    time.sleep(0.05)
                break
        
        if btn == "KEY3": # Cancel input
            return None
        
        if btn == "OK": # Confirm input
            if current_input_ref: # Basic validation
                return current_input_ref
            else:
                show_message(["Input cannot", "be empty!"], "red")
                time.sleep(2)
                current_input_ref = initial_text
                loot_source_path_cursor_pos = len(initial_text) - 1
                draw_ui(screen_state_name)
        
        if btn == "LEFT":
            loot_source_path_cursor_pos = max(0, loot_source_path_cursor_pos - 1)
            draw_ui(screen_state_name)
        elif btn == "RIGHT":
            loot_source_path_cursor_pos = min(len(current_input_ref), loot_source_path_cursor_pos + 1)
            draw_ui(screen_state_name)
        elif btn == "UP" or btn == "DOWN":
            if loot_source_path_cursor_pos < len(current_input_ref):
                char_list = list(current_input_ref)
                current_char = char_list[loot_source_path_cursor_pos]
                
                try:
                    char_index = char_set.index(current_char)
                    if btn == "UP":
                        char_index = (char_index + 1) % len(char_set)
                    else: # DOWN
                        char_index = (char_index - 1 + len(char_set)) % len(char_set)
                    char_list[loot_source_path_cursor_pos] = char_set[char_index]
                    current_input_ref = "".join(char_list)
                except ValueError: # If current char is not in char_set
                    char_list[loot_source_path_cursor_pos] = char_set[0] # Default to first char
                    current_input_ref = "".join(char_list)
                draw_ui(screen_state_name)
        
        time.sleep(0.1)
    return None

# ---------------------------------------------------------------------------
# 7) Main Loop
# ---------------------------------------------------------------------------
if not HARDWARE_LIBS_AVAILABLE:
    print("ERROR: Hardware libraries (RPi.GPIO, LCD drivers, PIL) are not available. Cannot run Loot Viewer.", file=sys.stderr)
    sys.exit(1)

current_screen = "main"
try:
    draw_ui("main") # Initial draw before gathering
    gather_loot()

    while running:
        if current_screen == "main":
            draw_ui("main")
            
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            if GPIO.input(PINS["OK"]) == 0:
                gather_loot()
                selected_index = 0
                time.sleep(0.3) # Debounce
            
            if GPIO.input(PINS["UP"]) == 0:
                if loot_items:
                    selected_index = (selected_index - 1) % len(loot_items)
                time.sleep(0.3) # Debounce
            elif GPIO.input(PINS["DOWN"]) == 0:
                if loot_items:
                    selected_index = (selected_index + 1) % len(loot_items)
                time.sleep(0.3) # Debounce
            
            if GPIO.input(PINS["KEY1"]) == 0: # Add new loot source
                current_loot_source_name = ""
                current_screen = "add_source_name"
                time.sleep(0.3) # Debounce
        
        elif current_screen == "add_source_name":
            char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
            new_name = handle_text_input_logic(current_loot_source_name, "add_source_name", char_set)
            if new_name:
                current_loot_source_name = new_name
                current_loot_source_path = "" # Reset path input
                current_screen = "add_source_path"
            else:
                current_screen = "main"
            time.sleep(0.3) # Debounce
        
        elif current_screen == "add_source_path":
            char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-"
            new_path = handle_text_input_logic(current_loot_source_path, "add_source_path", char_set)
            if new_path:
                if os.path.isdir(new_path):
                    LOOT_SOURCES[current_loot_source_name] = new_path
                    show_message(["Source added!", f"{current_loot_source_name}"], "lime")
                    time.sleep(2)
                    gather_loot() # Re-gather loot with new source
                else:
                    show_message(["Invalid Path!", "Not found."], "red")
                    time.sleep(2)
            current_screen = "main"
            time.sleep(0.3) # Debounce
        
        time.sleep(0.1)

except (KeyboardInterrupt, SystemExit):
    pass
except Exception as e:
    print(f"[ERROR] {e}", file=sys.stderr)
    show_message(["CRITICAL ERROR:", str(e)[:20]], "red")
    time.sleep(3)
finally:
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("Loot Viewer payload finished.")

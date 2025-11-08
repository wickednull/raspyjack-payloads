#!/usr/bin/env python3
"""
RaspyJack *payload* – **Evil: Filesystem Decryptor**
=====================================================
A utility payload to reverse the action of the `fs_encryptor.py`
ransomware simulator.

This script will:
1.  Scan the test directory for files with the `.locked` extension.
2.  "Decrypt" each file using the same hardcoded XOR key.
3.  Restore the original filenames.
"""

import os, sys, subprocess, signal, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
# ---------------------------- Third‑party libs ----------------------------
try:
    import RPi.GPIO as GPIO
    import LCD_1in44, LCD_Config
    from PIL import Image, ImageDraw, ImageFont
    HARDWARE_LIBS_AVAILABLE = True
except ImportError:
    HARDWARE_LIBS_AVAILABLE = False
    print("WARNING: RPi.GPIO or LCD drivers not available. UI will not function.", file=sys.stderr)

# --- CONFIGURATION ---
SANDBOX_DIR = os.path.expanduser("~/Desktop/RANSOMWARE_TEST_FILES/") # Default, will be configurable
XOR_KEY = 0xDE # Must be the same key used for encryption, will be configurable

# --- GPIO & LCD ---
PINS = { "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16 }
if HARDWARE_LIBS_AVAILABLE:
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
    FONT = ImageFont.load_default() # General purpose font
else:
    # Dummy objects if hardware libs are not available
    class DummyLCD:
        def LCD_Init(self, *args): pass
        def LCD_Clear(self): pass
        def LCD_ShowImage(self, *args): pass
    LCD = DummyLCD()
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

# --- Globals & Shutdown ---
running = True
current_dir_input = SANDBOX_DIR # For directory input
dir_input_cursor_pos = 0
current_key_input = str(XOR_KEY) # For key input
key_input_cursor_pos = 0

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI ---
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
            print(f"Sandbox Dir: {SANDBOX_DIR}")
            print(f"XOR Key: {XOR_KEY}")
        elif screen_state == "dir_input":
            print(f"Enter Dir: {current_dir_input}")
        elif screen_state == "key_input":
            print(f"Enter Key: {current_key_input}")
        return

    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "FS Decryptor", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)
    
    if screen_state == "main":
        d.text((5, 30), "Sandbox Dir:", font=FONT, fill="white")
        d.text((5, 45), SANDBOX_DIR[:16] + "...", font=FONT_TITLE, fill="yellow")
        d.text((5, 65), "XOR Key:", font=FONT, fill="white")
        d.text((5, 80), str(XOR_KEY), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "OK=Decrypt | KEY1=Edit Dir | KEY2=Edit Key | KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "dir_input":
        d.text((5, 30), "Enter Dir Path:", font=FONT, fill="white")
        display_dir = list(current_dir_input)
        if dir_input_cursor_pos < len(display_dir):
            display_dir[dir_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_dir[:16]), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Char | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "key_input":
        d.text((5, 30), "Enter XOR Key (0-255):", font=FONT, fill="white")
        display_key = list(current_key_input)
        if key_input_cursor_pos < len(display_key):
            display_key[key_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_key), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Digit | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "decrypting":
        d.text((5, 50), "Decrypting files...", font=FONT_TITLE, fill="yellow")
        d.text((5, 70), "Please wait.", font=FONT, fill="white")
        d.text((5, 115), "KEY3=Stop", font=FONT, fill="cyan")
    elif screen_state == "complete":
        d.text((5, 50), "Decryption Complete!", font=FONT_TITLE, fill="lime")
        d.text((5, 70), "Check directory.", font=FONT, fill="white")
        d.text((5, 115), "KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "error":
        d.text((5, 50), "ERROR!", font=FONT_TITLE, fill="red")
        d.text((5, 70), "Check console.", font=FONT, fill="white")
        d.text((5, 115), "KEY3=Exit", font=FONT, fill="cyan")
    
    LCD.LCD_ShowImage(img, 0, 0)

def handle_dir_input_logic(initial_dir):
    global current_dir_input, dir_input_cursor_pos
    current_dir_input = initial_dir
    dir_input_cursor_pos = len(initial_dir) - 1
    
    draw_ui("dir_input")
    
    char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-" # Common path chars
    
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
            if os.path.isdir(current_dir_input):
                return current_dir_input
            else:
                show_message(["Invalid Dir!", "Not found."], "red")
                time.sleep(2)
                current_dir_input = initial_dir
                dir_input_cursor_pos = len(initial_dir) - 1
                draw_ui("dir_input")
        
        if btn == "LEFT":
            dir_input_cursor_pos = max(0, dir_input_cursor_pos - 1)
            draw_ui("dir_input")
        elif btn == "RIGHT":
            dir_input_cursor_pos = min(len(current_dir_input), dir_input_cursor_pos + 1)
            draw_ui("dir_input")
        elif btn == "UP" or btn == "DOWN":
            if dir_input_cursor_pos < len(current_dir_input):
                char_list = list(current_dir_input)
                current_char = char_list[dir_input_cursor_pos]
                
                try:
                    char_index = char_set.index(current_char)
                    if btn == "UP":
                        char_index = (char_index + 1) % len(char_set)
                    else: # DOWN
                        char_index = (char_index - 1 + len(char_set)) % len(char_set)
                    char_list[dir_input_cursor_pos] = char_set[char_index]
                    current_dir_input = "".join(char_list)
                except ValueError: # If current char is not in char_set
                    char_list[dir_input_cursor_pos] = char_set[0] # Default to first char
                    current_dir_input = "".join(char_list)
                draw_ui("dir_input")
        
        time.sleep(0.1)
    return None

def handle_key_input_logic(initial_key):
    global current_key_input, key_input_cursor_pos
    current_key_input = str(initial_key)
    key_input_cursor_pos = len(current_key_input) - 1
    
    draw_ui("key_input")
    
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
            if current_key_input.isdigit() and 0 <= int(current_key_input) <= 255:
                return int(current_key_input)
            else:
                show_message(["Invalid Key!", "0-255 only."], "red")
                time.sleep(2)
                current_key_input = str(initial_key)
                key_input_cursor_pos = len(current_key_input) - 1
                draw_ui("key_input")
        
        if btn == "LEFT":
            key_input_cursor_pos = max(0, key_input_cursor_pos - 1)
            draw_ui("key_input")
        elif btn == "RIGHT":
            key_input_cursor_pos = min(len(current_key_input), key_input_cursor_pos + 1)
            draw_ui("key_input")
        elif btn == "UP" or btn == "DOWN":
            if key_input_cursor_pos < len(current_key_input):
                char_list = list(current_key_input)
                current_char = char_list[key_input_cursor_pos]
                
                if current_char.isdigit():
                    digit = int(current_char)
                    if btn == "UP":
                        digit = (digit + 1) % 10
                    else: # DOWN
                        digit = (digit - 1 + 10) % 10
                    char_list[key_input_cursor_pos] = str(digit)
                    current_key_input = "".join(char_list)
                draw_ui("key_input")
        
        time.sleep(0.1)
    return None

# --- Main ---
def run_decryption():
    global SANDBOX_DIR, XOR_KEY
    
    draw_ui("decrypting")
    decrypted_count = 0
    
    if not os.path.isdir(SANDBOX_DIR):
        show_message(["Test directory", "not found!"], "red")
        time.sleep(3)
        return

    for filename in os.listdir(SANDBOX_DIR):
        if filename.endswith(".locked"):
            filepath = os.path.join(SANDBOX_DIR, filename)
            try:
                with open(filepath, "rb") as f:
                    encrypted_data = f.read()
                
                decrypted_data = bytes([b ^ XOR_KEY for b in encrypted_data])
                
                original_filepath = filepath[:-7] # Remove ".locked"
                with open(original_filepath, "wb") as f:
                    f.write(decrypted_data)
                
                os.remove(filepath)
                decrypted_count += 1
                # show_message([f"Decrypting...", f"Files: {decrypted_count}"]) # Too frequent updates
                # time.sleep(0.1)
            except Exception as e:
                print(f"Could not decrypt {filepath}: {e}", file=sys.stderr)
        
    show_message([f"{decrypted_count} files", "decrypted!", "Check the test", "directory."])
    time.sleep(3)

if __name__ == '__main__':
    if not HARDWARE_LIBS_AVAILABLE:
        print("ERROR: Hardware libraries (RPi.GPIO, LCD drivers, PIL) are not available. Cannot run Decryptor.", file=sys.stderr)
        sys.exit(1)

    current_screen = "main"
    try:
        while running:
            if current_screen == "main":
                draw_ui("main")
                
                if GPIO.input(PINS["KEY3"]) == 0:
                    cleanup()
                    break
                
                if GPIO.input(PINS["OK"]) == 0:
                    run_decryption()
                    current_screen = "main"
                    time.sleep(0.3) # Debounce
                
                if GPIO.input(PINS["KEY1"]) == 0: # Edit Sandbox Dir
                    current_dir_input = SANDBOX_DIR
                    current_screen = "dir_input"
                    time.sleep(0.3) # Debounce
                
                if GPIO.input(PINS["KEY2"]) == 0: # Edit XOR Key
                    current_key_input = str(XOR_KEY)
                    current_screen = "key_input"
                    time.sleep(0.3) # Debounce
            
            elif current_screen == "dir_input":
                new_dir = handle_dir_input_logic(current_dir_input)
                if new_dir:
                    SANDBOX_DIR = new_dir
                current_screen = "main"
                time.sleep(0.3) # Debounce
            
            elif current_screen == "key_input":
                new_key = handle_key_input_logic(current_key_input)
                if new_key is not None: # Can be 0
                    XOR_KEY = new_key
                current_screen = "main"
                time.sleep(0.3) # Debounce
            
            time.sleep(0.1)
            
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Decryptor payload finished.")

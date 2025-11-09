#!/usr/bin/env python3
import sys
import os
import time
import signal
import subprocess
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

RASPYJACK_DIR = os.path.abspath(os.path.join(__file__, '..', '..'))
LOOT_DIR = os.path.join(RASPYJACK_DIR, "loot")
PAYLOADS_DIR = os.path.join(RASPYJACK_DIR, "payloads")
SELF_NAME = os.path.basename(__file__)

PINS = { "OK": 13, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)

def show_message(lines, color="red"):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    y = 20
    for line in lines:
        d.text((5, y), line, font=FONT_TITLE, fill=color)
        y += 15
    LCD.LCD_ShowImage(img, 0, 0)

def run_self_destruct():
    show_message(["!!! WARNING !!!", "Self-Destruct", "is irreversible.", "Press OK again", "to confirm."])
    
    start_wait = time.time()
    while time.time() - start_wait < 5.0:
        if GPIO.input(PINS["KEY3"]) == 0:
            show_message(["Aborted."])
            return
        if GPIO.input(PINS["OK"]) == 0:
            break
        time.sleep(0.1)
    else:
        show_message(["Aborted."])
        return

    show_message(["Deleting loot..."])
    if os.path.isdir(LOOT_DIR):
        subprocess.run(f"rm -rf {LOOT_DIR}/*", shell=True)
    time.sleep(1)

    show_message(["Deleting other", "payloads..."])
    if os.path.isdir(PAYLOADS_DIR):
        for filename in os.listdir(PAYLOADS_DIR):
            if filename != SELF_NAME and filename.endswith(".py"):
                os.remove(os.path.join(PAYLOADS_DIR, filename))
    time.sleep(1)
    
    show_message(["Self-Destruct", "Complete."], "lime")

if __name__ == '__main__':
    try:
        run_self_destruct()
        time.sleep(3)
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Self-Destruct payload finished.")
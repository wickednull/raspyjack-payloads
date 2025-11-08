#!/usr/bin/env python3
"""
RaspyJack *payload* – **Evil: Filesystem Decryptor**
=====================================================
A utility payload to reverse the action of the `fs_encryptor.py`
ransomware simulator.

This script will:
1.  Scan the test directory for files with the `.locked` extension.
2.  "Decrypt" each file using the same hardcoded XOR key.
3.  Restore the original filenames.
"""

import os, sys, subprocess, signal, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
SANDBOX_DIR = os.path.expanduser("~/Desktop/RANSOMWARE_TEST_FILES/")
XOR_KEY = 0xDE # Must be the same key used for encryption

# --- GPIO & LCD ---
PINS = { "OK": 13, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)

# --- Main ---
def show_message(lines, color="lime"):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    y = 40
    for line in lines:
        d.text((5, y), line, font=FONT_TITLE, fill=color)
        y += 15
    LCD.LCD_ShowImage(img, 0, 0)

def run_decryption():
    show_message(["Decrypting files..."])
    decrypted_count = 0
    
    if not os.path.isdir(SANDBOX_DIR):
        show_message(["Test directory", "not found!"], "red")
        return

    for filename in os.listdir(SANDBOX_DIR):
        if filename.endswith(".locked"):
            filepath = os.path.join(SANDBOX_DIR, filename)
            try:
                with open(filepath, "rb") as f:
                    encrypted_data = f.read()
                
                decrypted_data = bytes([b ^ XOR_KEY for b in encrypted_data])
                
                original_filepath = filepath[:-7] # Remove ".locked"
                with open(original_filepath, "wb") as f:
                    f.write(decrypted_data)
                
                os.remove(filepath)
                decrypted_count += 1
                show_message([f"Decrypting...", f"Files: {decrypted_count}"])
                time.sleep(0.5)
            except Exception as e:
                print(f"Could not decrypt {filepath}: {e}", file=sys.stderr)
        
    show_message([f"{decrypted_count} files", "decrypted!", "Check the test", "directory."])

if __name__ == '__main__':
    try:
        show_message(["Decrypt Files?", "Press OK."])
        while True:
            if GPIO.input(PINS["KEY3"]) == 0:
                break
            if GPIO.input(PINS["OK"]) == 0:
                run_decryption()
                time.sleep(4)
                break
            time.sleep(0.1)
            
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Decryptor payload finished.")

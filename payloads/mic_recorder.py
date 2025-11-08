#!/usr/bin/env python3
"""
RaspyJack *payload* – **Evil: Microphone Recorder**
====================================================
A payload that secretly records a short snippet of audio from a connected
microphone and saves it to the loot directory.

This requires `arecord` (from alsa-utils) to be installed, and for a
microphone to be available to the RaspyJack.

**NOTE:** This is a conceptual payload. The default RaspyJack setup may
not have a microphone configured.
"""

import os, sys, subprocess, signal, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
LOOT_DIR = "/root/Raspyjack/loot/Mic_Recordings/"
RECORD_DURATION = "10" # seconds

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
    show_message([f"Recording for", f"{RECORD_DURATION} seconds..."])
    
    try:
        os.makedirs(LOOT_DIR, exist_ok=True)
        timestamp = time.strftime("%Y-%m-%d_%H%M%S")
        output_file = os.path.join(LOOT_DIR, f"rec_{timestamp}.wav")
        
        # Command to record audio.
        # -d duration, -f format
        command = f"arecord -d {RECORD_DURATION} -f cd -t wav {output_file}"
        
        proc = subprocess.run(command, shell=True, check=True, capture_output=True, text=True, timeout=int(RECORD_DURATION) + 5)
        
        if os.path.exists(output_file):
            show_message(["Recording saved!", "Saved to loot."], "lime")
        else:
            raise Exception("File not created.")

    except subprocess.TimeoutExpired:
        show_message(["Capture timed out!"], "red")
    except Exception as e:
        show_message(["Capture FAILED!", "Is microphone", "connected?"], "red")
        print(f"Mic recording failed: {e}", file=sys.stderr)
        if 'proc' in locals(): print(proc.stderr, file=sys.stderr)

if __name__ == '__main__':
    try:
        if subprocess.run("which arecord", shell=True, capture_output=True).returncode != 0:
            show_message(["arecord", "not found!"], "red")
            time.sleep(3)
        else:
            show_message(["Mic Recorder", "Press OK to", f"record {RECORD_DURATION}s."])
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
        print("Mic Recorder payload finished.")

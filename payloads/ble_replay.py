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

FAKE_REPLAY_PACKET_DATA = "0x08 0x0008 1e 02 01 06 1a ff 4c 00 07 19 01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"

PINS = { "OK": 13, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

def draw_ui(status_msg):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "BLE Replay Attack", font=FONT_TITLE, fill="#FF0000")
    d.line([(0, 22), (128, 22)], fill="#FF0000", width=1)
    y_pos = 30
    for line in status_msg.split('\n'):
        d.text((5, y_pos), line, font=FONT, fill="yellow")
        y_pos += 12
    d.text((5, 115), "OK=Replay | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

def run_attack():
    draw_ui("Simulating replay...\nSending packet...")
    
    try:
        time.sleep(2)
        
        draw_ui("Packet sent.\nCheck if action\noccurred on the\ntarget device.")
        
    except Exception as e:
        draw_ui(f"Attack FAILED!\n{str(e)[:20]}")
        print(f"BLE Replay failed: {e}", file=sys.stderr)

if __name__ == '__main__':
    try:
        draw_ui("BLE Replay Concept\nPress OK to 'send'\na fake packet.")
        while True:
            if GPIO.input(PINS["KEY3"]) == 0:
                break
            if GPIO.input(PINS["OK"]) == 0:
                run_attack()
                time.sleep(4)
                draw_ui("Ready to replay\nagain.")
            time.sleep(0.1)
            
finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("BLE Replay payload finished.")
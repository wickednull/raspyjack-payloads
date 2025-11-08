#!/usr/bin/env python3
"""
RaspyJack *payload* – **Recon: Passive OS Fingerprinting**
===========================================================
A passive OS fingerprinting tool that makes an educated guess about a
target's operating system based on its TCP/IP stack characteristics.

This payload sends a single TCP SYN packet to an open port and analyzes
the TTL (Time To Live) and TCP Window Size of the SYN/ACK response. These
values are often characteristic of a particular OS.
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
TARGET_IP = "192.168.1.1"
TARGET_PORT = 80 # An open port on the target

# --- GPIO & LCD ---
PINS = { "OK": 13, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

# --- Globals & Shutdown ---
running = True

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI ---
def draw_ui(lines):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Passive OS Fingerprint", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    y_pos = 30
    for line in lines:
        d.text((5, y_pos), line, font=FONT, fill="white")
        y_pos += 12

    d.text((5, 115), "OK=Scan | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# --- Scanner ---
def run_scan():
    draw_ui([f"Pinging {TARGET_IP}..."])
    
    try:
        # Send a SYN packet and wait for a SYN/ACK response
        p = IP(dst=TARGET_IP)/TCP(dport=TARGET_PORT, flags='S')
        resp = sr1(p, timeout=3, verbose=0)
        
        if resp and resp.haslayer(TCP) and resp[TCP].flags == 'SA': # SYN/ACK
            ttl = resp[IP].ttl
            window_size = resp[TCP].window
            
            os_guess = "Unknown"
            # Simple TTL-based guessing
            if ttl <= 64:
                os_guess = "Linux / Unix"
            elif ttl <= 128:
                os_guess = "Windows"
            else:
                os_guess = "Solaris / Cisco"

            results = [
                f"Target: {TARGET_IP}",
                f"TTL: {ttl}",
                f"Window: {window_size}",
                "",
                "Guess:",
                os_guess
            ]
            draw_ui(results)
            
        else:
            draw_ui(["No SYN/ACK received.", "Port may be closed", "or host is down."])

    except Exception as e:
        draw_ui(["Scan failed!", str(e)[:20]])
        print(f"OS Scan failed: {e}", file=sys.stderr)

# --- Main Loop ---
try:
    draw_ui(["Press OK to scan", TARGET_IP])
    while running:
        if GPIO.input(PINS["KEY3"]) == 0:
            cleanup()
            break
        
        if GPIO.input(PINS["OK"]) == 0:
            run_scan()
            # Wait until a button is pressed to scan again
            while running and GPIO.input(PINS["OK"]) == 0:
                time.sleep(0.05)
            while running and GPIO.input(PINS["OK"]) != 0 and GPIO.input(PINS["KEY3"]) != 0:
                time.sleep(0.05)
        
        time.sleep(0.1)

except (KeyboardInterrupt, SystemExit):
    pass
finally:
    cleanup()
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("OS Fingerprint payload finished.")

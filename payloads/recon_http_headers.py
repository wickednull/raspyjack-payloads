#!/usr/bin/env python3
"""
RaspyJack *payload* – **Recon: HTTP Header Viewer**
====================================================
A simple reconnaissance tool that connects to a web server on a
specified port and prints the HTTP response headers.

This is useful for quickly identifying server software, versions,
enabled features (e.g., HSTS, cookies), and other configuration details.
"""

import os, sys, subprocess, signal, time, socket
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
TARGET_IP = "192.168.1.1"
TARGET_PORT = 80

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
selected_index = 0
headers = []

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI ---
def draw_ui(status_msg=None):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "HTTP Header Viewer", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    if status_msg:
        d.text((10, 60), status_msg, font=FONT, fill="yellow")
    else:
        start_index = max(0, selected_index - 4)
        end_index = min(len(headers), start_index + 8)
        y_pos = 25
        for i in range(start_index, end_index):
            color = "yellow" if i == selected_index else "white"
            line = headers[i]
            if len(line) > 20: line = line[:19] + "..."
            d.text((5, y_pos), line, font=FONT, fill=color)
            y_pos += 11

    d.text((5, 115), "OK=Get | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# --- Scanner ---
def get_headers():
    global headers, selected_index
    draw_ui("Connecting...")
    headers = []
    selected_index = 0
    
    try:
        # Use requests library for simplicity
        import requests
        url = f"http://{TARGET_IP}:{TARGET_PORT}"
        resp = requests.head(url, timeout=5)
        
        headers.append(f"Status: {resp.status_code}")
        for key, value in resp.headers.items():
            headers.append(f"{key}: {value}")

    except Exception as e:
        headers.append("Request failed!")
        headers.append(str(e)[:20])
        print(f"HTTP request failed: {e}", file=sys.stderr)

# --- Main Loop ---
try:
    draw_ui("Press OK to get")
    while running:
        if GPIO.input(PINS["KEY3"]) == 0:
            cleanup()
            break
        
        if GPIO.input(PINS["OK"]) == 0:
            get_headers()
            draw_ui()
            time.sleep(0.5) # Debounce
            # Enter viewing mode
            while running:
                if GPIO.input(PINS["KEY3"]) == 0:
                    break
                if GPIO.input(PINS["UP"]) == 0:
                    selected_index = (selected_index - 1) % len(headers)
                    draw_ui()
                    time.sleep(0.2)
                elif GPIO.input(PINS["DOWN"]) == 0:
                    selected_index = (selected_index + 1) % len(headers)
                    draw_ui()
                    time.sleep(0.2)
                time.sleep(0.05)
        
        time.sleep(0.1)

except (KeyboardInterrupt, SystemExit):
    pass
finally:
    cleanup()
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("HTTP Header payload finished.")

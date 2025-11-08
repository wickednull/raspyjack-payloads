#!/usr/bin/env python3
"""
RaspyJack *payload* – **Recon: Simple TCP Port Scanner**
=========================================================
A simple, fast TCP port scanner written in pure Python. This tool is
useful for quickly checking for open ports on a single target without
the overhead of Nmap.

It attempts to connect to a range of ports on a target IP and reports
which ones are open.
"""

import os, sys, subprocess, signal, time, threading, socket
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
TARGET_IP = "192.168.1.1"
# Common ports to scan
PORTS_TO_SCAN = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389, 8080]

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
scan_thread = None
open_ports = []
ui_lock = threading.Lock()
status_msg = "Press OK to scan"

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI ---
def draw_ui():
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "TCP Port Scanner", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    with ui_lock:
        if "Scanning" in status_msg or "Press" in status_msg:
            d.text((10, 60), status_msg, font=FONT, fill="yellow")
        else:
            d.text((5, 25), f"Open Ports: {len(open_ports)}", font=FONT, fill="yellow")
            y_pos = 40
            for port in open_ports[-7:]: # Show last 7 found
                d.text((10, y_pos), f"Port {port} is open", font=FONT, fill="white")
                y_pos += 11

    d.text((5, 115), "OK=Scan | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# --- Scanner ---
def run_scan():
    global open_ports, status_msg
    with ui_lock:
        status_msg = f"Scanning {TARGET_IP}..."
        open_ports = []

    socket.setdefaulttimeout(0.5)
    
    for port in PORTS_TO_SCAN:
        if not running: break
        with ui_lock:
            status_msg = f"Scanning Port: {port}"
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((TARGET_IP, port))
            if result == 0:
                with ui_lock:
                    if port not in open_ports:
                        open_ports.append(port)
            sock.close()
        except socket.error as e:
            print(f"Socket error on port {port}: {e}", file=sys.stderr)
            
    with ui_lock:
        status_msg = "Scan Finished"

# --- Main Loop ---
try:
    while running:
        draw_ui()
        
        if GPIO.input(PINS["KEY3"]) == 0:
            cleanup()
            break
        
        if GPIO.input(PINS["OK"]) == 0:
            if not (scan_thread and scan_thread.is_alive()):
                scan_thread = threading.Thread(target=run_scan, daemon=True)
                scan_thread.start()
            time.sleep(0.3)

        time.sleep(0.1)

except (KeyboardInterrupt, SystemExit):
    pass
finally:
    cleanup()
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("TCP Port Scanner payload finished.")

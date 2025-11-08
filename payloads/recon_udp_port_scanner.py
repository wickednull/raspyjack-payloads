#!/usr/bin/env python3
"""
RaspyJack *payload* – **Recon: Simple UDP Port Scanner**
=========================================================
A simple UDP port scanner. This is more complex than TCP scanning, as
UDP is a connectionless protocol.

This payload sends a UDP packet to each port in a list. If it receives
an ICMP "port unreachable" error, the port is considered closed. If no
response is received after a timeout, the port is considered "open" or
"filtered".
"""

import os, sys, subprocess, signal, time, threading
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
# Common UDP ports
PORTS_TO_SCAN = [53, 67, 68, 123, 161, 162, 500]

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
    d.text((5, 5), "UDP Port Scanner", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    with ui_lock:
        if "Scanning" in status_msg or "Press" in status_msg:
            d.text((10, 60), status_msg, font=FONT, fill="yellow")
        else:
            d.text((5, 25), f"Open/Filtered: {len(open_ports)}", font=FONT, fill="yellow")
            y_pos = 40
            for port in open_ports[-7:]:
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

    for port in PORTS_TO_SCAN:
        if not running: break
        with ui_lock:
            status_msg = f"Scanning Port: {port}"
        
        try:
            # Send a UDP packet to the target port
            p = IP(dst=TARGET_IP)/UDP(dport=port)
            # Wait for a response for 2 seconds
            resp = sr1(p, timeout=2, verbose=0)
            
            if resp is None:
                # No response -> port is open or filtered
                with ui_lock:
                    if port not in open_ports:
                        open_ports.append(port)
            elif resp.haslayer(ICMP) and resp[ICMP].type == 3 and resp[ICMP].code == 3:
                # ICMP "port unreachable" -> port is closed
                pass
            else:
                # Some other response -> port is open
                with ui_lock:
                    if port not in open_ports:
                        open_ports.append(port)

        except Exception as e:
            print(f"Scapy error on port {port}: {e}", file=sys.stderr)
            
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
    print("UDP Port Scanner payload finished.")

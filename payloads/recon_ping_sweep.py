#!/usr/bin/env python3
"""
RaspyJack *payload* – **Recon: ICMP Ping Sweep**
=================================================
A simple and fast reconnaissance tool that discovers live hosts on the
local network by sending ICMP Echo Requests (pings) to every IP address
in the subnet.

This is often faster than a full port scan for simple host discovery.
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

# --- GPIO & LCD ---
PINS = { "OK": 13, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

# --- Globals & Shutdown ---
ETH_INTERFACE = "eth0"
running = True
scan_thread = None
live_hosts = []
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
    d.text((5, 5), "ICMP Ping Sweep", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    with ui_lock:
        if "Scanning" in status_msg or "Press" in status_msg:
            d.text((10, 60), status_msg, font=FONT, fill="yellow")
        else:
            d.text((5, 25), f"Live Hosts: {len(live_hosts)}", font=FONT, fill="yellow")
            y_pos = 40
            for host in live_hosts[-7:]: # Show last 7 found
                d.text((10, y_pos), host, font=FONT, fill="white")
                y_pos += 11

    d.text((5, 115), "OK=Scan | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# --- Scanner ---
def run_scan():
    global live_hosts, status_msg
    with ui_lock:
        status_msg = "Scanning..."
        live_hosts = []

    try:
        network_range = subprocess.check_output(f"ip -o -4 addr show {ETH_INTERFACE} | awk '{{print $4}}'", shell=True).decode().strip()
        if not network_range:
            with ui_lock: status_msg = "eth0 has no IP!"
            return

        # Send ICMP echo requests
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/IP(dst=network_range)/ICMP(), timeout=5, iface=ETH_INTERFACE, verbose=0)
        
        temp_hosts = []
        for sent, received in ans:
            temp_hosts.append(received.psrc)
        
        with ui_lock:
            live_hosts = sorted(list(set(temp_hosts)), key=lambda ip: [int(y) for y in ip.split('.')])
            status_msg = "Scan Finished"
            
    except Exception as e:
        with ui_lock: status_msg = "Scan Failed!"
        print(f"Ping Sweep failed: {e}", file=sys.stderr)

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
    print("Ping Sweep payload finished.")

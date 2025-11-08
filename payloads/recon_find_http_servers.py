#!/usr/bin/env python3
"""
RaspyJack *payload* – **Recon: Find HTTP Servers**
===================================================
A simple reconnaissance payload that scans the local network to find
hosts with common HTTP ports (80, 8080) open.

This is useful for quickly identifying potential web servers to target.
"""

import os, sys, subprocess, signal, time, threading, socket
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
HTTP_PORTS = [80, 8080]
ETH_INTERFACE = "eth0"

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
http_servers = []
ui_lock = threading.Lock()
status_msg = "Press OK to scan"
selected_index = 0

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI ---
def draw_ui():
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Find HTTP Servers", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    with ui_lock:
        if "Scanning" in status_msg or "Press" in status_msg:
            d.text((10, 60), status_msg, font=FONT, fill="yellow")
        else:
            d.text((5, 25), f"Servers Found: {len(http_servers)}", font=FONT, fill="yellow")
            start_index = max(0, selected_index - 4)
            end_index = min(len(http_servers), start_index + 8)
            y_pos = 40
            for i in range(start_index, end_index):
                color = "yellow" if i == selected_index else "white"
                d.text((10, y_pos), http_servers[i], font=FONT, fill=color)
                y_pos += 11

    d.text((5, 115), "OK=Scan | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# --- Scanner ---
def run_scan():
    global http_servers, status_msg, selected_index
    with ui_lock:
        status_msg = "Scanning network..."
        http_servers = []
        selected_index = 0

    try:
        network_range_str = subprocess.check_output(f"ip -o -4 addr show {ETH_INTERFACE} | awk '{{print $4}}'", shell=True).decode().strip()
        from ipaddress import ip_network
        network = ip_network(network_range_str, strict=False)
        
        socket.setdefaulttimeout(0.2)
        for ip in network.hosts():
            if not running: break
            ip_str = str(ip)
            with ui_lock: status_msg = f"Scanning: {ip_str}"
            for port in HTTP_PORTS:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    if sock.connect_ex((ip_str, port)) == 0:
                        with ui_lock:
                            server_str = f"{ip_str}:{port}"
                            if server_str not in http_servers:
                                http_servers.append(server_str)
                    sock.close()
                except socket.error:
                    pass
            
    except Exception as e:
        with ui_lock: status_msg = "Scan Failed!"
        print(f"Scan failed: {e}", file=sys.stderr)
        
    if running:
        with ui_lock: status_msg = "Scan Finished"

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
        
        if not (scan_thread and scan_thread.is_alive()):
            if GPIO.input(PINS["UP"]) == 0:
                with ui_lock:
                    if http_servers: selected_index = (selected_index - 1) % len(http_servers)
                time.sleep(0.2)
            elif GPIO.input(PINS["DOWN"]) == 0:
                with ui_lock:
                    if http_servers: selected_index = (selected_index + 1) % len(http_servers)
                time.sleep(0.2)

        time.sleep(0.1)

except (KeyboardInterrupt, SystemExit):
    pass
finally:
    cleanup()
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("Find HTTP Servers payload finished.")

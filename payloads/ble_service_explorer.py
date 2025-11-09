#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
"""
RaspyJack *payload* – **Recon: BLE Service Explorer**
======================================================
A Bluetooth Low Energy reconnaissance tool that provides a quick,
high-level overview of the services offered by nearby devices.

This payload scans for BLE devices and, for each one found, attempts a
quick connection to discover and list only its primary services. This is
faster than a full characteristic scan and is useful for quickly mapping
out the capabilities of surrounding BLE devices.
"""

import os, sys, subprocess, signal, time, re
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

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
results = [] # List of strings to display

def cleanup(*_):
    global running
    if running:
        running = False
        # Explicitly stop bluetoothctl scanning and disconnect
        subprocess.run("bluetoothctl power off", shell=True, capture_output=True)
        subprocess.run("bluetoothctl disconnect", shell=True, capture_output=True)
        subprocess.run("bluetoothctl scan off", shell=True, capture_output=True)
        subprocess.run("pkill -f bluetoothctl", shell=True, capture_output=True) # Aggressive kill if needed

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI ---
def draw_ui(status_msg=None):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "BLE Service Explorer", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    if status_msg:
        d.text((10, 60), status_msg, font=FONT, fill="yellow")
    else:
        start_index = max(0, selected_index - 4)
        end_index = min(len(results), start_index + 8)
        y_pos = 25
        for i in range(start_index, end_index):
            color = "yellow" if i == selected_index else "white"
            line = results[i]
            if len(line) > 20: line = line[:19] + "..."
            d.text((5, y_pos), line, font=FONT, fill=color)
            y_pos += 11

    d.text((5, 115), "OK=Scan | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# --- Scanner ---
def run_scan():
    global results, selected_index
    draw_ui("Scanning BLE...")
    results = []
    selected_index = 0
    
    try:
        # 1. Scan for devices
        scan_proc = subprocess.Popen(["bluetoothctl"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        scan_proc.stdin.write("scan on\n"); scan_proc.stdin.flush()
        time.sleep(8)
        scan_proc.stdin.write("scan off\n"); scan_proc.stdin.flush()
        scan_proc.stdin.write("exit\n"); scan_proc.stdin.flush()
        out, _ = scan_proc.communicate(timeout=5)
        
        devices = {}
        for line in out.split('\n'):
            match = re.search(r"Device ([0-9A-F:]{17}) (.+)", line)
            if match:
                mac, name = match.group(1), match.group(2).strip()
                if name != "n/a": devices[mac] = name
        
        if not devices:
            results.append("No devices found.")
            return

        # 2. Connect to each device and get services
        for mac, name in devices.items():
            if not running: break
            draw_ui(f"Checking {name[:10]}...")
            
            conn_proc = subprocess.Popen(["bluetoothctl"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            conn_proc.stdin.write(f"connect {mac}\n"); conn_proc.stdin.flush()
            time.sleep(4) # Give time to connect
            
            # Check if connection was successful
            conn_proc.stdin.write("info\n"); conn_proc.stdin.flush()
            time.sleep(1)
            
            conn_proc.stdin.write("exit\n"); conn_proc.stdin.flush()
            out, _ = conn_proc.communicate(timeout=10)
            
            if "Connected: yes" in out:
                results.append(f"DEV: {name[:12]}")
                # Find primary services
                for line in out.split('\n'):
                    if "Primary" in line:
                        uuid_match = re.search(r"([0-9a-f-]{36})", line)
                        if uuid_match:
                            uuid = uuid_match.group(1)
                            # Try to find common names for UUIDs
                            if "1800" in uuid: results.append("  Generic Access")
                            elif "1801" in uuid: results.append("  Generic Attribute")
                            elif "180f" in uuid: results.append("  Battery Service")
                            elif "180d" in uuid: results.append("  Heart Rate")
                            else: results.append(f"  {uuid[:8]}...")
            
    except Exception as e:
        results.append("Scan error!")
        print(f"BLE scan failed: {e}", file=sys.stderr)

# --- Main Loop ---
try:
    # Dependency check for bluetoothctl
    if subprocess.run("which bluetoothctl", shell=True, capture_output=True).returncode != 0:
        draw_message("bluetoothctl not found!", "red")
        time.sleep(5)
        raise SystemExit("bluetoothctl not found.")

    draw_ui("Press OK to scan")
    while running:
        if GPIO.input(PINS["KEY3"]) == 0:
            cleanup()
            break
        
        if GPIO.input(PINS["OK"]) == 0:
            run_scan()
            draw_ui()
            time.sleep(0.5)
            # Enter viewing mode
            while running:
                if GPIO.input(PINS["KEY3"]) == 0:
                    break
                if GPIO.input(PINS["UP"]) == 0:
                    selected_index = (selected_index - 1) % len(results) if results else 0
                    draw_ui()
                    time.sleep(0.2)
                elif GPIO.input(PINS["DOWN"]) == 0:
                    selected_index = (selected_index + 1) % len(results) if results else 0
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
    print("BLE Service Explorer payload finished.")

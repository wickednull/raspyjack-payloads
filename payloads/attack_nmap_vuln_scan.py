#!/usr/bin/env python3
"""
RaspyJack *payload* – **Attack: Nmap Vuln Scan**
==================================================
A convenience payload that launches a dedicated Nmap vulnerability scan
against a target. This uses the `--script vuln` argument to run all
scripts in Nmap's "vuln" category.

This is a "fire-and-forget" scan that saves its output to a loot file.
"""

import os, sys, subprocess, signal, time, threading
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
TARGET_IP = "192.168.1.1"
LOOT_DIR = "/root/Raspyjack/loot/Nmap_Vuln/"

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
status_msg = "Press OK to scan"

def cleanup(*_):
    global running
    running = False
    # In a real scenario, you might want to kill the nmap process
    # but for a fire-and-forget script, we let it finish.

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI ---
def draw_ui():
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Nmap Vuln Scan", font=FONT_TITLE, fill="#FF0000")
    d.line([(0, 22), (128, 22)], fill="#FF0000", width=1)
    d.text((10, 60), status_msg, font=FONT, fill="yellow")
    d.text((5, 115), "OK=Scan | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# --- Scanner ---
def run_scan():
    global status_msg
    
    os.makedirs(LOOT_DIR, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H%M%S")
    output_file = os.path.join(LOOT_DIR, f"vuln_scan_{TARGET_IP}_{timestamp}.txt")
    
    status_msg = f"Scanning {TARGET_IP}..."
    
    try:
        command = f"nmap --script vuln -oN {output_file} {TARGET_IP}"
        subprocess.run(command, shell=True, check=True, timeout=600) # 10 minute timeout
        status_msg = "Scan complete!"
    except subprocess.TimeoutExpired:
        status_msg = "Scan timed out!"
    except Exception as e:
        status_msg = "Scan failed!"
        print(f"Nmap scan failed: {e}", file=sys.stderr)

# --- Main Loop ---
try:
    if subprocess.run("which nmap", shell=True, capture_output=True).returncode != 0:
        status_msg = "nmap not found!"
        draw_ui()
        time.sleep(3)
        raise SystemExit("`nmap` command not found.")

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
    print("Nmap Vuln Scan payload finished.")

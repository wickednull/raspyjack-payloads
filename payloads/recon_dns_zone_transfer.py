#!/usr/bin/env python3
"""
RaspyJack *payload* – **Recon: DNS Zone Transfer**
===================================================
A reconnaissance tool that attempts to perform a DNS zone transfer (AXFR)
against a specified domain using its authoritative name servers.

If a name server is misconfigured, this attack will dump all of its DNS
records for the domain, providing a treasure trove of information about
the target's infrastructure (subdomains, IP addresses, etc.).
"""

import os, sys, subprocess, signal, time, threading
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
TARGET_DOMAIN = "example.com"

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
results = []
ui_lock = threading.Lock()
status_msg = "Press OK to start"

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI ---
def draw_ui():
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "DNS Zone Transfer", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    with ui_lock:
        if "Press" in status_msg or "Finding" in status_msg or "Testing" in status_msg:
            d.text((10, 60), status_msg, font=FONT, fill="yellow")
        elif "SUCCESS" in status_msg:
            d.text((10, 40), status_msg, font=FONT_TITLE, fill="lime")
            d.text((10, 60), f"Saved {len(results)} records", font=FONT, fill="white")
        else:
            d.text((10, 60), status_msg, font=FONT_TITLE, fill="red")

    d.text((5, 115), "OK=Start | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# --- Scanner ---
def run_scan():
    global results, status_msg
    with ui_lock:
        status_msg = f"Finding NS for\n{TARGET_DOMAIN}..."
        results = []

    try:
        # 1. Find the Name Servers (NS) for the domain
        ns_proc = subprocess.run(f"host -t ns {TARGET_DOMAIN}", shell=True, capture_output=True, text=True)
        if ns_proc.returncode != 0:
            with ui_lock: status_msg = "Domain not found"
            return
            
        name_servers = [line.split()[-1] for line in ns_proc.stdout.strip().split('\n')]
        
        # 2. Attempt a zone transfer from each name server
        for ns in name_servers:
            if not running: break
            with ui_lock: status_msg = f"Testing {ns[:-1][:16]}..."
            
            axfr_proc = subprocess.run(f"host -l {TARGET_DOMAIN} {ns}", shell=True, capture_output=True, text=True)
            
            if "Transfer failed" not in axfr_proc.stdout and "has address" in axfr_proc.stdout:
                # SUCCESS!
                with ui_lock:
                    results = axfr_proc.stdout.strip().split('\n')
                    status_msg = "SUCCESS!"
                
                # Save loot
                os.makedirs("/root/Raspyjack/loot/DNS_Zone_Transfer/", exist_ok=True)
                loot_file = f"/root/Raspyjack/loot/DNS_Zone_Transfer/{TARGET_DOMAIN}.txt"
                with open(loot_file, "w") as f:
                    f.write(f"Zone transfer results for {TARGET_DOMAIN} from {ns}\n\n")
                    f.write(axfr_proc.stdout)
                return # Stop after first success

        if running:
             with ui_lock: status_msg = "Transfer FAILED"

    except Exception as e:
        with ui_lock: status_msg = "Scan Error!"
        print(f"AXFR Scan failed: {e}", file=sys.stderr)

# --- Main Loop ---
try:
    if subprocess.run("which host", shell=True, capture_output=True).returncode != 0:
        status_msg = "host tool not found!"
        draw_ui()
        time.sleep(3)
        raise SystemExit("`host` command not found.")

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
    print("DNS Zone Transfer payload finished.")

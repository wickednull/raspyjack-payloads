#!/usr/bin/env python3
"""
RaspyJack *payload* – **Recon: SNMP Walk**
===========================================
A reconnaissance tool that performs an SNMP (Simple Network Management
Protocol) walk on a target device using a common community string.

If a device has a default or guessable community string (like "public"),
an SNMP walk can dump a huge amount of information, including network
interfaces, routing tables, system uptime, and much more.
"""

import os, sys, subprocess, signal, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
TARGET_IP = "192.168.1.1"
COMMUNITY_STRING = "public"

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
results = []

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI ---
def draw_ui(status_msg=None):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "SNMP Walk", font=FONT_TITLE, fill="#00FF00")
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

    d.text((5, 115), "OK=Walk | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# --- Scanner ---
def run_scan():
    global results, selected_index
    draw_ui("Walking...")
    results = []
    selected_index = 0
    
    try:
        # Use snmpwalk to query the device
        command = f"snmpwalk -v2c -c {COMMUNITY_STRING} {TARGET_IP}"
        proc = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        
        if proc.returncode == 0 and proc.stdout:
            # For this payload, we'll just show the first few interesting lines
            # A full walk can be thousands of lines long
            lines = proc.stdout.strip().split('\n')
            for line in lines:
                if "sysDescr" in line or "sysName" in line or "ifDescr" in line:
                    # Clean up the output for display
                    clean_line = line.split(' = ')[-1].replace('"', '')
                    results.append(clean_line)
            
            if not results:
                results.append("Walk complete.")
                results.append("No common info found.")
            
            # Save full loot
            os.makedirs("/root/Raspyjack/loot/SNMP/", exist_ok=True)
            loot_file = f"/root/Raspyjack/loot/SNMP/{TARGET_IP}_walk.txt"
            with open(loot_file, "w") as f:
                f.write(proc.stdout)
            results.append(f"Saved to loot!")

        else:
            if "Timeout" in proc.stderr:
                results.append("Timeout: No response")
            else:
                results.append("Walk failed.")
                print(proc.stderr, file=sys.stderr)

    except Exception as e:
        results.append("Scan error!")
        print(f"snmpwalk failed: {e}", file=sys.stderr)

# --- Main Loop ---
try:
    if subprocess.run("which snmpwalk", shell=True, capture_output=True).returncode != 0:
        draw_ui("snmpwalk not found!")
        time.sleep(3)
        raise SystemExit("`snmpwalk` command not found.")

    draw_ui("Press OK to walk")
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
    print("SNMP Walk payload finished.")

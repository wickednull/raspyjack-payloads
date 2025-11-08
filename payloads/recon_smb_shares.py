#!/usr/bin/env python3
"""
RaspyJack *payload* – **Recon: SMB Share Enumeration**
=======================================================
A reconnaissance tool that scans a target IP address for open SMB
(Server Message Block) shares. This is useful for finding file shares
on a Windows machine or a Samba server.

This payload uses the `smbclient` command-line tool with the -L flag
to list shares. It attempts an anonymous (null session) connection.
"""

import os, sys, subprocess, signal, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
TARGET_IP = "192.168.1.10"

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
shares = []

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI ---
def draw_ui(status_msg=None):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "SMB Share Scanner", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    if status_msg:
        d.text((10, 60), status_msg, font=FONT, fill="yellow")
    else:
        start_index = max(0, selected_index - 4)
        end_index = min(len(shares), start_index + 8)
        y_pos = 25
        for i in range(start_index, end_index):
            color = "yellow" if i == selected_index else "white"
            line = shares[i]
            if len(line) > 20: line = line[:19] + "..."
            d.text((5, y_pos), line, font=FONT, fill=color)
            y_pos += 11

    d.text((5, 115), "OK=Scan | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# --- Scanner ---
def run_scan():
    global shares, selected_index
    draw_ui("Scanning...")
    shares = []
    selected_index = 0
    
    try:
        # Use smbclient to list shares with a null session (-N)
        command = f"smbclient -L //{TARGET_IP} -N"
        proc = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=15)
        
        if proc.returncode == 0:
            for line in proc.stdout.split('\n'):
                # Look for lines indicating a disk share
                if "Disk" in line:
                    share_name = line.split('|')[0].strip()
                    if share_name:
                        shares.append(share_name)
            if not shares:
                shares.append("No shares found")
        else:
            # Parse common errors
            if "Connection refused" in proc.stderr:
                shares.append("Connection refused")
            elif "NT_STATUS_HOST_UNREACH" in proc.stderr:
                shares.append("Host unreachable")
            else:
                shares.append("Scan failed")
                print(proc.stderr, file=sys.stderr)

    except Exception as e:
        shares.append("Scan error!")
        print(f"smbclient scan failed: {e}", file=sys.stderr)

# --- Main Loop ---
try:
    if subprocess.run("which smbclient", shell=True, capture_output=True).returncode != 0:
        draw_ui("smbclient not found!")
        time.sleep(3)
        raise SystemExit("`smbclient` command not found.")

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
                    selected_index = (selected_index - 1) % len(shares) if shares else 0
                    draw_ui()
                    time.sleep(0.2)
                elif GPIO.input(PINS["DOWN"]) == 0:
                    selected_index = (selected_index + 1) % len(shares) if shares else 0
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
    print("SMB Share payload finished.")

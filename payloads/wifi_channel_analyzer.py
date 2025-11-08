#!/usr/bin/env python3
"""
RaspyJack *payload* – **Recon: WiFi Channel Analyzer**
=======================================================
A WiFi reconnaissance tool that hops through 2.4GHz and 5GHz channels
to analyze network congestion.

It counts the number of Access Points (APs) on each channel, helping to
identify the most and least crowded channels. This is useful for planning
attacks like an Evil Twin, where choosing a quieter channel can be more
effective.
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
WIFI_INTERFACE = "wlan1mon" # Must be in monitor mode
CHANNELS_2_4GHZ = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
# A subset of common 5GHz channels
CHANNELS_5GHZ = [36, 40, 44, 48, 149, 153, 157, 161]
SCAN_TIME_PER_CHANNEL = 1 # seconds

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
channel_data = {}
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
    d.text((5, 5), "WiFi Channel Analyzer", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    with ui_lock:
        if "Scanning" in status_msg or "Press" in status_msg:
            d.text((10, 60), status_msg, font=FONT, fill="yellow")
        else:
            sorted_channels = sorted(channel_data.items(), key=lambda x: x[0])
            start_index = max(0, selected_index - 4)
            end_index = min(len(sorted_channels), start_index + 8)
            y_pos = 25
            for i in range(start_index, end_index):
                color = "yellow" if i == selected_index else "white"
                ch, count = sorted_channels[i]
                d.text((5, y_pos), f"Channel {ch:<3}: {count} APs", font=FONT, fill=color)
                y_pos += 11

    d.text((5, 115), "OK=Scan | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# --- Scanner ---
def run_scan():
    global channel_data, status_msg
    
    all_channels = CHANNELS_2_4GHZ + CHANNELS_5GHZ
    
    for channel in all_channels:
        if not running: break
        with ui_lock:
            status_msg = f"Scanning Ch: {channel}"
            channel_data[channel] = 0
        
        try:
            # Set channel
            subprocess.run(f"iwconfig {WIFI_INTERFACE} channel {channel}", shell=True, check=True, capture_output=True)
            
            # Sniff for beacon frames
            beacons = set()
            def sniff_beacons(pkt):
                if pkt.haslayer(Dot11Beacon):
                    bssid = pkt[Dot11].addr2
                    if bssid not in beacons:
                        beacons.add(bssid)
                        with ui_lock:
                            channel_data[channel] += 1
            
            sniff(iface=WIFI_INTERFACE, prn=sniff_beacons, timeout=SCAN_TIME_PER_CHANNEL)

        except Exception as e:
            print(f"Error scanning channel {channel}: {e}", file=sys.stderr)
            
    with ui_lock:
        status_msg = "Scan Finished"

# --- Main Loop ---
try:
    if "mon" not in subprocess.check_output(f"iwconfig {WIFI_INTERFACE}", shell=True, text=True):
        draw_ui("Not in Monitor Mode!")
        time.sleep(3)
        raise SystemExit("Interface not in monitor mode.")

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
        
        # Allow scrolling while not scanning
        if not (scan_thread and scan_thread.is_alive()):
            if GPIO.input(PINS["UP"]) == 0:
                with ui_lock:
                    if channel_data: selected_index = (selected_index - 1) % len(channel_data)
                time.sleep(0.2)
            elif GPIO.input(PINS["DOWN"]) == 0:
                with ui_lock:
                    if channel_data: selected_index = (selected_index + 1) % len(channel_data)
                time.sleep(0.2)

        time.sleep(0.1)

except (KeyboardInterrupt, SystemExit):
    pass
finally:
    cleanup()
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("WiFi Channel Analyzer payload finished.")

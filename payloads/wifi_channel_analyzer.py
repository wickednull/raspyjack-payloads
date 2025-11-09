#!/usr/bin/env python3
import sys
import os
import time
import signal
import subprocess
import threading
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from scapy.all import *
conf.verb = 0
from wifi.raspyjack_integration import get_available_interfaces
from wifi.wifi_manager import WiFiManager

WIFI_INTERFACE = None
CHANNELS_2_4GHZ = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
CHANNELS_5GHZ = [36, 40, 44, 48, 149, 153, 157, 161]
SCAN_TIME_PER_CHANNEL = 1

PINS = { "UP": 6, "DOWN": 19, "OK": 13, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

running = True
scan_thread = None
channel_data = {}
ui_lock = threading.Lock()
status_msg = "Press OK to scan"
selected_index = 0
current_menu_selection = 0
wifi_manager = WiFiManager()

def cleanup(*_):
    global running
    running = False
    if scan_thread and scan_thread.is_alive():
        scan_thread.join(timeout=1)
    
    if WIFI_INTERFACE and wifi_manager:
        print(f"Deactivating monitor mode on {WIFI_INTERFACE}...")
        wifi_manager.deactivate_monitor_mode(WIFI_INTERFACE)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def draw_message(message: str, color: str = "yellow"):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    bbox = d.textbbox((0, 0), message, font=FONT_TITLE)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
    x = (128 - w) // 2
    y = (128 - h) // 2
    d.text((x, y), message, font=FONT_TITLE, fill=color)
    LCD.LCD_ShowImage(img, 0, 0)

def draw_ui_main():
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

def draw_ui_interface_selection(interfaces, current_selection):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Select Interface", font=FONT_TITLE, fill="cyan")
    d.line([(0, 22), (128, 22)], fill="cyan", width=1)

    y_pos = 25
    for i, iface in enumerate(interfaces):
        color = "yellow" if i == current_selection else "white"
        d.text((5, y_pos), iface, font=FONT, fill=color)
        y_pos += 11
    
    d.text((5, 115), "UP/DOWN=Select | OK=Confirm", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

def select_interface_menu():
    global WIFI_INTERFACE, current_menu_selection, status_msg
    
    available_interfaces = [iface for iface in get_available_interfaces() if iface.startswith('wlan')]
    if not available_interfaces:
        draw_message("No WiFi interfaces found!", "red")
        time.sleep(3)
        return False

    current_menu_selection = 0
    while running:
        draw_ui_interface_selection(available_interfaces, current_menu_selection)
        
        if GPIO.input(PINS["UP"]) == 0:
            current_menu_selection = (current_menu_selection - 1 + len(available_interfaces)) % len(available_interfaces)
            time.sleep(0.2)
        elif GPIO.input(PINS["DOWN"]) == 0:
            current_menu_selection = (current_menu_selection + 1) % len(available_interfaces)
            time.sleep(0.2)
        elif GPIO.input(PINS["OK"]) == 0:
            selected_iface = available_interfaces[current_menu_selection]
            draw_message(f"Activating monitor\nmode on {selected_iface}...", "yellow")
            
            monitor_iface = wifi_manager.activate_monitor_mode(selected_iface)
            if monitor_iface:
                WIFI_INTERFACE = monitor_iface
                draw_message(f"Monitor mode active\non {WIFI_INTERFACE}", "lime")
                time.sleep(2)
                return True
            else:
                draw_message(f"Failed to activate\nmonitor mode on {selected_iface}", "red")
                time.sleep(3)
                return False
        elif GPIO.input(PINS["KEY3"]) == 0:
            return False
        
        time.sleep(0.1)

def run_scan():
    global channel_data, status_msg
    
    if not WIFI_INTERFACE:
        with ui_lock:
            status_msg = "No interface selected!"
        return

    all_channels = CHANNELS_2_4GHZ + CHANNELS_5GHZ
    
    for channel in all_channels:
        if not running: break
        with ui_lock:
            status_msg = f"Scanning Ch: {channel}"
            channel_data[channel] = 0
        
        try:
            subprocess.run(f"iwconfig {WIFI_INTERFACE} channel {channel}", shell=True, check=True, capture_output=True)
            
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

if __name__ == "__main__":
    try:
        if not select_interface_menu():
            draw_message("No interface selected\nor monitor mode failed.", "red")
            time.sleep(3)
            raise SystemExit("No interface selected or monitor mode failed.")

        while running:
            draw_ui_main()
            
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
#!/usr/bin/env python3
"""
RaspyJack *payload* – **WiFi Probe Sniffer**
==========================================
This payload passively sniffs for Wi-Fi probe requests, which are sent by
devices searching for known networks. By capturing these, you can identify
SSIDs that devices have previously connected to, potentially revealing
information about their owners or their network habits.

Features:
- Interactive UI for selecting the wireless interface.
- Activates monitor mode on the selected interface.
- Captures and displays SSIDs from probe requests in real-time.
- Saves captured SSIDs to a loot file (`probed_ssids.txt`).
- Allows scrolling through the list of captured SSIDs.
- Graceful exit via KEY3 or Ctrl-C, deactivating monitor mode.

Controls:
- INTERFACE SELECTION SCREEN:
    - UP/DOWN: Navigate available wireless interfaces.
    - OK: Select interface and activate monitor mode.
    - KEY3: Cancel selection and exit.
- MAIN SCREEN:
    - UP/DOWN: Scroll through captured SSIDs.
    - KEY3: Exit Payload (stops sniffing and deactivates monitor mode).
"""
import sys
import os
import time
import signal
import subprocess
import threading
from collections import OrderedDict
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from scapy.all import *
from wifi.raspyjack_integration import get_available_interfaces
from wifi.wifi_manager import WiFiManager

PINS: dict[str, int] = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13,
    "KEY1": 21, "KEY2": 20, "KEY3": 16,
}

GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
FONT = ImageFont.load_default()
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)

WIFI_INTERFACE = None
ORIGINAL_WIFI_INTERFACE = None
RASPYJACK_DIR = os.path.abspath(os.path.join(__file__, '..', '..'))
LOOT_DIR = os.path.join(RASPYJACK_DIR, "loot", "ProbeRequests")
running = True
sniff_thread = None
probed_ssids = OrderedDict()
ui_lock = threading.Lock()
selected_index = 0
wifi_manager = WiFiManager()

def cleanup(*_):
    global running, WIFI_INTERFACE, ORIGINAL_WIFI_INTERFACE
    if running:
        running = False
    
    if WIFI_INTERFACE and wifi_manager and ORIGINAL_WIFI_INTERFACE:
        print(f"Attempting to deactivate monitor mode on {WIFI_INTERFACE} and restoring {ORIGINAL_WIFI_INTERFACE}...", file=sys.stderr)
        success = wifi_manager.deactivate_monitor_mode(WIFI_INTERFACE)
        if success:
            print(f"Successfully deactivated monitor mode on {WIFI_INTERFACE}", file=sys.stderr)
        else:
            print(f"ERROR: Failed to deactivate monitor mode on {WIFI_INTERFACE}", file=sys.stderr)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

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
    global WIFI_INTERFACE, ORIGINAL_WIFI_INTERFACE
    
    available_interfaces = [iface for iface in get_available_interfaces() if iface.startswith('wlan')]
    if not available_interfaces:
        draw_message(["No WiFi interfaces found!"], "red")
        time.sleep(3)
        return False

    current_menu_selection = 0
    last_button_press_time = 0
    BUTTON_DEBOUNCE_TIME = 0.2 # seconds

    while running:
        current_time = time.time()
        draw_ui_interface_selection(available_interfaces, current_menu_selection)
        
        if GPIO.input(PINS["UP"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
            last_button_press_time = current_time
            current_menu_selection = (current_menu_selection - 1 + len(available_interfaces)) % len(available_interfaces)
            time.sleep(BUTTON_DEBOUNCE_TIME)
        elif GPIO.input(PINS["DOWN"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
            last_button_press_time = current_time
            current_menu_selection = (current_menu_selection + 1) % len(available_interfaces)
            time.sleep(BUTTON_DEBOUNCE_TIME)
        elif GPIO.input(PINS["OK"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
            last_button_press_time = current_time
            selected_iface = available_interfaces[current_menu_selection]
            draw_message([f"Activating monitor", f"mode on {selected_iface}..."], "yellow")
            print(f"Attempting to activate monitor mode on {selected_iface}...", file=sys.stderr)
            
            monitor_iface = wifi_manager.activate_monitor_mode(selected_iface)
            if monitor_iface:
                WIFI_INTERFACE = monitor_iface
                ORIGINAL_WIFI_INTERFACE = selected_iface
                draw_message([f"Monitor mode active", f"on {WIFI_INTERFACE}"], "lime")
                print(f"Successfully activated monitor mode on {WIFI_INTERFACE}", file=sys.stderr)
                time.sleep(2)
                return True
            else:
                draw_message(["ERROR:", "Failed to activate", "monitor mode!"], "red")
                print(f"ERROR: wifi_manager.activate_monitor_mode failed for {selected_iface}", file=sys.stderr)
                time.sleep(3)
                return False
        elif GPIO.input(PINS["KEY3"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
            last_button_press_time = current_time
            return False
        
        time.sleep(0.05)

def packet_handler(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        ssid = pkt[Dot11Elt].info.decode(errors="ignore")
        if ssid:
            with ui_lock:
                if ssid not in probed_ssids:
                    probed_ssids[ssid] = time.strftime("%Y-%m-%d %H:%M:%S")
                    save_loot()

def sniffer_worker():
    while running:
        sniff(iface=WIFI_INTERFACE, prn=packet_handler, store=0, stop_filter=lambda p: not running)

def save_loot():
    os.makedirs(LOOT_DIR, exist_ok=True)
    loot_file = os.path.join(LOOT_DIR, "probed_ssids.txt")
    with open(loot_file, "w") as f:
        for ssid, ts in probed_ssids.items():
            f.write(f"{ts} - {ssid}\n")

def draw_ui():
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "WiFi Probe Sniffer", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    with ui_lock:
        if not probed_ssids:
            d.text((10, 60), "Sniffing...", font=FONT, fill="yellow")
        else:
            sorted_probes = list(probed_ssids.keys())
            start_index = max(0, selected_index - 4)
            end_index = min(len(sorted_probes), start_index + 8)
            y_pos = 25
            for i in range(start_index, end_index):
                color = "yellow" if i == selected_index else "white"
                ssid = sorted_probes[i]
                d.text((5, y_pos), ssid[:20], font=FONT, fill=color)
                y_pos += 11

    d.text((5, 115), "OK=Start | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

if __name__ == "__main__":
    try:
        if not select_interface_menu():
            draw_message(["No interface selected", "or monitor mode failed."], "red")
            time.sleep(3)
            raise SystemExit("No interface selected or monitor mode failed.")

        sniff_thread = threading.Thread(target=sniffer_worker, daemon=True)
        sniff_thread.start()

        last_button_press_time = 0
        BUTTON_DEBOUNCE_TIME = 0.3 # seconds

        while running:
            current_time = time.time()
            draw_ui()
            
            button_pressed = False
            start_wait = time.time()
            while time.time() - start_wait < 1.0 and not button_pressed:
                if GPIO.input(PINS["KEY3"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    cleanup()
                    break
                
                if GPIO.input(PINS["UP"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with ui_lock:
                        if probed_ssids:
                            selected_index = (selected_index - 1) % len(probed_ssids)
                    button_pressed = True
                    time.sleep(BUTTON_DEBOUNCE_TIME)
                elif GPIO.input(PINS["DOWN"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with ui_lock:
                        if probed_ssids:
                            selected_index = (selected_index + 1) % len(probed_ssids)
                    button_pressed = True
                    time.sleep(BUTTON_DEBOUNCE_TIME)
                
                time.sleep(0.05)
            
            if not running:
                break

    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        draw_message([f"ERROR:", f"{str(e)[:20]}"], "red")
        time.sleep(3)
    finally:
        cleanup()
        if sniff_thread:
            sniff_thread.join(timeout=1)
        draw_message(["Cleaning up..."])
        time.sleep(1)
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Probe Sniffer payload finished.")
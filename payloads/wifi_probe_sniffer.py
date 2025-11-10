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
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))) # Add parent directory for monitor_mode_helper
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from scapy.all import *
conf.verb = 0
from wifi.raspyjack_integration import get_available_interfaces
import re
import monitor_mode_helper

WIFI_INTERFACE = None
ORIGINAL_WIFI_INTERFACE = None
PROBES: dict[str, set[str]] = {}

PINS = { "UP": 6, "DOWN": 19, "OK": 13, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

running = True
sniff_thread = None
ui_lock = threading.Lock()
status_msg = "Press OK to start"
current_menu_selection = 0
selected_probe_index = 0
# wifi_manager = WiFiManager() # No longer needed for monitor mode

# --- Local Monitor Mode Functions ---


def cleanup(*_):
    global running
    running = False
    if sniff_thread and sniff_thread.is_alive():
        sniff_thread.join(timeout=1)
    
    if WIFI_INTERFACE: # Check if monitor mode was ever activated
        print(f"Attempting to deactivate monitor mode on {WIFI_INTERFACE}...", file=sys.stderr)
        success = monitor_mode_helper.deactivate_monitor_mode(WIFI_INTERFACE)
        if success:
            print(f"Successfully deactivated monitor mode on {WIFI_INTERFACE}", file=sys.stderr)
        else:
            print(f"ERROR: Failed to deactivate monitor mode on {WIFI_INTERFACE}", file=sys.stderr)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def draw_message(lines, color="yellow"):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    font = FONT_TITLE
    y = 40
    message_list = lines if isinstance(lines, list) else [lines]
    for line in message_list:
        bbox = d.textbbox((0, 0), line, font=font)
        w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        x = (WIDTH - w) // 2
        d.text((x, y), line, font=font, fill=color)
        y += h + 5
    LCD.LCD_ShowImage(img, 0, 0)

def draw_ui():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "WiFi Probe Sniffer", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    with ui_lock:
        if not PROBES:
            d.text((10, 60), status_msg, font=FONT, fill="yellow")
        else:
            # Sort by number of SSIDs, then by MAC address
            sorted_probes = sorted(PROBES.items(), key=lambda item: (len(item[1]), item[0]), reverse=True)
            
            # Calculate visible range for scrolling
            start_index = max(0, selected_probe_index - 2) # Show 2 items above selected
            end_index = min(len(sorted_probes), start_index + 3) # Show 3 items (MAC + 2 SSIDs)

            y_pos = 25
            for i in range(start_index, end_index):
                if y_pos > HEIGHT - 30: # Prevent drawing off-screen
                    break
                
                mac, ssids = sorted_probes[i]
                
                text_color = "yellow" if i == selected_probe_index else "white"
                
                # Display MAC address
                d.text((5, y_pos), f"{mac}", font=FONT, fill=text_color)
                y_pos += 11
                
                # Display associated SSIDs (up to 2)
                for j, ssid in enumerate(list(ssids)[:2]):
                    if y_pos > HEIGHT - 30:
                        break
                    d.text((10, y_pos), f"- {ssid[:16]}", font=FONT, fill=text_color)
                    y_pos += 11
                
                y_pos += 5 # Small gap between entries

    d.text((5, 115), "UP/DOWN=Scroll | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

def draw_ui_interface_selection(interfaces, current_selection):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
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
    global WIFI_INTERFACE, ORIGINAL_WIFI_INTERFACE, current_menu_selection, status_msg
    
    available_interfaces = [iface for iface in get_available_interfaces() if iface.startswith('wlan')]
    if not available_interfaces:
        draw_message(["No WiFi", "interfaces found!"], "red")
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
            draw_message([f"Activating monitor", f"mode on {selected_iface}...",], "yellow")
            print(f"Attempting to activate monitor mode on {selected_iface}...", file=sys.stderr)
            
            ORIGINAL_WIFI_INTERFACE = selected_iface # Store original interface before activation
            monitor_iface = monitor_mode_helper.activate_monitor_mode(selected_iface)
            if monitor_iface:
                WIFI_INTERFACE = monitor_iface
                draw_message([f"Monitor mode active", f"on {WIFI_INTERFACE}"], "lime")
                print(f"Successfully activated monitor mode on {WIFI_INTERFACE}", file=sys.stderr)
                time.sleep(2)
                return True
            else:
                draw_message(["ERROR:", "Monitor mode failed!", "Check stderr for details."], "red")
                print(f"ERROR: monitor_mode_helper.activate_monitor_mode failed for {selected_iface}. See stderr for details from helper.", file=sys.stderr)
                time.sleep(3)
                return False
        elif GPIO.input(PINS["KEY3"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
            last_button_press_time = current_time
            return False
        
        time.sleep(0.05)

def packet_handler(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        mac_address = pkt.addr2
        ssid = pkt[Dot11Elt].info.decode(errors="ignore")
        if mac_address and ssid:
            with ui_lock:
                if mac_address not in PROBES:
                    PROBES[mac_address] = set()
                if ssid not in PROBES[mac_address]:
                    PROBES[mac_address].add(ssid)
                    save_loot() # Save loot whenever a new SSID is found for a MAC

def sniffer_worker():
    while running:
        sniff(iface=WIFI_INTERFACE, prn=packet_handler, store=0, stop_filter=lambda p: not running)

def save_loot():
    os.makedirs(LOOT_DIR, exist_ok=True)
    loot_file = os.path.join(LOOT_DIR, "probed_ssids.txt")
    with open(loot_file, "w") as f:
        for mac, ssids in PROBES.items():
            f.write(f"MAC: {mac}\n")
            for ssid in ssids:
                f.write(f"  SSID: {ssid}\n")
            f.write("\n") # Add a blank line for readability

def draw_ui():
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "WiFi Probe Sniffer", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    with ui_lock:
        if not PROBES: # Changed from probed_ssids to PROBES
            d.text((10, 60), "Sniffing...", font=FONT, fill="yellow")
        else:
            sorted_probes = list(PROBES.keys()) # Changed from probed_ssids to PROBES
            start_index = max(0, selected_probe_index - 4)
            end_index = min(len(sorted_probes), start_index + 8)
            y_pos = 25
            for i in range(start_index, end_index):
                color = "yellow" if i == selected_probe_index else "white"
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
                        if PROBES:
                            sorted_probes = sorted(PROBES.items(), key=lambda item: (len(item[1]), item[0]), reverse=True)
                            selected_probe_index = (selected_probe_index - 1 + len(sorted_probes)) % len(sorted_probes)
                    button_pressed = True
                    time.sleep(BUTTON_DEBOUNCE_TIME)
                elif GPIO.input(PINS["DOWN"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    with ui_lock:
                        if PROBES:
                            sorted_probes = sorted(PROBES.items(), key=lambda item: (len(item[1]), item[0]), reverse=True)
                            selected_probe_index = (selected_probe_index + 1) % len(sorted_probes)
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

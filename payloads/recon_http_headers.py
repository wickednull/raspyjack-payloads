#!/usr/bin/env python3
import sys
import os
import time
import signal
import subprocess
import socket
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from wifi.raspyjack_integration import get_available_interfaces, set_raspyjack_interface
from wifi.wifi_manager import WiFiManager

PINS: dict[str, int] = { "OK": 13, "KEY3": 16, "KEY1": 21, "KEY2": 20, "UP": 6, "DOWN": 19 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

TARGET_IP = "192.168.1.1"
TARGET_PORT = 80
running = True
selected_index = 0
headers = []
current_ip_input = TARGET_IP
ip_input_cursor_pos = 0
current_port_input = str(TARGET_PORT)
port_input_cursor_pos = 0
wifi_manager = WiFiManager()

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
    global status_msg
    
    available_interfaces = get_available_interfaces()
    if not available_interfaces:
        show_message(["No network", "interfaces found!"], "red")
        time.sleep(3)
        return None

    current_menu_selection = 0
    while running:
        draw_ui_interface_selection(available_interfaces, current_menu_selection)
        
        if GPIO.input(PINS["KEY3"]) == 0:
            return None
        
        if GPIO.input(PINS["UP"]) == 0:
            current_menu_selection = (current_menu_selection - 1 + len(available_interfaces)) % len(available_interfaces)
            time.sleep(0.2)
        elif GPIO.input(PINS["DOWN"]) == 0:
            current_menu_selection = (current_menu_selection + 1) % len(available_interfaces)
            time.sleep(0.2)
        elif GPIO.input(PINS["OK"]) == 0:
            selected_iface = available_interfaces[current_menu_selection]
            show_message([f"Selected:", f"{selected_iface}"], "lime")
            time.sleep(1)
            return selected_iface
        
        time.sleep(0.1)

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def draw_ui(status_msg=None):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "HTTP Header Viewer", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    if status_msg:
        d.text((10, 60), status_msg, font=FONT, fill="yellow")
    else:
        start_index = max(0, selected_index - 4)
        end_index = min(len(headers), start_index + 8)
        y_pos = 25
        for i in range(start_index, end_index):
            color = "yellow" if i == selected_index else "white"
            line = headers[i]
            if len(line) > 20: line = line[:19] + "..."
            d.text((5, y_pos), line, font=FONT, fill=color)
            y_pos += 11

    d.text((5, 115), "OK=Get | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

def get_headers(interface):
    global headers, selected_index
    draw_ui("Connecting...")
    headers = []
    selected_index = 0
    
    try:
        if set_raspyjack_interface(interface):
            show_message([f"Interface {interface}", "activated."], "lime")
            time.sleep(1)
        else:
            show_message([f"Failed to activate", f"{interface}."], "red")
            return

        import requests
        url = f"http://{TARGET_IP}:{TARGET_PORT}"
        resp = requests.head(url, timeout=5)
        
        headers.append(f"Status: {resp.status_code}")
        for key, value in resp.headers.items():
            headers.append(f"{key}: {value}")

    except Exception as e:
        headers.append("Request failed!")
        headers.append(str(e)[:20])
        print(f"HTTP request failed: {e}", file=sys.stderr)

if __name__ == '__main__':
    try:
        import requests
    except ImportError:
        show_message(["ERROR:", "requests not found!"], "red")
        time.sleep(3)
        sys.exit(1)

    selected_interface = select_interface_menu()
    if not selected_interface:
        show_message(["No interface", "selected!", "Exiting..."], "red")
        time.sleep(3)
        sys.exit(1)

    draw_ui("Press OK to get")
    while running:
        if GPIO.input(PINS["KEY3"]) == 0:
            cleanup()
            break
        
        if GPIO.input(PINS["OK"]) == 0:
            get_headers(selected_interface)
            draw_ui()
            time.sleep(0.5)
            while running:
                if GPIO.input(PINS["KEY3"]) == 0:
                    break
                if GPIO.input(PINS["UP"]) == 0:
                    selected_index = (selected_index - 1) % len(headers)
                    draw_ui()
                    time.sleep(0.2)
                elif GPIO.input(PINS["DOWN"]) == 0:
                    selected_index = (selected_index + 1) % len(headers)
                    draw_ui()
                    time.sleep(0.2)
                time.sleep(0.05)
        
        time.sleep(0.1)

    cleanup()
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("HTTP Header payload finished.")
#!/usr/bin/env python3
"""
RaspyJack *payload* – **SMB Share Scanner**
=========================================
This payload scans a target IP address for accessible Server Message Block (SMB)
shares. It uses the `smbclient` utility to list shares, which can reveal
valuable information about network resources and potential data exfiltration
points.

Features:
- Interactive UI for selecting the network interface.
- Interactive UI for entering the target IP address.
- Uses `smbclient` to enumerate SMB shares.
- Displays found shares on the LCD with scrolling capabilities.
- Graceful exit via KEY3 or Ctrl-C.

Controls:
- MAIN SCREEN:
    - OK: Start scanning for SMB shares.
    - KEY1: Edit target IP.
    - KEY3: Exit Payload.
- IP INPUT SCREEN:
    - UP/DOWN: Change digit at cursor position.
    - LEFT/RIGHT: Move cursor.
    - OK: Confirm IP.
    - KEY3: Cancel input.
- INTERFACE SELECTION SCREEN:
    - UP/DOWN: Navigate interfaces.
    - OK: Select interface.
    - KEY3: Cancel selection.
"""
import sys
import os
import time
import signal
import subprocess
import threading
import socket
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from wifi.raspyjack_integration import get_available_interfaces, set_raspyjack_interface
from wifi.wifi_manager import WiFiManager

PINS: dict[str, int] = { "OK": 13, "KEY3": 16, "KEY1": 21, "KEY2": 20, "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

TARGET_IP = "192.168.1.10"
running = True
selected_index = 0
shares = []
current_ip_input = TARGET_IP
ip_input_cursor_pos = 0
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

def show_message(lines, color="lime"):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    font = FONT_TITLE
    y = 40
    for line in lines:
        bbox = d.textbbox((0, 0), line, font=font)
        w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        x = (128 - w) // 2
        d.text((x, y), line, font=font, fill=color)
        y += h + 5
    LCD.LCD_ShowImage(img, 0, 0)

def draw_ui(screen_state="main"):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "SMB Share Scanner", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    if screen_state == "main":
        d.text((5, 25), "Target IP:", font=FONT, fill="white")
        d.text((5, 40), TARGET_IP, font=FONT_TITLE, fill="yellow")
        
        if not shares:
            d.text((10, 60), "No shares found.", font=FONT, fill="white")
        else:
            d.text((5, 55), f"Shares Found: {len(shares)}", font=FONT, fill="yellow")
            start_index = max(0, selected_index - 2)
            end_index = min(len(shares), start_index + 4)
            y_pos = 70
            for i in range(start_index, end_index):
                color = "yellow" if i == selected_index else "white"
                d.text((10, y_pos), shares[i], font=FONT, fill=color)
                y_pos += 11

        d.text((5, 115), "OK=Scan | KEY1=Edit IP | KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "ip_input":
        d.text((5, 30), "Enter Target IP:", font=FONT, fill="white")
        display_ip = list(current_ip_input)
        if ip_input_cursor_pos < len(display_ip):
            display_ip[ip_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_ip), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Digit | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "scanning":
        d.text((5, 50), "Scanning...", font=FONT_TITLE, fill="yellow")
        d.text((5, 70), f"Target: {TARGET_IP}", font=FONT, fill="white")
        d.text((5, 115), "KEY3=Stop", font=FONT, fill="cyan")
    
    LCD.LCD_ShowImage(img, 0, 0)

def handle_ip_input_logic(initial_ip):
    global current_ip_input, ip_input_cursor_pos
    current_ip_input = initial_ip
    ip_input_cursor_pos = len(initial_ip) - 1
    
    draw_ui("ip_input")
    
    while running:
        btn = None
        for name, pin in PINS.items():
            if GPIO.input(pin) == 0:
                btn = name
                while GPIO.input(pin) == 0:
                    time.sleep(0.05)
                break
        
        if btn == "KEY3":
            return None
        
        if btn == "OK":
            parts = current_ip_input.split('.')
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return current_ip_input
            else:
                show_message(["Invalid IP!", "Try again."], "red")
                time.sleep(2)
                current_ip_input = initial_ip
                ip_input_cursor_pos = len(initial_ip) - 1
                draw_ui("ip_input")
        
        if btn == "LEFT":
            ip_input_cursor_pos = max(0, ip_input_cursor_pos - 1)
            draw_ui("ip_input")
        elif btn == "RIGHT":
            ip_input_cursor_pos = min(len(current_ip_input), ip_input_cursor_pos + 1)
            draw_ui("ip_input")
        elif btn == "UP" or btn == "DOWN":
            if ip_input_cursor_pos < len(current_ip_input):
                char_list = list(current_ip_input)
                current_char = char_list[ip_input_cursor_pos]
                
                if current_char.isdigit():
                    digit = int(current_char)
                    if btn == "UP":
                        digit = (digit + 1) % 10
                    else:
                        digit = (digit - 1 + 10) % 10
                    char_list[ip_input_cursor_pos] = str(digit)
                    current_ip_input = "".join(char_list)
                elif current_char == '.':
                    if btn == "UP":
                        ip_input_cursor_pos = min(len(current_ip_input), ip_input_cursor_pos + 1)
                    else:
                        ip_input_cursor_pos = max(0, ip_input_cursor_pos - 1)
                draw_ui("ip_input")
        
        time.sleep(0.1)
    return None

def run_scan(interface):
    global shares, selected_index, TARGET_IP
    draw_ui("scanning")
    shares = []
    selected_index = 0
    
    try:
        if set_raspyjack_interface(interface):
            show_message([f"Interface {interface}", "activated."], "lime")
            time.sleep(1)
        else:
            show_message([f"Failed to activate", f"{interface}."], "red")
            return

        command = f"smbclient -L //{TARGET_IP} -N"
        proc = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=15)
        
        if proc.returncode == 0:
            for line in proc.stdout.split('\n'):
                if "Disk" in line:
                    share_name = line.split('|')[0].strip()
                    if share_name:
                        shares.append(share_name)
            if not shares:
                shares.append("No shares found")
        else:
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

if __name__ == '__main__':
            last_button_press_time = 0
            BUTTON_DEBOUNCE_TIME = 0.3 # seconds
    
            if subprocess.run("which smbclient", shell=True, capture_output=True).returncode != 0:
                show_message(["ERROR:", "smbclient", "not found!"], "red")
                time.sleep(3)
                sys.exit(1)
    
            selected_interface = select_interface_menu()
            if not selected_interface:
                show_message(["No interface", "selected!", "Exiting..."], "red")
                time.sleep(3)
                sys.exit(1)
    
            while running:
                current_time = time.time()
                
                if current_screen == "main":
                    draw_ui("main")
                    
                    if GPIO.input(PINS["KEY3"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                        last_button_press_time = current_time
                        cleanup()
                        break
                    
                    if GPIO.input(PINS["OK"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                        last_button_press_time = current_time
                        run_scan(selected_interface)
                        current_screen = "main"
                        time.sleep(BUTTON_DEBOUNCE_TIME)
                    
                    if GPIO.input(PINS["UP"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                        last_button_press_time = current_time
                        if shares:
                            selected_index = (selected_index - 1) % len(shares)
                        time.sleep(BUTTON_DEBOUNCE_TIME)
                    elif GPIO.input(PINS["DOWN"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                        last_button_press_time = current_time
                        if shares:
                            selected_index = (selected_index + 1) % len(shares)
                        time.sleep(BUTTON_DEBOUNCE_TIME)
                    
                    if GPIO.input(PINS["KEY1"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                        last_button_press_time = current_time
                        current_ip_input = TARGET_IP
                        current_screen = "ip_input"
                        time.sleep(BUTTON_DEBOUNCE_TIME)
                
                elif current_screen == "ip_input":
                    char_set = "0123456789."
                    new_ip = handle_ip_input_logic(current_ip_input)
                    if new_ip:
                        TARGET_IP = new_ip
                    current_screen = "main"
                    time.sleep(BUTTON_DEBOUNCE_TIME)
                
                time.sleep(0.1)
    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        show_message(["CRITICAL ERROR:", str(e)[:20]], "red")
        time.sleep(3)
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("SMB Share payload finished.")
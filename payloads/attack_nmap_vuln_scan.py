#!/usr/bin/env python3
"""
RaspyJack *payload* – **Nmap Vulnerability Scan**
================================================
This payload performs an Nmap vulnerability scan against a target IP address.
It allows the user to input the target IP and select a network interface
for the scan. The scan runs in a background thread to keep the UI responsive.

Features:
- Interactive UI for entering target IP address.
- Allows selection of network interface for the scan.
- Uses `nmap` with `--script vuln` for vulnerability detection.
- Displays scan status on the LCD.
- Runs Nmap scan in a background thread.
- Graceful exit via KEY3 or Ctrl-C, ensuring `nmap` is terminated.
- Dynamically determines the active network interface.

Controls:
- MAIN SCREEN:
    - OK: Start/Enter Target IP
    - KEY3: Exit Payload
- IP INPUT SCREEN:
    - UP/DOWN: Change digit at cursor position
    - LEFT/RIGHT: Move cursor
    - OK: Confirm IP and start scan
    - KEY3: Cancel IP input and return to main screen
- INTERFACE SELECTION SCREEN:
    - UP/DOWN: Navigate interfaces
    - OK: Select interface
    - KEY3: Cancel selection and return to main screen
"""

import sys
import os
import time
import signal
import subprocess
import threading
import re # For IP validation

sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# WiFi Integration - Import dynamic interface support
try:

    sys.path.append('/root/Raspyjack/wifi/')
    from wifi.raspyjack_integration import get_best_interface, get_available_interfaces
    WIFI_INTEGRATION_AVAILABLE = True
except ImportError:
    WIFI_INTEGRATION_AVAILABLE = False
    def get_best_interface():
        return "eth0" # Fallback
    def get_available_interfaces():
        # Fallback for when wifi integration is not available
        try:
            output = subprocess.check_output("ls /sys/class/net | grep -E 'eth|wlan'", shell=True).decode().strip()
            return output.split('\n') if output else ["eth0"]
        except:
            return ["eth0"]

RASPYJACK_DIR = os.path.abspath(os.path.join(__file__, '..', '..'))
TARGET_IP = "192.168.1.1"
LOOT_DIR = os.path.join(RASPYJACK_DIR, "loot", "Nmap_Vuln")

PINS = { "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

running = True
scan_thread = None
nmap_process = None # To keep track of the nmap subprocess
status_msg = "Press OK to scan"
current_ip_input = "192.168.1.1"
ip_input_cursor_pos = 0
ip_input_segment = 0
NETWORK_INTERFACE = get_best_interface() # Dynamically get the best interface

def cleanup(*_):
    global running
    running = False
    stop_scan_process() # Ensure nmap is terminated

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def stop_scan_process():
    """Terminate the nmap process if it's running."""
    global nmap_process
    if nmap_process and nmap_process.poll() is None:
        try:
            nmap_process.terminate()
            nmap_process.wait(timeout=5)
            print("Nmap process terminated.")
        except (subprocess.TimeoutExpired, ProcessLookupError):
            nmap_process.kill()
            print("Nmap process killed.")
        nmap_process = None

def draw_ui(screen_state="main", message_lines=None):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    
    # Header
    d.text((5, 5), "Nmap Vuln Scan", font=FONT_TITLE, fill="#FF0000")
    d.line([(0, 22), (128, 22)], fill="#FF0000", width=1)
    d.text((5, 115), f"IF: {NETWORK_INTERFACE}", font=FONT, fill="gray") # Display interface

    if message_lines:
        if isinstance(message_lines, str):
            message_lines = [message_lines]
        y_offset = (HEIGHT - len(message_lines) * 12) // 2
        for line in message_lines:
            bbox = d.textbbox((0, 0), line, font=FONT)
            w = bbox[2] - bbox[0]
            x = (WIDTH - w) // 2
            d.text((x, y_offset), line, font=FONT, fill="yellow")
            y_offset += 12
    elif screen_state == "main":
        d.text((10, 60), status_msg, font=FONT, fill="yellow")
        d.text((5, 100), "OK=Scan | KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "ip_input":
        d.text((5, 30), "Enter Target IP:", font=FONT, fill="white")
        display_ip = list(current_ip_input)
        if ip_input_cursor_pos < len(display_ip):
            display_ip[ip_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_ip), font=FONT_TITLE, fill="yellow")
        d.text((5, 100), "UP/DOWN=Digit | LEFT/RIGHT=Move", font=FONT, fill="cyan")
        d.text((5, 110), "OK=Confirm | KEY3=Cancel", font=FONT, fill="cyan")
    
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
    
    d.text((5, 100), "UP/DOWN=Select | OK=Confirm", font=FONT, fill="cyan")
    d.text((5, 110), "KEY3=Cancel", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

def select_interface_menu():
    global NETWORK_INTERFACE, status_msg
    
    available_interfaces = get_available_interfaces()
    if not available_interfaces:
        draw_ui(message_lines=["No network", "interfaces found!"], color="red")
        time.sleep(3)
        return None

    current_menu_selection = 0
    while running:
        draw_ui_interface_selection(available_interfaces, current_menu_selection)
        
        btn = None
        for name, pin in PINS.items():
            if GPIO.input(pin) == 0:
                btn = name
                while GPIO.input(pin) == 0:
                    time.sleep(0.05)
                break

        if btn == "KEY3":
            return None
        
        if btn == "UP":
            current_menu_selection = (current_menu_selection - 1 + len(available_interfaces)) % len(available_interfaces)
        elif btn == "DOWN":
            current_menu_selection = (current_menu_selection + 1) % len(available_interfaces)
        elif btn == "OK":
            selected_iface = available_interfaces[current_menu_selection]
            draw_ui(message_lines=[f"Selected:", f"{selected_iface}"], color="lime")
            time.sleep(1)
            return selected_iface
        
        time.sleep(0.1)

def handle_ip_input():
    global current_ip_input, ip_input_cursor_pos, ip_input_segment
    
    # Ensure IP is valid or reset
    parts = current_ip_input.split('.')
    if not (len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)):
        current_ip_input = "192.168.1.1"
        ip_input_cursor_pos = 0
        ip_input_segment = 0
    
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
            return False # Cancel
        
        if btn == "OK":
            parts = current_ip_input.split('.')
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return True # Valid IP
            else:
                draw_ui(message_lines=["Invalid IP!", "Try again."])
                time.sleep(2)
                current_ip_input = "192.168.1.1"
                ip_input_cursor_pos = 0
                ip_input_segment = 0
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
                    # Move past the dot
                    if btn == "UP": # Treat UP/DOWN on a dot as moving right/left
                        ip_input_cursor_pos = min(len(current_ip_input), ip_input_cursor_pos + 1)
                    else:
                        ip_input_cursor_pos = max(0, ip_input_cursor_pos - 1)
                draw_ui("ip_input")
        
        time.sleep(0.1)
    return False

def run_scan(target_ip, interface):
    global status_msg, nmap_process
    
    os.makedirs(LOOT_DIR, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H%M%S")
    output_file = os.path.join(LOOT_DIR, f"vuln_scan_{target_ip}_{timestamp}.txt")
    
    status_msg = f"Scanning {target_ip} on {interface}..."
    draw_ui("main") # Update UI with status
    
    try:
        command = ["nmap", "-e", interface, "--script", "vuln", "-oN", output_file, target_ip]
        # Use Popen to allow termination
        nmap_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = nmap_process.communicate(timeout=600) # Wait for process to complete or timeout
        
        if nmap_process.returncode == 0:
            status_msg = "Scan complete!"
        else:
            status_msg = f"Nmap exited with error: {nmap_process.returncode}"
            print(f"Nmap stderr: {stderr}", file=sys.stderr)

    except subprocess.TimeoutExpired:
        stop_scan_process() # Ensure nmap is killed if it times out
        status_msg = "Scan timed out!"
    except Exception as e:
        status_msg = "Scan failed!"
        print(f"Nmap scan failed: {e}", file=sys.stderr)
    finally:
        nmap_process = None # Clear process reference
    draw_ui("main") # Update UI with final status

if __name__ == "__main__":
    try:
        if subprocess.run("which nmap", shell=True, capture_output=True).returncode != 0:
            draw_ui(message_lines=["ERROR:", "`nmap` not found!", "Install with:", "`sudo apt install nmap`"])
            time.sleep(5)
            raise SystemExit("`nmap` command not found.")

        # Use the dynamically determined NETWORK_INTERFACE as default
        selected_interface = NETWORK_INTERFACE
        
        current_screen = "main"

        while running:
            if current_screen == "main":
                draw_ui("main")
                
                if GPIO.input(PINS["KEY3"]) == 0:
                    cleanup()
                    break
                
                if GPIO.input(PINS["OK"]) == 0:
                    # Allow user to select interface before IP input
                    temp_interface = select_interface_menu()
                    if temp_interface:
                        selected_interface = temp_interface
                    
                    current_screen = "ip_input"
                    time.sleep(0.3)
            
            elif current_screen == "ip_input":
                if handle_ip_input():
                    TARGET_IP = current_ip_input
                    if not (scan_thread and scan_thread.is_alive()):
                        scan_thread = threading.Thread(target=run_scan, args=(TARGET_IP, selected_interface,), daemon=True)
                        scan_thread.start()
                    current_screen = "main"
                else: # IP input cancelled or invalid
                    current_screen = "main"
                time.sleep(0.3)

            time.sleep(0.1)

    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        draw_ui(message_lines=[f"CRITICAL ERROR:", f"{str(e)[:20]}"], color="red")
        time.sleep(3)
    finally:
        stop_scan_process() # Ensure nmap is terminated on final exit
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Nmap Vuln Scan payload finished.")
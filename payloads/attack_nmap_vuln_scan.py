#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
"""
RaspyJack *payload* – **Attack: Nmap Vuln Scan**
==================================================
A convenience payload that launches a dedicated Nmap vulnerability scan
against a target. This uses the `--script vuln` argument to run all
scripts in Nmap's "vuln" category.

This is a "fire-and-forget" scan that saves its output to a loot file.
"""

import os, sys, subprocess, signal, time, threading
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
try:
    sys.path.append('/root/Raspyjack/wifi/')
    from wifi.raspyjack_integration import get_available_interfaces
    from wifi.wifi_manager import WiFiManager
    WIFI_INTEGRATION = True
    wifi_manager = WiFiManager()
    print("✅ WiFi integration loaded - dynamic interface support enabled")
except ImportError as e:
    print(f"⚠️  WiFi integration not available: {e}")
    WIFI_INTEGRATION = False
    wifi_manager = None # Ensure wifi_manager is None if import fails

TARGET_IP = "192.168.1.1" # Default IP, will be configurable
LOOT_DIR = "/root/Raspyjack/loot/Nmap_Vuln/"

# --- GPIO & LCD ---
PINS = { "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

# --- Globals & Shutdown ---
running = True
scan_thread = None
status_msg = "Press OK to scan"
current_ip_input = "192.168.1.1" # Initial value for IP input
ip_input_cursor_pos = 0 # Cursor position for IP input
ip_input_segment = 0 # Which segment of the IP (0-3) is being edited

def cleanup(*_):
    global running
    running = False
    # In a real scenario, you might want to kill the nmap process
    # but for a fire-and-forget script, we let it finish.

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI ---
def draw_ui(screen_state="main"):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Nmap Vuln Scan", font=FONT_TITLE, fill="#FF0000")
    d.line([(0, 22), (128, 22)], fill="#FF0000", width=1)
    
    if screen_state == "main":
        d.text((10, 60), status_msg, font=FONT, fill="yellow")
        d.text((5, 115), "OK=Scan | KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "ip_input":
        d.text((5, 30), "Enter Target IP:", font=FONT, fill="white")
        display_ip = list(current_ip_input)
        if ip_input_cursor_pos < len(display_ip):
            display_ip[ip_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_ip), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Digit | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    
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
    global WIFI_INTERFACE, status_msg
    
    if not WIFI_INTEGRATION or not wifi_manager:
        draw_message("WiFi integration not available!", "red")
        time.sleep(3)
        return None # Return None if integration is not available

    available_interfaces = get_available_interfaces() # Get all available interfaces
    if not available_interfaces:
        draw_message("No network interfaces found!", "red")
        time.sleep(3)
        return None

    current_menu_selection = 0
    while running:
        draw_ui_interface_selection(available_interfaces, current_menu_selection)
        
        if GPIO.input(PINS["KEY3"]) == 0: # Cancel
            return None
        
        if GPIO.input(PINS["UP"]) == 0:
            current_menu_selection = (current_menu_selection - 1 + len(available_interfaces)) % len(available_interfaces)
            time.sleep(0.2)
        elif GPIO.input(PINS["DOWN"]) == 0:
            current_menu_selection = (current_menu_selection + 1) % len(available_interfaces)
            time.sleep(0.2)
        elif GPIO.input(PINS["OK"]) == 0:
            selected_iface = available_interfaces[current_menu_selection]
            draw_message(f"Selected:\n{selected_iface}", "lime")
            time.sleep(1)
            return selected_iface
        
        time.sleep(0.1)

def handle_ip_input():
    global current_ip_input, ip_input_cursor_pos, ip_input_segment
    
    ip_segments = current_ip_input.split('.')
    if len(ip_segments) != 4: # Reset if invalid format
        ip_segments = ["192", "168", "1", "1"]
        current_ip_input = ".".join(ip_segments)
    
    draw_ui("ip_input")
    
    while running:
        btn = None
        for name, pin in PINS.items():
            if GPIO.input(pin) == 0:
                btn = name
                while GPIO.input(pin) == 0: # Debounce
                    time.sleep(0.05)
                break
        
        if btn == "KEY3": # Cancel IP input
            return False
        
        if btn == "OK": # Confirm IP
            # Validate IP format
            parts = current_ip_input.split('.')
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return True
            else:
                draw_ui("ip_input")
                draw_message("Invalid IP!\nTry again.")
                time.sleep(2)
                current_ip_input = "192.168.1.1" # Reset to default
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
                    else: # DOWN
                        digit = (digit - 1 + 10) % 10
                    char_list[ip_input_cursor_pos] = str(digit)
                    current_ip_input = "".join(char_list)
                elif current_char == '.':
                    # Cannot change dot, move cursor
                    if btn == "UP":
                        ip_input_cursor_pos = min(len(current_ip_input), ip_input_cursor_pos + 1)
                    else:
                        ip_input_cursor_pos = max(0, ip_input_cursor_pos - 1)
                draw_ui("ip_input")
        
        time.sleep(0.1)
    return False

# --- Scanner ---
def run_scan(target_ip, interface):
    global status_msg
    
    os.makedirs(LOOT_DIR, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H%M%S")
    output_file = os.path.join(LOOT_DIR, f"vuln_scan_{target_ip}_{timestamp}.txt")
    
    status_msg = f"Scanning {target_ip} on {interface}..."
    
    try:
        command = f"nmap -e {interface} --script vuln -oN {output_file} {target_ip}"
        subprocess.run(command, shell=True, check=True, timeout=600) # 10 minute timeout
        status_msg = "Scan complete!"
    except subprocess.TimeoutExpired:
        status_msg = "Scan timed out!"
    except Exception as e:
        status_msg = "Scan failed!"
        print(f"Nmap scan failed: {e}", file=sys.stderr)

# --- Main Loop ---
try:
    if subprocess.run("which nmap", shell=True, capture_output=True).returncode != 0:
        status_msg = "nmap not found!"
        draw_ui()
        time.sleep(3)
        raise SystemExit("`nmap` command not found.")

    selected_interface = None
    if WIFI_INTEGRATION:
        selected_interface = select_interface_menu()
        if not selected_interface:
            draw_message("No interface selected!", "red")
            time.sleep(3)
            raise SystemExit("No interface selected for scan.")
    else:
        # Fallback if WIFI_INTEGRATION is not available
        selected_interface = "eth0" # Default to eth0 if no dynamic selection

    current_screen = "main" # State variable for the main loop

    while running:
        if current_screen == "main":
            draw_ui("main")
            
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            if GPIO.input(PINS["OK"]) == 0:
                # Transition to IP input screen
                current_screen = "ip_input"
                time.sleep(0.3) # Debounce
        
        elif current_screen == "ip_input":
            if handle_ip_input(): # If IP input is confirmed
                TARGET_IP = current_ip_input # Update global TARGET_IP
                if not (scan_thread and scan_thread.is_alive()):
                    scan_thread = threading.Thread(target=run_scan, args=(TARGET_IP, selected_interface,), daemon=True)
                    scan_thread.start()
                current_screen = "main" # Go back to main screen after starting scan
            else: # If IP input is cancelled
                current_screen = "main"
            time.sleep(0.3) # Debounce

        time.sleep(0.1)

except (KeyboardInterrupt, SystemExit):
    pass
finally:
    cleanup()
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("Nmap Vuln Scan payload finished.")

#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
"""
RaspyJack *payload* – **Recon: Passive OS Fingerprinting**
===========================================================
A passive OS fingerprinting tool that makes an educated guess about a
target's operating system based on its TCP/IP stack characteristics.

This payload sends a single TCP SYN packet to an open port and analyzes
the TTL (Time To Live) and TCP Window Size of the SYN/ACK response. These
values are often characteristic of a particular OS.
"""

import os, sys, subprocess, signal, time
# ---------------------------- Third‑party libs ----------------------------
try:
    import RPi.GPIO as GPIO
    import LCD_1in44, LCD_Config
    from PIL import Image, ImageDraw, ImageFont
    HARDWARE_LIBS_AVAILABLE = True
except ImportError:
    HARDWARE_LIBS_AVAILABLE = False
    print("WARNING: RPi.GPIO or LCD drivers not available. UI will not function.", file=sys.stderr)

try:
    from scapy.all import *
    conf.verb = 0
except ImportError:
    sys.exit(1)

# --- CONFIGURATION ---
try:
    sys.path.append('/root/Raspyjack/wifi/')
    from wifi.raspyjack_integration import get_available_interfaces, set_raspyjack_interface
    from wifi.wifi_manager import WiFiManager
    WIFI_INTEGRATION = True
    wifi_manager = WiFiManager()
    print("✅ WiFi integration loaded - dynamic interface support enabled")
except ImportError as e:
    print(f"⚠️  WiFi integration not available: {e}")
    WIFI_INTEGRATION = False
    wifi_manager = None # Ensure wifi_manager is None if import fails

TARGET_IP = "192.168.1.1" # Will be configurable
TARGET_PORT = 80 # An open port on the target, will be configurable

# --- Globals & Shutdown ---
running = True
current_ip_input = TARGET_IP # Initial value for IP input
ip_input_cursor_pos = 0 # Cursor position for IP input
current_port_input = str(TARGET_PORT) # Initial value for Port input
port_input_cursor_pos = 0 # Cursor position for Port input

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
    global ETH_INTERFACE, status_msg
    
    if not WIFI_INTEGRATION or not wifi_manager:
        show_message(["WiFi integration", "not available!"], "red")
        time.sleep(3)
        return None # Return None if integration is not available

    available_interfaces = get_available_interfaces() # Get all available interfaces
    if not available_interfaces:
        show_message(["No network", "interfaces found!"], "red")
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
            show_message([f"Selected:", f"{selected_iface}"], "lime")
            time.sleep(1)
            return selected_iface
        
        time.sleep(0.1)

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI ---
def show_message(lines, color="lime"):
    if not HARDWARE_LIBS_AVAILABLE:
        for line in lines:
            print(line)
        return
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    font = FONT_TITLE # Use FONT_TITLE for messages
    y = 40
    for line in lines:
        bbox = d.textbbox((0, 0), line, font=font)
        w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        x = (128 - w) // 2
        d.text((x, y), line, font=font, fill=color)
        y += h + 5
    LCD.LCD_ShowImage(img, 0, 0)

def draw_ui(screen_state="main", scan_results=None):
    if not HARDWARE_LIBS_AVAILABLE:
        print(f"UI State: {screen_state}")
        if screen_state == "main":
            print(f"Target IP: {TARGET_IP}")
            print(f"Target Port: {TARGET_PORT}")
            if scan_results:
                for line in scan_results:
                    print(line)
        return

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Passive OS Fingerprint", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    if screen_state == "main":
        d.text((5, 25), "Target IP:", font=FONT, fill="white")
        d.text((5, 40), TARGET_IP, font=FONT_TITLE, fill="yellow")
        d.text((5, 60), "Target Port:", font=FONT, fill="white")
        d.text((5, 75), str(TARGET_PORT), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "OK=Scan | KEY1=Edit IP | KEY2=Edit Port | KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "ip_input":
        d.text((5, 30), "Enter Target IP:", font=FONT, fill="white")
        display_ip = list(current_ip_input)
        if ip_input_cursor_pos < len(display_ip):
            display_ip[ip_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_ip), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Digit | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "port_input":
        d.text((5, 30), "Enter Target Port:", font=FONT, fill="white")
        display_port = list(current_port_input)
        if port_input_cursor_pos < len(display_port):
            display_port[port_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_port), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Digit | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "scanning":
        d.text((5, 50), "Scanning...", font=FONT_TITLE, fill="yellow")
        d.text((5, 70), f"Target: {TARGET_IP}:{TARGET_PORT}", font=FONT, fill="white")
        d.text((5, 115), "KEY3=Stop", font=FONT, fill="cyan")
    elif screen_state == "results":
        y_pos = 25
        for line in scan_results:
            d.text((5, y_pos), line, font=FONT, fill="white")
            y_pos += 12
        d.text((5, 115), "OK=Scan | KEY3=Exit", font=FONT, fill="cyan")
    
    LCD.LCD_ShowImage(img, 0, 0)

def handle_ip_input_logic(initial_ip):
    global current_ip_input, ip_input_cursor_pos
    current_ip_input = initial_ip
    ip_input_cursor_pos = len(initial_ip) - 1 # Start cursor at end
    
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
            return None
        
        if btn == "OK": # Confirm IP
            # Validate IP format
            parts = current_ip_input.split('.')
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return current_ip_input
            else:
                show_message(["Invalid IP!", "Try again."], "red")
                time.sleep(2)
                current_ip_input = initial_ip # Reset to initial
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
    return None

def handle_port_input_logic(initial_port):
    global current_port_input, port_input_cursor_pos
    current_port_input = initial_port
    port_input_cursor_pos = len(initial_port) - 1
    
    draw_ui("port_input")
    
    while running:
        btn = None
        for name, pin in PINS.items():
            if GPIO.input(pin) == 0:
                btn = name
                while GPIO.input(pin) == 0: # Debounce
                    time.sleep(0.05)
                break
        
        if btn == "KEY3": # Cancel Port input
            return None
        
        if btn == "OK": # Confirm Port
            if current_port_input.isdigit() and 1 <= int(current_port_input) <= 65535:
                return current_port_input
            else:
                show_message(["Invalid Port!", "Try again."], "red")
                time.sleep(2)
                current_port_input = initial_port # Reset to initial
                port_input_cursor_pos = len(initial_port) - 1
                draw_ui("port_input")
        
        if btn == "LEFT":
            port_input_cursor_pos = max(0, port_input_cursor_pos - 1)
            draw_ui("port_input")
        elif btn == "RIGHT":
            port_input_cursor_pos = min(len(current_port_input), port_input_cursor_pos + 1)
            draw_ui("port_input")
        elif btn == "UP" or btn == "DOWN":
            if port_input_cursor_pos < len(current_port_input):
                char_list = list(current_port_input)
                current_char = char_list[port_input_cursor_pos]
                
                if current_char.isdigit():
                    digit = int(current_char)
                    if btn == "UP":
                        digit = (digit + 1) % 10
                    else: # DOWN
                        digit = (digit - 1 + 10) % 10
                    char_list[port_input_cursor_pos] = str(digit)
                    current_port_input = "".join(char_list)
                draw_ui("port_input")
        
        time.sleep(0.1)
    return None

# --- Scanner ---
def run_scan(interface):
    global TARGET_IP, TARGET_PORT
    
    draw_ui("scanning")
    scan_results = []
    
    try:
        # Set the selected interface as the primary interface for routing
        if WIFI_INTEGRATION and set_raspyjack_interface(interface):
            show_message([f"Interface {interface}", "activated."], "lime")
            time.sleep(1)
        else:
            show_message([f"Failed to activate", f"{interface}."], "red")
            return []

        # Send a SYN packet and wait for a SYN/ACK response
        p = IP(dst=TARGET_IP)/TCP(dport=int(TARGET_PORT), flags='S')
        resp = sr1(p, timeout=3, verbose=0, iface=interface)
        
        if resp and resp.haslayer(TCP) and resp[TCP].flags == 'SA': # SYN/ACK
            ttl = resp[IP].ttl
            window_size = resp[TCP].window
            
            os_guess = "Unknown"
            # Simple TTL-based guessing
            if ttl <= 64:
                os_guess = "Linux / Unix"
            elif ttl <= 128:
                os_guess = "Windows"
            else:
                os_guess = "Solaris / Cisco"

            scan_results = [
                f"Target: {TARGET_IP}",
                f"TTL: {ttl}",
                f"Window: {window_size}",
                "",
                "Guess:",
                os_guess
            ]
            
        else:
            scan_results = ["No SYN/ACK received.", "Port may be closed", "or host is down."]

    except Exception as e:
        scan_results = ["Scan failed!", str(e)[:20]]
        print(f"OS Scan failed: {e}", file=sys.stderr)
    
    return scan_results

# --- Main Loop ---
if not HARDWARE_LIBS_AVAILABLE:
    print("ERROR: Hardware libraries (RPi.GPIO, LCD drivers, PIL) are not available. Cannot run Passive OS Fingerprinting.", file=sys.stderr)
    sys.exit(1)

current_screen = "main"
last_scan_results = []
try:
    # Check for scapy dependency
    try:
        from scapy.all import *
    except ImportError:
        show_message(["ERROR:", "Scapy not found!"], "red")
        time.sleep(3)
        sys.exit(1)

    selected_interface = None
    if WIFI_INTEGRATION:
        selected_interface = select_interface_menu()
        if not selected_interface:
            show_message(["No interface", "selected!", "Exiting..."], "red")
            time.sleep(3)
            sys.exit(1)
    else:
        # Fallback if WIFI_INTEGRATION is not available
        selected_interface = "eth0" # Default to eth0 if no dynamic selection
        show_message([f"Using default:", f"{selected_interface}"], "lime")
        time.sleep(2)

    while running:
        if current_screen == "main":
            draw_ui("main", scan_results=last_scan_results)
            
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            if GPIO.input(PINS["OK"]) == 0:
                last_scan_results = run_scan(selected_interface)
                current_screen = "results"
                time.sleep(0.3) # Debounce
            
            if GPIO.input(PINS["KEY1"]) == 0: # Edit Target IP
                current_ip_input = TARGET_IP
                current_screen = "ip_input"
                time.sleep(0.3) # Debounce
            
            if GPIO.input(PINS["KEY2"]) == 0: # Edit Target Port
                current_port_input = str(TARGET_PORT)
                current_screen = "port_input"
                time.sleep(0.3) # Debounce
        
        elif current_screen == "ip_input":
            char_set = "0123456789."
            new_ip = handle_ip_input_logic(current_ip_input)
            if new_ip:
                TARGET_IP = new_ip
            current_screen = "main"
            time.sleep(0.3) # Debounce
        
        elif current_screen == "port_input":
            char_set = "0123456789"
            new_port = handle_port_input_logic(current_port_input)
            if new_port:
                TARGET_PORT = int(new_port)
            current_screen = "main"
            time.sleep(0.3) # Debounce
        
        elif current_screen == "results":
            draw_ui("results", scan_results=last_scan_results)
            if GPIO.input(PINS["KEY3"]) == 0:
                current_screen = "main"
                time.sleep(0.3) # Debounce
            if GPIO.input(PINS["OK"]) == 0:
                last_scan_results = run_scan(selected_interface)
                time.sleep(0.3) # Debounce
            time.sleep(0.1)

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
    print("OS Fingerprint payload finished.")



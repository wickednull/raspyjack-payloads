#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
"""
RaspyJack *payload* – **Recon: SMB Share Enumeration**
=======================================================
A reconnaissance tool that scans a target IP address for open SMB
(Server Message Block) shares. This is useful for finding file shares
on a Windows machine or a Samba server.

This payload uses the `smbclient` command-line tool with the -L flag
to list shares. It attempts an anonymous (null session) connection.
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

# ---------------------------------------------------------------------------
# 1) GPIO mapping (BCM)
# ---------------------------------------------------------------------------
PINS = { "OK": 13, "KEY3": 16, "KEY1": 21 } # Added KEY1 for config

# ---------------------------------------------------------------------------
# 2) GPIO & LCD initialisation
# ---------------------------------------------------------------------------
if HARDWARE_LIBS_AVAILABLE:
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
    FONT = ImageFont.load_default()
else:
    # Dummy objects if hardware libs are not available
    class DummyLCD:
        def LCD_Init(self, *args): pass
        def LCD_Clear(self): pass
        def LCD_ShowImage(self, *args): pass
    LCD = DummyLCD()
    WIDTH, HEIGHT = 128, 128
    class DummyGPIO:
        def setmode(self, *args): pass
        def setup(self, *args): pass
        def input(self, pin): return 1 # Simulate no button pressed
        def cleanup(self): pass
    GPIO = DummyGPIO()
    class DummyImageFont:
        def truetype(self, *args, **kwargs): return None
        def load_default(self): return None
    ImageFont = DummyImageFont()
    FONT_TITLE = ImageFont.load_default() # Fallback to default font
    FONT = ImageFont.load_default() # Fallback to default font

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

TARGET_IP = "192.168.1.10" # Will be configurable

# --- Globals & Shutdown ---
running = True
selected_index = 0
shares = []
current_ip_input = TARGET_IP # Initial value for IP input
ip_input_cursor_pos = 0

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

def draw_ui(screen_state="main"):
    if not HARDWARE_LIBS_AVAILABLE:
        print(f"UI State: {screen_state}")
        if screen_state == "main":
            print(f"Target IP: {TARGET_IP}")
        return

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
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

# --- Scanner ---
def run_scan(interface):
    global shares, selected_index, TARGET_IP
    draw_ui("scanning")
    shares = []
    selected_index = 0
    
    try:
        # Set the selected interface as the primary interface for routing
        if WIFI_INTEGRATION and set_raspyjack_interface(interface):
            show_message([f"Interface {interface}", "activated."], "lime")
            time.sleep(1)
        else:
            show_message([f"Failed to activate", f"{interface}."], "red")
            return

        # Use smbclient to list shares with a null session (-N)
        command = f"smbclient -L //{TARGET_IP} -N"
        proc = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=15)
        
        if proc.returncode == 0:
            for line in proc.stdout.split('\n'):
                # Look for lines indicating a disk share
                if "Disk" in line:
                    share_name = line.split('|')[0].strip()
                    if share_name:
                        shares.append(share_name)
            if not shares:
                shares.append("No shares found")
        else:
            # Parse common errors
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

# --- Main Loop ---
if not HARDWARE_LIBS_AVAILABLE:
    print("ERROR: Hardware libraries (RPi.GPIO, LCD drivers, PIL) are not available. Cannot run SMB Share Enumeration.", file=sys.stderr)
    sys.exit(1)

current_screen = "main"
try:
    if subprocess.run("which smbclient", shell=True, capture_output=True).returncode != 0:
        show_message(["ERROR:", "smbclient", "not found!"], "red")
        time.sleep(3)
        sys.exit(1)

    while running:
        if current_screen == "main":
            draw_ui("main")
            
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            if GPIO.input(PINS["OK"]) == 0:
                run_scan()
                current_screen = "main"
                time.sleep(0.3) # Debounce
            
            if GPIO.input(PINS["UP"]) == 0:
                if shares:
                    selected_index = (selected_index - 1) % len(shares)
                time.sleep(0.2)
            elif GPIO.input(PINS["DOWN"]) == 0:
                if shares:
                    selected_index = (selected_index + 1) % len(shares)
                time.sleep(0.2)
            
            if GPIO.input(PINS["KEY1"]) == 0: # Edit Target IP
                current_ip_input = TARGET_IP
                current_screen = "ip_input"
                time.sleep(0.3) # Debounce
        
        elif current_screen == "ip_input":
            char_set = "0123456789."
            new_ip = handle_ip_input_logic(current_ip_input, "ip_input", char_set)
            if new_ip:
                TARGET_IP = new_ip
            current_screen = "main"
            time.sleep(0.3) # Debounce
        
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

#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
"""
RaspyJack *payload* – **Recon: HTTP Header Viewer**
====================================================
A simple reconnaissance tool that connects to a web server on a
specified port and prints the HTTP response headers.

This is useful for quickly identifying server software, versions,
enabled features (e.g., HSTS, cookies), and other configuration details.
"""

import os, sys, subprocess, signal, time, socket
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
PINS: dict[str, int] = { "OK": 13, "KEY3": 16, "KEY1": 21, "KEY2": 20 } # Added KEY1, KEY2 for config

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

TARGET_IP = "192.168.1.1" # Will be configurable
TARGET_PORT = 80 # Will be configurable

# --- Globals & Shutdown ---
running = True
selected_index = 0
headers = []
current_ip_input = TARGET_IP # For IP input
ip_input_cursor_pos = 0
current_port_input = str(TARGET_PORT) # For Port input
port_input_cursor_pos = 0

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

# --- Scanner ---
def get_headers(interface):
    global headers, selected_index
    draw_ui("Connecting...")
    headers = []
    selected_index = 0
    
    try:
        # Set the selected interface as the primary interface for routing
        if WIFI_INTEGRATION and set_raspyjack_interface(interface):
            show_message([f"Interface {interface}", "activated."], "lime")
            time.sleep(1)
        else:
            show_message([f"Failed to activate", f"{interface}."], "red")
            return

        # Use requests library for simplicity
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

# --- Main Loop ---
try:
    # Dependency check for requests
    try:
        import requests
    except ImportError:
        show_message(["ERROR:", "requests not found!"], "red")
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

    draw_ui("Press OK to get")
    while running:
        if GPIO.input(PINS["KEY3"]) == 0:
            cleanup()
            break
        
        if GPIO.input(PINS["OK"]) == 0:
            get_headers(selected_interface)
            draw_ui()
            time.sleep(0.5) # Debounce
            # Enter viewing mode
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

except (KeyboardInterrupt, SystemExit):
    pass
finally:
    cleanup()
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("HTTP Header payload finished.")

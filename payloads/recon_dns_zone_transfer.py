#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
"""
RaspyJack *payload* – **Recon: DNS Zone Transfer**
===================================================
A reconnaissance tool that attempts to perform a DNS zone transfer (AXFR)
against a specified domain using its authoritative name servers.

If a name server is misconfigured, this attack will dump all of its DNS
records for the domain, providing a treasure trove of information about
the target's infrastructure (subdomains, IP addresses, etc.).
"""

import os, sys, subprocess, signal, time, threading
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
PINS: dict[str, int] = { "OK": 13, "KEY3": 16, "KEY1": 21 } # Added KEY1 for editing

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

TARGET_DOMAIN = "example.com" # Will be configurable

# --- Globals & Shutdown ---
running = True
scan_thread = None
results = []
ui_lock = threading.Lock()
status_msg = "Press OK to start"
current_domain_input = TARGET_DOMAIN # For domain input
domain_input_cursor_pos = 0

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
            print(f"Target Domain: {TARGET_DOMAIN}")
            print(f"Status: {status_msg}")
        return

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "DNS Zone Transfer", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    if screen_state == "main":
        with ui_lock:
            d.text((5, 25), f"Domain: {TARGET_DOMAIN[:16]}...", font=FONT, fill="white")
            if "Press" in status_msg or "Finding" in status_msg or "Testing" in status_msg:
                d.text((5, 45), status_msg, font=FONT, fill="yellow")
            elif "SUCCESS" in status_msg:
                d.text((5, 45), status_msg, font=FONT_TITLE, fill="lime")
                d.text((5, 60), f"Saved {len(results)} records", font=FONT, fill="white")
            else:
                d.text((5, 45), status_msg, font=FONT_TITLE, fill="red")

        d.text((5, 115), "OK=Start | KEY1=Edit Domain | KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "domain_input":
        d.text((5, 30), "Enter Domain:", font=FONT, fill="white")
        display_domain = list(current_domain_input)
        if domain_input_cursor_pos < len(display_domain):
            display_domain[domain_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_domain[:16]), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Char | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "scanning":
        d.text((5, 25), f"Domain: {TARGET_DOMAIN[:16]}...", font=FONT, fill="white")
        d.text((5, 45), status_msg, font=FONT, fill="yellow")
        d.text((5, 115), "KEY3=Stop", font=FONT, fill="cyan")
    
    LCD.LCD_ShowImage(img, 0, 0)

def handle_text_input_logic(initial_text, screen_state_name, char_set):
    global current_domain_input, domain_input_cursor_pos
    
    current_input_ref = current_domain_input
    cursor_pos_ref = domain_input_cursor_pos

    current_input_ref = initial_text
    cursor_pos_ref = len(initial_text) - 1
    
    draw_ui(screen_state_name)
    
    while running:
        btn = None
        for name, pin in PINS.items():
            if GPIO.input(pin) == 0:
                btn = name
                while GPIO.input(pin) == 0: # Debounce
                    time.sleep(0.05)
                break
        
        if btn == "KEY3": # Cancel input
            return None
        
        if btn == "OK": # Confirm input
            if current_input_ref: # Basic validation
                return current_input_ref
            else:
                show_message(["Input cannot", "be empty!"], "red")
                time.sleep(2)
                current_input_ref = initial_text
                cursor_pos_ref = len(initial_text) - 1
                draw_ui(screen_state_name)
        
        if btn == "LEFT":
            cursor_pos_ref = max(0, cursor_pos_ref - 1)
            draw_ui(screen_state_name)
        elif btn == "RIGHT":
            cursor_pos_ref = min(len(current_input_ref), cursor_pos_ref + 1)
            draw_ui(screen_state_name)
        elif btn == "UP" or btn == "DOWN":
            if cursor_pos_ref < len(current_input_ref):
                char_list = list(current_input_ref)
                current_char = char_list[cursor_pos_ref]
                
                try:
                    char_index = char_set.index(current_char)
                    if btn == "UP":
                        char_index = (char_index + 1) % len(char_set)
                    else: # DOWN
                        char_index = (char_index - 1 + len(char_set)) % len(char_set)
                    char_list[cursor_pos_ref] = char_set[char_index]
                    current_input_ref = "".join(char_list)
                except ValueError: # If current char is not in char_set
                    char_list[cursor_pos_ref] = char_set[0] # Default to first char
                    current_input_ref = "".join(char_list)
                draw_ui(screen_state_name)
        
        time.sleep(0.1)
    return None

# --- Scanner ---
def run_scan(interface):
    global results, status_msg, TARGET_DOMAIN
    with ui_lock:
        status_msg = f"Finding NS for\n{TARGET_DOMAIN}..."
        results = []

    try:
        # Set the selected interface as the primary interface for routing
        if WIFI_INTEGRATION and set_raspyjack_interface(interface):
            show_message([f"Interface {interface}", "activated."], "lime")
            time.sleep(1)
        else:
            show_message([f"Failed to activate", f"{interface}."], "red")
            return

        # 1. Find the Name Servers (NS) for the domain
        ns_proc = subprocess.run(f"host -t ns {TARGET_DOMAIN}", shell=True, capture_output=True, text=True)
        if ns_proc.returncode != 0:
            with ui_lock: status_msg = "Domain not found"
            return
            
        name_servers = [line.split()[-1] for line in ns_proc.stdout.strip().split('\n') if "name server" in line]
        
        if not name_servers:
            with ui_lock: status_msg = "No NS found!"
            return

        # 2. Attempt a zone transfer from each name server
        for ns in name_servers:
            if not running: break
            with ui_lock: status_msg = f"Testing {ns[:-1][:16]}..."
            
            axfr_proc = subprocess.run(f"host -l {TARGET_DOMAIN} {ns}", shell=True, capture_output=True, text=True)
            
            if "Transfer failed" not in axfr_proc.stdout and "has address" in axfr_proc.stdout:
                # SUCCESS!
                with ui_lock:
                    results = axfr_proc.stdout.strip().split('\n')
                    status_msg = "SUCCESS!"
                
                # Save loot
                os.makedirs("/root/Raspyjack/loot/DNS_Zone_Transfer/", exist_ok=True)
                loot_file = f"/root/Raspyjack/loot/DNS_Zone_Transfer/{TARGET_DOMAIN}.txt"
                with open(loot_file, "w") as f:
                    f.write(f"Zone transfer results for {TARGET_DOMAIN} from {ns}\n\n")
                    f.write(axfr_proc.stdout)
                return # Stop after first success

        if running:
             with ui_lock: status_msg = "Transfer FAILED"

    except Exception as e:
        with ui_lock: status_msg = "Scan Error!"
        print(f"AXFR Scan failed: {e}", file=sys.stderr)

# ---------------------------------------------------------------------------
# 7) Main Loop
# ---------------------------------------------------------------------------
if not HARDWARE_LIBS_AVAILABLE:
    print("ERROR: Hardware libraries (RPi.GPIO, LCD drivers, PIL) are not available. Cannot run DNS Zone Transfer.", file=sys.stderr)
    sys.exit(1)

current_screen = "main"
try:
    if subprocess.run("which host", shell=True, capture_output=True).returncode != 0:
        show_message(["ERROR:", "host tool", "not found!"], "red")
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
            draw_ui("main")
            
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            if GPIO.input(PINS["OK"]) == 0:
                if not (scan_thread and scan_thread.is_alive()):
                    scan_thread = threading.Thread(target=run_scan, args=(selected_interface,), daemon=True)
                    scan_thread.start()
                current_screen = "scanning"
                time.sleep(0.3) # Debounce
            
            if GPIO.input(PINS["KEY1"]) == 0: # Edit Domain
                current_domain_input = TARGET_DOMAIN
                current_screen = "domain_input"
                time.sleep(0.3) # Debounce
        
        elif current_screen == "domain_input":
            char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-" # Common domain chars
            new_domain = handle_text_input_logic(current_domain_input, "domain_input", char_set)
            if new_domain:
                TARGET_DOMAIN = new_domain
            current_screen = "main"
            time.sleep(0.3) # Debounce
        
        elif current_screen == "scanning":
            draw_ui("scanning")
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            if not (scan_thread and scan_thread.is_alive()): # Scan finished
                current_screen = "main"
            time.sleep(0.1)

        time.sleep(0.1)

except (KeyboardInterrupt, SystemExit):
    pass
except Exception as e:
    print(f"[ERROR] {e}", file=sys.stderr)
    show_message(["CRITICAL ERROR:", str(e)[:20]], "red")
    time.sleep(3)
finally:
    cleanup()
    if scan_thread and scan_thread.is_alive():
        scan_thread.join(timeout=1)
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("DNS Zone Transfer payload finished.")

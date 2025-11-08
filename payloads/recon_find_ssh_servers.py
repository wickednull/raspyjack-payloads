#!/usr/bin/env python3
"""
RaspyJack *payload* – **Recon: Find SSH Servers**
==================================================
A simple reconnaissance payload that scans the local network to find
hosts with the SSH port (22) open.
"""

import os, sys, subprocess, signal, time, threading, socket
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
SSH_PORT = 22 # Will be configurable
ETH_INTERFACE = "eth0" # Will be configurable

# --- Globals & Shutdown ---
running = True
scan_thread = None
ssh_servers = []
ui_lock = threading.Lock()
status_msg = "Press OK to scan"
selected_index = 0
current_interface_input = ETH_INTERFACE # For interface input
interface_input_cursor_pos = 0
current_port_input = str(SSH_PORT) # For port input
port_input_cursor_pos = 0

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
            print(f"Interface: {ETH_INTERFACE}")
            print(f"SSH Port: {SSH_PORT}")
            print(f"Status: {status_msg}")
        return

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Find SSH Servers", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    if screen_state == "main":
        with ui_lock:
            d.text((5, 25), f"Interface: {ETH_INTERFACE}", font=FONT, fill="white")
            d.text((5, 40), f"Port: {SSH_PORT}", font=FONT, fill="white")
            if "Scanning" in status_msg or "Press" in status_msg:
                d.text((5, 55), status_msg, font=FONT, fill="yellow")
            else:
                d.text((5, 55), f"Servers Found: {len(ssh_servers)}", font=FONT, fill="yellow")
                start_index = max(0, selected_index - 2)
                end_index = min(len(ssh_servers), start_index + 4)
                y_pos = 70
                for i in range(start_index, end_index):
                    color = "yellow" if i == selected_index else "white"
                    d.text((10, y_pos), ssh_servers[i], font=FONT, fill=color)
                    y_pos += 11

        d.text((5, 115), "OK=Scan | KEY1=Edit Iface | KEY2=Edit Port | KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "iface_input":
        d.text((5, 30), "Enter Interface:", font=FONT, fill="white")
        display_iface = list(current_interface_input)
        if interface_input_cursor_pos < len(display_iface):
            display_iface[interface_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_iface[:16]), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Char | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "port_input":
        d.text((5, 30), "Enter Port:", font=FONT, fill="white")
        display_port = list(current_port_input)
        if port_input_cursor_pos < len(display_port):
            display_port[port_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_port), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Digit | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    
    LCD.LCD_ShowImage(img, 0, 0)

def handle_text_input_logic(initial_text, screen_state_name, char_set):
    global current_interface_input, interface_input_cursor_pos, current_port_input, port_input_cursor_pos
    
    if screen_state_name == "iface_input":
        current_input_ref = current_interface_input
        cursor_pos_ref = interface_input_cursor_pos
    else: # port_input
        current_input_ref = current_port_input
        cursor_pos_ref = port_input_cursor_pos

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
def run_scan():
    global ssh_servers, status_msg, selected_index, ETH_INTERFACE, SSH_PORT
    with ui_lock:
        status_msg = "Scanning network..."
        ssh_servers = []
        selected_index = 0

    try:
        # Check if interface exists and has IP
        try:
            ip_output = subprocess.check_output(f"ip -o -4 addr show {ETH_INTERFACE}", shell=True).decode()
            if "inet " not in ip_output:
                with ui_lock: status_msg = f"{ETH_INTERFACE} No IP!"
                return
            network_range_str = ip_output.split("inet ")[1].split(" ")[0]
        except subprocess.CalledProcessError:
            with ui_lock: status_msg = f"{ETH_INTERFACE} not found!"
            return
        
        from ipaddress import ip_network
        network = ip_network(network_range_str, strict=False)
        
        socket.setdefaulttimeout(0.2)
        for ip in network.hosts():
            if not running: break
            ip_str = str(ip)
            with ui_lock: status_msg = f"Scanning: {ip_str}"
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if sock.connect_ex((ip_str, SSH_PORT)) == 0:
                    with ui_lock:
                        if ip_str not in ssh_servers:
                            ssh_servers.append(ip_str)
                sock.close()
            except socket.error:
                pass
            
    except Exception as e:
        with ui_lock: status_msg = "Scan Failed!"
        print(f"Scan failed: {e}", file=sys.stderr)
        
    if running:
        with ui_lock: status_msg = "Scan Finished"

# --- Main Loop ---
if not HARDWARE_LIBS_AVAILABLE:
    print("ERROR: Hardware libraries (RPi.GPIO, LCD drivers, PIL) are not available. Cannot run Find SSH Servers.", file=sys.stderr)
    sys.exit(1)

current_screen = "main"
try:
    while running:
        if current_screen == "main":
            draw_ui("main")
            
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            if GPIO.input(PINS["OK"]) == 0:
                if not (scan_thread and scan_thread.is_alive()):
                    scan_thread = threading.Thread(target=run_scan, daemon=True)
                    scan_thread.start()
                time.sleep(0.3)
            
            if GPIO.input(PINS["UP"]) == 0:
                with ui_lock:
                    if ssh_servers: selected_index = (selected_index - 1) % len(ssh_servers)
                time.sleep(0.2)
            elif GPIO.input(PINS["DOWN"]) == 0:
                with ui_lock:
                    if ssh_servers: selected_index = (selected_index + 1) % len(ssh_servers)
                time.sleep(0.2)
            
            if GPIO.input(PINS["KEY1"]) == 0: # Edit Interface
                current_interface_input = ETH_INTERFACE
                current_screen = "iface_input"
                time.sleep(0.3) # Debounce
            
            if GPIO.input(PINS["KEY2"]) == 0: # Edit Port
                current_port_input = str(SSH_PORT)
                current_screen = "port_input"
                time.sleep(0.3) # Debounce
        
        elif current_screen == "iface_input":
            char_set = "abcdefghijklmnopqrstuvwxyz0123456789" # Common interface chars
            new_iface = handle_text_input_logic(current_interface_input, "iface_input", char_set)
            if new_iface:
                ETH_INTERFACE = new_iface
            current_screen = "main"
            time.sleep(0.3) # Debounce
        
        elif current_screen == "port_input":
            char_set = "0123456789"
            new_port = handle_text_input_logic(current_port_input, "port_input", char_set)
            if new_port:
                SSH_PORT = int(new_port)
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
    if scan_thread and scan_thread.is_alive():
        scan_thread.join(timeout=1)
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("Find SSH Servers payload finished.")

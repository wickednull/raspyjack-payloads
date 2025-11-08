#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
"""
RaspyJack *payload* – **Internet Connectivity Checker**
=======================================================
A simple utility to check for a working internet connection by pinging a
list of reliable hosts.

Features:
1.  Pings multiple reliable hosts (e.g., Google DNS, Cloudflare DNS).
2.  Uses the system's `ping` command with a short timeout.
3.  Displays the status of each ping in real-time on the LCD.
4.  Shows a final summary of the connection status.
5.  Allows the user to re-run the test.
"""

# ---------------------------------------------------------------------------
# 0) Imports & boilerplate
# ---------------------------------------------------------------------------
import os, sys, subprocess, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

# ---------------------------- Third‑party libs ----------------------------
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
    FONT_BIG = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 16)
else:
    # Dummy objects if hardware libs are not available
    class DummyLCD:
        def LCD_Init(self, *args): pass
        def LCD_Clear(self): pass
        def LCD_ShowImage(self, *args): pass
    LCD = DummyLCD()
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
    FONT_BIG = ImageFont.load_default() # Fallback to default font

# --- CONFIGURATION ---
HOSTS_TO_CHECK = ["8.8.8.8", "1.1.1.1", "google.com"] # Will be configurable
running = True
current_hosts_input = ", ".join(HOSTS_TO_CHECK) # For hosts input
hosts_input_cursor_pos = 0

# ---------------------------------------------------------------------------
# 4) Graceful shutdown
# ---------------------------------------------------------------------------
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
    img = Image.new("RGB", (128, 128), "black")
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

def draw_ui(screen_state="main", results=None, summary=""):
    if not HARDWARE_LIBS_AVAILABLE:
        print(f"UI State: {screen_state}")
        if screen_state == "main":
            print(f"Hosts: {', '.join(HOSTS_TO_CHECK)}")
            print(f"Summary: {summary}")
        return

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)

    d.text((5, 5), "Internet Check", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    if screen_state == "main":
        y_pos = 25
        if results:
            for line in results:
                d.text((5, y_pos), line, font=FONT, fill="white")
                y_pos += 12
        else:
            d.text((5, y_pos), "Press OK to run", font=FONT, fill="white")
            y_pos += 12
            d.text((5, y_pos), f"Hosts: {', '.join(HOSTS_TO_CHECK)[:16]}...", font=FONT, fill="white")
            
        if summary:
            color = "lime" if "OK" in summary else "red"
            bbox = d.textbbox((0, 0), summary, font=FONT_BIG)
            w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
            x = (WIDTH - w) // 2
            d.text((x, 90), summary, font=FONT_BIG, fill=color)

        d.text((5, 115), "OK=Re-run | KEY1=Edit Hosts | KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "hosts_input":
        d.text((5, 30), "Enter Hosts (CSV):", font=FONT, fill="white")
        display_hosts = list(current_hosts_input)
        if hosts_input_cursor_pos < len(display_hosts):
            display_hosts[hosts_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_hosts[:16]), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Char | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    
    LCD.LCD_ShowImage(img, 0, 0)

def handle_text_input_logic(initial_text, screen_state_name, char_set):
    global current_hosts_input, hosts_input_cursor_pos
    
    current_input_ref = current_hosts_input
    cursor_pos_ref = hosts_input_cursor_pos

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
                    char_set.index(current_char)
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

def run_test():
    """Pings the hosts and updates the UI in real-time."""
    results = []
    success_count = 0
    
    for host in HOSTS_TO_CHECK:
        if not running: return
        
        results.append(f"Pinging {host}...")
        draw_ui("main", results=results) # Pass results to draw_ui
        
        try:
            # Use ping with a 2-second timeout (-W) and 1 packet (-c)
            command = f"ping -c 1 -W 2 {host}"
            response = subprocess.run(command, shell=True, capture_output=True)
            
            if response.returncode == 0:
                results[-1] = f"[  OK  ] {host}"
                success_count += 1
            else:
                results[-1] = f"[ FAIL ] {host}"
        except Exception:
            results[-1] = f"[ ERROR ] {host}"
            
        draw_ui("main", results=results) # Pass results to draw_ui
        time.sleep(0.5)

    if not running: return
    
    if success_count > 0:
        summary = "Internet OK"
    else:
        summary = "No Internet"
        
    draw_ui("main", results=results, summary=summary)

# ---------------------------------------------------------------------------
# 6) Main Loop
# ---------------------------------------------------------------------------
if not HARDWARE_LIBS_AVAILABLE:
    print("ERROR: Hardware libraries (RPi.GPIO, LCD drivers, PIL) are not available. Cannot run Internet Check.", file=sys.stderr)
    sys.exit(1)

current_screen = "main"
try:
    while running:
        if current_screen == "main":
            draw_ui("main", results=None, summary="Ready") # Initial state
            
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            if GPIO.input(PINS["OK"]) == 0:
                run_test()
                time.sleep(0.3) # Debounce
            
            if GPIO.input(PINS["KEY1"]) == 0: # Edit Hosts
                current_hosts_input = ", ".join(HOSTS_TO_CHECK)
                current_screen = "hosts_input"
                time.sleep(0.3) # Debounce
        
        elif current_screen == "hosts_input":
            char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-, " # Common host chars
            new_hosts_str = handle_text_input_logic(current_hosts_input, "hosts_input", char_set)
            if new_hosts_str:
                HOSTS_TO_CHECK = [h.strip() for h in new_hosts_str.split(',') if h.strip()]
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
    print("Internet Check payload finished.")

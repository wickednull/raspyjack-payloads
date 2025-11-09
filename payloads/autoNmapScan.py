#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
"""
RaspyJack *payload* – **Periodic Nmap Scan**
==========================================
This standalone script resides in the ``payloads/`` folder of your RaspyJack
installation.  It continuously *monitors* the joystick/buttons and can:

1. **Launch** a *standard* Nmap scan on demand (KEY1).
2. **Toggle** automatic scans every **2 hours** (KEY2).
3. **Display** clear status messages on the 1.44-inch LCD.
4. **Exit cleanly** when KEY3 is pressed, on Ctrl-C, or on system SIGTERM.

The code is *heavily commented* to remain beginner-friendly and mirrors the
style of ``example_show_buttons.py``.
"""

# ---------------------------------------------------------------------------
# 0) Allow imports of RaspyJack helper modules when run manually  
# ---------------------------------------------------------------------------
import os, sys

# ---------------------------- Standard library ----------------------------
import time               # timing & debouncing
import signal             # graceful shutdown (SIGINT / SIGTERM)
import threading          # background periodic scans
import subprocess         # running nmap
from datetime import datetime, timedelta

# ----------------------------- Third-party libs ---------------------------
# These come pre-installed with RaspyJack.
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# ---------------------------------------------------------------------------
# 1) Configuration – GPIO pins (BCM numbering) & constants
# ---------------------------------------------------------------------------
PINS: dict[str, int] = {
    "UP"   : 6,
    "DOWN" : 19,
    "LEFT" : 5,
    "RIGHT": 26,
    "OK"   : 13,     # joystick centre push
    "KEY1" : 21,     # ← launch an *immediate* scan
    "KEY2" : 20,     # ← toggle periodic scans every 2 h
    "KEY3" : 16,     # ← exit back to RaspyJack UI
}

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

# Scan settings
NMAP_ARGS   = ["-T4"]           # standard quick+service scan
SCAN_PERIOD = 2 * 60 * 60               # 2 hours in seconds
LOOT_DIR    = "/root/Raspyjack/loot/Nmap/"  # output directory

# Create output directory if it doesn't exist
os.makedirs(LOOT_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# 2) GPIO initialisation
# ---------------------------------------------------------------------------
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)   # active-LOW buttons

# ---------------------------------------------------------------------------
# 3) LCD initialisation
# ---------------------------------------------------------------------------
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
font_small = ImageFont.load_default()                    # 5×8 pix font
font_large = ImageFont.truetype(
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10
)

# In-memory canvas reused every frame
canvas = Image.new("RGB", (WIDTH, HEIGHT), "black")
draw   = ImageDraw.Draw(canvas)

# ---------------------------------------------------------------------------
# 4) Helper: draw centred multiline text
# ---------------------------------------------------------------------------

def show(
    lines: str | list[str],
    *,
    invert: bool = False,
    spacing: int = 2,           # marge verticale en pixels
):
    """Clear screen and render *lines* centred on LCD."""
    if isinstance(lines, str):
        lines = lines.split("\n")

    bg = "white" if invert else "black"
    fg = "black" if invert else "#00FF00"

    # Efface l’écran (un seul tuple (x0, y0, x1, y1))
    draw.rectangle((0, 0, WIDTH, HEIGHT), fill=bg)

    # -- hauteur de chaque ligne
    line_heights = [
        draw.textbbox((0, 0), l, font=font_large)[3]    # y1 ⇒ hauteur
        for l in lines
    ]
    total_h = sum(h + spacing for h in line_heights) - spacing
    y = (HEIGHT - total_h) // 2

    # -- rendu
    for line, h in zip(lines, line_heights):
        w = draw.textbbox((0, 0), line, font=font_large)[2]  # x1 ⇒ largeur
        x = (WIDTH - w) // 2
        draw.text((x, y), line, font=font_large, fill=fg)
        y += h + spacing

    LCD.LCD_ShowImage(canvas, 0, 0)



# ---------------------------------------------------------------------------
# 5) Global flags / threading primitives
# ---------------------------------------------------------------------------
running          = True            # main loop flag
periodic_enabled = False           # is the auto-scan thread active?
periodic_stop    = threading.Event()

# ---------------------------------------------------------------------------
# 6) Nmap scan routine
# ---------------------------------------------------------------------------
def draw_ui_interface_selection(interfaces, current_selection):
    draw.rectangle((0, 0, WIDTH, HEIGHT), fill="black")
    draw.text((5, 5), "Select Interface", font=font_large, fill="cyan")
    draw.line([(0, 22), (WIDTH, 22)], fill="cyan", width=1)

    y_pos = 25
    for i, iface in enumerate(interfaces):
        color = "yellow" if i == current_selection else "white"
        draw.text((5, y_pos), iface, font=font_large, fill=color)
        y_pos += 11
    
    draw.text((5, 115), "UP/DOWN=Select | OK=Confirm", font=font_large, fill="cyan")
    LCD.LCD_ShowImage(canvas, 0, 0)

def select_interface_menu():
    global WIFI_INTERFACE
    
    if not WIFI_INTEGRATION or not wifi_manager:
        show(["WiFi integration", "not available!"], invert=True)
        time.sleep(3)
        return None # Return None if integration is not available

    available_interfaces = get_available_interfaces() # Get all available interfaces
    if not available_interfaces:
        show(["No network", "interfaces found!"], invert=True)
        time.sleep(3)
        return None

    current_menu_selection = 0
    while running:
        draw_ui_interface_selection(available_interfaces, current_menu_selection)
        
        if pressed_button() == "KEY3": # Cancel
            return None
        
        if pressed_button() == "UP":
            current_menu_selection = (current_menu_selection - 1 + len(available_interfaces)) % len(available_interfaces)
            time.sleep(0.2)
        elif pressed_button() == "DOWN":
            current_menu_selection = (current_menu_selection + 1) % len(available_interfaces)
            time.sleep(0.2)
        elif pressed_button() == "OK":
            selected_iface = available_interfaces[current_menu_selection]
            show([f"Selected:", f"{selected_iface}"], invert=False)
            time.sleep(1)
            return selected_iface
        
        time.sleep(0.1)

def current_target(interface: str) -> str | None:
    """Return the IPv4 address + CIDR mask of the given interface."""
    try:
        cmd = f"ip -4 addr show {interface} | awk '/inet / {{ print $2 }}'"
        output = subprocess.check_output(cmd, shell=True).decode().strip()
        if not output:
            return None
        return output
    except subprocess.CalledProcessError:
        return None
    except Exception as e:
        print(f"Error getting current target for {interface}: {e}", file=sys.stderr)
        return None

def nmap_scan(interface: str) -> None:
    """Run a single Nmap scan and save results under *LOOT_DIR*."""
    target = current_target(interface)
    if not target:
        show(["Error:", f"{interface} not configured", "or no IP!"], invert=True)
        time.sleep(3)
        return

    ts     = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    out    = f"{LOOT_DIR}periodic_scan_{ts}.txt"

    show(["Nmap scan", "in progress…"])
    try:
        subprocess.run(["nmap", "-e", interface, *NMAP_ARGS, "-oN", out, target], check=True)
        # Clean output like RaspyJack main script
        subprocess.run(["sed", "-i", "s/Nmap scan report for //g", out])
        show(["Scan finished!", ts])
    except subprocess.CalledProcessError as exc:
        show(["Scan failed :(", str(exc.returncode)], invert=True)
    time.sleep(2)   # small pause so user can read the result

# ---------------------------------------------------------------------------
# 7) Periodic scan thread
# ---------------------------------------------------------------------------

def periodic_loop(interface: str):
    """Run *nmap_scan* every *SCAN_PERIOD* seconds until *periodic_stop* set."""
    next_run = datetime.now()
    while not periodic_stop.is_set():
        now = datetime.now()
        if now >= next_run:
            nmap_scan(interface)
            next_run = now + timedelta(seconds=SCAN_PERIOD)
        # Update idle screen to show next scan time
        wait_msg = f"Next @ {next_run.strftime('%H:%M')}"
        show(["Idle (AUTO)", wait_msg])
        # Sleep in short chunks to stay responsive to stop event
        for _ in range(60):
            if periodic_stop.is_set():
                break
            time.sleep(1)

# ---------------------------------------------------------------------------
# 8) Clean-up handler
# ---------------------------------------------------------------------------

def cleanup(*_):
    global running
    running = False
    periodic_stop.set()

signal.signal(signal.SIGINT,  cleanup)    # Ctrl-C
signal.signal(signal.SIGTERM, cleanup)    # RaspyJack UI stop

# ---------------------------------------------------------------------------
# 9) Button-handling helpers
# ---------------------------------------------------------------------------

def pressed_button() -> str | None:
    """Return the *name* of the first button currently pressed (active-LOW)."""
    for name, pin in PINS.items():
        if GPIO.input(pin) == 0:
            return name
    return None

# ---------------------------------------------------------------------------
# 10) Main event loop
# ---------------------------------------------------------------------------

# Check for nmap dependency
if subprocess.run("which nmap", shell=True, capture_output=True).returncode != 0:
    show(["ERROR:", "nmap not found!"], invert=True)
    time.sleep(4)
    sys.exit(1)

show(["Ready!", "KEY1 : scan now", "KEY2 : auto/stop", "KEY3 : exit"], invert=False)

periodic_thread: threading.Thread | None = None

try:
    selected_interface = None
    if WIFI_INTEGRATION:
        selected_interface = select_interface_menu()
        if not selected_interface:
            show(["No interface", "selected!", "Exiting..."], invert=True)
            time.sleep(3)
            sys.exit(1)
    else:
        # Fallback if WIFI_INTEGRATION is not available
        selected_interface = "eth0" # Default to eth0 if no dynamic selection
        show([f"Using default:", f"{selected_interface}"], invert=False)
        time.sleep(2)

    while running:
        btn = pressed_button()

        if btn == "KEY1":                 # immediate scan
            while pressed_button() == "KEY1":
                time.sleep(0.05)          # wait release (debounce)
            nmap_scan(selected_interface)
            show(["Ready!", "KEY1 : scan now", "KEY2 : auto/stop", "KEY3 : exit"])

        elif btn == "KEY2":               # toggle periodic
            while pressed_button() == "KEY2":
                time.sleep(0.05)
            periodic_enabled = not periodic_enabled

            if periodic_enabled:
                periodic_stop.clear()
                periodic_thread = threading.Thread(target=periodic_loop, args=(selected_interface,), daemon=True)
                periodic_thread.start()
                show(["AUTO enabled", "Scanning every", "2 hours…"])
                time.sleep(2)
            else:
                periodic_stop.set()
                show(["AUTO disabled"])
            time.sleep(1)

        elif btn == "KEY3":               # exit
            running = False
            break

        else:
            time.sleep(0.05)              # idle CPU-friendly delay

finally:
    # -----------------------------------------------------------------------
    # 11) Graceful exit – clear screen, stop threads, release GPIO
    # -----------------------------------------------------------------------
    periodic_stop.set()
    if periodic_thread and periodic_thread.is_alive():
        periodic_thread.join(timeout=1)

    LCD.LCD_Clear()
    GPIO.cleanup()

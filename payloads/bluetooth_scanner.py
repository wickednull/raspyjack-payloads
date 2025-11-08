#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
"""
RaspyJack *payload* – **Bluetooth Scanner**
=============================================
This script performs a passive scan for nearby Bluetooth devices and displays
their MAC address and name on the LCD.

It demonstrates how to:
1. Use 'bluetoothctl' to discover devices.
2. Parse the output to create a list of devices.
3. Display the list in a scrollable format on the LCD.
4. Exit cleanly on KEY3 press or SIGTERM signal.
"""

# ---------------------------------------------------------------------------
# 0) Imports & boilerplate
# ---------------------------------------------------------------------------
import os, sys, subprocess, signal, time, re
from select import select
from typing import List, Tuple
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

# ---------------------------------------------------------------------------
# 3) Graceful shutdown
# ---------------------------------------------------------------------------
running = True

def cleanup(*_):
    """Signal handler to stop the main loop."""
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 4) UI and Drawing Functions
# ---------------------------------------------------------------------------

def draw_message(lines: List[str]) -> None:
    """Clear the LCD and write centered message lines."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    y = 30
    for ln in lines:
        bbox = d.textbbox((0, 0), ln, font=FONT_TITLE)
        w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        x = (WIDTH - w) // 2
        d.text((x, y), ln, font=FONT_TITLE, fill="#00FF00")
        y += h + 10
    LCD.LCD_ShowImage(img, 0, 0)

def draw_device_list(devices: List[Tuple[str, str]], selected_index: int):
    """Draws a scrollable list of discovered devices."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    
    title = f"BT Scan ({len(devices)})"
    d.text((5, 5), title, font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    if not devices:
        d.text((10, 50), "No devices found", font=FONT, fill="white")
    else:
        # Display up to 6 devices at a time
        start_index = max(0, selected_index - 2)
        end_index = min(len(devices), start_index + 6)
        
        y_pos = 30
        for i in range(start_index, end_index):
            mac, name = devices[i]
            display_name = name if name else "N/A"
            line = f"{mac} {display_name[:10]}"
            
            fill = "yellow" if i == selected_index else "white"
            d.text((5, y_pos), line, font=FONT, fill=fill)
            y_pos += 15

    d.text((5, 110), "UP/DOWN | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# 5) Bluetooth Discovery
# ---------------------------------------------------------------------------
SCAN_SECONDS = 10

def discover_devices() -> List[Tuple[str, str]]:
    """Scans for Bluetooth devices and returns a list of (MAC, name)."""
    draw_message(["Scanning for", "Bluetooth devices...", f"({SCAN_SECONDS}s)"])

    proc = subprocess.Popen(
        ["bluetoothctl"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdin and proc.stdout
    proc.stdin.write("scan on\n"); proc.stdin.flush()

    seen: dict[str, str] = {}
    start_time = time.time()
    try:
        while running and (time.time() - start_time) < SCAN_SECONDS:
            # Check for exit signal while waiting
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            ready, _, _ = select([proc.stdout], [], [], 0.2)
            if ready:
                line = proc.stdout.readline()
                m = re.search(r"Device ([0-9A-F:]{17}) (.+)", line)
                if m:
                    mac, name = m.group(1), m.group(2).strip()
                    if name != "n/a":
                        seen[mac] = name
    finally:
        proc.stdin.write("scan off\n"); proc.stdin.flush()
        time.sleep(1) # Give it a moment to stop
        proc.terminate()

    return sorted(seen.items(), key=lambda t: (t[1].lower(), t[0]))

# ---------------------------------------------------------------------------
# 6) Main Loop
# ---------------------------------------------------------------------------
try:
    # Initial scan
    devices = discover_devices()
    selected_index = 0
    
    if not running:
        raise KeyboardInterrupt

    draw_device_list(devices, selected_index)

    while running:
        # Wait for button press
        button_pressed = False
        while not button_pressed and running:
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            if GPIO.input(PINS["UP"]) == 0:
                selected_index = (selected_index - 1) % len(devices) if devices else 0
                button_pressed = True
            elif GPIO.input(PINS["DOWN"]) == 0:
                selected_index = (selected_index + 1) % len(devices) if devices else 0
                button_pressed = True
            elif GPIO.input(PINS["OK"]) == 0: # Rescan
                devices = discover_devices()
                selected_index = 0
                button_pressed = True
            
            time.sleep(0.1)

        if button_pressed:
            draw_device_list(devices, selected_index)
            time.sleep(0.2) # Debounce

except (KeyboardInterrupt, SystemExit):
    pass
except Exception as e:
    print(f"[ERROR] {e}", file=sys.stderr)
    draw_message(["An error occurred.", str(e)[:20]])
    time.sleep(3)
finally:
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("Bluetooth Scanner payload finished.")

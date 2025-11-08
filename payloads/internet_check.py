#!/usr/bin/env python3
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
FONT_BIG = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 16)

# ---------------------------------------------------------------------------
# 3) Global State & Configuration
# ---------------------------------------------------------------------------
HOSTS_TO_CHECK = ["8.8.8.8", "1.1.1.1", "google.com"]
running = True

# ---------------------------------------------------------------------------
# 4) Graceful shutdown
# ---------------------------------------------------------------------------
def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 5) Core & UI Functions
# ---------------------------------------------------------------------------
def draw_ui(results, summary=""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)

    d.text((5, 5), "Internet Check", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    y_pos = 25
    for line in results:
        d.text((5, y_pos), line, font=FONT, fill="white")
        y_pos += 12
        
    if summary:
        color = "lime" if "OK" in summary else "red"
        bbox = d.textbbox((0, 0), summary, font=FONT_BIG)
        w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        x = (WIDTH - w) // 2
        d.text((x, 90), summary, font=FONT_BIG, fill=color)

    d.text((5, 110), "OK=Re-run | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

def run_test():
    """Pings the hosts and updates the UI in real-time."""
    results = []
    success_count = 0
    
    for host in HOSTS_TO_CHECK:
        if not running: return
        
        results.append(f"Pinging {host}...")
        draw_ui(results)
        
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
            
        draw_ui(results)
        time.sleep(0.5)

    if not running: return
    
    if success_count > 0:
        summary = "Internet OK"
    else:
        summary = "No Internet"
        
    draw_ui(results, summary)

# ---------------------------------------------------------------------------
# 6) Main Loop
# ---------------------------------------------------------------------------
try:
    while running:
        run_test()
        
        # Wait for user input to re-run or exit
        while running:
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            if GPIO.input(PINS["OK"]) == 0:
                break # Break inner loop to re-run test
            
            time.sleep(0.1)

except (KeyboardInterrupt, SystemExit):
    pass
except Exception as e:
    print(f"[ERROR] {e}", file=sys.stderr)
finally:
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("Internet Check payload finished.")

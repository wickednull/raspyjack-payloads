#!/usr/bin/env python3
"""
RaspyJack *payload* – **Start Monitor Mode (wlan1)**
==================================================
This payload attempts to activate monitor mode on the specified Wi-Fi interface
(defaulting to `wlan1`). Monitor mode is essential for many Wi-Fi attacks and
reconnaissance tasks, allowing the interface to capture all network traffic
in its vicinity.

Features:
- Automatically attempts to put `wlan1` into monitor mode.
- Displays status messages on the LCD regarding the activation process.
- Uses `WiFiManager` for robust interface management.
- Graceful exit via Ctrl-C or SIGTERM.

Controls:
- This payload is designed to be executed directly.
- No interactive controls after launch, it performs its function and exits.
"""
import sys
import os
import time
import signal
import subprocess
import threading
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))) # Add parent directory for monitor_mode_helper
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
import monitor_mode_helper

TARGET_INTERFACE = "wlan1"
MONITOR_INTERFACE = None

PINS: dict[str, int] = {
    "OK": 13, "KEY3": 16,
}

GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
FONT = ImageFont.load_default()
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)

running = True

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def draw_message(lines, color="lime"):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    y = 40
    for line in lines:
        bbox = d.textbbox((0, 0), line, font=FONT_TITLE)
        w = bbox[2] - bbox[0]
        x = (WIDTH - w) // 2
        d.text((x, y), line, font=FONT_TITLE, fill=color)
        y += 15
    LCD.LCD_ShowImage(img, 0, 0)

def main():
    global MONITOR_INTERFACE
    draw_message(["Activating monitor", f"mode on {TARGET_INTERFACE}...", "Please wait."], "yellow")

    print(f"Attempting to activate monitor mode on {TARGET_INTERFACE}...", file=sys.stderr)
    try:
        MONITOR_INTERFACE = monitor_mode_helper.activate_monitor_mode(TARGET_INTERFACE)
        if MONITOR_INTERFACE:
            draw_message(["Monitor mode", "ACTIVE!", f"Interface: {MONITOR_INTERFACE}"], "lime")
            print(f"Successfully activated monitor mode on {MONITOR_INTERFACE}", file=sys.stderr)
        else:
            draw_message(["ERROR:", "Failed to activate", "monitor mode!"], "red")
            print(f"ERROR: monitor_mode_helper.activate_monitor_mode failed for {TARGET_INTERFACE}", file=sys.stderr)
    except Exception as e:
        draw_message(["CRITICAL ERROR:", str(e)[:20]], "red")
        print(f"Critical error during monitor mode activation: {e}", file=sys.stderr)
    
    time.sleep(5)

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        pass
    except KeyboardInterrupt:
        draw_message(["Payload", "interrupted."], "yellow")
        time.sleep(2)
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Start Monitor Mode payload finished.")
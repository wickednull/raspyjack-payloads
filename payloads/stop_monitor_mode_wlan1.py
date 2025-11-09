#!/usr/bin/env python3
"""
RaspyJack *payload* – **Stop Monitor Mode (wlan1)**
=================================================
This payload attempts to deactivate monitor mode on the specified Wi-Fi interface
(defaulting to `wlan1`) and restore it to managed mode. This is useful after
completing Wi-Fi reconnaissance or attacks that require monitor mode.

Features:
- Automatically attempts to put `wlan1` into managed mode.
- Displays status messages on the LCD regarding the deactivation process.
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
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from wifi.wifi_manager import WiFiManager

TARGET_INTERFACE_BASE = "wlan1"

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
    draw_message(["Deactivating monitor", f"mode on {TARGET_INTERFACE_BASE}...", "Please wait."], "yellow")

    wifi_manager = WiFiManager()
    print(f"Attempting to deactivate monitor mode on {TARGET_INTERFACE_BASE}...", file=sys.stderr)
    try:
        success = wifi_manager.deactivate_monitor_mode(TARGET_INTERFACE_BASE)
        if success:
            draw_message(["Monitor mode", "DEACTIVATED!", f"Interface: {TARGET_INTERFACE_BASE}"], "lime")
            print(f"Successfully deactivated monitor mode on {TARGET_INTERFACE_BASE}", file=sys.stderr)
        else:
            draw_message(["ERROR:", "Failed to deactivate", "monitor mode!"], "red")
            print(f"ERROR: wifi_manager.deactivate_monitor_mode failed for {TARGET_INTERFACE_BASE}", file=sys.stderr)
    except Exception as e:
        draw_message(["CRITICAL ERROR:", str(e)[:20]], "red")
        print(f"Critical error during monitor mode deactivation: {e}", file=sys.stderr)
    
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
        print("Stop Monitor Mode payload finished.")
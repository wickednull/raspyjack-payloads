#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
"""
RaspyJack *payload* – **WiFi: Stop Monitor Mode (wlan1)**
==========================================================
This payload deactivates monitor mode on the 'wlan1' interface (or its
monitor mode equivalent like 'wlan1mon') and returns it to managed mode.
It uses the RaspyJack WiFiManager to ensure proper handling and
provides feedback on the LCD or console.
"""

import os, sys, subprocess, signal, time, threading

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
# RaspyJack WiFi Integration
# ---------------------------------------------------------------------------
try:
    from wifi.wifi_manager import WiFiManager
    WIFI_MANAGER_AVAILABLE = True
    wifi_manager = WiFiManager()
except ImportError as e:
    WIFI_MANAGER_AVAILABLE = False
    print(f"ERROR: WiFiManager not available: {e}", file=sys.stderr)
    sys.exit(1) # Exit if WiFiManager is not available, as it's critical for this payload

# --- CONFIGURATION ---
TARGET_INTERFACE_BASE = "wlan1" # The base interface name
# We need to find the actual monitor interface name, which could be wlan1mon or similar
# The WiFiManager.deactivate_monitor_mode handles finding the correct monitor interface

# ---------------------------------------------------------------------------
# 1) GPIO mapping (BCM)
# ---------------------------------------------------------------------------
PINS: dict[str, int] = {
    "OK": 13, "KEY3": 16,
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
    FONT_TITLE = None # Fallback to None if ImageFont is a dummy
    FONT = None # Fallback to None if ImageFont is a dummy

# --- Globals & Shutdown ---
running = True

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI Functions ---
def draw_message(lines, color="lime"):
    if not HARDWARE_LIBS_AVAILABLE:
        for line in lines:
            print(f"[{color.upper()}] {line}")
        return
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

# --- Main Logic ---
def main():
    draw_message(["Deactivating monitor", f"mode on {TARGET_INTERFACE_BASE}...", "Please wait."], "yellow")

    if not WIFI_MANAGER_AVAILABLE:
        draw_message(["ERROR:", "WiFiManager not", "available!"], "red")
        time.sleep(3)
        sys.exit(1)

    try:
        success = wifi_manager.deactivate_monitor_mode(TARGET_INTERFACE_BASE)
        if success:
            draw_message(["Monitor mode", "DEACTIVATED!", f"Interface: {TARGET_INTERFACE_BASE}"], "lime")
        else:
            draw_message(["ERROR:", "Failed to deactivate", "monitor mode!"], "red")
    except Exception as e:
        draw_message(["CRITICAL ERROR:", str(e)[:20]], "red")
        print(f"Critical error: {e}", file=sys.stderr)
    
    time.sleep(5) # Display message for a few seconds

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        pass # Handled by sys.exit(1) in main()
    except KeyboardInterrupt:
        draw_message(["Payload", "interrupted."], "yellow")
        time.sleep(2)
    finally:
        if HARDWARE_LIBS_AVAILABLE:
            LCD.LCD_Clear()
            GPIO.cleanup()
        print("Stop Monitor Mode payload finished.")

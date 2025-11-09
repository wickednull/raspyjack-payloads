#!/usr/bin/env python3
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

    wifi_manager = WiFiManager()
    try:
        MONITOR_INTERFACE = wifi_manager.activate_monitor_mode(TARGET_INTERFACE)
        if MONITOR_INTERFACE:
            draw_message(["Monitor mode", "ACTIVE!", f"Interface: {MONITOR_INTERFACE}"], "lime")
        else:
            draw_message(["ERROR:", "Failed to activate", "monitor mode!"], "red")
    except Exception as e:
        draw_message(["CRITICAL ERROR:", str(e)[:20]], "red")
        print(f"Critical error: {e}", file=sys.stderr)
    
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
#!/usr/bin/env python3
# Raspyjack Clock Payload

import sys
import os
import time
import signal
import math
from datetime import datetime

# Add Raspyjack root to the Python path
RASPYJACK_ROOT = '/root/Raspyjack'
if os.path.isdir(RASPYJACK_ROOT) and RASPYJACK_ROOT not in sys.path:
    sys.path.insert(0, RASPYJACK_ROOT)

try:
    import LCD_Config
    import LCD_1in44
    import RPi.GPIO as GPIO
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("Error: Required libraries not found. Please run install_raspyjack.sh")
    sys.exit(1)

# --- Pin Definitions ---
PINS = {
    "KEY_UP": 6,
    "KEY_DOWN": 19,
    "KEY_LEFT": 5,
    "KEY_RIGHT": 26,
    "KEY_PRESS": 13,
    "KEY1": 21,
    "KEY2": 20,
    "KEY3": 16
}

# --- Global State ---
RUNNING = True
MODE = "digital"  # "digital" or "analog"

# --- Cleanup Function ---
def cleanup(*_):
    global RUNNING
    if not RUNNING:
        return
    RUNNING = False
    print("Clock: Cleaning up GPIO...")
    GPIO.cleanup()
    print("Clock: Exiting.")
    sys.exit(0)

# --- Main Drawing Functions ---
def draw_digital_clock(draw, font):
    now = datetime.now()
    time_str = now.strftime("%H:%M:%S")
    date_str = now.strftime("%Y-%m-%d")

    # Clear background
    draw.rectangle([(0, 0), (128, 128)], fill="BLACK")

    # Draw Time
    time_bbox = draw.textbbox((0, 0), time_str, font=font)
    time_width = time_bbox[2] - time_bbox[0]
    time_height = time_bbox[3] - time_bbox[1]
    draw.text(((128 - time_width) // 2, (128 - time_height) // 2 - 10), time_str, font=font, fill="LIME")

    # Draw Date
    date_bbox = draw.textbbox((0, 0), date_str, font=font)
    date_width = date_bbox[2] - date_bbox[0]
    draw.text(((128 - date_width) // 2, (128 // 2) + 10), date_str, font=font, fill="CYAN")

def draw_analog_clock(draw):
    now = datetime.now()
    center_x, center_y = 64, 64
    radius = 60

    # Clear background
    draw.rectangle([(0, 0), (128, 128)], fill="BLACK")

    # Draw clock face
    draw.ellipse([(center_x - radius, center_y - radius), (center_x + radius, center_y + radius)], outline="WHITE", width=2)

    # Draw hour markers
    for i in range(12):
        angle = math.radians(i * 30 - 90)
        x1 = center_x + int(radius * 0.9 * math.cos(angle))
        y1 = center_y + int(radius * 0.9 * math.sin(angle))
        x2 = center_x + int(radius * math.cos(angle))
        y2 = center_y + int(radius * math.sin(angle))
        draw.line([(x1, y1), (x2, y2)], fill="WHITE", width=2)

    # Hour hand
    hour_angle = math.radians((now.hour % 12 + now.minute / 60) * 30 - 90)
    hx = center_x + int(radius * 0.5 * math.cos(hour_angle))
    hy = center_y + int(radius * 0.5 * math.sin(hour_angle))
    draw.line([(center_x, center_y), (hx, hy)], fill="RED", width=4)

    # Minute hand
    minute_angle = math.radians((now.minute + now.second / 60) * 6 - 90)
    mx = center_x + int(radius * 0.8 * math.cos(minute_angle))
    my = center_y + int(radius * 0.8 * math.sin(minute_angle))
    draw.line([(center_x, center_y), (mx, my)], fill="CYAN", width=3)

    # Second hand
    second_angle = math.radians(now.second * 6 - 90)
    sx = center_x + int(radius * 0.9 * math.cos(second_angle))
    sy = center_y + int(radius * 0.9 * math.sin(second_angle))
    draw.line([(center_x, center_y), (sx, sy)], fill="YELLOW", width=1)

# --- Main Execution Block ---
if __name__ == "__main__":
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    last_press_time = 0
    DEBOUNCE_DELAY = 0.2

    try:
        # --- Hardware Initialization ---
        GPIO.setmode(GPIO.BCM)
        for pin in PINS.values():
            GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

        LCD = LCD_1in44.LCD()
        LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
        LCD.LCD_Clear()

        image = Image.new("RGB", (128, 128), "BLACK")
        draw = ImageDraw.Draw(image)
        
        try:
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 20)
        except IOError:
            font = ImageFont.load_default()


        # --- Main Loop ---
        while RUNNING:
            current_time = time.time()

            # --- Input Handling ---
            if (current_time - last_press_time) > DEBOUNCE_DELAY:
                # Exit button
                if GPIO.input(PINS["KEY3"]) == 0:
                    break

                # Mode switch button
                if GPIO.input(PINS["KEY_PRESS"]) == 0:
                    last_press_time = current_time
                    if MODE == "digital":
                        MODE = "analog"
                    else:
                        MODE = "digital"

            # --- Drawing ---
            if MODE == "digital":
                draw_digital_clock(draw, font)
            else:
                draw_analog_clock(draw)

            # Display the image
            LCD.LCD_ShowImage(image, 0, 0)
            time.sleep(0.1) # Refresh rate

    finally:
        LCD.LCD_Clear()
        cleanup()

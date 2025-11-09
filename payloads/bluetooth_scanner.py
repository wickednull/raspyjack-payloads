#!/usr/bin/env python3
import sys
import os
import time
import signal
import subprocess
import re
from select import select
from typing import List, Tuple
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

PINS: dict[str, int] = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13,
    "KEY1": 21, "KEY2": 20, "KEY3": 16,
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
    if running:
        running = False
        subprocess.run("bluetoothctl power off", shell=True, capture_output=True)
        subprocess.run("bluetoothctl scan off", shell=True, capture_output=True)
        subprocess.run("pkill -f bluetoothctl", shell=True, capture_output=True)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def draw_message(lines: List[str]) -> None:
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
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    
    title = f"BT Scan ({len(devices)})")
    d.text((5, 5), title, font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    if not devices:
        d.text((10, 50), "No devices found", font=FONT, fill="white")
    else:
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

SCAN_SECONDS = 10

def discover_devices() -> List[Tuple[str, str]]:
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
        time.sleep(1)
        proc.terminate()

    return sorted(seen.items(), key=lambda t: (t[1].lower(), t[0]))

if __name__ == "__main__":
    try:
        if subprocess.run("which bluetoothctl", shell=True, capture_output=True).returncode != 0:
            draw_message(["bluetoothctl not found!", "Exiting..."])
            time.sleep(3)
            raise SystemExit("bluetoothctl not found.")

        devices = discover_devices()
        selected_index = 0
        
        if not running:
            raise KeyboardInterrupt

        draw_device_list(devices, selected_index)

        while running:
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
                elif GPIO.input(PINS["OK"]) == 0:
                    devices = discover_devices()
                    selected_index = 0
                    button_pressed = True
                
                time.sleep(0.1)

            if button_pressed:
                draw_device_list(devices, selected_index)
                time.sleep(0.2)

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
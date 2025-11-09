#!/usr/bin/env python3
"""
RaspyJack *payload* – **WiFi Rogue AP**
=====================================
This payload sets up a rogue Wi-Fi access point (AP) with a customizable SSID
and channel. A rogue AP can be used for various purposes, including phishing,
man-in-the-middle attacks, or simply to attract clients for further exploitation.

Features:
- Interactive UI for selecting the wireless interface.
- Allows configuration of the rogue AP's SSID and channel.
- Uses `hostapd` to create the rogue access point.
- Displays status messages on the LCD.
- Graceful exit via KEY3 or Ctrl-C, cleaning up `hostapd` and restoring
  network settings.

Controls:
- INTERFACE SELECTION SCREEN:
    - UP/DOWN: Navigate available wireless interfaces.
    - OK: Select interface.
    - KEY3: Cancel selection and exit.
- MAIN CONFIGURATION SCREEN:
    - UP/DOWN: Navigate configuration parameters (SSID, Channel).
    - OK: Edit selected parameter.
    - KEY2: Start Rogue AP.
    - KEY3: Exit Payload.
- SSID INPUT SCREEN:
    - UP/DOWN: Change character at cursor position.
    - LEFT/RIGHT: Move cursor.
    - OK: Confirm SSID.
    - KEY3: Cancel input.
- CHANNEL INPUT SCREEN:
    - UP/DOWN: Increment/decrement channel.
    - OK: Confirm channel.
    - KEY3: Cancel input.
"""
import sys
import os
import time
import signal
import subprocess
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from wifi.raspyjack_integration import (
    get_best_interface,
    set_raspyjack_interface
)

WIFI_INTERFACE = get_best_interface(prefer_wifi=True)
ORIGINAL_WIFI_INTERFACE = None
ROGUE_SSID = "Unsecured_Free_WiFi"
ROGUE_CHANNEL = "6"
RASPYJACK_DIR = os.path.abspath(os.path.join(__file__, '..', '..'))
TEMP_CONF_DIR = os.path.join(RASPYJACK_DIR, "tmp", "raspyjack_rogueap")

PINS = { "OK": 13, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

running = True
attack_process = None
current_ssid_input = ROGUE_SSID
ssid_input_cursor_pos = 0
status_msg = "Press OK to start"

def run_command(command_parts, error_message, timeout=10, shell=False, check=False):
    try:
        if shell:
            result = subprocess.run(command_parts, shell=True, check=check, capture_output=True, text=True, timeout=timeout)
        else:
            result = subprocess.run(command_parts, shell=False, check=check, capture_output=True, text=True, timeout=timeout)
        if result.stderr:
            print(f"WARNING: {error_message} - STDERR: {result.stderr.strip()}", file=sys.stderr)
        return result.stdout, result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"ERROR: {error_message} - Command: {command_parts} - STDERR: {e.stderr.strip()}", file=sys.stderr)
        return e.stdout, False
    except subprocess.TimeoutExpired:
        print(f"ERROR: {error_message} - Command timed out: {command_parts}", file=sys.stderr)
        return "", False
    except FileNotFoundError:
        print(f"ERROR: {error_message} - Command not found: {command_parts.split()[0]}", file=sys.stderr)
        return "", False
    except Exception as e:
        print(f"CRITICAL ERROR during {error_message}: {e}", file=sys.stderr)
        return "", False

def cleanup(*_):
    global running, WIFI_INTERFACE, ORIGINAL_WIFI_INTERFACE
    if running:
        running = False
        if attack_process:
            try: os.killpg(os.getpgid(attack_process.pid), signal.SIGTERM)
            except: pass
        
        run_command("pkill hostapd", "Failed to kill hostapd", shell=True)
        
        if ORIGINAL_WIFI_INTERFACE:
            print(f"Attempting to restore {ORIGINAL_WIFI_INTERFACE}...", file=sys.stderr)
            run_command(f"ifconfig {WIFI_INTERFACE} down", f"Failed to bring down {WIFI_INTERFACE}", shell=True)
            run_command(f"iwconfig {WIFI_INTERFACE} mode managed", f"Failed to set {WIFI_INTERFACE} to managed mode", shell=True)
            run_command(f"ifconfig {WIFI_INTERFACE} up", f"Failed to bring up {WIFI_INTERFACE}", shell=True)
            time.sleep(1)
            
            run_command(f"nmcli device set {ORIGINAL_WIFI_INTERFACE} managed yes", f"Failed to set {ORIGINAL_WIFI_INTERFACE} to managed", shell=True)
            run_command(f"nmcli device connect {ORIGINAL_WIFI_INTERFACE}", f"Failed to connect {ORIGINAL_WIFI_INTERFACE}", shell=True)
            time.sleep(5)
            
            run_command("systemctl restart NetworkManager", "Failed to restart NetworkManager", shell=True)
            time.sleep(5)
            
            WIFI_INTERFACE = ORIGINAL_WIFI_INTERFACE
            
        if os.path.exists(TEMP_CONF_DIR): run_command(f"rm -rf {TEMP_CONF_DIR}", "Failed to remove temp config dir", shell=True)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def draw_message(lines, color="yellow"):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    y = 40
    for line in lines:
        bbox = d.textbbox((0, 0), line, font=FONT_TITLE)
        w = bbox[2] - bbox[0]
        x = (WIDTH - w) // 2
        d.text((x, y), line, font=FONT_TITLE, fill=color)
        y += 15
    LCD.LCD_ShowImage(img, 0, 0)

def draw_ui_main(params, selected_index):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "WiFi Rogue AP", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    y_pos = 25
    param_keys = list(params.keys())
    for i, key in enumerate(param_keys):
        color = "yellow" if i == selected_index else "white"
        d.text((5, y_pos), f"{key}: {params[key]}", font=FONT, fill=color)
        y_pos += 11
    
    d.text((5, 80), status_msg, font=FONT, fill="yellow")
    d.text((5, 115), "OK=Edit | KEY2=Start | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

def draw_ui_interface_selection(interfaces, current_selection):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Select Interface", font=FONT_TITLE, fill="cyan")
    d.line([(0, 22), (128, 22)], fill="cyan", width=1)

    y_pos = 25
    for i, iface in enumerate(interfaces):
        color = "yellow" if i == current_selection else "white"
        d.text((5, y_pos), iface, font=FONT, fill=color)
        y_pos += 11
    
    d.text((5, 115), "UP/DOWN=Select | OK=Confirm", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

def select_interface_menu():
    global WIFI_INTERFACE, ORIGINAL_WIFI_INTERFACE
    
    available_interfaces = [iface for iface in get_available_interfaces() if iface.startswith('wlan')]
    if not available_interfaces:
        draw_message(["No WiFi interfaces found!"], "red")
        time.sleep(3)
        return False

    current_menu_selection = 0
    last_button_press_time = 0
    BUTTON_DEBOUNCE_TIME = 0.2 # seconds

    while running:
        current_time = time.time()
        draw_ui_interface_selection(available_interfaces, current_menu_selection)
        
        if GPIO.input(PINS["UP"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
            last_button_press_time = current_time
            current_menu_selection = (current_menu_selection - 1 + len(available_interfaces)) % len(available_interfaces)
            time.sleep(BUTTON_DEBOUNCE_TIME)
        elif GPIO.input(PINS["DOWN"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
            last_button_press_time = current_time
            current_menu_selection = (current_menu_selection + 1) % len(available_interfaces)
            time.sleep(BUTTON_DEBOUNCE_TIME)
        elif GPIO.input(PINS["OK"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
            last_button_press_time = current_time
            selected_iface = available_interfaces[current_menu_selection]
            draw_message([f"Activating {selected_iface}", "for Rogue AP..."], "yellow")
            print(f"Attempting to set {selected_iface} as primary interface...", file=sys.stderr)
            
            if set_raspyjack_interface(selected_iface):
                WIFI_INTERFACE = selected_iface
                ORIGINAL_WIFI_INTERFACE = selected_iface # Store original for cleanup
                draw_message([f"Interface set to", f"{WIFI_INTERFACE}"], "lime")
                print(f"Successfully set {WIFI_INTERFACE} as primary interface.", file=sys.stderr)
                time.sleep(2)
                return True
            else:
                draw_message(["ERROR:", "Failed to activate", "interface!"], "red")
                print(f"ERROR: set_raspyjack_interface failed for {selected_iface}", file=sys.stderr)
                time.sleep(3)
                return False
        elif GPIO.input(PINS["KEY3"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
            last_button_press_time = current_time
            return False
        
        time.sleep(0.05)

def handle_text_input_logic(initial_text, prompt, char_set):
    global current_ssid_input, ssid_input_cursor_pos
    
    current_input_ref = initial_text
    ssid_input_cursor_pos = len(initial_text) - 1
    
    while running:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ImageDraw.Draw(img)
        d.text((5, 5), f"Enter {prompt}:", font=FONT_TITLE, fill="cyan")
        d.line([(0, 22), (128, 22)], fill="cyan", width=1)

        display_text = list(current_input_ref)
        if ssid_input_cursor_pos < len(display_text):
            display_text[ssid_input_cursor_pos] = '_'
        d.text((5, 40), "".join(display_text[:16]), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Char | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
        LCD.LCD_ShowImage(img, 0, 0)

        last_button_press_time = 0
        BUTTON_DEBOUNCE_TIME = 0.2 # seconds
        current_time = time.time()

        btn = None
        for name, pin in PINS.items():
            if GPIO.input(pin) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                btn = name
                last_button_press_time = current_time
                break
        
        if btn == "KEY3":
            return None
        
        if btn == "OK":
            if current_input_ref:
                return current_input_ref
            else:
                draw_message(["Input cannot", "be empty!"], "red")
                time.sleep(2)
                current_input_ref = initial_text
                ssid_input_cursor_pos = len(initial_text) - 1
        
        if btn == "LEFT":
            ssid_input_cursor_pos = max(0, ssid_input_cursor_pos - 1)
        elif btn == "RIGHT":
            ssid_input_cursor_pos = min(len(current_input_ref), ssid_input_cursor_pos + 1)
        elif btn == "UP" or btn == "DOWN":
            if ssid_input_cursor_pos < len(current_input_ref):
                char_list = list(current_input_ref)
                current_char = char_list[ssid_input_cursor_pos]
                
                try:
                    char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
                    char_index = char_set.index(current_char)
                    if btn == "UP":
                        char_index = (char_index + 1) % len(char_set)
                    else:
                        char_index = (char_index - 1 + len(char_set)) % len(char_set)
                    char_list[ssid_input_cursor_pos] = char_set[char_index]
                    current_input_ref = "".join(char_list)
                except ValueError:
                    char_list[ssid_input_cursor_pos] = char_set[0]
                    current_input_ref = "".join(char_list)
        
        time.sleep(0.05)
    return None

def get_user_number(prompt, initial_value, min_val=1, max_val=165):
    value = initial_value
    last_button_press_time = 0
    BUTTON_DEBOUNCE_TIME = 0.2 # seconds

    while running:
        current_time = time.time()
        draw_message([f"{prompt}:", f"{value}", "UP/DOWN | OK=Save"])
        
        if GPIO.input(PINS["UP"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
            last_button_press_time = current_time
            value = min(max_val, value + 1)
            time.sleep(BUTTON_DEBOUNCE_TIME)
        elif GPIO.input(PINS["DOWN"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
            last_button_press_time = current_time
            value = max(min_val, value - 1)
            time.sleep(BUTTON_DEBOUNCE_TIME)
        elif GPIO.input(PINS["OK"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
            last_button_press_time = current_time
            return value
        elif GPIO.input(PINS["KEY3"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
            last_button_press_time = current_time
            return initial_value
        time.sleep(0.05)

def start_attack():
    global attack_process, ORIGINAL_WIFI_INTERFACE, status_msg
    
    print(f"Attempting to activate {WIFI_INTERFACE} as primary interface...", file=sys.stderr)
    if not set_raspyjack_interface(WIFI_INTERFACE):
        print(f"ERROR: Failed to activate {WIFI_INTERFACE}", file=sys.stderr)
        status_msg = "Failed to set interface!"
        return False
    
    run_command(f"nmcli device disconnect {WIFI_INTERFACE}", f"Failed to disconnect {WIFI_INTERFACE}", shell=True)
    run_command(f"nmcli device set {WIFI_INTERFACE} managed off", f"Failed to set {WIFI_INTERFACE} to unmanaged", shell=True)
    time.sleep(1)
    
    run_command("pkill hostapd", "Failed to kill hostapd", shell=True)
    
    os.makedirs(TEMP_CONF_DIR, exist_ok=True)
    hostapd_conf_path = os.path.join(TEMP_CONF_DIR, "hostapd.conf")
    with open(hostapd_conf_path, "w") as f: f.write(f"interface={WIFI_INTERFACE}\ndriver=nl80211\nssid={ROGUE_SSID}\nhw_mode=g\nchannel={ROGUE_CHANNEL}\n")
    
    print(f"Starting hostapd on {WIFI_INTERFACE} with SSID {ROGUE_SSID}...", file=sys.stderr)
    attack_process = subprocess.Popen(f"hostapd {hostapd_conf_path}", shell=True, preexec_fn=os.setsid)
    status_msg = "Rogue AP Running!"
    return True

if __name__ == '__main__':
    current_screen = "interface_select"
    selected_param_index = 0
    params = {
        "SSID": ROGUE_SSID,
        "Channel": ROGUE_CHANNEL
    }
    param_keys = list(params.keys())
    
    try:
        stdout, success = run_command(f"which hostapd", "Checking for hostapd", shell=True)
        if not success:
            draw_message(["hostapd not found!"], "red")
            time.sleep(3)
            raise SystemExit("`hostapd` command not found.")

        if not select_interface_menu():
            draw_message(["No interface selected", "or activation failed."], "red")
            time.sleep(3)
            raise SystemExit("No interface selected or activation failed.")
        
        current_screen = "main_config"
        last_button_press_time = 0
        BUTTON_DEBOUNCE_TIME = 0.3 # seconds

        while running:
            current_time = time.time()
            if current_screen == "main_config":
                draw_ui_main(params, selected_param_index)
                
                if GPIO.input(PINS["KEY3"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    cleanup()
                    break
                
                if GPIO.input(PINS["UP"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    selected_param_index = (selected_param_index - 1) % len(param_keys)
                    time.sleep(BUTTON_DEBOUNCE_TIME)
                elif GPIO.input(PINS["DOWN"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    selected_param_index = (selected_param_index + 1) % len(param_keys)
                    time.sleep(BUTTON_DEBOUNCE_TIME)
                elif GPIO.input(PINS["OK"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    key = param_keys[selected_param_index]
                    if key == "SSID":
                        char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
                        new_ssid = handle_text_input_logic(params[key], "SSID", char_set)
                        if new_ssid:
                            params[key] = new_ssid
                            ROGUE_SSID = new_ssid
                    elif key == "Channel":
                        new_channel = get_user_number("Channel", int(params[key]), 1, 165)
                        params[key] = str(new_channel)
                        ROGUE_CHANNEL = str(new_channel)
                    time.sleep(BUTTON_DEBOUNCE_TIME)
                elif GPIO.input(PINS["KEY2"]) == 0 and (current_time - last_button_press_time > BUTTON_DEBOUNCE_TIME):
                    last_button_press_time = current_time
                    if start_attack():
                        status_msg = "Rogue AP Running!"
                    else:
                        status_msg = "Failed to start AP!"
                    time.sleep(BUTTON_DEBOUNCE_TIME)
            
            time.sleep(0.05)

    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        cleanup()
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Rogue AP payload finished.")
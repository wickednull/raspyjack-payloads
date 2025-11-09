#!/usr/bin/env python3
import sys
import os
import time
import signal
import subprocess
import re
from select import select
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

PINS: dict[str, int] = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13,
    "KEY1": 21, "KEY2": 20, "KEY3": 16,
}

GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
FONT = ImageFont.load_default()
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)

RASPYJACK_DIR = os.path.abspath(os.path.join(__file__, '..', '..'))
LOOT_DIR = os.path.join(RASPYJACK_DIR, "loot", "BLE_GATT")
running = True

def cleanup(*_):
    global running
    if running:
        running = False
        subprocess.run("bluetoothctl power off", shell=True, capture_output=True)
        subprocess.run("bluetoothctl disconnect", shell=True, capture_output=True)
        subprocess.run("bluetoothctl scan off", shell=True, capture_output=True)
        subprocess.run("pkill -f bluetoothctl", shell=True, capture_output=True)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def draw_message(message, color="yellow"):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    y = 40
    for line in message.split('\n'):
        bbox = d.textbbox((0, 0), line, font=FONT_TITLE)
        w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        x = (WIDTH - w) // 2
        d.text((x, y), line, font=FONT_TITLE, fill=color)
        y += h + 5
    LCD.LCD_ShowImage(img, 0, 0)

def draw_list_ui(title, items, selected_index):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), title, font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    if not items:
        d.text((10, 60), "Nothing found.", font=FONT, fill="white")
    else:
        start_index = max(0, selected_index - 4)
        end_index = min(len(items), start_index + 8)
        y_pos = 25
        for i in range(start_index, end_index):
            color = "yellow" if i == selected_index else "white"
            line = items[i]
            if len(line) > 20:
                line = line[:19] + "..."
            d.text((5, y_pos), line, font=FONT, fill=color)
            y_pos += 11
            
    d.text((5, 115), "OK=Select | KEY3=Back", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

def bluetoothctl_command(commands):
    output = ""
    try:
        proc = subprocess.Popen(
            ["bluetoothctl"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        
        for command in commands:
            proc.stdin.write(command + "\n")
            proc.stdin.flush()
            time.sleep(0.5)

        proc.stdin.write("exit\n")
        proc.stdin.flush()
        
        out, _ = proc.communicate(timeout=15)
        output = out
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
        output = out + "\n[Timeout]"
    except Exception as e:
        output = f"Error: {e}"
        
    return output

def scan_ble_devices():
    draw_message("Scanning BLE...")
    output = bluetoothctl_command(["scan on", "scan off"])
    
    devices = {}
    for line in output.split('\n'):
        match = re.search(r"Device ([0-9A-F:]{17}) (.+)", line)
        if match:
            mac, name = match.group(1), match.group(2).strip()
            if name != "n/a":
                devices[mac] = name
    return devices

def get_gatt_table(mac):
    draw_message(f"Connecting to\n{mac}")
    
    commands = [
        "power on",
        f"connect {mac}",
        "menu gatt",
        "list-attributes",
        f"disconnect {mac}"
    ]
    
    output = ""
    try:
        proc = subprocess.Popen(["bluetoothctl"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        
        proc.stdin.write(f"connect {mac}\n"); proc.stdin.flush()
        time.sleep(5)
        
        proc.stdin.write("menu gatt\n"); proc.stdin.flush()
        time.sleep(1)
        
        proc.stdin.write("list-attributes\n"); proc.stdin.flush()
        time.sleep(5)
        
        proc.stdin.write(f"disconnect {mac}\n"); proc.stdin.flush()
        time.sleep(1)
        
        proc.stdin.write("exit\n"); proc.stdin.flush()
        
        out, _ = proc.communicate(timeout=20)
        output = out
    except Exception as e:
        output = f"Error: {e}"

    attributes = []
    for line in output.split('\n'):
        if "Attribute" in line or "Primary Service" in line or "Characteristic" in line:
            cleaned_line = line.replace("Attribute", "").strip()
            attributes.append(cleaned_line)
            
    return attributes

if __name__ == "__main__":
    try:
        if subprocess.run("which bluetoothctl", shell=True, capture_output=True).returncode != 0:
            draw_message("bluetoothctl not found!", "red")
            time.sleep(5)
            raise SystemExit("bluetoothctl not found.")

        while running:
            devices = scan_ble_devices()
            if not devices:
                draw_message("No BLE devices\nfound.")
                time.sleep(3)
                continue
                
            device_list = [f"{name} {mac[-5:]}" for mac, name in devices.items()]
            mac_list = list(devices.keys())
            selected_index = 0

            while running:
                draw_list_ui("Select BLE Target", device_list, selected_index)
                
                if GPIO.input(PINS["KEY3"]) == 0:
                    time.sleep(0.3)
                    break
                
                if GPIO.input(PINS["UP"]) == 0:
                    selected_index = (selected_index - 1) % len(device_list)
                    time.sleep(0.2)
                elif GPIO.input(PINS["DOWN"]) == 0:
                    selected_index = (selected_index + 1) % len(device_list)
                    time.sleep(0.2)
                elif GPIO.input(PINS["OK"]) == 0:
                    target_mac = mac_list[selected_index]
                    target_name = devices[target_mac]
                    
                    attributes = get_gatt_table(target_mac)
                    
                    if attributes:
                        os.makedirs(LOOT_DIR, exist_ok=True)
                        loot_file = os.path.join(LOOT_DIR, f"{target_mac.replace(':', '')}.txt")
                        with open(loot_file, "w") as f:
                            f.write(f"GATT Table for {target_name} ({target_mac})\n\n")
                            f.writelines([f"{attr}\n" for attr in attributes])
                        
                        attr_selected_index = 0
                        while running:
                            draw_list_ui(f"GATT: {target_name[:10]}", attributes, attr_selected_index)
                            if GPIO.input(PINS["KEY3"]) == 0:
                                time.sleep(0.3)
                                break
                            if GPIO.input(PINS["UP"]) == 0:
                                attr_selected_index = (attr_selected_index - 1) % len(attributes)
                                time.sleep(0.2)
                            elif GPIO.input(PINS["DOWN"]) == 0:
                                attr_selected_index = (attr_selected_index + 1) % len(attributes)
                                time.sleep(0.2)
                    else:
                        draw_message("Failed to get\nattributes.")
                        time.sleep(3)
                    
                    break
                
                time.sleep(0.05)
            
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()

    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("BLE Char Scanner payload finished.")
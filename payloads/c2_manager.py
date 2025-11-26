#!/usr/bin/env python3
import sys
import os
import time
import signal
import subprocess

RASPYJACK_ROOT = '/root/Raspyjack'
if os.path.isdir(RASPYJACK_ROOT) and RASPYJACK_ROOT not in sys.path:
    sys.path.insert(0, RASPYJACK_ROOT)

try:
    import LCD_Config
    import LCD_1in44
    import RPi.GPIO as GPIO
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("This payload must be run on the Raspyjack hardware.")
    sys.exit(0)

# --- CONFIG & STATE ---
PINS = {"UP": 6, "DOWN": 19, "KEY_PRESS": 13, "KEY3": 16}
RUNNING = True
DEBOUNCE_DELAY = 0.25
CLIENT_SCRIPT_PATH = "c2_client/client.py"
CLIENT_PROCESS_NAME = f"python3 {CLIENT_SCRIPT_PATH}"

# --- CLEANUP ---
def cleanup(*_):
    global RUNNING
    if not RUNNING: return
    RUNNING = False
    GPIO.cleanup()
    sys.exit(0)

# --- UI & LOGIC ---
def draw_menu(draw, menu_items, selected_index, status):
    draw.rectangle([(0, 0), (128, 128)], fill="BLACK")
    font = ImageFont.load_default()
    
    # Title
    bbox = draw.textbbox((0, 0), "C2 Client Manager", font=font); text_width = bbox[2] - bbox[0]
    draw.text(((128 - text_width) // 2, 5), "C2 Client Manager", font=font, fill="CYAN")
    
    # Status
    status_color = "LIME" if status == "Running" else "RED"
    bbox = draw.textbbox((0, 0), f"Status: {status}", font=font); text_width = bbox[2] - bbox[0]
    draw.text(((128 - text_width) // 2, 25), f"Status: {status}", font=font, fill=status_color)

    # Menu
    y = 50
    for i, item in enumerate(menu_items):
        if i == selected_index:
            draw.rectangle([(0, y - 2), (128, y + 12)], fill="BLUE")
            bbox = draw.textbbox((0, 0), item, font=font); text_width = bbox[2] - bbox[0]
            draw.text(((128 - text_width) // 2, y), item, font=font, fill="YELLOW")
        else:
            bbox = draw.textbbox((0, 0), item, font=font); text_width = bbox[2] - bbox[0]
            draw.text(((128 - text_width) // 2, y), item, font=font, fill="WHITE")
        y += 20
    
    bbox = draw.textbbox((0, 0), "KEY3 to Exit", font=font); text_width = bbox[2] - bbox[0]
    draw.text(((128 - text_width) // 2, 115), "KEY3 to Exit", font=font, fill="WHITE")

def get_client_status():
    try:
        subprocess.check_output(["pgrep", "-f", CLIENT_PROCESS_NAME])
        return "Running"
    except subprocess.CalledProcessError:
        return "Stopped"

def start_client():
    if get_client_status() == "Running": return
    command = f"nohup python3 {CLIENT_SCRIPT_PATH} > /tmp/c2_client.log 2>&1 &"
    subprocess.Popen(command, shell=True, cwd=RASPYJACK_ROOT)

def stop_client():
    if get_client_status() == "Stopped": return
    subprocess.run(["pkill", "-f", CLIENT_PROCESS_NAME])

# --- MAIN ---
if __name__ == "__main__":
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    try:
        # Hardware Init
        GPIO.setmode(GPIO.BCM)
        for pin in PINS.values():
            GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
        
        LCD = LCD_1in44.LCD()
        LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
        LCD.LCD_Clear()
        
        image = Image.new("RGB", (128, 128), "BLACK")
        draw = ImageDraw.Draw(image)
        
        # State Variables
        menu_items = ["Start Client", "Stop Client", "Refresh Status"]
        selected_index = 0
        last_press_time = 0
        
        while RUNNING:
            current_time = time.time()
            
            # Always check status for drawing
            client_status = get_client_status()
            
            # Draw the screen
            draw_menu(draw, menu_items, selected_index, client_status)
            LCD.LCD_ShowImage(image, 0, 0)

            # Handle Input after debounce
            if (current_time - last_press_time) > DEBOUNCE_DELAY:
                # QUIT
                if GPIO.input(PINS["KEY3"]) == 0:
                    RUNNING = False
                    break
                # UP
                elif GPIO.input(PINS["UP"]) == 0:
                    last_press_time = current_time
                    selected_index = (selected_index - 1) % len(menu_items)
                # DOWN
                elif GPIO.input(PINS["DOWN"]) == 0:
                    last_press_time = current_time
                    selected_index = (selected_index + 1) % len(menu_items)
                # OK
                elif GPIO.input(PINS["KEY_PRESS"]) == 0:
                    last_press_time = current_time
                    action = menu_items[selected_index]
                    if action == "Start Client":
                        start_client()
                    elif action == "Stop Client":
                        stop_client()
                    # "Refresh Status" does nothing on its own, the loop does it
            
            time.sleep(0.1)

    finally:
        LCD.LCD_Clear()
        cleanup()

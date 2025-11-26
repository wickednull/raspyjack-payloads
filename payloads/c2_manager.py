#!/usr/bin/env python3
#
# c2_manager.py - A Raspyjack payload to start/stop the C2 client service.
#

import sys
import os
import time
import signal
import subprocess

# Add Raspyjack root to the Python path
RASPYJACK_ROOT = '/root/Raspyjack'
if os.path.isdir(RASPYJACK_ROOT) and RASPYJACK_ROOT not in sys.path:
    sys.path.insert(0, RASPYJACK_ROOT)

# Hardware Imports
try:
    import LCD_Config
    import LCD_1in44
    import RPi.GPIO as GPIO
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("This payload must be run on the Raspyjack hardware.")
    sys.exit(0)

# --- Globals ---
PINS = {"UP": 6, "DOWN": 19, "OK": 20, "KEY3": 16}
RUNNING = True
DEBOUNCE_DELAY = 0.2
last_press_time = 0

# --- Menu State ---
menu_items = ["Start Client", "Stop Client"]
selected_index = 0
client_status = "Unknown"

# --- Client Process Info ---
CLIENT_SCRIPT_PATH = "c2_client/client.py"
CLIENT_PROCESS_NAME = f"python3 {CLIENT_SCRIPT_PATH}"

# --- Cleanup ---
def cleanup(*_):
    global RUNNING
    if not RUNNING: return
    RUNNING = False
    print("C2 Manager: Cleaning up GPIO...")
    GPIO.cleanup()
    print("C2 Manager: Exiting.")
    sys.exit(0)

# --- Helper Functions ---
def draw_centered_message(draw, text, y_position, font, fill="WHITE"):
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    x_position = (128 - text_width) // 2
    draw.text((x_position, y_position), text, font=font, fill=fill)

def draw_menu(draw, font):
    global client_status
    draw.rectangle([(0, 0), (128, 128)], fill="BLACK")
    draw_centered_message(draw, "C2 Client Manager", 5, font, fill="CYAN")
    
    # Display Status
    status_color = "LIME" if client_status == "Running" else "RED"
    draw_centered_message(draw, f"Status: {client_status}", 25, font, fill=status_color)

    # Display Menu
    y = 50
    for i, item in enumerate(menu_items):
        if i == selected_index:
            draw.rectangle([(0, y - 2), (128, y + 12)], fill="BLUE")
            draw_centered_message(draw, item, y, font, fill="YELLOW")
        else:
            draw_centered_message(draw, item, y, font, fill="WHITE")
        y += 20
    
    draw_centered_message(draw, "KEY3 to Exit", 115, font, fill="WHITE")

def check_client_status():
    global client_status
    try:
        # Use pgrep to find the process. The -f flag matches against the full command line.
        subprocess.check_output(["pgrep", "-f", CLIENT_PROCESS_NAME])
        client_status = "Running"
    except subprocess.CalledProcessError:
        client_status = "Stopped"

def start_client():
    global client_status
    check_client_status()
    if client_status == "Running":
        print("Client is already running.")
        return
    
    print("Starting C2 client as a background process...")
    # Use nohup to ensure the process continues running after this payload exits.
    # The process is started from the Raspyjack root directory.
    command = f"nohup python3 {CLIENT_SCRIPT_PATH} > /tmp/c2_client.log 2>&1 &"
    subprocess.Popen(command, shell=True, cwd=RASPYJACK_ROOT)
    time.sleep(1) # Give it a moment to start
    check_client_status()

def stop_client():
    global client_status
    check_client_status()
    if client_status == "Stopped":
        print("Client is not running.")
        return
        
    print("Stopping C2 client process...")
    # Use pkill to stop all processes matching the name.
    subprocess.run(["pkill", "-f", CLIENT_PROCESS_NAME])
    time.sleep(1) # Give it a moment to stop
    check_client_status()

# --- Main Execution ---
if __name__ == "__main__":
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    try:
        # --- Hardware Init ---
        GPIO.setmode(GPIO.BCM)
        for pin in PINS.values():
            GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

        LCD = LCD_1in44.LCD()
        LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
        LCD.LCD_Clear()

        image = Image.new("RGB", (128, 128), "BLACK")
        draw = ImageDraw.Draw(image)
        font = ImageFont.load_default()

        check_client_status()

        # --- Main Loop ---
        while RUNNING:
            current_time = time.time()
            
            # Drawing
            draw_menu(draw, font)
            LCD.LCD_ShowImage(image, 0, 0)

            # Input Handling
            if (current_time - last_press_time) > DEBOUNCE_DELAY:
                if GPIO.input(PINS["UP"]) == 0:
                    last_press_time = current_time
                    selected_index = (selected_index - 1) % len(menu_items)
                
                elif GPIO.input(PINS["DOWN"]) == 0:
                    last_press_time = current_time
                    selected_index = (selected_index + 1) % len(menu_items)

                elif GPIO.input(PINS["OK"]) == 0:
                    last_press_time = current_time
                    action = menu_items[selected_index]
                    if action == "Start Client":
                        start_client()
                        draw_menu(draw, font)
                        LCD.LCD_ShowImage(image, 0, 0)
                    elif action == "Stop Client":
                        stop_client()
                        draw_menu(draw, font)
                        LCD.LCD_ShowImage(image, 0, 0)

                elif GPIO.input(PINS["KEY3"]) == 0:
                    break # Exit loop

            time.sleep(0.1)

    finally:
        LCD.LCD_Clear()
        cleanup()

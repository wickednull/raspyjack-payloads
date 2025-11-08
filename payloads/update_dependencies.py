#!/usr/bin/env python3
"""
RaspyJack *payload* – **Update & Install Dependencies**
========================================================
A utility payload that updates the system's package list and installs
all the necessary dependencies for the advanced payloads.

This script will:
1.  Run `apt-get update`.
2.  Install a list of required packages using `apt-get`.
3.  Install a list of required Python packages using `pip`.
4.  Download and build `hcxdumptool` from source, as it is often not
    available in default repositories.
"""

import os, sys, subprocess, signal, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
APT_DEPS = [
    "hydra", "mitmproxy", "fswebcam", "alsa-utils", "macchanger",
    "reaver", "hostapd", "dnsmasq", "smbclient", "snmp", "php-cgi",
    "ettercap-common", "nmap", "git", "build-essential", "libcurl4-openssl-dev",
    "libssl-dev", "pkg-config"
]
PIP_DEPS = ["qrcode[pil]", "requests"]
HCXDUMPTOOL_REPO = "https://github.com/ZerBea/hcxdumptool.git"
HCXDUMPTOOL_DIR = "/tmp/hcxdumptool"

# --- GPIO & LCD ---
PINS = { "OK": 13, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

# --- Main ---
def show_message(lines, color="lime"):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    y = 20
    for line in lines:
        d.text((5, y), line, font=FONT_TITLE, fill=color)
        y += 15
    LCD.LCD_ShowImage(img, 0, 0)

def run_command(command, step_name):
    """Runs a command and shows status on the LCD."""
    show_message([f"Running:", f"{step_name}..."])
    try:
        proc = subprocess.run(command, shell=True, check=True, capture_output=True, text=True, timeout=600)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        error_msg = e.stderr or e.stdout or str(e)
        show_message([f"ERROR:", f"{step_name}", f"failed."], "red")
        print(f"Error during '{step_name}': {error_msg}", file=sys.stderr)
        time.sleep(5)
        return False

def install_all():
    if not run_command("apt-get update", "apt update"):
        return

    if not run_command(f"apt-get install -y {' '.join(APT_DEPS)}", "apt install"):
        return
        
    if not run_command(f"pip install {' '.join(PIP_DEPS)}", "pip install"):
        return

    # Install hcxdumptool from source
    show_message(["Installing", "hcxdumptool..."])
    if os.path.exists(HCXDUMPTOOL_DIR):
        subprocess.run(f"rm -rf {HCXDUMPTOOL_DIR}", shell=True)
    if not run_command(f"git clone {HCXDUMPTOOL_REPO} {HCXDUMPTOOL_DIR}", "git clone"):
        return
    if not run_command(f"cd {HCXDUMPTOOL_DIR} && make && make install", "make install"):
        return
        
    show_message(["Installation", "Complete!"], "lime")
    time.sleep(5)

if __name__ == '__main__':
    try:
        # Check for root
        if os.geteuid() != 0:
            show_message(["Run this", "payload as root!"], "red")
            time.sleep(3)
        else:
            show_message(["Install all", "dependencies?", "Press OK."])
            while True:
                if GPIO.input(PINS["KEY3"]) == 0:
                    break
                if GPIO.input(PINS["OK"]) == 0:
                    install_all()
                    break
                time.sleep(0.1)
            
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Dependency Installer payload finished.")

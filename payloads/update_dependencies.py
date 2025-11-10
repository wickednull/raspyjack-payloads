#!/usr/bin/env python3
"""
RaspyJack *payload* – **Dependency Updater**
==========================================
This payload installs all necessary dependencies for the RaspyJack payloads.
It is designed to be run on a Raspberry Pi with a Raspbian-based OS.

Features:
- Checks for root privileges.
- Installs required APT packages.
- Installs required Python packages via pip.
- Displays installation progress on the LCD.
"""

import sys
import os
import time
import signal
import subprocess
import threading

# ----------------------------
# RaspyJack PATH and ROOT check
# ----------------------------
def is_root():
    return os.geteuid() == 0

# Dynamically add Raspyjack path
RASPYJACK_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'Raspyjack'))
if RASPYJACK_PATH not in sys.path:
    sys.path.append(RASPYJACK_PATH)

# ----------------------------
# Third-party library imports 
# ----------------------------
try:
    import RPi.GPIO as GPIO
    import LCD_1in44, LCD_Config
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("ERROR: Hardware libraries (RPi.GPIO, LCD, PIL) not found.", file=sys.stderr)
    print("Please run 'sudo pip3 install RPi.GPIO spidev Pillow'.", file=sys.stderr)
    sys.exit(1)

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

def draw_message(lines, color="yellow"):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    font = FONT_TITLE
    y = 40
    message_list = lines if isinstance(lines, list) else [lines]
    for line in message_list:
        bbox = d.textbbox((0, 0), line, font=font)
        w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        x = (WIDTH - w) // 2
        d.text((x, y), line, font=font, fill=color)
        y += h + 5
    LCD.LCD_ShowImage(img, 0, 0)

def run_command(command):
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while process.poll() is None:
            draw_message(["Installing...", command.split(" ")[-1]], "lime")
            time.sleep(1)
        if process.returncode != 0:
            draw_message(["Error installing", command.split(" ")[-1]], "red")
            time.sleep(3)
            return False
        return True
    except Exception as e:
        draw_message(["Error:", str(e)], "red")
        time.sleep(3)
        return False

def main():
    if not is_root():
        draw_message(["ERROR:", "Root privileges", "required."], "red")
        sys.exit(1)

    draw_message(["Updating APT..."])
    if not run_command("sudo apt-get update -y"):
        sys.exit(1)

    apt_packages = [
        "python3-scapy", "python3-netifaces", "python3-pyudev", "python3-serial",
        "python3-smbus", "python3-rpi.gpio", "python3-spidev", "python3-pil", "python3-numpy",
        "python3-setuptools", "python3-cryptography", "python3-requests", "fonts-dejavu-core",
        "nmap", "ncat", "tcpdump", "arp-scan", "dsniff", "ettercap-text-only", "php", "procps",
        "aircrack-ng", "wireless-tools", "wpasupplicant", "iw",
        "firmware-linux-nonfree", "firmware-realtek", "firmware-atheros",
        "git", "i2c-tools", "reaver", "bluez", "python3-pip"
    ]

    for package in apt_packages:
        if not run_command(f"sudo apt-get install -y {package}"):
            sys.exit(1)

    pip_packages = [
        "zero-hid"
    ]

    for package in pip_packages:
        if not run_command(f"sudo pip3 install {package}"):
            sys.exit(1)

    draw_message(["All dependencies", "installed successfully!"], "lime")
    time.sleep(3)

if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Dependency update payload finished.")

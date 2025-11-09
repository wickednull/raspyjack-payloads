#!/usr/bin/env python3
import sys
import os
import time
import signal
import subprocess
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

PROCESSES_TO_KILL = [
    "hostapd", "dnsmasq", "php", "reaver", "wash", "hcxdumptool",
    "arpspoof", "mitmdump", "ettercap", "aireplay-ng", "airodump-ng",
    "hydra", "nmap"
]

PINS = { "OK": 13, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

def show_message(lines, color="lime"):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    y = 30
    for line in lines:
        d.text((5, y), line, font=FONT_TITLE, fill=color)
        y += 15
    LCD.LCD_ShowImage(img, 0, 0)

def run_cleanup():
    show_message(["Cleaning up...", "Please wait..."])
    
    for proc in PROCESSES_TO_KILL:
        subprocess.run(f"pkill -f {proc}", shell=True, capture_output=True)
        time.sleep(0.1)
        
    subprocess.run("iptables -F && iptables -t nat -F", shell=True)
    
    subprocess.run("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)
    
    subprocess.run("ifconfig wlan0 down && iwconfig wlan0 mode managed && ifconfig wlan0 up", shell=True, capture_output=True)
    subprocess.run("ifconfig wlan1 down && iwconfig wlan1 mode managed && ifconfig wlan1 up", shell=True, capture_output=True)
    
    subprocess.run("systemctl restart dhcpcd", shell=True)
    
    show_message(["Cleanup complete!", "System should be", "back to normal."], "lime")

if __name__ == '__main__':
    try:
        run_cleanup()
        time.sleep(5)
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Full Cleanup payload finished.")
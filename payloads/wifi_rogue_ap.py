#!/usr/bin/env python3
"""
RaspyJack *payload* – **WiFi: Simple Rogue AP**
=================================================
A payload that creates a simple, open (unencrypted) wireless Access
Point.

This can be used as a basic tool to attract clients, whose traffic
could then be sniffed by another tool. It is a building block for more
complex attacks and does not perform any redirection or phishing itself.
"""

import os, sys, subprocess, signal, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
WIFI_INTERFACE = "wlan1"
ROGUE_SSID = "Unsecured_Free_WiFi"
ROGUE_CHANNEL = "6"
TEMP_CONF_DIR = "/tmp/raspyjack_rogueap/"

# --- GPIO & LCD ---
PINS = { "OK": 13, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)

# --- Globals & Shutdown ---
running = True
attack_process = None

def cleanup(*_):
    global running
    if running:
        running = False
        if attack_process:
            try: os.killpg(os.getpgid(attack_process.pid), signal.SIGTERM)
            except: pass
        subprocess.run(f"ifconfig {WIFI_INTERFACE} down; iwconfig {WIFI_INTERFACE} mode managed; ifconfig {WIFI_INTERFACE} up", shell=True)
        if os.path.exists(TEMP_CONF_DIR): subprocess.run(f"rm -rf {TEMP_CONF_DIR}", shell=True)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI & Core Logic ---
def draw_ui(status: str):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Simple Rogue AP", font=FONT_TITLE, fill="#FFC300")
    d.line([(0, 22), (128, 22)], fill="#FFC300", width=1)
    status_color = "lime" if status == "ACTIVE" else "red"
    d.text((30, 40), status, font=FONT_TITLE, fill=status_color)
    d.text((5, 60), f"SSID: {ROGUE_SSID}", font=FONT)
    d.text((5, 110), "Press KEY3 to Stop", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

def start_attack():
    global attack_process
    subprocess.run("pkill wpa_supplicant; pkill hostapd", shell=True, capture_output=True)
    os.makedirs(TEMP_CONF_DIR, exist_ok=True)
    hostapd_conf_path = os.path.join(TEMP_CONF_DIR, "hostapd.conf")
    with open(hostapd_conf_path, "w") as f: f.write(f"interface={WIFI_INTERFACE}\\ndriver=nl80211\\nssid={ROGUE_SSID}\\nhw_mode=g\\nchannel={ROGUE_CHANNEL}\\n")
    
    attack_process = subprocess.Popen(f"hostapd {hostapd_conf_path}", shell=True, preexec_fn=os.setsid)
    return True

# --- Main Loop ---
try:
    if subprocess.run("which hostapd", shell=True, capture_output=True).returncode != 0:
        draw_ui("hostapd not found!")
        time.sleep(3)
        raise SystemExit("`hostapd` command not found.")

    draw_ui("STARTING")
    if start_attack():
        while running:
            draw_ui("ACTIVE")
            if GPIO.input(PINS["KEY3"]) == 0: cleanup()
            time.sleep(1)
    else:
        draw_ui("FAILED")
        time.sleep(3)
except (KeyboardInterrupt, SystemExit):
    pass
finally:
    cleanup()
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("Rogue AP payload finished.")

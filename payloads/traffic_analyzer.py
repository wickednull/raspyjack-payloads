#!/usr/bin/env python3
"""
RaspyJack *payload* – **Live Traffic Analyzer (eth0)**
=======================================================
A passive reconnaissance tool that sniffs traffic on the eth0 interface
and displays real-time statistics about the protocols and top talkers
on the network.

Features:
1.  Uses Scapy to sniff and analyze packets in a background thread.
2.  Does not store packets, only aggregates statistics to save memory.
3.  Tracks total packet count and breakdown by common protocols (TCP, UDP, etc.).
4.  Identifies the top 5 IP addresses sending the most traffic.
5.  Provides a real-time, refreshing display on the LCD.
"""

# ---------------------------------------------------------------------------
# 0) Imports & boilerplate
# ---------------------------------------------------------------------------
import os, sys, subprocess, signal, time, threading
from collections import Counter
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
sniff_thread = None
ui_lock = threading.Lock()

# Statistics
packet_count = 0
protocol_counts = Counter()
ip_counts = Counter()

# ---------------------------------------------------------------------------
# 4) Graceful shutdown
# ---------------------------------------------------------------------------
def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 5) Sniffing & Analysis Functions
# ---------------------------------------------------------------------------
def packet_handler(pkt):
    """Packet handler to update statistics."""
    global packet_count
    with ui_lock:
        packet_count += 1
        
        if pkt.haslayer(IP):
            ip_counts[pkt[IP].src] += 1
            
            if pkt.haslayer(TCP):
                protocol_counts['TCP'] += 1
            elif pkt.haslayer(UDP):
                protocol_counts['UDP'] += 1
            elif pkt.haslayer(ICMP):
                protocol_counts['ICMP'] += 1
        elif pkt.haslayer(ARP):
            protocol_counts['ARP'] += 1
        else:
            protocol_counts['Other'] += 1

def sniffer_worker():
    """Thread worker to run the Scapy sniffer."""
    sniff(iface=ETH_INTERFACE, prn=packet_handler, store=0, stop_filter=lambda p: not running)

# ---------------------------------------------------------------------------
# 6) UI Functions
# ---------------------------------------------------------------------------
def draw_ui():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)

    d.text((5, 5), "Traffic Analyzer (eth0)", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    with ui_lock:
        d.text((5, 25), f"Total Packets: {packet_count}", font=FONT, fill="white")
        
        # Protocol breakdown
        proto_str_1 = f"T:{protocol_counts['TCP']} U:{protocol_counts['UDP']}"
        proto_str_2 = f"I:{protocol_counts['ICMP']} A:{protocol_counts['ARP']}"
        d.text((5, 40), proto_str_1, font=FONT, fill="cyan")
        d.text((5, 50), proto_str_2, font=FONT, fill="cyan")

        # Top talkers
        d.text((5, 65), "Top Talkers:", font=FONT, fill="yellow")
        y_pos = 75
        top_5 = ip_counts.most_common(4)
        for ip, count in top_5:
            d.text((8, y_pos), f"{ip}", font=FONT, fill="white")
            y_pos += 10

    d.text((5, 115), "Press KEY3 to Exit", font=FONT, fill="orange")
    LCD.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# 7) Main Loop
# ---------------------------------------------------------------------------
try:
    # Check for eth0 connectivity
    if "NO-CARRIER" in subprocess.check_output(f"ip link show {ETH_INTERFACE}", shell=True).decode():
        draw_ui()
        time.sleep(1)
        d = ImageDraw.Draw(Image.new("RGB", (WIDTH, HEIGHT), "black"))
        d.text((10, 60), "eth0 Disconnected", font=FONT_TITLE, fill="red")
        LCD.LCD_ShowImage(d.im, 0, 0)
        time.sleep(3)
        raise SystemExit("Ethernet cable not connected.")

    sniff_thread = threading.Thread(target=sniffer_worker, daemon=True)
    sniff_thread.start()

    while running:
        draw_ui()
        
        # Wait for exit signal
        start_wait = time.time()
        while time.time() - start_wait < 2.0: # Refresh UI every 2 seconds
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            time.sleep(0.1)
        
        if not running:
            break

except (KeyboardInterrupt, SystemExit):
    pass
except Exception as e:
    print(f"[ERROR] {e}", file=sys.stderr)
finally:
    cleanup()
    if sniff_thread:
        sniff_thread.join(timeout=1)
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("Traffic Analyzer payload finished.")

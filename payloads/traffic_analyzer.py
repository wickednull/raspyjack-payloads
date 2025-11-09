#!/usr/bin/env python3
import sys
import os
import time
import signal
import subprocess
import threading
from collections import Counter
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from scapy.all import *
conf.verb = 0

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

ETH_INTERFACE = "eth0"
running = True
sniff_thread = None
ui_lock = threading.Lock()

packet_count = 0
protocol_counts = Counter()
ip_counts = Counter()

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def packet_handler(pkt):
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
    sniff(iface=ETH_INTERFACE, prn=packet_handler, store=0, stop_filter=lambda p: not running)

def draw_ui():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)

    d.text((5, 5), "Traffic Analyzer (eth0)", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    with ui_lock:
        d.text((5, 25), f"Total Packets: {packet_count}", font=FONT, fill="white")
        
        proto_str_1 = f"T:{protocol_counts['TCP']} U:{protocol_counts['UDP']}"
        proto_str_2 = f"I:{protocol_counts['ICMP']} A:{protocol_counts['ARP']}"
        d.text((5, 40), proto_str_1, font=FONT, fill="cyan")
        d.text((5, 50), proto_str_2, font=FONT, fill="cyan")

        d.text((5, 65), "Top Talkers:", font=FONT, fill="yellow")
        y_pos = 75
        top_5 = ip_counts.most_common(4)
        for ip, count in top_5:
            d.text((8, y_pos), f"{ip}", font=FONT, fill="white")
            y_pos += 10

    d.text((5, 115), "Press KEY3 to Exit", font=FONT, fill="orange")
    LCD.LCD_ShowImage(img, 0, 0)

if __name__ == "__main__":
    try:
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
            
            start_wait = time.time()
            while time.time() - start_wait < 2.0:
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
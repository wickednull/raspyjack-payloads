import os
import sys
import time
import subprocess
import re
import threading
from datetime import datetime

# Add Raspyjack root to sys.path for imports
sys.path.append('/root/Raspyjack/')

# Add the parent directory of the current script to sys.path to find helpers
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(script_dir)
sys.path.append(parent_dir)

# Import Raspyjack LCD modules
try:
    import LCD_1in44, LCD_Config
    from PIL import Image, ImageDraw, ImageFont
    import RPi.GPIO as GPIO
    LCD_AVAILABLE = True
except ImportError as e:
    print(f"LCD import error: {e}")
    LCD_AVAILABLE = False

# Import monitor mode helper
try:
    import monitor_mode_helper
except ImportError as e:
    print(f"monitor_mode_helper import error: {e}")
    sys.exit("monitor_mode_helper not found. Exiting.")

# Import scapy for pcap processing
try:
    from scapy.all import rdpcap, Dot11, Dot11Elt, EAPOL
    from scapy.utils import wrpcap
    SCAPY_AVAILABLE = True
except ImportError as e:
    print(f"Scapy import error: {e}")
    SCAPY_AVAILABLE = False

# --- Configuration ---
PWNAGOTCHI_LOG_FILE = "/tmp/pwnagotchi_payload.log"
PWNAGOTCHI_PCAP_DIR = "/root/Raspyjack/loot/pwnagotchi_pcaps/"
PWNAGOTCHI_HANDSHAKE_DIR = "/root/Raspyjack/loot/handshakes/" # Where verified handshakes will go

# --- Logging ---
def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[{timestamp}] [PWNAGOTCHI] {message}"
    print(log_msg)
    try:
        with open(PWNAGOTCHI_LOG_FILE, 'a') as f:
            f.write(log_msg + "\n")
    except Exception as e:
        print(f"Error writing to log file: {e}")

# --- Pwnagotchi UI Class ---
class PwnagotchiUI:
    def __init__(self, lcd_display):
        self.lcd = lcd_display
        self.width = self.lcd.width
        self.height = self.lcd.height
        self.image = Image.new("RGB", (self.width, self.height), "BLACK")
        self.draw = ImageDraw.Draw(self.image)
        
        # Fonts (assuming these are available from LCD_1in44 or similar)
        self.font_small = ImageFont.load_default() # Fallback
        try:
            self.font_small = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 10)
            self.font_medium = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 12)
            self.font_large = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 16)
        except:
            log("Could not load DejaVuSansMono fonts, using default.")

        self.face_state = 0 # 0: neutral, 1: happy, 2: sad, 3: pwned
        self.status_message = "Initializing..."
        self.handshakes_count = 0
        self.channel = "N/A"
        self.uptime = 0 # in seconds
        self.last_update_time = time.time()

    def _draw_face(self):
        # Simple Pwnagotchi-like face based on state
        self.draw.rectangle([(self.width - 30, 5), (self.width - 5, 30)], fill="BLACK", outline="WHITE")
        
        if self.face_state == 0: # Neutral
            self.draw.ellipse([(self.width - 25, 10), (self.width - 20, 15)], fill="WHITE") # Left eye
            self.draw.ellipse([(self.width - 15, 10), (self.width - 10, 15)], fill="WHITE") # Right eye
            self.draw.line([(self.width - 20, 20), (self.width - 15, 20)], fill="WHITE", width=1) # Mouth
        elif self.face_state == 1: # Happy
            self.draw.ellipse([(self.width - 25, 10), (self.width - 20, 15)], fill="WHITE")
            self.draw.ellipse([(self.width - 15, 10), (self.width - 10, 15)], fill="WHITE")
            self.draw.arc([(self.width - 20, 15), (self.width - 15, 25)], 0, 180, fill="WHITE", width=1) # Smile
        elif self.face_state == 2: # Sad
            self.draw.ellipse([(self.width - 25, 10), (self.width - 20, 15)], fill="WHITE")
            self.draw.ellipse([(self.width - 15, 10), (self.width - 10, 15)], fill="WHITE")
            self.draw.arc([(self.width - 20, 15), (self.width - 15, 25)], 180, 360, fill="WHITE", width=1) # Frown
        elif self.face_state == 3: # Pwned (eyes closed, big smile)
            self.draw.line([(self.width - 25, 12), (self.width - 20, 12)], fill="WHITE", width=1)
            self.draw.line([(self.width - 15, 12), (self.width - 10, 12)], fill="WHITE", width=1)
            self.draw.arc([(self.width - 22, 18), (self.width - 13, 28)], 0, 180, fill="WHITE", width=2) # Big smile

    def update_display(self):
        self.draw.rectangle((0, 0, self.width, self.height), fill="BLACK") # Clear screen
        
        # Draw Pwnagotchi title
        self.draw.text((5, 5), "Pwnagotchi", fill="WHITE", font=self.font_large)
        
        # Draw face
        self._draw_face()

        # Display status
        self.draw.text((5, 30), f"Status: {self.status_message}", fill="WHITE", font=self.font_small)
        self.draw.text((5, 45), f"Handshakes: {self.handshakes_count}", fill="WHITE", font=self.font_small)
        self.draw.text((5, 60), f"Channel: {self.channel}", fill="WHITE", font=self.font_small)
        
        # Update uptime
        current_time = time.time()
        self.uptime += (current_time - self.last_update_time)
        self.last_update_time = current_time
        
        hours, remainder = divmod(int(self.uptime), 3600)
        minutes, seconds = divmod(remainder, 60)
        self.draw.text((5, 75), f"Uptime: {hours:02d}:{minutes:02d}:{seconds:02d}", fill="WHITE", font=self.font_small)

        self.lcd.LCD_ShowImage(self.image)

# --- Pwnagotchi Payload Class ---
class PwnagotchiPayload:
    def __init__(self):
        self.lcd = None
        self.ui = None
        self.monitor_interface = None
        self.bettercap_process = None
        self.running = False
        self.handshakes_captured = 0
        self.current_channel = "N/A"
        
        os.makedirs(PWNAGOTCHI_PCAP_DIR, exist_ok=True)
        os.makedirs(PWNAGOTCHI_HANDSHAKE_DIR, exist_ok=True)

    def _check_bettercap(self):
        log("Checking for bettercap installation...")
        try:
            subprocess.run(['which', 'bettercap'], check=True, capture_output=True)
            log("bettercap found.")
            return True
        except subprocess.CalledProcessError:
            log("bettercap not found. Please install bettercap to use this payload.")
            return False
        except FileNotFoundError:
            log("bettercap command not found. Please install bettercap to use this payload.")
            return False

    def _init_lcd(self):
        if not LCD_AVAILABLE:
            log("LCD modules not available. Running headless.")
            return False
        
        log("Initializing LCD...")
        try:
            LCD_Config.GPIO_Init()
            self.lcd = LCD_1in44.LCD()
            self.lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
            self.lcd.LCD_Clear()
            self.ui = PwnagotchiUI(self.lcd)
            log("LCD initialized successfully.")
            return True
        except Exception as e:
            log(f"Failed to initialize LCD: {e}")
            return False

    def _cleanup(self):
        log("Cleaning up Pwnagotchi payload...")
        self.running = False
        
        if self.bettercap_process:
            log("Terminating bettercap process...")
            self.bettercap_process.terminate()
            try:
                self.bettercap_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                log("bettercap did not terminate, killing...")
                self.bettercap_process.kill()
            self.bettercap_process = None

        if self.monitor_interface:
            log(f"Deactivating monitor mode on {self.monitor_interface}...")
            try:
                monitor_mode_helper.deactivate_monitor_mode(self.monitor_interface)
            except Exception as e:
                log(f"Error deactivating monitor mode: {e}")
            self.monitor_interface = None

        if self.lcd:
            log("Clearing LCD and cleaning up GPIO...")
            try:
                self.lcd.LCD_Clear()
                GPIO.cleanup()
            except Exception as e:
                log(f"Error during LCD cleanup: {e}")
            self.lcd = None
            self.ui = None
        
        log("Cleanup complete.")

    def _start_bettercap(self):
        log(f"Starting bettercap on {self.monitor_interface}...")
        
        # Create a temporary caplet for basic sniffing and handshake saving
        # bettercap will save handshakes to a .pcap file in the current directory
        # We'll then move/process these files.
        caplet_content = f"""
        set events.stream.output off
        set ui.update.interval 1s
        set wifi.show.uptime true
        set wifi.recon.channel hop
        set wifi.recon.channels 1,6,11
        set wifi.recon.interval 5s
        set wifi.handshakes.file {PWNAGOTCHI_PCAP_DIR}/bettercap_handshakes.pcap # bettercap saves to this file
        wifi.recon on
        wifi.handshakes on
        """
        caplet_path = "/tmp/pwnagotchi.cap"
        try:
            with open(caplet_path, "w") as f:
                f.write(caplet_content)
            log(f"Created temporary bettercap caplet at {caplet_path}")
        except Exception as e:
            log(f"Failed to create bettercap caplet: {e}")
            return False

        try:
            # Start bettercap with the caplet in a non-interactive way
            self.bettercap_process = subprocess.Popen(
                ['bettercap', '-iface', self.monitor_interface, '-caplet', caplet_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1, # Line-buffered output
                universal_newlines=True
            )
            log(f"bettercap started with PID {self.bettercap_process.pid}")
            
            # Start a thread to read bettercap's output
            threading.Thread(target=self._read_bettercap_output, daemon=True).start()
            
            return True
        except FileNotFoundError:
            log("bettercap command not found. Please ensure it's installed and in your PATH.")
            return False
        except Exception as e:
            log(f"Failed to start bettercap: {e}")
            return False

    def _read_bettercap_output(self):
        log("Starting bettercap output reader thread...")
        try:
            for line in iter(self.bettercap_process.stdout.readline, ''):
                if not self.running: # Exit thread if payload is stopping
                    break
                log(f"[BETTERCAP] {line.strip()}")
                # Parse bettercap output for handshakes, channel changes, etc.
                if "full handshake captured" in line or "PMKID captured" in line:
                    self.handshakes_captured += 1
                    if self.ui:
                        self.ui.face_state = 3 # Pwned face
                        self.ui.status_message = "Handshake!"
                    log(f"Handshake detected! Total: {self.handshakes_captured}")
                elif "hopping on channel" in line:
                    match = re.search(r'hopping on channel (\d+)', line)
                    if match:
                        self.current_channel = match.group(1)
                        if self.ui:
                            self.ui.channel = self.current_channel
                            self.ui.face_state = 0 # Neutral face
                
                # Update UI status based on bettercap output
                if "wifi.recon.started" in line and self.ui:
                    self.ui.status_message = "Reconnaissance"
                elif "wifi.client.new" in line and self.ui:
                    self.ui.face_state = 1 # Happy face for new client
                elif "wifi.ap.new" in line and self.ui:
                    self.ui.face_state = 0 # Neutral for new AP
        except Exception as e:
            log(f"Error reading bettercap output: {e}")
        finally:
            log("Bettercap output reader thread finished.")

    def _process_pcap_files(self):
        if not SCAPY_AVAILABLE:
            log("Scapy not available, cannot process pcap files.")
            return

        source_pcap = os.path.join(PWNAGOTCHI_PCAP_DIR, "bettercap_handshakes.pcap")
        if not os.path.exists(source_pcap) or os.path.getsize(source_pcap) == 0:
            return

        # Move the source file to a temporary location for processing.
        # This is an atomic operation and prevents reprocessing.
        processing_pcap = os.path.join(PWNAGOTCHI_PCAP_DIR, f"processing_{int(time.time())}.pcap")
        try:
            os.rename(source_pcap, processing_pcap)
            log(f"Moved {source_pcap} to {processing_pcap} for processing.")
        except Exception as e:
            log(f"Error renaming pcap file for processing: {e}")
            return

        try:
            log(f"Scanning {processing_pcap} for EAPOL packets...")
            packets = rdpcap(processing_pcap)
            
            handshake_packets = []
            for packet in packets:
                if packet.haslayer(EAPOL):
                    handshake_packets.append(packet)
            
            if handshake_packets:
                count = len(handshake_packets)
                log(f"Found {count} EAPOL packets.")
                
                # Save the verified handshake packets to a new, permanent file
                final_pcap_name = f"handshake_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
                final_pcap_path = os.path.join(PWNAGOTCHI_HANDSHAKE_DIR, final_pcap_name)
                
                wrpcap(final_pcap_path, handshake_packets)

                log(f"Saved {count} handshake packets to {final_pcap_path}")
                self.handshakes_captured += 1 # Increment by 1 for each file with handshakes, not each packet
                if self.ui:
                    self.ui.face_state = 3 # Pwned face
                    self.ui.status_message = "Handshake saved!"
            else:
                log("No new EAPOL packets found in this batch.")

        except Exception as e:
            log(f"Error processing pcap file {processing_pcap}: {e}")
        finally:
            # Clean up the processed file
            try:
                log(f"Deleting processed file: {processing_pcap}")
                os.remove(processing_pcap)
            except Exception as e:
                log(f"Error deleting processed file {processing_pcap}: {e}")

    def run(self):
        if not self._check_bettercap():
            if self.ui:
                self.ui.status_message = "bettercap missing!"
                self.ui.face_state = 2 # Sad face
                self.ui.update_display()
            log("bettercap not found. Exiting Pwnagotchi payload.")
            self._cleanup()
            return

        if not SCAPY_AVAILABLE:
            if self.ui:
                self.ui.status_message = "Scapy missing!"
                self.ui.face_state = 2 # Sad face
                self.ui.update_display()
            log("Scapy not found. Exiting Pwnagotchi payload.")
            self._cleanup()
            return

        if not self._init_lcd():
            log("Could not initialize LCD. Running headless is not fully supported for Pwnagotchi UI.")
            # Decide if we want to continue headless or exit
            self.ui = PwnagotchiUI(None) # Create a dummy UI to avoid errors, but it won't display
            # For now, let's exit if LCD is critical for Pwnagotchi experience
            log("Exiting Pwnagotchi payload due to LCD failure.")
            self._cleanup()
            return

        self.ui.status_message = "Activating monitor mode..."
        self.ui.update_display()

        # Find and activate monitor mode
        # We need to iterate through available interfaces and try to activate monitor mode
        # The monitor_mode_helper.activate_monitor_mode already handles the onboard WiFi check
        
        # First, detect available WiFi interfaces using wifi_manager's logic
        # We need to import wifi_manager or replicate its interface detection
        # For simplicity, let's assume monitor_mode_helper can take any interface and try
        
        # Let's try to get a list of interfaces from /sys/class/net
        potential_interfaces = []
        try:
            for iface in os.listdir("/sys/class/net"):
                wireless_path = f"/sys/class/net/{iface}/wireless"
                if os.path.exists(wireless_path):
                    potential_interfaces.append(iface)
            # Prioritize wlan1 over wlan0
            potential_interfaces.sort(key=lambda x: (x != 'wlan1', x != 'wlan0', x))
        except Exception as e:
            log(f"Error detecting potential interfaces: {e}")
        
        if not potential_interfaces:
            self.ui.status_message = "No WiFi interfaces!"
            self.ui.face_state = 2 # Sad face
            self.ui.update_display()
            log("No WiFi interfaces detected. Exiting.")
            self._cleanup()
            return

        for iface in potential_interfaces:
            log(f"Attempting monitor mode on {iface}...")
            self.monitor_interface = monitor_mode_helper.activate_monitor_mode(iface)
            if self.monitor_interface:
                log(f"Monitor mode activated on {self.monitor_interface}")
                self.ui.status_message = f"Monitor: {self.monitor_interface}"
                self.ui.face_state = 0 # Neutral face
                self.ui.update_display()
                break
            else:
                log(f"Failed to activate monitor mode on {iface}")
        
        if not self.monitor_interface:
            self.ui.status_message = "Monitor mode failed!"
            self.ui.face_state = 2 # Sad face
            self.ui.update_display()
            log("Failed to activate monitor mode on any interface. Exiting.")
            self._cleanup()
            return

        if not self._start_bettercap():
            self.ui.status_message = "bettercap failed!"
            self.ui.face_state = 2 # Sad face
            self.ui.update_display()
            log("Failed to start bettercap. Exiting.")
            self._cleanup()
            return

        self.running = True
        self.ui.status_message = "Pwnagotchi running!"
        self.ui.update_display()

        # Main loop
        try:
            last_pcap_process_time = time.time()
            while self.running:
                # Check for exit condition (e.g., button press)
                # For now, just a simple sleep and check
                time.sleep(0.5) # Update UI more frequently
                
                # Update UI
                self.ui.handshakes_count = self.handshakes_captured
                self.ui.update_display()
                
                # --- DIAGNOSTIC: Temporarily disable pcap processing to isolate crash ---
                # if time.time() - last_pcap_process_time > 10: # Every 10 seconds
                #     self._process_pcap_files()
                #     last_pcap_process_time = time.time()

        except KeyboardInterrupt:
            log("KeyboardInterrupt detected.")
        finally:
            self._cleanup()

if __name__ == "__main__":
    payload = PwnagotchiPayload()
    payload.run()

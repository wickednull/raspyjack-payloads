#!/usr/bin/env python3
"""
RaspyJack Payload: Wifite GUI
=============================
A graphical wrapper for Wifite to simplify wireless auditing on the RaspyJack.
"""

import os
import sys
import time
import signal
import subprocess
from threading import Thread

# Ensure local Raspyjack modules can be imported
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

try:
    import RPi.GPIO as GPIO
    import LCD_1in44
    import LCD_Config
    from PIL import Image, ImageDraw, ImageFont
    HARDWARE_AVAILABLE = True
except ImportError:
    print("Warning: Hardware modules not found. Using mock objects for testing.")
    HARDWARE_AVAILABLE = False

# --- Mock objects for testing on a non-Pi environment ---
if not HARDWARE_AVAILABLE:
    class MockGPIO:
        BCM = 0
        IN = 0
        PUD_UP = 0
        LOW = 0
        def setmode(self, *args): pass
        def setup(self, *args, **kwargs): pass
        def input(self, *args): return 1
        def cleanup(self): print("GPIO cleanup called.")
    GPIO = MockGPIO()

    class MockLCD:
        width = 128
        height = 128
        def LCD_Init(self, *args): pass
        def LCD_ShowImage(self, *args): pass
        def LCD_Clear(self): pass
    LCD_1in44 = type("LCD_1in44", (), {"LCD": MockLCD, "SCAN_DIR_DFT": 0})()

    class MockImage:
        def new(self, *args, **kwargs): return self
        def paste(self, *args): pass
    Image = MockImage()
    ImageDraw = type("ImageDraw", (), {"Draw": lambda *args: None})()
    ImageFont = type("ImageFont", (), {"load_default": lambda: None, "truetype": lambda *args: None})()


class Network:
    """A simple class to hold network information."""
    def __init__(self, bssid, essid, channel, power, encryption):
        self.bssid = bssid
        self.essid = essid if essid else "Hidden Network"
        self.channel = channel
        self.power = power
        self.encryption = encryption

    def __repr__(self):
        return f"{self.essid} ({self.encryption}) - {self.power}dBm"

class WifiteGUI:
    def __init__(self):
        # --- Pin Definitions ---
        self.PINS = {
            "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "SELECT": 13,
            "KEY1": 21, "KEY2": 20, "KEY3": 16,
        }

        # --- GPIO Setup ---
        GPIO.setmode(GPIO.BCM)
        for pin in self.PINS.values():
            GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

        # --- LCD Setup ---
        self.LCD = LCD_1in44.LCD()
        self.LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
        self.image = Image.new("RGB", (self.LCD.width, self.LCD.height), "BLACK")
        self.draw = ImageDraw.Draw(self.image)
        try:
            self.font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 14)
            self.small_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 11)
        except IOError:
            self.font = ImageFont.load_default()
            self.small_font = ImageFont.load_default()

        # --- State Management ---
        self.running = True
        self.state = "menu"
        self.menu_selection = 0
        self.networks = []
        self.scan_process = None
        self.scan_thread = None
        self.status_message = ""
        self.target_scroll_offset = 0
        self.attack_process = None
        self.attack_thread = None
        self.attack_target = None
        self.cracked_password = None
        self.config = {
            "interface": "wlan1mon",
            "attack_wpa": True,
            "attack_wps": True,
            "attack_pmkid": True,
            "power": 50,
            "channel": None, # None means all channels
            "clients_only": False
        }

    def _draw_text(self, text, xy, font=None, fill="WHITE"):
        font = font or self.font
        self.draw.text(xy, text, font=font, fill=fill)

    def _update_display(self):
        self.LCD.LCD_ShowImage(self.image)

    def _clear_screen(self):
        self.draw.rectangle([(0, 0), (self.LCD.width, self.LCD.height)], fill="BLACK")

    def _get_pressed_button(self):
        """Checks for a button press and returns its name."""
        for name, pin in self.PINS.items():
            if GPIO.input(pin) == GPIO.LOW:
                time.sleep(0.1)
                if GPIO.input(pin) == GPIO.LOW:
                    return name
        return None

    def stop(self):
        """Stops the main loop."""
        self.running = False

    def get_interfaces(self):
        """Gets a list of wireless network interfaces."""
        try:
            all_ifaces = os.listdir('/sys/class/net/')
            wireless_ifaces = [i for i in all_ifaces if i.startswith(('wlan', 'ath', 'ra'))]
            return wireless_ifaces if wireless_ifaces else ["wlan1mon"]
        except FileNotFoundError:
            return ["wlan1mon"]

    def run(self):
        """Main application loop."""
        while self.running:
            button = self._get_pressed_button()

            if button == "KEY3":
                self.stop()
                continue

            self._clear_screen()

            if self.state == "menu":
                self.render_menu()
                if button == "SELECT":
                    if self.menu_selection == 0: self.state = "scanning"; self.start_scan()
                    elif self.menu_selection == 1: self.state = "settings"; self.menu_selection = 0
                    elif self.menu_selection == 2: self.stop()
                elif button == "UP": self.menu_selection = (self.menu_selection - 1) % 3
                elif button == "DOWN": self.menu_selection = (self.menu_selection + 1) % 3

            elif self.state == "settings":
                self.render_settings()
                if button == "SELECT":
                    if self.menu_selection == 0: self.state = "select_interface"; self.menu_selection = 0
                    elif self.menu_selection == 1: self.state = "select_attack_types"; self.menu_selection = 0
                    elif self.menu_selection == 2: self.state = "advanced_settings"; self.menu_selection = 0
                elif button == "UP": self.menu_selection = (self.menu_selection - 1) % 3
                elif button == "DOWN": self.menu_selection = (self.menu_selection + 1) % 3
                elif button == "LEFT": self.state = "menu"; self.menu_selection = 0

            elif self.state == "advanced_settings":
                self.render_advanced_settings()
                if button == "SELECT":
                    if self.menu_selection == 0: self.state = "select_power"
                    elif self.menu_selection == 1: self.state = "select_channel"
                    elif self.menu_selection == 2: self.config["clients_only"] = not self.config["clients_only"]
                elif button == "UP": self.menu_selection = (self.menu_selection - 1) % 3
                elif button == "DOWN": self.menu_selection = (self.menu_selection + 1) % 3
                elif button == "LEFT": self.state = "settings"; self.menu_selection = 0

            elif self.state == "select_interface":
                self.render_select_interface()
                interfaces = self.get_interfaces()
                if button == "UP": self.menu_selection = (self.menu_selection - 1) % len(interfaces)
                elif button == "DOWN": self.menu_selection = (self.menu_selection + 1) % len(interfaces)
                elif button == "SELECT": self.config["interface"] = interfaces[self.menu_selection]; self.state = "settings"; self.menu_selection = 0
                elif button == "LEFT": self.state = "settings"; self.menu_selection = 0

            elif self.state == "select_attack_types":
                self.render_select_attack_types()
                attack_keys = ["attack_wpa", "attack_wps", "attack_pmkid"]
                if button == "UP": self.menu_selection = (self.menu_selection - 1) % len(attack_keys)
                elif button == "DOWN": self.menu_selection = (self.menu_selection + 1) % len(attack_keys)
                elif button == "SELECT": self.config[attack_keys[self.menu_selection]] = not self.config[attack_keys[self.menu_selection]]
                elif button == "LEFT": self.state = "settings"; self.menu_selection = 0

            elif self.state == "select_power":
                self.render_select_power()
                if button == "UP": self.config["power"] = min(100, self.config["power"] + 5)
                elif button == "DOWN": self.config["power"] = max(0, self.config["power"] - 5)
                elif button == "LEFT": self.state = "advanced_settings"

            elif self.state == "select_channel":
                self.render_select_channel()
                if button == "UP":
                    if self.config["channel"] is None: self.config["channel"] = 1
                    else: self.config["channel"] = min(14, self.config["channel"] + 1)
                elif button == "DOWN":
                    if self.config["channel"] is None: self.config["channel"] = 14
                    else: self.config["channel"] = max(1, self.config["channel"] - 1)
                elif button == "SELECT": self.config["channel"] = None
                elif button == "LEFT": self.state = "advanced_settings"

            elif self.state == "scanning":
                self.render_scanning()
                if button == "LEFT": self.scan_process.terminate(); self.state = "menu"

            elif self.state == "targets":
                self.render_targets()
                if button == "UP": self.menu_selection = max(0, self.menu_selection - 1)
                elif button == "DOWN": self.menu_selection = min(len(self.networks) - 1, self.menu_selection + 1)
                elif button == "SELECT":
                    if self.networks: self.start_attack(self.networks[self.menu_selection])
                elif button == "LEFT": self.state = "menu"

            elif self.state == "attacking":
                self.render_attacking()
                if button == "LEFT": self.attack_process.terminate(); self.state = "targets"

            elif self.state == "results":
                self.render_results()
                if button: self.state = "menu"

            self._update_display()
            if button:
                while self._get_pressed_button() is not None: time.sleep(0.05)
            time.sleep(0.05)

    def render_menu(self):
        self._draw_text("Wifite GUI", (28, 10)); self.draw.line([(10, 30), (118, 30)], fill="#333", width=1)
        options = ["Start Scan", "Settings", "Exit"]
        for i, option in enumerate(options):
            fill = "WHITE"; y_pos = 40 + i * 25
            if i == self.menu_selection: self.draw.rectangle([(5, y_pos - 2), (123, y_pos + 15)], fill="#003366"); fill = "#FFFF00"
            self._draw_text(option, (20, y_pos), fill=fill)

    def render_settings(self):
        self._draw_text("Settings", (35, 10)); self.draw.line([(10, 30), (118, 30)], fill="#333", width=1)
        options = ["Interface", "Attack Types", "Advanced"]
        for i, option in enumerate(options):
            fill = "WHITE"; y_pos = 40 + i * 25
            if i == self.menu_selection: self.draw.rectangle([(5, y_pos - 2), (123, y_pos + 15)], fill="#003366"); fill = "#FFFF00"
            value = f": {self.config['interface']}" if i == 0 else ""
            self._draw_text(f"{option}{value}", (10, y_pos), font=self.small_font, fill=fill)
        self._draw_text("LEFT for Back", (20, 110), font=self.small_font, fill="#888")

    def render_advanced_settings(self):
        self._draw_text("Advanced Settings", (10, 10)); self.draw.line([(10, 30), (118, 30)], fill="#333", width=1)
        options = ["Power", "Channel", "Clients Only"]
        for i, option in enumerate(options):
            fill = "WHITE"; y_pos = 40 + i * 25
            if i == self.menu_selection: self.draw.rectangle([(5, y_pos - 2), (123, y_pos + 15)], fill="#003366"); fill = "#FFFF00"
            if i == 0: value = f": {self.config['power']}"
            elif i == 1: value = f": {self.config['channel'] or 'All'}"
            else: value = f": {'On' if self.config['clients_only'] else 'Off'}"
            self._draw_text(f"{option}{value}", (10, y_pos), font=self.small_font, fill=fill)
        self._draw_text("LEFT for Back", (20, 110), font=self.small_font, fill="#888")

    def render_select_interface(self):
        self._draw_text("Select Interface", (15, 10)); self.draw.line([(10, 30), (118, 30)], fill="#333", width=1)
        interfaces = self.get_interfaces()
        for i, iface in enumerate(interfaces):
            fill = "WHITE"; y_pos = 40 + i * 25
            if i == self.menu_selection: self.draw.rectangle([(5, y_pos - 2), (123, y_pos + 15)], fill="#003366"); fill = "#FFFF00"
            self._draw_text(iface, (20, y_pos), fill=fill)
        self._draw_text("LEFT for Back", (20, 110), font=self.small_font, fill="#888")

    def render_select_attack_types(self):
        self._draw_text("Attack Types", (25, 10)); self.draw.line([(10, 30), (118, 30)], fill="#333", width=1)
        options = {"attack_wpa": "WPA (Handshake)", "attack_wps": "WPS (PIN Attack)", "attack_pmkid": "PMKID Attack"}
        for i, key in enumerate(options):
            fill = "WHITE"; y_pos = 40 + i * 25
            if i == self.menu_selection: self.draw.rectangle([(5, y_pos - 2), (123, y_pos + 15)], fill="#003366"); fill = "#FFFF00"
            status = "[x]" if self.config[key] else "[ ]"
            self._draw_text(f"{status} {options[key]}", (10, y_pos), font=self.small_font, fill=fill)
        self._draw_text("LEFT for Back", (20, 110), font=self.small_font, fill="#888")

    def render_select_power(self):
        self._draw_text("Set Power", (30, 10)); self.draw.line([(10, 30), (118, 30)], fill="#333", width=1)
        self._draw_text(f"{self.config['power']}", (50, 50), font=self.font)
        self._draw_text("Up/Down to change", (10, 80), font=self.small_font)
        self._draw_text("LEFT for Back", (20, 110), font=self.small_font, fill="#888")

    def render_select_channel(self):
        self._draw_text("Set Channel", (25, 10)); self.draw.line([(10, 30), (118, 30)], fill="#333", width=1)
        self._draw_text(f"{self.config['channel'] or 'All'}", (50, 50), font=self.font)
        self._draw_text("Up/Down to change", (10, 80), font=self.small_font)
        self._draw_text("Select for 'All'", (20, 95), font=self.small_font)
        self._draw_text("LEFT for Back", (20, 110), font=self.small_font, fill="#888")

    def render_scanning(self):
        self._draw_text("Scanning...", (25, 40))
        if self.status_message: self._draw_text(self.status_message, (10, 60), font=self.small_font, fill="#00FF00")
        else: self._draw_text("Please wait.", (25, 60), font=self.small_font)
        self._draw_text("KEY3=Exit | LEFT=Back", (10, 110), font=self.small_font, fill="#888")

    def render_targets(self):
        self._draw_text("Select Target", (20, 5), font=self.small_font); self.draw.line([(0, 18), (128, 18)], fill="#333", width=1)
        if not self.networks: self._draw_text("No networks found.", (10, 50)); return
        visible_items = 6
        if self.menu_selection < self.target_scroll_offset: self.target_scroll_offset = self.menu_selection
        if self.menu_selection >= self.target_scroll_offset + visible_items: self.target_scroll_offset = self.menu_selection - visible_items + 1
        for i in range(self.target_scroll_offset, self.target_scroll_offset + visible_items):
            if i >= len(self.networks): break
            network = self.networks[i]; display_y = 25 + (i - self.target_scroll_offset) * 16; fill = "WHITE"
            if i == self.menu_selection: self.draw.rectangle([(0, display_y - 2), (128, display_y + 13)], fill="#003366"); fill = "#FFFF00"
            self._draw_text(f"{network.essid[:14]}", (5, display_y), font=self.small_font, fill=fill)
            self._draw_text(f"{network.power}dBm", (90, display_y), font=self.small_font, fill=fill)

    def render_attacking(self):
        if not self.attack_target: return
        self._draw_text("Attacking:", (5, 5), font=self.small_font)
        self._draw_text(self.attack_target.essid[:18], (5, 20), fill="#FF0000"); self.draw.line([(0, 38), (128, 38)], fill="#333", width=1)
        if self.status_message: self._draw_text(self.status_message, (5, 45), font=self.small_font, fill="#00FF00")
        self._draw_text("KEY3=Exit | LEFT=Back", (10, 110), font=self.small_font, fill="#888")

    def render_results(self):
        self._draw_text("Result", (40, 10)); self.draw.line([(10, 30), (118, 30)], fill="#333", width=1)
        if self.cracked_password:
            self._draw_text("Success!", (35, 40), fill="#00FF00")
            self._draw_text("Password:", (5, 60), font=self.small_font)
            self._draw_text(self.cracked_password, (5, 75), font=self.font, fill="#00FF00")
        else:
            self._draw_text("Failed", (40, 40), fill="#FF0000")
            self._draw_text("Could not crack network.", (5, 60), font=self.small_font)
        self._draw_text("Press any key...", (15, 110), font=self.small_font, fill="#888")

    def start_scan(self):
        self.status_message = "Starting wifite..."; self.networks = []; self.menu_selection = 0; self.target_scroll_offset = 0
        cmd = ["wifite", "--csv", "-i", self.config['interface'], '--power', str(self.config['power'])]
        if not self.config['attack_wps']: cmd.append('--no-wps')
        if not self.config['attack_wpa']: cmd.append('--no-wpa')
        if not self.config['attack_pmkid']: cmd.append('--no-pmkid')
        if self.config['channel']: cmd.extend(['-c', str(self.config['channel'])])
        if self.config['clients_only']: cmd.append('--clients-only')
        def scan_worker():
            try:
                self.scan_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                self.status_message = "Wifite process started."
                header = False
                for line in iter(self.scan_process.stdout.readline, ''):
                    if not self.running or self.state != "scanning": break
                    if not header and "BSSID,ESSID" in line: header = True; self.status_message = "Parsing targets..."; continue
                    if header:
                        try:
                            parts = line.strip().split(','); bssid, essid, channel, power, enc = parts[0], parts[1], parts[2], parts[3], parts[4]
                            if not any(n.bssid == bssid for n in self.networks):
                                self.networks.append(Network(bssid, essid, channel, power, enc))
                                self.status_message = f"Found: {len(self.networks)}"
                        except Exception: continue
                self.scan_process.wait()
                if self.state == "scanning": self.status_message = f"Scan finished."; time.sleep(1); self.state = "targets"
            except FileNotFoundError: self.status_message = "Error: wifite not found!"; time.sleep(2); self.state = "menu"
            except Exception as e: self.status_message = f"Error: {str(e)[:20]}"; time.sleep(2); self.state = "menu"
        self.scan_thread = Thread(target=scan_worker, daemon=True); self.scan_thread.start()

    def start_attack(self, network):
        self.state = "attacking"; self.attack_target = network; self.cracked_password = None; self.status_message = "Initializing attack..."
        cmd = ["wifite", "--bssid", network.bssid, "-i", self.config['interface']]
        if not self.config['attack_wps']: cmd.append('--no-wps')
        if not self.config['attack_wpa']: cmd.append('--no-wpa')
        if not self.config['attack_pmkid']: cmd.append('--no-pmkid')
        if self.config['clients_only']: cmd.append('--clients-only')
        def attack_worker():
            try:
                self.attack_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                for line in iter(self.attack_process.stdout.readline, ''):
                    if not self.running or self.state != "attacking": break
                    line_lower = line.lower()
                    if "wps pin attack" in line_lower: self.status_message = "WPS PIN Attack..."
                    elif "wpa handshake" in line_lower: self.status_message = "WPA Handshake Capture..."
                    elif "pmkid attack" in line_lower: self.status_message = "PMKID Attack..."
                    elif "cracked" in line_lower:
                        try: self.cracked_password = line.split('"')[1]
                        except IndexError: self.cracked_password = "See logs"
                        break
                    elif "failed" in line_lower: self.status_message = "Attack failed."
                self.attack_process.wait()
                if self.state == "attacking": self.state = "results"
            except Exception as e: self.status_message = f"Attack Error: {str(e)[:20]}"; time.sleep(2); self.state = "targets"
        self.attack_thread = Thread(target=attack_worker, daemon=True); self.attack_thread.start()

if __name__ == "__main__":
    gui = None
    running = True
    def cleanup_handler(signum, frame):
        global running
        print(f"Signal {signum} received. Shutting down.")
        running = False
        if gui: gui.stop()
    signal.signal(signal.SIGINT, cleanup_handler)
    signal.signal(signal.SIGTERM, cleanup_handler)
    try:
        gui = WifiteGUI()
        while running and gui.running:
            gui.run()
            running = gui.running
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        with open("/tmp/wifite_gui_error.log", "w") as f: f.write(str(e))
    finally:
        print("Cleaning up GPIO...")
        if HARDWARE_AVAILABLE:
            try: gui.LCD.LCD_Clear()
            except: pass
            GPIO.cleanup()
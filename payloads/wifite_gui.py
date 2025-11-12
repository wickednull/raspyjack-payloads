#!/usr/bin/env python3
"""
RaspyJack Payload: Wifite GUI
=============================
A graphical wrapper for Wifite to simplify wireless auditing on the RaspyJack.
"""

# ---------------------------------------------------------------------------
# 0) Make sure we can import local helper modules when launched directly
# ---------------------------------------------------------------------------
import os, sys
# This line is required for the payload to find the Raspyjack libraries.
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

# ---------------------------- Standard library ----------------------------
import time
import signal
import subprocess
from threading import Thread

# ----------------------------- Third‑party libs ---------------------------
try:
    import RPi.GPIO as GPIO
    import LCD_Config
    import LCD_1in44
    from PIL import Image, ImageDraw, ImageFont
    HARDWARE_AVAILABLE = True
except ImportError:
    print("FATAL: Hardware libraries not found.", file=sys.stderr)
    HARDWARE_AVAILABLE = False

# ============================================================================
# --- Global Variables & State Management ---
# ============================================================================

# Hardware objects
PINS = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "SELECT": 13, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}
LCD, IMAGE, DRAW, FONT, SMALL_FONT = None, None, None, None, None

# Global state machine
APP_STATE = "menu"
IS_RUNNING = True

# UI and data state
MENU_SELECTION = 0
STATUS_MESSAGE = ""

# ============================================================================
# --- Core Hardware & Drawing Functions ---
# ============================================================================

def init_hardware():
    """Initializes all hardware components."""
    global LCD, IMAGE, DRAW, FONT, SMALL_FONT
    if not HARDWARE_AVAILABLE: return
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    
    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    IMAGE = Image.new("RGB", (LCD.width, LCD.height), "BLACK")
    DRAW = ImageDraw.Draw(IMAGE)
    try:
        FONT = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 14)
        SMALL_FONT = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 11)
    except IOError:
        FONT = ImageFont.load_default()
        SMALL_FONT = ImageFont.load_default()
    LCD.LCD_Clear()

def get_pressed_button():
    """Checks for a button press and returns its name, with debouncing."""
    if not HARDWARE_AVAILABLE: return None
    for name, pin in PINS.items():
        if GPIO.input(pin) == GPIO.LOW:
            time.sleep(0.05)
            if GPIO.input(pin) == GPIO.LOW:
                return name
    return None

def update_display():
    """Pushes the virtual canvas to the actual LCD screen."""
    if LCD: LCD.LCD_ShowImage(IMAGE)

def clear_screen():
    """Wipes the virtual canvas clear."""
    if DRAW: DRAW.rectangle([(0, 0), (128, 128)], fill="BLACK")

# ============================================================================
# --- UI Rendering Functions ---
# ============================================================================

def render_ui():
    """Calls the appropriate rendering function based on the global APP_STATE."""
    clear_screen()
    if APP_STATE == "menu":
        DRAW.text((28, 10), "Wifite GUI", font=FONT, fill="WHITE")
        DRAW.line([(10, 30), (118, 30)], fill="#333", width=1)
        # For now, only two options. Settings will be added next.
        options = ["Start Scan", "Exit"]
        for i, option in enumerate(options):
            fill = "WHITE"; y_pos = 40 + i * 25
            if i == MENU_SELECTION:
                DRAW.rectangle([(5, y_pos - 2), (123, y_pos + 15)], fill="#003366")
                fill = "#FFFF00"
            DRAW.text((20, y_pos), option, font=FONT, fill=fill)

    elif APP_STATE == "scanning": # Placeholder screen
        DRAW.text((25, 40), "Scanning...", font=FONT, fill="WHITE")
        DRAW.text("(Not Implemented)", font=SMALL_FONT, fill="YELLOW")
        DRAW.text("Press LEFT to go back", (10, 110), font=SMALL_FONT, fill="#888")

    update_display()

# ============================================================================
# --- Main Application Controller ---
# ============================================================================

def handle_input(button):
    """Updates the application state based on button presses."""
    global IS_RUNNING, APP_STATE, MENU_SELECTION

    if button is None:
        return

    if APP_STATE == "menu":
        if button == "SELECT":
            if MENU_SELECTION == 0: # Start Scan
                APP_STATE = "scanning" 
            elif MENU_SELECTION == 1: # Exit
                IS_RUNNING = False
        elif button == "UP": MENU_SELECTION = (MENU_SELECTION - 1) % 2
        elif button == "DOWN": MENU_SELECTION = (MENU_SELECTION + 1) % 2
    
    elif APP_STATE == "scanning":
        if button == "LEFT":
            APP_STATE = "menu"

def main():
    """The main entry point and state machine loop of the application."""
    global IS_RUNNING
    
    init_hardware()

    while IS_RUNNING:
        button = get_pressed_button()
        
        # Global exit key
        if button == "KEY3":
            IS_RUNNING = False
            continue
        
        handle_input(button)
        render_ui()

        if button:
            while get_pressed_button() is not None: time.sleep(0.05)
        time.sleep(0.05)

# ============================================================================
# --- Payload Execution Entry Point ---
# ============================================================================

if __name__ == "__main__":
    def cleanup_handler(signum, frame):
        global IS_RUNNING
        print(f"Signal {signum} received. Shutting down.")
        IS_RUNNING = False
    
    signal.signal(signal.SIGINT, cleanup_handler)
    signal.signal(signal.SIGTERM, cleanup_handler)

    try:
        main()
    except Exception as e:
        # Log any unexpected errors for debugging
        with open("/tmp/wifite_gui_error.log", "w") as f:
            f.write(f"{type(e).__name__}: {e}\n")
            import traceback
            traceback.print_exc(file=f)
    finally:
        # Essential cleanup for returning control to Raspyjack cleanly.
        print("Cleaning up GPIO...")
        if HARDWARE_AVAILABLE:
            try:
                if LCD: LCD.LCD_Clear()
            except:
                pass
            GPIO.cleanup()

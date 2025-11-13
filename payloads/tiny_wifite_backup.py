#!/usr/bin/env python3
"""
RaspyJack payload – tiny_wifite (LCD TTY)
========================================
Run full wifite inside a tiny terminal rendered on the 1.44" LCD, with
RaspyJack buttons mapped to common keys.
- Enables monitor mode before launch (monitor_mode_helper)
- Spawns real wifite connected to a PTY so it behaves normally
- Buttons send keystrokes (Enter, Ctrl+C, arrows, 1/2, etc.) to wifite
- Output is rendered in a small monospace terminal on the LCD (like shell.py)
- Mirrors discovered capture files into loot/TinyWifite

Controls (buttons → keys)
- OK / RIGHT: Enter
- LEFT / KEY3: Ctrl+C (stop)
- UP/DOWN: Arrow Up/Down (navigate lists)
- KEY1: "1"
- KEY2: "2"

Notes
- Requires root, and wifite must be installed.
"""
import os
import sys
import time
import json
import signal
import fcntl
import pty
import tty
import termios
import threading
import shutil
import re
import select

# RaspyJack pathing
BASE_DIR = os.path.dirname(__file__)
sys.path.append(os.path.abspath(os.path.join(BASE_DIR, '..', '..')))
# Prefer installed RaspyJack first
if os.path.isdir('/root/Raspyjack'):
    if '/root/Raspyjack' not in sys.path:
        sys.path.insert(0, '/root/Raspyjack')

# Hardware + LCD
try:
    import RPi.GPIO as GPIO
    import LCD_Config
    import LCD_1in44
    from PIL import Image, ImageDraw, ImageFont
except Exception as e:
    print(f"[ERROR] Hardware libraries not available: {e}", file=sys.stderr)
    sys.exit(1)

# WiFi helpers
try:
    from wifi.raspyjack_integration import get_available_interfaces
    import monitor_mode_helper
    WIFI_OK = True
except Exception:
    WIFI_OK = False

# Pins via gui_conf.json (robust lookup)
PINS = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}

def _find_gui_conf():
    cands = [
        os.path.join(os.getcwd(), 'gui_conf.json'),
        os.path.join('/root/Raspyjack', 'gui_conf.json'),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Raspyjack', 'gui_conf.json'),
    ]
    for sp in list(sys.path):
        try:
            if sp and os.path.basename(sp) == 'Raspyjack':
                cands.append(os.path.join(sp, 'gui_conf.json'))
        except Exception:
            pass
    for p in cands:
        if os.path.exists(p):
            return p
    return None

try:
    cfg = _find_gui_conf()
    if cfg:
        with open(cfg, 'r') as f:
            data = json.load(f)
        mp = data.get('PINS', {})
        PINS = {
            "UP": mp.get("KEY_UP_PIN", PINS["UP"]),
            "DOWN": mp.get("KEY_DOWN_PIN", PINS["DOWN"]),
            "LEFT": mp.get("KEY_LEFT_PIN", PINS["LEFT"]),
            "RIGHT": mp.get("KEY_RIGHT_PIN", PINS["RIGHT"]),
            "OK": mp.get("KEY_PRESS_PIN", PINS["OK"]),
            "KEY1": mp.get("KEY1_PIN", PINS["KEY1"]),
            "KEY2": mp.get("KEY2_PIN", PINS["KEY2"]),
            "KEY3": mp.get("KEY3_PIN", PINS["KEY3"]),
        }
except Exception:
    pass

GPIO.setmode(GPIO.BCM)
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

# LCD + fonts (monospace terminal like shell.py)
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
try:
    FONT_TITLE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
except Exception:
    FONT_TITLE = ImageFont.load_default()
# Terminal appearance (user adjustable)
TERM_FONT_SIZE = 8   # px
TERM_COLOR = "#00FF00"  # default green
FONT_MONO = None
MONO_CHAR_W = MONO_CHAR_H = MONO_COLS = MONO_ROWS = 0

def set_terminal_font(size: int):
    global TERM_FONT_SIZE, FONT_MONO, MONO_CHAR_W, MONO_CHAR_H, MONO_COLS, MONO_ROWS
    TERM_FONT_SIZE = max(4, min(18, int(size)))  # allow very small fonts
    try:
        FONT_MONO = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", TERM_FONT_SIZE)
    except Exception:
        FONT_MONO = ImageFont.load_default()
    _tmp = Image.new("RGB", (10,10)); _d = ImageDraw.Draw(_tmp)
    bbox = _d.textbbox((0,0), "M", font=FONT_MONO)
    MONO_CHAR_W = max(1, bbox[2]-bbox[0])
    MONO_CHAR_H = max(1, bbox[3]-bbox[1])
    MONO_COLS = max(10, (WIDTH - 2) // MONO_CHAR_W)
    MONO_ROWS = max(4, (HEIGHT - 2) // MONO_CHAR_H)

set_terminal_font(TERM_FONT_SIZE)

# Loot
RASPYJACK_ROOT = '/root/Raspyjack' if os.path.isdir('/root/Raspyjack') else os.path.abspath(os.path.join(BASE_DIR, '..', '..'))
LOOT_DIR = os.path.join(RASPYJACK_ROOT, 'loot', 'TinyWifite')
os.makedirs(LOOT_DIR, exist_ok=True)

RUN = True
WIFI_IFACE = None
MON_IFACE = None

# LCD terminal buffer (like shell.py)
scrollback = []  # type: list[str]
current_line = ""

def draw_buffer(lines: list[str], partial: str = ""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    # show last MONO_ROWS-1 lines plus partial
    visible = lines[-(MONO_ROWS-1):] + [partial]
    y = 0
    for line in visible:
        # pad/trim to columns
        d.text((0, y), line.ljust(MONO_COLS)[:MONO_COLS], font=FONT_MONO, fill=TERM_COLOR)
        y += MONO_CHAR_H
    LCD.LCD_ShowImage(img, 0, 0)

def draw_message(lines, color="white"):
    if isinstance(lines, str):
        lines = [lines]
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    y = (HEIGHT - len(lines)*14)//2
    for ln in lines:
        d.text((6, y), ln, font=FONT_TITLE, fill=color)
        y += 14
    LCD.LCD_ShowImage(img, 0, 0)

def wrap_print(s: str):
    global current_line, scrollback
    s = s.rstrip('\n')
    # split into soft-wrapped chunks for LCD terminal
    while len(s) > MONO_COLS:
        scrollback.append(s[:MONO_COLS])
        s = s[MONO_COLS:]
    if s:
        scrollback.append(s)
    # cap scrollback
    if len(scrollback) > 256:
        scrollback = scrollback[-256:]
    draw_buffer(scrollback, "")

# Settings menu (font size & color)
COLORS = ["#00FF00", "white", "cyan", "yellow", "red", "#00FFFF", "#FF00FF"]

def open_settings_menu():
    global TERM_FONT_SIZE, TERM_COLOR, scrollback
    idx = COLORS.index(TERM_COLOR) if TERM_COLOR in COLORS else 0
    last = 0.0
    while True:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ImageDraw.Draw(img)
        d.text((36, 6), "Settings", font=FONT_TITLE, fill="white")
        d.line([(6, 22), (122, 22)], fill="#333", width=1)
        d.text((10, 40), f"Font: {TERM_FONT_SIZE}px", font=FONT_TITLE, fill="white")
        d.text((10, 60), f"Color: {COLORS[idx]}", font=FONT_TITLE, fill=COLORS[idx])
        d.text((8, 100), "UP/DOWN size  LEFT/RIGHT color", font=ImageFont.load_default(), fill="#888")
        d.text((8, 112), "OK=Save  KEY3/LEFT=Back", font=ImageFont.load_default(), fill="#888")
        LCD.LCD_ShowImage(img, 0, 0)
        now = time.time()
        if GPIO.input(PINS['UP']) == 0 and now - last > 0.18:
            last = now; set_terminal_font(TERM_FONT_SIZE + 1); scrollback = []
        elif GPIO.input(PINS['DOWN']) == 0 and now - last > 0.18:
            last = now; set_terminal_font(TERM_FONT_SIZE - 1); scrollback = []
        elif GPIO.input(PINS['LEFT']) == 0 and now - last > 0.18:
            last = now; idx = (idx - 1) % len(COLORS)
        elif GPIO.input(PINS['RIGHT']) == 0 and now - last > 0.18:
            last = now; idx = (idx + 1) % len(COLORS)
        elif GPIO.input(PINS['OK']) == 0 and now - last > 0.18:
            last = now; TERM_COLOR = COLORS[idx]; return
        elif GPIO.input(PINS['KEY3']) == 0 and now - last > 0.18:
            last = now; return
        time.sleep(0.06)

# Mirror capture files when lines show a saved filename
CAP_RE = re.compile(r"(\S+\.(?:pcap|pcapng|cap|hccapx|22000))\b", re.I)

def try_mirror_capture(line: str):
    m = CAP_RE.search(line)
    if not m:
        return
    path = m.group(1)
    try:
        if os.path.exists(path):
            base = os.path.basename(path)
            dest = os.path.join(LOOT_DIR, base)
            if os.path.abspath(path) != os.path.abspath(dest):
                shutil.copy2(path, dest)
                wrap_print(f"[loot] mirrored -> {dest}")
    except Exception as e:
        wrap_print(f"[loot] mirror failed: {e}")

# Button scanner → send bytes to child PTY
def btn_sender(master_fd: int):
    debounce = 0.18
    last = 0.0
    while RUN:
        now = time.time()
        fired = None
        if GPIO.input(PINS["LEFT"]) == 0 or GPIO.input(PINS["KEY3"]) == 0:
            fired = b"\x03"  # Ctrl+C
        elif GPIO.input(PINS["OK"]) == 0 or GPIO.input(PINS["RIGHT"]) == 0:
            fired = b"\n"    # Enter
        elif GPIO.input(PINS["UP"]) == 0:
            fired = b"\x1b[A"  # Arrow Up
        elif GPIO.input(PINS["DOWN"]) == 0:
            fired = b"\x1b[B"  # Arrow Down
        elif GPIO.input(PINS["KEY1"]) == 0:
            fired = b"1"
        elif GPIO.input(PINS["KEY2"]) == 0:
            fired = b"2"
        if fired and (now - last) > debounce:
            last = now
            try:
                os.write(master_fd, fired)
            except OSError:
                pass
        time.sleep(0.03)

# PTY reader → print output, wrap, mirror loot
def pty_reader(master_fd: int):
    # Non-blocking read
    fl = fcntl.fcntl(master_fd, fcntl.F_GETFL)
    fcntl.fcntl(master_fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    buf = b""
    while RUN:
        r, _, _ = select.select([master_fd], [], [], 0.2)
        if master_fd in r:
            try:
                chunk = os.read(master_fd, 4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    try:
                        s = line.decode('utf-8', errors='replace')
                    except Exception:
                        s = str(line)
                    try_mirror_capture(s)
                    wrap_print(s)
            except OSError:
                break
    # Flush remainder
    if buf:
        try:
            s = buf.decode('utf-8', errors='replace')
            wrap_print(s)
        except Exception:
            pass

# Cleanup
def cleanup(*_):
    global RUN
    RUN = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

if __name__ == '__main__':
    try:
        if os.geteuid() != 0:
            print("[ERROR] Run as root", file=sys.stderr)
            sys.exit(1)
        if not WIFI_OK:
            print("[ERROR] WiFi helpers missing", file=sys.stderr)
            sys.exit(1)
        if shutil.which('wifite') is None:
            print("[ERROR] wifite not found", file=sys.stderr)
            sys.exit(1)

        # Interface selection on LCD
        options = [i for i in get_available_interfaces() if i.startswith('wlan')]
        if 'wlan1' in options:
            options.remove('wlan1'); options.insert(0, 'wlan1')
        if not options:
            draw_message(["No WiFi interfaces"], "red"); time.sleep(3); sys.exit(1)
        sel = 0
        last = 0.0
        while True:
            # Draw menu
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ImageDraw.Draw(img)
            d.text((24, 6), "tiny_wifite", font=FONT_TITLE, fill="white")
            d.line([(6, 22), (122, 22)], fill="#333", width=1)
            y = 32
            for i, iface in enumerate(options):
                if i == sel:
                    d.rectangle([(8, y-2), (120, y+12)], fill="#003366")
                    fill = "#FFFF00"
                else:
                    fill = "white"
                d.text((14, y), iface, font=FONT_TITLE, fill=fill)
                y += 18
            d.text((8, 110), "UP/DOWN select  OK confirm  LEFT exit", font=ImageFont.load_default(), fill="#888")
            d.text((8, 118), "KEY1=Settings", font=ImageFont.load_default(), fill="#888")
            LCD.LCD_ShowImage(img, 0, 0)
            # Handle input
            now = time.time()
            if GPIO.input(PINS['UP']) == 0 and now - last > 0.2:
                last = now; sel = (sel - 1) % len(options)
            elif GPIO.input(PINS['DOWN']) == 0 and now - last > 0.2:
                last = now; sel = (sel + 1) % len(options)
            elif GPIO.input(PINS['OK']) == 0 and now - last > 0.2:
                last = now; WIFI_IFACE = options[sel]; break
            elif GPIO.input(PINS['LEFT']) == 0 and now - last > 0.2:
                cleanup(); LCD.LCD_Clear(); GPIO.cleanup(); sys.exit(0)
            elif GPIO.input(PINS['KEY1']) == 0 and now - last > 0.2:
                last = now; open_settings_menu()
            time.sleep(0.06)

        # Enable monitor mode before launching wifite
        draw_message([f"Enabling monitor", f"on {WIFI_IFACE}..."], "yellow")
        MON_IFACE = monitor_mode_helper.activate_monitor_mode(WIFI_IFACE)
        if not MON_IFACE:
            draw_message(["Monitor mode failed"], "red"); time.sleep(3)
            sys.exit(1)
        time.sleep(0.3)

        # Launch wifite under a PTY (real TTY behaviour)
        master_fd, slave_fd = pty.openpty()
        # child uses the slave end as stdio
        pid = os.fork()
        if pid == 0:
            try:
                os.setsid()
                os.dup2(slave_fd, 0)
                os.dup2(slave_fd, 1)
                os.dup2(slave_fd, 2)
                if slave_fd > 2:
                    os.close(slave_fd)
                if master_fd > 2:
                    os.close(master_fd)
                # Run full wifite with our monitor iface; let wifite own everything else
                os.execvp('wifite', ['wifite', '-i', MON_IFACE, '--kill'])
            except Exception as e:
                print(f"exec error: {e}")
                os._exit(127)
        # parent
        os.close(slave_fd)

        draw_message(["Running wifite...", "OK/RIGHT=Enter  LEFT/KEY3=^C", "UP/DOWN=Arrows  1/2 keys"], "white")
        t_reader = threading.Thread(target=pty_reader, args=(master_fd,), daemon=True)
        t_btns = threading.Thread(target=btn_sender, args=(master_fd,), daemon=True)
        t_reader.start(); t_btns.start()

        # Wait for child to exit
        exited_pid = None
        while RUN:
            try:
                exited_pid, status = os.waitpid(pid, os.WNOHANG)
                if exited_pid == pid:
                    break
            except ChildProcessError:
                break
            time.sleep(0.2)
        RUN = False
        t_reader.join(timeout=1.0)
        t_btns.join(timeout=1.0)
        try:
            os.close(master_fd)
        except Exception:
            pass

    except SystemExit:
        pass
    except Exception as e:
        print(f"[FATAL] {e}", file=sys.stderr)
    finally:
        # Cleanup monitor mode
        try:
            if MON_IFACE:
                monitor_mode_helper.deactivate_monitor_mode(MON_IFACE)
        except Exception:
            pass
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        # GPIO cleanup
        try:
            GPIO.cleanup()
        except Exception:
            pass

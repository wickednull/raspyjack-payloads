#!/usr/bin/env python3
"""
RaspyJack payload – tiny_wifite (shell TUI)
==========================================
Run full wifite in a small shell view with RaspyJack buttons mapped to keys.
- Sets monitor mode before launch (uses monitor_mode_helper)
- Runs the real wifite with a TTY so it behaves normally
- Buttons send keystrokes (Enter, Ctrl+C, arrows, 1/2, etc.) to wifite
- Pass-through, wrapped output so it stays readable on small terminals
- Mirrors discovered capture files into loot/TinyWifite

Controls (buttons → keys)
- OK / RIGHT: Enter
- LEFT / KEY3: Ctrl+C (stop)
- UP/DOWN: Arrow Up/Down (navigate lists)
- KEY1: "1"
- KEY2: "2"

Notes
- This payload prints to the shell. It does not use the LCD drawing API.
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

# Hardware buttons
try:
    import RPi.GPIO as GPIO
except Exception as e:
    print(f"[ERROR] GPIO not available: {e}", file=sys.stderr)
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

# Loot
RASPYJACK_ROOT = '/root/Raspyjack' if os.path.isdir('/root/Raspyjack') else os.path.abspath(os.path.join(BASE_DIR, '..', '..'))
LOOT_DIR = os.path.join(RASPYJACK_ROOT, 'loot', 'TinyWifite')
os.makedirs(LOOT_DIR, exist_ok=True)

RUN = True
WIFI_IFACE = None
MON_IFACE = None

# Wrap long lines to fit small shells
def term_width(default=64):
    try:
        import shutil as _sh
        return max(40, min(96, _sh.get_terminal_size((default, 24)).columns))
    except Exception:
        return default

WRAP = term_width()

def wrap_print(s: str):
    s = s.rstrip('\n')
    while len(s) > WRAP:
        print(s[:WRAP])
        s = s[WRAP:]
    if s:
        print(s)

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

        # Interface selection (console, minimal)
        options = [i for i in get_available_interfaces() if i.startswith('wlan')]
        if 'wlan1' in options:
            options.remove('wlan1'); options.insert(0, 'wlan1')
        if not options:
            print("[ERROR] No WiFi interfaces", file=sys.stderr)
            sys.exit(1)
        sel = 0
        last = 0.0
        print("Select interface (UP/DOWN, OK to confirm, LEFT to exit):")
        while True:
            now = time.time()
            for i, iface in enumerate(options):
                pref = '>' if i == sel else ' '
                print(f" {pref} {iface}")
            # quick poll of buttons
            if GPIO.input(PINS['UP']) == 0 and now - last > 0.2:
                last = now; sel = (sel - 1) % len(options)
            elif GPIO.input(PINS['DOWN']) == 0 and now - last > 0.2:
                last = now; sel = (sel + 1) % len(options)
            elif GPIO.input(PINS['OK']) == 0 and now - last > 0.2:
                last = now; WIFI_IFACE = options[sel]; break
            elif GPIO.input(PINS['LEFT']) == 0 and now - last > 0.2:
                sys.exit(0)
            time.sleep(0.05)
            # Clear the menu output between draws
            # Move cursor up len(options) lines
            sys.stdout.write(f"\x1b[{len(options)}A")
        # Clear menu one last time
        sys.stdout.write(f"\x1b[{len(options)}B\n")

        # Enable monitor mode before launching wifite
        print(f"[info] Enabling monitor mode on {WIFI_IFACE}...")
        MON_IFACE = monitor_mode_helper.activate_monitor_mode(WIFI_IFACE)
        if not MON_IFACE:
            print("[ERROR] Monitor mode failed", file=sys.stderr)
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

        print("[tiny_wifite] Running wifite. Controls: OK/RIGHT=Enter, LEFT/KEY3=Ctrl+C, UP/DOWN=Arrows, KEY1=1, KEY2=2\n")
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
        # GPIO cleanup
        try:
            GPIO.cleanup()
        except Exception:
            pass

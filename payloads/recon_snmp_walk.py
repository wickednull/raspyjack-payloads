#!/usr/bin/env python3
import sys
sys.path.append('/root/Raspyjack/')
"""
RaspyJack *payload* – **Recon: SNMP Walk**
===========================================
A reconnaissance tool that performs an SNMP (Simple Network Management
Protocol) walk on a target device using a common community string.

If a device has a default or guessable community string (like "public"),
an SNMP walk can dump a huge amount of information, including network
interfaces, routing tables, system uptime, and much more.
"""

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

# --- CONFIGURATION ---
TARGET_IP = "192.168.1.1" # Will be configurable
COMMUNITY_STRING = "public" # Will be configurable

# --- Globals & Shutdown ---
running = True
selected_index = 0
results = []
current_ip_input = TARGET_IP # Initial value for IP input
ip_input_cursor_pos = 0
current_community_input = COMMUNITY_STRING # Initial value for community string input
community_input_cursor_pos = 0

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- UI ---
def show_message(lines, color="lime"):
    if not HARDWARE_LIBS_AVAILABLE:
        for line in lines:
            print(line)
        return
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    font = FONT_TITLE # Use FONT_TITLE for messages
    y = 40
    for line in lines:
        bbox = d.textbbox((0, 0), line, font=font)
        w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        x = (128 - w) // 2
        d.text((x, y), line, font=font, fill=color)
        y += h + 5
    LCD.LCD_ShowImage(img, 0, 0)

def draw_ui(screen_state="main"):
    if not HARDWARE_LIBS_AVAILABLE:
        print(f"UI State: {screen_state}")
        if screen_state == "main":
            print(f"Target IP: {TARGET_IP}")
            print(f"Community String: {COMMUNITY_STRING}")
        return

    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    d.text((5, 5), "SNMP Walk", font=FONT_TITLE, fill="#00FF00")
    d.line([(0, 22), (128, 22)], fill="#00FF00", width=1)

    if screen_state == "main":
        d.text((5, 25), "Target IP:", font=FONT, fill="white")
        d.text((5, 40), TARGET_IP, font=FONT_TITLE, fill="yellow")
        d.text((5, 60), "Community:", font=FONT, fill="white")
        d.text((5, 75), COMMUNITY_STRING[:16], font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "OK=Walk | KEY1=Edit IP | KEY2=Edit Comm | KEY3=Exit", font=FONT, fill="cyan")
    elif screen_state == "ip_input":
        d.text((5, 30), "Enter Target IP:", font=FONT, fill="white")
        display_ip = list(current_ip_input)
        if ip_input_cursor_pos < len(display_ip):
            display_ip[ip_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_ip), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Digit | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "community_input":
        d.text((5, 30), "Enter Community String:", font=FONT, fill="white")
        display_community = list(current_community_input)
        if community_input_cursor_pos < len(display_community):
            display_community[community_input_cursor_pos] = '_'
        d.text((5, 50), "".join(display_community[:16]), font=FONT_TITLE, fill="yellow")
        d.text((5, 115), "UP/DOWN=Char | LEFT/RIGHT=Move | OK=Confirm", font=FONT, fill="cyan")
    elif screen_state == "scanning":
        d.text((5, 50), "Walking...", font=FONT_TITLE, fill="yellow")
        d.text((5, 70), f"Target: {TARGET_IP}", font=FONT, fill="white")
        d.text((5, 115), "KEY3=Stop", font=FONT, fill="cyan")
    elif screen_state == "results":
        start_index = max(0, selected_index - 4)
        end_index = min(len(results), start_index + 8)
        y_pos = 25
        for i in range(start_index, end_index):
            color = "yellow" if i == selected_index else "white"
            line = results[i]
            if len(line) > 20: line = line[:19] + "..."
            d.text((5, y_pos), line, font=FONT, fill=color)
            y_pos += 11
        d.text((5, 115), "OK=Walk | KEY3=Exit", font=FONT, fill="cyan")
    
    LCD.LCD_ShowImage(img, 0, 0)

def handle_ip_input_logic(initial_ip):
    global current_ip_input, ip_input_cursor_pos
    current_ip_input = initial_ip
    ip_input_cursor_pos = len(initial_ip) - 1 # Start cursor at end
    
    draw_ui("ip_input")
    
    while running:
        btn = None
        for name, pin in PINS.items():
            if GPIO.input(pin) == 0:
                btn = name
                while GPIO.input(pin) == 0: # Debounce
                    time.sleep(0.05)
                break
        
        if btn == "KEY3": # Cancel IP input
            return None
        
        if btn == "OK": # Confirm IP
            # Validate IP format
            parts = current_ip_input.split('.')
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return current_ip_input
            else:
                show_message(["Invalid IP!", "Try again."], "red")
                time.sleep(2)
                current_ip_input = initial_ip # Reset to initial
                ip_input_cursor_pos = len(initial_ip) - 1
                draw_ui("ip_input")
        
        if btn == "LEFT":
            ip_input_cursor_pos = max(0, ip_input_cursor_pos - 1)
            draw_ui("ip_input")
        elif btn == "RIGHT":
            ip_input_cursor_pos = min(len(current_ip_input), ip_input_cursor_pos + 1)
            draw_ui("ip_input")
        elif btn == "UP" or btn == "DOWN":
            if ip_input_cursor_pos < len(current_ip_input):
                char_list = list(current_ip_input)
                current_char = char_list[ip_input_cursor_pos]
                
                if current_char.isdigit():
                    digit = int(current_char)
                    if btn == "UP":
                        digit = (digit + 1) % 10
                    else: # DOWN
                        digit = (digit - 1 + 10) % 10
                    char_list[ip_input_cursor_pos] = str(digit)
                    current_ip_input = "".join(char_list)
                elif current_char == '.':
                    # Cannot change dot, move cursor
                    if btn == "UP":
                        ip_input_cursor_pos = min(len(current_ip_input), ip_input_cursor_pos + 1)
                    else:
                        ip_input_cursor_pos = max(0, ip_input_cursor_pos - 1)
                draw_ui("ip_input")
        
        time.sleep(0.1)
    return None

def handle_text_input_logic(initial_text, screen_state_name, char_set):
    global current_community_input, community_input_cursor_pos
    
    current_input_ref = current_community_input
    cursor_pos_ref = community_input_cursor_pos

    current_input_ref = initial_text
    cursor_pos_ref = len(initial_text) - 1
    
    draw_ui(screen_state_name)
    
    while running:
        btn = None
        for name, pin in PINS.items():
            if GPIO.input(pin) == 0:
                btn = name
                while GPIO.input(pin) == 0: # Debounce
                    time.sleep(0.05)
                break
        
        if btn == "KEY3": # Cancel input
            return None
        
        if btn == "OK": # Confirm input
            if current_input_ref: # Basic validation
                return current_input_ref
            else:
                show_message(["Input cannot", "be empty!"], "red")
                time.sleep(2)
                current_input_ref = initial_text
                cursor_pos_ref = len(initial_text) - 1
                draw_ui(screen_state_name)
        
        if btn == "LEFT":
            cursor_pos_ref = max(0, cursor_pos_ref - 1)
            draw_ui(screen_state_name)
        elif btn == "RIGHT":
            cursor_pos_ref = min(len(current_input_ref), cursor_pos_ref + 1)
            draw_ui(screen_state_name)
        elif btn == "UP" or btn == "DOWN":
            if cursor_pos_ref < len(current_input_ref):
                char_list = list(current_input_ref)
                current_char = char_list[cursor_pos_ref]
                
                try:
                    char_index = char_set.index(current_char)
                    if btn == "UP":
                        char_index = (char_index + 1) % len(char_set)
                    else: # DOWN
                        char_index = (char_index - 1 + len(char_set)) % len(char_set)
                    char_list[cursor_pos_ref] = char_set[char_index]
                    current_input_ref = "".join(char_list)
                except ValueError: # If current char is not in char_set
                    char_list[cursor_pos_ref] = char_set[0] # Default to first char
                    current_input_ref = "".join(char_list)
                draw_ui(screen_state_name)
        
        time.sleep(0.1)
    return None

# --- Scanner ---
def run_scan():
    global results, selected_index, TARGET_IP, COMMUNITY_STRING
    draw_ui("scanning")
    results = []
    selected_index = 0
    
    try:
        # Use snmpwalk to query the device
        command = f"snmpwalk -v2c -c {COMMUNITY_STRING} {TARGET_IP}"
        proc = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        
        if proc.returncode == 0 and proc.stdout:
            # For this payload, we'll just show the first few interesting lines
            # A full walk can be thousands of lines long
            lines = proc.stdout.strip().split('\n')
            for line in lines:
                if "sysDescr" in line or "sysName" in line or "ifDescr" in line:
                    # Clean up the output for display
                    clean_line = line.split(' = ')[-1].replace('"', '')
                    results.append(clean_line)
            
            if not results:
                results.append("Walk complete.")
                results.append("No common info found.")
            
            # Save full loot
            os.makedirs("/root/Raspyjack/loot/SNMP/", exist_ok=True)
            loot_file = f"/root/Raspyjack/loot/SNMP/{TARGET_IP}_walk.txt"
            with open(loot_file, "w") as f:
                f.write(f"Zone transfer results for {TARGET_IP} from {COMMUNITY_STRING}\n\n")
                f.write(proc.stdout)
            results.append(f"Saved to loot!")

        else:
            if "Timeout" in proc.stderr:
                results.append("Timeout: No response")
            else:
                results.append("Walk failed.")
                print(proc.stderr, file=sys.stderr)

    except Exception as e:
        results.append("Scan error!")
        print(f"snmpwalk failed: {e}", file=sys.stderr)
    
    return results

# --- Main Loop ---
if not HARDWARE_LIBS_AVAILABLE:
    print("ERROR: Hardware libraries (RPi.GPIO, LCD drivers, PIL) are not available. Cannot run SNMP Walk.", file=sys.stderr)
    sys.exit(1)

current_screen = "main"
last_scan_results = []
try:
    if subprocess.run("which snmpwalk", shell=True, capture_output=True).returncode != 0:
        show_message(["ERROR:", "snmpwalk", "not found!"], "red")
        time.sleep(3)
        sys.exit(1)

    while running:
        if current_screen == "main":
            draw_ui("main")
            
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            
            if GPIO.input(PINS["OK"]) == 0:
                last_scan_results = run_scan()
                current_screen = "results"
                time.sleep(0.3) # Debounce
            
            if GPIO.input(PINS["UP"]) == 0:
                if last_scan_results:
                    selected_index = (selected_index - 1) % len(last_scan_results)
                time.sleep(0.2)
            elif GPIO.input(PINS["DOWN"]) == 0:
                if last_scan_results:
                    selected_index = (selected_index + 1) % len(last_scan_results)
                time.sleep(0.2)
            
            if GPIO.input(PINS["KEY1"]) == 0: # Edit Target IP
                current_ip_input = TARGET_IP
                current_screen = "ip_input"
                time.sleep(0.3) # Debounce
            
            if GPIO.input(PINS["KEY2"]) == 0: # Edit Community String
                current_community_input = COMMUNITY_STRING
                current_screen = "community_input"
                time.sleep(0.3) # Debounce
        
        elif current_screen == "ip_input":
            char_set = "0123456789."
            new_ip = handle_ip_input_logic(current_ip_input)
            if new_ip:
                TARGET_IP = new_ip
            current_screen = "main"
            time.sleep(0.3) # Debounce
        
        elif current_screen == "community_input":
            char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
            new_community = handle_text_input_logic(current_community_input, "community_input", char_set)
            if new_community:
                COMMUNITY_STRING = new_community
            current_screen = "main"
            time.sleep(0.3) # Debounce
        
        elif current_screen == "scanning":
            draw_ui("scanning")
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
                break
            # No explicit stop for snmpwalk, it will finish or timeout
            time.sleep(0.1)
        
        elif current_screen == "results":
            draw_ui("results", scan_results=last_scan_results)
            if GPIO.input(PINS["KEY3"]) == 0:
                current_screen = "main"
                time.sleep(0.3) # Debounce
            if GPIO.input(PINS["OK"]) == 0:
                last_scan_results = run_scan()
                time.sleep(0.3) # Debounce
            
            if GPIO.input(PINS["UP"]) == 0:
                if last_scan_results:
                    selected_index = (selected_index - 1) % len(last_scan_results)
                time.sleep(0.2)
            elif GPIO.input(PINS["DOWN"]) == 0:
                if last_scan_results:
                    selected_index = (selected_index + 1) % len(last_scan_results)
                time.sleep(0.2)
            
            time.sleep(0.1)

        time.sleep(0.1)

except (KeyboardInterrupt, SystemExit):
    pass
except Exception as e:
    print(f"[ERROR] {e}", file=sys.stderr)
    show_message(["CRITICAL ERROR:", str(e)[:20]], "red")
    time.sleep(3)
finally:
    LCD.LCD_Clear()
    GPIO.cleanup()
    print("SNMP Walk payload finished.")

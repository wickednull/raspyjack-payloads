# raspyjack-payloads
 Just a repo where I keep my custom RaspyJack payloads. Got a little bit of    everything—network tools, wireless attacks, Trying to figure out HID attacks lol, and  phishing pages for testing.    Heads up: This is all for education and testing on your own gear.    Don't be a jerk with it.



 # Raspyjack Payload Development: A Comprehensive Guide

Welcome to Raspyjack payload development! This guide will walk you through everything you need to know to create your own powerful tools and applications for the Raspyjack device.

---

### **Chapter 1: The Big Picture - How Payloads Work**

Before you write a single line of code, it's important to understand the environment your payload will run in.

#### **1.1 The Execution Flow**

When a user selects your payload from the main menu, a simple but important sequence of events occurs:

1.  **Launch:** The main `raspyjack.py` script, which runs the UI, finds your payload file (e.g., `my_payload.py`).
2.  **New Process:** It then executes your payload as a completely **new and separate Python process** using the `subprocess.Popen` command.
3.  **Isolation:** Your payload runs in isolation. It does not share memory or state with the main menu. This means your script is responsible for initializing everything it needs, especially the hardware (LCD and buttons).

#### **1.2 The "Sandbox"**

Think of your payload as running in a small sandbox. It has access to the file system and system commands, but it's on its own.

-   **Hardware Control:** Your script must take control of the GPIO pins for the screen and buttons.
-   **Cleanup is Your Job:** Because you took control of the hardware, you **must** release it when your script is done. We'll cover this in detail in Chapter 4.

#### **1.3 File System Context**

This is a common point of confusion. No matter where your payload script is located (`payloads/`, `payloads/new/`, etc.), it is always **executed from the root of the project directory**, which is `/root/Raspyjack`.

This means if you need to open a file, the path should be relative to `/root/Raspyjack`.

-   **Correct:** `open("loot/my_payload/results.txt", "w")`
-   **Incorrect:** `open("results.txt", "w")` (This would try to write to `/root/Raspyjack/results.txt`)
-   **Correct:** `Image.open("Icons/my_icon.bmp")`

---

### **Chapter 2: Your First Payload - "Hello, World!"**

Let's break down a simple "Hello, World!" payload line by line. This is the fundamental structure for almost any payload you will create.

```python
#!/usr/bin/env python3
# ^ This is called a "shebang". It tells the system to use Python 3.

# --- Section 1: Imports ---
import sys
import os
import time
import signal
# These are standard Python libraries for system interaction.

# Add Raspyjack root to the Python path to find helper modules.
RASPYJACK_ROOT = '/root/Raspyjack'
if os.path.isdir(RASPYJACK_ROOT) and RASPYJACK_ROOT not in sys.path:
    sys.path.insert(0, RASPYJACK_ROOT)

# --- Section 2: Hardware Imports ---
# CRITICAL: LCD_Config MUST be imported before LCD_1in44 to set up the hardware correctly.
import LCD_Config
import LCD_1in44
import RPi.GPIO as GPIO
from PIL import Image, ImageDraw, ImageFont
# PIL (Pillow) is the library used for all drawing operations.

# --- Section 3: Global State ---
PINS = {"KEY3": 16} # Define the pins you'll use. KEY3 is the exit button.
RUNNING = True     # A flag to control the main loop.

# --- Section 4: Cleanup Function ---
# This function will be called to safely exit the script.
def cleanup(*_):
    global RUNNING
    if not RUNNING:
        return # Avoid running cleanup multiple times
    RUNNING = False
    print("Hello World: Cleaning up GPIO...")
    GPIO.cleanup() # This releases the GPIO pins.
    print("Hello World: Exiting.")

# --- Section 5: Main Execution Block ---
if __name__ == "__main__":
    # Register the cleanup function to run on script exit/interruption.
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    try:
        # --- Hardware Initialization ---
        GPIO.setmode(GPIO.BCM) # Use the BCM pin numbering scheme.
        GPIO.setup(PINS["KEY3"], GPIO.IN, pull_up_down=GPIO.PUD_UP) # Set KEY3 as an input with a pull-up resistor.

        LCD = LCD_1in44.LCD() # Create an LCD object.
        LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT) # Initialize it.
        LCD.LCD_Clear() # Clear the screen to black.

        # --- Drawing ---
        # Create a blank 128x128 pixel image.
        image = Image.new("RGB", (128, 128), "BLACK")
        # Create a drawing context for the image.
        draw = ImageDraw.Draw(image)
        # Load a font.
        font = ImageFont.load_default()

        # Draw the text onto the image buffer.
        draw.text((10, 10), "Hello, Raspyjack!", font=font, fill="LIME")
        draw.text((10, 50), "Press KEY3 to exit.", font=font, fill="CYAN")

        # Display the image buffer on the actual LCD screen.
        LCD.LCD_ShowImage(image, 0, 0)

        # --- Main Loop ---
        # This loop keeps the script alive, waiting for input.
        while RUNNING:
            if GPIO.input(PINS["KEY3"]) == 0: # "== 0" means the button is pressed.
                break # Exit the loop.
            time.sleep(0.1) # A short delay to prevent high CPU usage.

    finally:
        # This block will run no matter what, even if the script crashes.
        LCD.LCD_Clear()
        cleanup()
```

---

### **Chapter 3: Interacting with the User**

#### **3.1 The Display**

-   **Coordinate System:** The screen is 128x128 pixels. The coordinate `(0, 0)` is the **top-left corner**.
-   **Colors:** Colors can be specified by name (e.g., `"RED"`, `"LIME"`, `"CYAN"`) or by hex code (e.g., `"#FF00FF"`).
-   **Fonts:** You can load custom `.ttf` fonts for better-looking text. The default path is `/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf`.

#### **3.2 The Buttons & Debouncing**

When you press a button, the electrical contact can "bounce" for a few milliseconds, making the code think you pressed it multiple times. We must account for this with "debouncing".

Here is a simple and effective way to handle button presses:

```python
last_press_time = 0
DEBOUNCE_DELAY = 0.2 # 200 milliseconds

while RUNNING:
    current_time = time.time()
    if (current_time - last_press_time) > DEBOUNCE_DELAY:
        if GPIO.input(PINS["OK"]) == 0:
            last_press_time = current_time
            # --- Handle OK button press ---
            print("OK was pressed!")

        elif GPIO.input(PINS["UP"]) == 0:
            last_press_time = current_time
            # --- Handle UP button press ---
            print("UP was pressed!")
```

#### **3.3 Key Conventions**

To keep the user experience consistent across all payloads, please follow these conventions:

-   `KEY3`: **Exit** the entire payload and return to the main menu.
-   `LEFT`: **Go back** from a sub-menu or cancel the current action.
-   `OK` / `KEY_PRESS`: **Confirm** a selection or action.
-   `UP` / `DOWN`: Navigate lists or menus.

---

### **Chapter 4: The Golden Rule - Always Clean Up!**

**This is the most important rule of payload development.**

When your script takes control of the GPIO pins, it "owns" them. If you exit without releasing them, they remain in a locked state. The next script that tries to use them will either fail or throw `RuntimeWarning` messages.

The `try...finally` block is your best tool for this. The code in the `finally` block is **guaranteed** to run, even if your script has an error and crashes.

```python
try:
    # All your main payload logic goes here.
    # If an error happens here...
    pass
finally:
    # ...this code will still run!
    print("Cleaning up...")
    GPIO.cleanup()
```

---

### **Chapter 5: Debugging Your Payload**

#### **5.1 The Black Box Problem**

Because your payload is a separate process, its `print()` statements don't go to the same place as the main menu's logs. If your script crashes right at the start, you will see no output.

#### **5.2 Your Best Friend: The Log File**

The solution is to write your own log file to the `/tmp/` directory, which is a temporary folder that all processes can access.

Here is a robust debugging setup:

```python
# At the top of your script
LOG_FILE = "/tmp/my_payload_debug.log"

# A helper function to log messages
def log(message):
    with open(LOG_FILE, "a") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")

# In your main block, redirect errors to the log file
try:
    log("Payload started.")
    # ... your code ...
    a = 1 / 0 # This will cause an error
except Exception as e:
    log(f"An unhandled exception occurred: {e}")
    import traceback
    with open(LOG_FILE, "a") as f:
        traceback.print_exc(file=f) # This prints the full error traceback
finally:
    log("Payload finished.")
    cleanup()
```

#### **5.3 Reading the Log**

To see your debug messages, connect to the Raspyjack via SSH and use this command:

`tail -f /tmp/my_payload_debug.log`

The `-f` flag means "follow", so you will see new log messages appear in real-time as your payload runs.

---

### **Chapter 6: Expanding Your Payload's Power**

#### **6.1 Using Other Tools**

You can run any command-line tool from your payload using Python's `subprocess` module.

```python
import subprocess

log("Running nmap...")
# The command is broken into a list of arguments.
process = subprocess.run(["nmap", "-sV", "192.168.1.1"], capture_output=True, text=True)

if process.returncode == 0:
    log("Nmap scan successful!")
    log(process.stdout)
    # Save the results
    with open("/root/Raspyjack/loot/my_payload/nmap_scan.txt", "w") as f:
        f.write(process.stdout)
else:
    log(f"Nmap scan failed: {process.stderr}")
```

#### **6.2 Managing Dependencies**

If your payload needs a new tool (like `hcxdumptool`) or a new Python library (like `impacket`), you must add it to the dependency installation script.

1.  **Edit the script:** `/root/Raspyjack/payloads/update_dependencies.sh`
2.  **System Tools:** Add the package name to the `PACKAGES` array (e.g., `hostapd`, `bluez`).
3.  **Python Libraries:** Add the library name to the `PIP_PACKAGES` array (e.g., `impacket`).
4.  **Run the script:** Connect to the Raspyjack and run `sudo /root/Raspyjack/payloads/update_dependencies.sh`.

#### **6.3 Saving Your Findings**

Captured data is called "loot". All loot should be saved in a dedicated sub-directory inside `/root/Raspyjack/loot/`.

```python
LOOT_DIR = "/root/Raspyjack/loot/my_awesome_payload"
os.makedirs(LOOT_DIR, exist_ok=True) # Create the directory if it doesn't exist

loot_file_path = os.path.join(LOOT_DIR, "credentials.txt")
with open(loot_file_path, "w") as f:
    f.write("user:password\n")

log(f"Loot saved to {loot_file_path}")
```

---

### **Appendix: Code Recipes**

#### **Recipe: Draw a Centered Message**

```python
def draw_centered_message(draw, text, y_position, font, fill="WHITE"):
    """Draws a single line of text centered on the screen."""
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    x_position = (128 - text_width) // 2
    draw.text((x_position, y_position), text, font=font, fill=fill)
```

#### **Recipe: Display a Menu**

```python
def draw_menu(draw, menu_items, selected_index, font):
    """Draws a list of items, highlighting the selected one."""
    y = 25
    for i, item in enumerate(menu_items):
        if i == selected_index:
            draw.rectangle([(0, y - 2), (128, y + 12)], fill="BLUE")
            draw_centered_message(draw, item, y, font, fill="YELLOW")
        else:
            draw_centered_message(draw, item, y, font, fill="WHITE")
        y += 15
```

Happy hacking!



@null_lyfe                                                   11/16

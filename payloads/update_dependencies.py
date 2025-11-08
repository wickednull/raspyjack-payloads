#!/usr/bin/env python3
"""
RaspyJack *payload* – **Update & Install Dependencies**
========================================================
A utility payload that updates the system's package list and installs
all the necessary dependencies for the advanced payloads.

This script will:
1.  Run `apt-get update`.
2.  Install a list of required packages using `apt-get`.
3.  Install a list of required Python packages using `pip`.
4.  Download and build `hcxdumptool` from source, as it is often not
    available in default repositories.
"""

import os, sys, subprocess, signal, time

# --- CONFIGURATION ---
HCXDUMPTOOL_DIR = "/opt/hcxdumptool"
HCXDUMPTOOL_REPO = "https://github.com/ZerBea/hcxdumptool.git"

APT_DEPS = [
    "python3-scapy", "python3-netifaces", "python3-pyudev", "python3-serial",
    "python3-smbus", "python3-rpi.gpio", "python3-spidev", "python3-pil", "python3-numpy",
    "python3-setuptools", "python3-cryptography", "python3-requests", "fonts-dejavu-core",
    "python3-pip", # Added for pip functionality
    "hydra", "mitmproxy", "fswebcam", "alsa-utils", "macchanger",
    "reaver", "hostapd", "dnsmasq", "smbclient", "snmp", "php-cgi",
    "ettercap-common", "nmap", "git", "build-essential", "libcurl4-openssl-dev",
    "libssl-dev", "pkg-config",
    "aircrack-ng", "wireless-tools", "wpasupplicant", "iw", # WiFi attack tools
    "firmware-linux-nonfree", "firmware-realtek", "firmware-atheros", # USB WiFi dongle support
    "i2c-tools", # Misc
    "dos2unix", # For script conversion
    "wget", # For font download
    "ncat", "tcpdump", "arp-scan", "dsniff", "procps", # General network/offensive tools
    # Bluetooth dependencies
    "bluetooth", "bluez", "bluez-utils", # Bluetooth dependencies
    "sqlite3", # Added for browser_password_stealer.py
    "python3-evdev", # Added for keyboard_tester.py
    "dnsutils" # Added for recon_dns_zone_transfer.py (provides 'host' command)
]
PIP_DEPS = ["qrcode[pil]", "requests", "zero-hid"] # Added zero-hid for HID emulation

# --- Main ---
def show_message(lines, color="lime"):
    # In headless mode, print messages to console
    for line in lines:
        print(f"[{color.upper()}] {line}")

def run_command(command, step_name):
    """Runs a command and shows status on the console."""
    print(f"\n--- Running: {step_name} ---")
    print(f"Command: {command}")
    try:
        proc = subprocess.run(command, shell=True, check=True, capture_output=True, text=True, timeout=600)
        print(f"STDOUT:\n{proc.stdout}")
        if proc.stderr:
            print(f"STDERR:\n{proc.stderr}")
        print(f"--- {step_name} SUCCEEDED ---")
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        error_msg = e.stderr or e.stdout or str(e)
        print(f"--- {step_name} FAILED ---")
        print(f"ERROR: {error_msg}", file=sys.stderr)
        return False

def install_all():
    print("\nStarting dependency installation...")
    if not run_command("apt-get update", "apt update"):
        print("APT update failed. Exiting.")
        return

    if not run_command(f"apt-get install -y {' '.join(APT_DEPS)}", "apt install"):
        print("APT install failed. Exiting.")
        return
    
    # Ensure pip is up-to-date
    if not run_command("python3 -m pip install --upgrade pip setuptools", "pip upgrade"):
        print("PIP upgrade failed. Exiting.")
        return
        
    if not run_command(f"pip install {' '.join(PIP_DEPS)}", "pip install"):
        print("PIP install failed. Exiting.")
        return

    # Install hcxdumptool from source
    print("\nInstalling hcxdumptool from source...")
    if os.path.exists(HCXDUMPTOOL_DIR):
        print(f"Removing existing {HCXDUMPTOOL_DIR}...")
        subprocess.run(f"rm -rf {HCXDUMPTOOL_DIR}", shell=True, check=True)
    if not run_command(f"git clone {HCXDUMPTOOL_REPO} {HCXDUMPTOOL_DIR}", "git clone hcxdumptool"):
        print("hcxdumptool git clone failed. Exiting.")
        return
    if not run_command(f"cd {HCXDUMPTOOL_DIR} && make && make install", "hcxdumptool make install"):
        print("hcxdumptool make install failed. Exiting.")
        return
        
    print("\nInstallation Complete!")
    print("IMPORTANT: To enable USB HID Gadget, you might need to:")
    print("  1. Edit /boot/config.txt: add 'dtoverlay=dwc2'")
    print("  2. Edit /etc/modules: add 'dwc2' and 'libcomposite'")
    print("Then reboot your RaspyJack!")

if __name__ == '__main__':
    try:
        # Check for root
        if os.geteuid() != 0:
            print("ERROR: This script must be run as root!")
            print("Please run with 'sudo python3 update_dependencies.py'")
        else:
            install_all()
            
    except KeyboardInterrupt:
        print("\nDependency Installer interrupted by user.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
    finally:
        print("Dependency Installer payload finished.")


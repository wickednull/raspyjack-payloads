#!/usr/bin/env bash
# RaspyJack Dependencies Update Script
# ------------------------------------------------------------
# This script installs all necessary dependencies for the 
# RaspyJack payloads, including the new ones.
# ------------------------------------------------------------
set -euo pipefail

# ───── helpers ───────────────────────────────────────────────
step()  { printf "\e[1;34m[STEP]\e[0m %s\n"  "$*"; }
info()  { printf "\e[1;32m[INFO]\e[0m %s\n"  "$*"; }
warn()  { printf "\e[1;33m[WARN]\e[0m %s\n"  "$*"; }
fail()  { printf "\e[1;31m[FAIL]\e[0m %s\n"  "$*"; exit 1; }
cmd()   { command -v "$1" >/dev/null 2>&1; }

# ───── 1 ▸ install / upgrade required APT packages ───────────
PACKAGES=(
  # ‣ python libs from original script
  python3-scapy python3-netifaces python3-pyudev python3-serial \
  python3-smbus python3-rpi.gpio python3-spidev python3-pil python3-numpy \
  python3-setuptools python3-cryptography python3-requests fonts-dejavu-core \
  # ‣ network / offensive tools from original script
  nmap ncat tcpdump arp-scan dsniff ettercap-text-only php procps \
  # ‣ WiFi attack tools from original script
  aircrack-ng wireless-tools wpasupplicant iw reaver \
  # ‣ USB WiFi dongle support from original script
  firmware-linux-nonfree firmware-realtek firmware-atheros \
  # ‣ misc from original script
  git i2c-tools \
  # ‣ New dependencies
  bluez hostapd dnsmasq wifite hcxdumptool
)

step "Updating APT and installing dependencies …"
sudo apt-get update -qq
to_install=($(sudo apt-get -qq --just-print install "${PACKAGES[@]}" | awk '/^Inst/ {print $2}'))
if ((${#to_install[@]})); then
  info "Will install/upgrade: ${to_install[*]}"
  sudo apt-get install -y --no-install-recommends "${PACKAGES[@]}"
else
  info "All APT packages already installed & up‑to‑date."
fi

# ───── 2 ▸ install required PIP packages ────────────────────
PIP_PACKAGES=(
    impacket
)

step "Installing pip dependencies..."
sudo pip3 install "${PIP_PACKAGES[@]}"


# ───── 3 ▸ final health‑check ────────────────────────────────
step "Running post install checks …"

# 3‑a python imports
python3 - <<'PY' || fail "Python dependency test failed"
import importlib, sys
for mod in ("scapy", "netifaces", "pyudev", "serial", "smbus2", "RPi.GPIO", "spidev", "PIL", "requests", "impacket"):
    try:
        importlib.import_module(mod.split('.')[0])
    except Exception as e:
        print("[FAIL]", mod, e)
        sys.exit(1)
print("[OK] All Python modules import correctly")
PY

# 3‑b tool check
TOOLS=(nmap aircrack-ng reaver hcxdumptool wifite hostapd dnsmasq php)
for tool in "${TOOLS[@]}"; do
    if cmd "$tool"; then
        info "$tool found"
    else
        warn "$tool NOT found"
    fi
done


step "Installation finished successfully!"
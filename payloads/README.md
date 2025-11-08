# RaspyJack Custom Payloads

This directory contains custom payloads for the RaspyJack. Payloads are Python scripts that can be executed from the main menu and can interact with the device's hardware (LCD, buttons) and perform various networking or system tasks.

## New Payloads

Here is a list of the new payloads that have been added, categorized by their function.

### Wi-Fi Payloads

#### `wifi_beacon_flood.py`
*   **Type:** Offensive (Denial of Service)
*   **Description:** Floods the 2.4GHz spectrum with fake Wi-Fi beacon frames, creating hundreds of non-existent networks to clutter network lists and potentially confuse users or network scanners.
*   **Requirements:** A Wi-Fi interface capable of monitor mode and packet injection.

#### `wifi_probe_sniffer.py`
*   **Type:** Reconnaissance (Passive)
*   **Description:** Passively sniffs for 802.11 Probe Request frames to discover the SSIDs of networks that nearby devices are searching for. This can reveal networks a device has connected to previously.
*   **Requirements:** A Wi-Fi interface in monitor mode.

#### `pmkid_capture.py`
*   **Type:** Offensive (Credential Attack)
*   **Description:** An advanced attack that targets WPA/WPA2 networks to capture PMKIDs without needing to wait for a client handshake. The captured data can be cracked offline with tools like hashcat.
*   **Requirements:** A compatible Wi-Fi interface and `hcxdumptool` installed.

#### `evil_twin.py`
*   **Type:** Offensive (Credential Attack / Social Engineering)
*   **Description:** Creates a fake "Evil Twin" access point and funnels all traffic to a captive portal (phishing page) to steal credentials. This is a powerful and complex attack.
*   **Requirements:** `hostapd`, `dnsmasq`, `php`, and a Wi-Fi interface that supports AP mode.

### Ethernet (`eth0`) Payloads

#### `arp_scanner.py`
*   **Type:** Reconnaissance (Active)
*   **Description:** A very fast host discovery tool that sends ARP requests to every IP on the local subnet to find live hosts on the wired network.
*   **Requirements:** A connection on the `eth0` interface.

#### `dhcp_starvation.py`
*   **Type:** Offensive (Denial of Service)
*   **Description:** Floods the network with DHCP discover packets from spoofed MAC addresses, exhausting the DHCP server's IP pool and preventing legitimate clients from joining the network.
*   **Requirements:** A connection on the `eth0` interface.

#### `traffic_analyzer.py`
*   **Type:** Reconnaissance (Passive)
*   **Description:** A live network traffic analyzer that sniffs packets on `eth0` and provides real-time statistics on protocols (TCP, UDP, etc.) and the top IP addresses sending traffic.
*   **Requirements:** A connection on the `eth0` interface.

### Bluetooth Payloads

#### `bluetooth_scanner.py`
*   **Type:** Reconnaissance (Active)
*   **Description:** Scans for nearby Bluetooth (Classic and LE) devices and displays their MAC address and name.
*   **Requirements:** A working Bluetooth adapter.

#### `ble_spam.py`
*   **Type:** Offensive (Annoyance / DoS)
*   **Description:** Floods the area with Bluetooth Low Energy (BLE) advertisement packets mimicking Apple devices, which can trigger frequent pop-ups on iPhones and other Apple devices.
*   **Requirements:** A working Bluetooth adapter.

### HID (Keyboard Emulation) Payloads

#### `hid_attack.py`
*   **Type:** Offensive (Keystroke Injection)
*   **Description:** Turns the RaspyJack into a BadUSB device. It can run pre-defined scripts that emulate a keyboard to type commands, open websites, or execute reverse shells on a target machine.
*   **Requirements:** The RaspyJack must be connected to a target computer via a USB port that allows HID. Requires `P4wnP1_cli`.

### Utility Payloads

#### `loot_viewer.py`
*   **Type:** Utility
*   **Description:** A convenience tool that scans all known loot directories (from Responder, DNSSpoof, Evil Twin, etc.) and displays all captured credentials and hashes in a single, unified list.
*   **Requirements:** None.

#### `internet_check.py`
*   **Type:** Utility
*   **Description:** A simple diagnostic tool that pings reliable internet hosts (like Google and Cloudflare DNS) to quickly determine if the device has a working internet connection.
*   **Requirements:** A network connection (eth0 or Wi-Fi).

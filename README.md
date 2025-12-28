# DagShell - Orbic RCL400 Custom Firmware

```
 ____             ____  _          _ _ 
|  _ \  __ _  __ / ___|| |__   ___| | |
| | | |/ _` |/ _\___ \| '_ \ / _ \ | |
| |_| | (_| | (_| |__) | | | |  __/ | |
|____/ \__,_|\__, |___/|_| |_|\___|_|_|
             |___/                     
```

A terminal-styled custom firmware for the **Orbic RCL400** hotspot with hacking tools and privacy features.

🌐 **Documentation:** [dagnazty.github.io/DagShell](https://dagnazty.github.io/DagShell)

## Features

### 🏠 Dashboard
- System uptime display
- AT command interface for direct modem control

### 🌐 Network
- Current IP and interface info
- Routing table viewer
- Active connections monitor

### 🔒 Privacy
- **TTL Fix**: Mask hotspot traffic (set TTL to 65)
- **MAC Spoofing**: Randomize your MAC address
- **AdBlock**: DNS-level ad blocking via hosts file

### 📱 SMS
- Send SMS messages via AT commands
- Link to Orbic's inbox for viewing messages

### 🔧 Tools (Hacking)
- **IMSI Catcher Detector**: Monitor cell tower info for anomalies
- **Port Scanner**: Scan IPs for open ports
- **Firewall Manager**: Block/unblock IPs with iptables

### ⚔️ Attack Tools
- **DNS Sniffer**: Log DNS queries from connected clients (iptables-based, no promiscuous mode)
- **ARP Scanner**: Discover devices on local network with OUI vendor lookup
- **Traceroute**: Network path visualization with hop-by-hop RTT
- **Evil Twin AP**: Create a fake AP cloning existing SSIDs (uses wlan1)
- **Captive Portal**: Phishing page templates (WiFi login, social media) with credential logging

### 📍 GPS Tracker
- **Pi GPS Only** - GPS data comes exclusively from the Raspberry Pi companion
- Auto-refresh every 5 seconds
- No browser geolocation popups
- Shared GPS state between processes

### 🥧 Pi Companion
- **Raspberry Pi 3B+** or newer (Zero lacks USB power for peripherals)
- **GPS via USB dongle** (U-Blox7) - sends coordinates to Orbic with ECEF auto-conversion
- **Bluetooth scanning** (BLE) - remotely controlled from Orbic UI with OUI manufacturer lookup
- **OUI Database** - Prefix-based API from [OUI Master Database](https://dagnazty.github.io/OUI-Master-Database)
- **WiFi scanning** - Pi scans networks and sends to Orbic for logging
- **Deauth attacks** - One-shot or continuous deauth, controlled from Orbic scan page
- **Remote control** - Start/Stop BT scanning from Orbic web interface
- **Auto-start on boot** - systemd service starts automatically
- Data persisted to CSV files (Wigle-compatible)

### 📶 Wardriver
- Scan WiFi networks with GPS coordinates
- **Waits for GPS fix before starting** (no 0,0 entries)
- Wigle-compatible CSV export
- **Browser-based Wigle upload** - Upload directly from Files page
- Continuous loop mode (scans every 5 seconds)

### 📁 File Explorer
- Browse `/data/` directory
- Download wardrive logs and other files
- Delete files with confirmation

## Requirements

- Orbic RCL400 hotspot
- **Windows:** ARM cross-compiler (included in `gcc_win/` folder)
- **macOS:** Custom ARM toolchain (included in `gcc_mac/` folder, built with crosstool-ng targeting kernel 3.2 for compatibility)
- Python 3 with `requests` and `cryptography` modules

## Building

```powershell
# Windows
cd orbic_fw_c
python gen_pki.py   # Generate 2-Tier PKI (Root + Leaf)
.\build.ps1        # Compile firmware
```

```bash
# macOS / Linux
cd orbic_fw_c
python3 gen_pki.py  # Generate 2-Tier PKI (Root + Leaf)
./build.sh          # Compile firmware (auto-builds BearSSL)
```

> **Note for macOS:** The `gcc_mac/` folder contains a custom ARM toolchain built with crosstool-ng targeting Linux kernel 3.2 headers. This ensures compatibility with the Orbic's older kernel (3.18). Standard Homebrew ARM compilers target newer kernels and will NOT work.

This produces `orbic_app` (static ARM binary) and DER certificate files.

## Deploying

### Option A: Webflasher (Recommended)

Use our browser-based flasher at **[dagnazty.github.io/DagShell/orbic.html](https://dagnazty.github.io/DagShell/orbic.html)**

1. Generate PKI certificates in-browser
2. Download firmware files
3. Run `enable_shell.py` with your admin password
4. Run `deploy_base64.py` to install

### Option B: Manual Build & Deploy

#### Step 1: Enable Root Shell

```powershell
python enable_shell.py YOUR_ADMIN_PASSWORD
```

This exploits the Orbic web API to open a shell on port 24.

#### Step 2: Deploy Firmware

```powershell
python deploy_base64.py
```

This uploads and installs:
- DagShell Firmware (`/data/orbic_app`)
- Certificate Chain (`/data/root.der`, `/data/server.der`)
- Boot Persistence Script

The firmware auto-starts on reboot (port 8443).

## Accessing

Open your browser to: **`https://192.168.1.1:8443/`**

> **Note:** You will see a "Not Secure" or "Not Trusted" warning because the certificate is self-signed.
> - **PC:** Click "Advanced" -> "Proceed to 192.168.1.1 (unsafe)".
> - **Mobile (iOS/Android):** Click "Show Details" -> "visit this website". 
> 
> The connection IS encrypted (TLS 1.2+), but the root CA is not in your device's trust store. This is expected behavior for custom firmware.

## Screenshots

The firmware features a terminal/hacker aesthetic with:
- ASCII art logo
- Green-on-black color scheme
- Monospace font (Fira Code)
- Scanline effects
- Glowing text

## Disclaimer

This firmware is for **educational purposes only**. Use responsibly and only on devices you own. The authors are not responsible for any misuse.

## License

MIT License - See LICENSE file.

## Credits

- **dag** - Creator
- Built with ❤️ and `gcc`

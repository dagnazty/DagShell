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

### 📍 GPS Tracker
- **Auto-GPS on every page** - GPS indicator polls every 30 seconds
- **Cell tower lookup via OpenCellID** - Browser calls API automatically
- Browser geolocation as primary source
- File-based GPS sharing between processes
- JSON API for programmatic access

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
- ARM cross-compiler (included in `gcc/` folder)
- Python 3 with `requests` module

## Building

```powershell
cd orbic_fw_c
python gen_pki.py   # Generate 2-Tier PKI (Root + Leaf)
.\build.ps1        # Compile firmware
```

This produces `orbic_app` (static ARM binary) and DER certificate files.

## Deploying

### Step 1: Enable Root Shell

```powershell
python enable_shell.py YOUR_ADMIN_PASSWORD
```

This exploits the Orbic web API to open a shell on port 24.

### Step 2: Deploy Firmware

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

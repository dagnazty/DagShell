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

## Requirements

- Orbic RCL400 hotspot with root access (via exploit)
- ARM cross-compiler (`arm-linux-gnueabi-gcc`)
- Python 3 for deployment scripts

## Building

```powershell
cd orbic_fw_c
.\build.ps1
```

This produces `orbic_app` - a statically-linked ARM binary.

## Deploying

1. Connect to the hotspot's WiFi
2. Run the deployment script:

```powershell
python deploy_base64.py
```

This uploads the binary to the device via the diagnostic port (24) and executes it.

## Accessing

Open your browser to: `http://192.168.1.1:8081/`

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

- **Daggy** - Creator
- Built with ❤️ and `gcc`

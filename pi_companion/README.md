# DagShell Pi Companion

A companion scanner for Raspberry Pi that sends GPS, Bluetooth, and WiFi data to your Orbic DagShell server.

## Hardware Requirements

- Raspberry Pi 3B+ or newer (Pi Zero lacks USB power for peripherals)
- U-Blox7 GPS dongle (USB)
- Bluetooth adapter (built-in or USB like Kinovo BTD400)
- AC600 WiFi adapter (external USB, for scanning)
- USB hub (for multiple adapters)

## Quick Start

```bash
# 1. Run setup script (installs deps + enables auto-start)
chmod +x setup.sh
./setup.sh

# 2. Configure GPS
sudo nano /etc/default/gpsd
# Set DEVICES="/dev/ttyACM0" and GPSD_OPTIONS="-n"
sudo systemctl restart gpsd

# 3. Connect to Orbic via USB (recommended)
# Pi connects to Orbic via USB gadget mode (192.168.1.1)

# 4. Start service (or reboot)
sudo systemctl start dagshell-companion
```

## Auto-Start on Boot

The setup script installs a systemd service that starts the scanner automatically on boot.

```bash
# Service management commands
sudo systemctl start dagshell-companion   # Start now
sudo systemctl stop dagshell-companion    # Stop
sudo systemctl status dagshell-companion  # Check status
sudo journalctl -u dagshell-companion -f  # View live logs
sudo systemctl disable dagshell-companion # Disable auto-start
sudo systemctl enable dagshell-companion  # Re-enable auto-start
```

The service waits 10 seconds after boot to ensure GPS and Bluetooth hardware are ready.

## Usage

```bash
# Basic usage (GPS + Bluetooth + WiFi scanning)
sudo python3 dagshell_companion.py

# Custom Orbic URL
sudo python3 dagshell_companion.py --orbic https://192.168.1.1:8443

# Specify adapters manually
sudo python3 dagshell_companion.py --bt-iface hci0 --wifi-iface wlan1

# Disable features
sudo python3 dagshell_companion.py --no-gps
sudo python3 dagshell_companion.py --no-bt

# One-shot deauth attack (CLI mode)
sudo python3 dagshell_companion.py --deauth AA:BB:CC:DD:EE:FF
```

## Features

| Feature | Description |
|---------|-------------|
| **GPS** | Reads from gpsd with ECEF-to-geodetic conversion for u-blox modules |
| **Bluetooth** | BLE scanning with OUI manufacturer lookup |
| **OUI Lookup** | Prefix-based API from [OUI Master Database](https://dagnazty.github.io/OUI-Master-Database) |
| **WiFi** | Scans networks via `iw`, sends to Orbic for logging |
| **Remote Control** | Orbic UI can start/stop BT scanning on Pi |
| **Deauth Attacks** | Remote deauth via Orbic scan page (one-shot or continuous) |
| **Auto-Detection** | Automatically selects best Bluetooth adapter (USB preferred) |
| **Error Recovery** | Auto-resets Bluetooth adapter on errors |
| **Auto-Start** | Systemd service starts on boot |

## Remote Control

The Pi Companion polls the Orbic for commands every 3 seconds:

1. **Start BT Scan** - Click "▶ Start BT Scan" on Orbic Wardrive page
2. **Stop BT Scan** - Click "⏹ Stop BT Scan" on Orbic Wardrive page
3. **Status Display** - Pi scan status shown on Orbic UI

### Deauth Attacks

1. Go to **Scan** page on Orbic
2. Click **Scan Networks** to find targets
3. Check the networks you want to deauth
4. Click **💀 Deauth Once** for single attack or **🔄 Continuous** for persistent attack
5. Click **⏹ Stop** to stop continuous attacks

> **Note:** Requires external WiFi adapter (wlan1) that supports monitor mode.

## Data Flow

```
[Pi GPS Dongle] → dagshell_companion.py → Orbic /?set_gps=
[Pi BT Adapter] → dagshell_companion.py → Orbic /?set_bt=
[Pi WiFi Adapter] → dagshell_companion.py → Orbic /?cmd=ingest_wifi
                                         ↓
                               Orbic wardrive_*.csv
                               Orbic wardrive_bt_*.csv
```

## Files Created on Orbic

| File | Contents |
|------|----------|
| `/data/wardrive_YYYYMMDD_HHMMSS.csv` | WiFi networks (Wigle format) |
| `/data/wardrive_bt_YYYYMMDD_HHMMSS.csv` | Bluetooth devices |

## Troubleshooting

### No GPS Fix
- Check GPS antenna has clear sky view
- Verify: `gpspipe -w -n 10` (should show `lat`/`lon` or `ecefx`/`ecefy`/`ecefz`)
- Check gpsd service: `sudo systemctl status gpsd`
- u-blox modules may output ECEF coordinates - the companion auto-converts these

### GPS Shows 0.0, 0.0
- The companion now handles ECEF-to-geodetic conversion automatically
- Check `gpsmon` to verify fix (LTP Pos should show valid coordinates)
- Ensure gpsd is running with `-n` flag for immediate polling

### Bluetooth Shows "Unknown" Manufacturer
- OUI data is fetched on-demand from the prefix-based API
- Check internet connectivity on Pi
- Cache is stored in `/tmp/oui_cache/`
- Random/Private MACs (locally administered) won't have OUI entries

### Bluetooth Errors
- Script auto-detects best adapter
- Manual reset: `sudo hciconfig hci0 reset`
- Check adapter: `hciconfig -a`

### WiFi Scan Fails
- Ensure wlan1 exists: `ip link`
- Interface must not be connected to a network
- Try: `sudo iw dev wlan1 scan`

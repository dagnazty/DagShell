#!/bin/bash
# DagShell Pi Companion Setup Script
# Run this on your Raspberry Pi Zero 2 W

set -e

echo "=========================================="
echo "DagShell Pi Companion Setup"
echo "=========================================="

# Update system
echo "[1/6] Updating system..."
sudo apt update

# Install GPS daemon
echo "[2/6] Installing GPS (gpsd)..."
sudo apt install -y gpsd gpsd-clients python3-gps

# Install Bluetooth tools
echo "[3/6] Installing Bluetooth (bluez)..."
sudo apt install -y bluez bluetooth rfkill

# Unblock Bluetooth (fixes RF-kill issue)
sudo rfkill unblock bluetooth

# Install WiFi attack tools
echo "[4/6] Installing WiFi tools (aircrack-ng)..."
sudo apt install -y aircrack-ng iw wireless-tools

# Install Python dependencies
echo "[5/6] Installing Python dependencies..."
sudo apt install -y python3-pip python3-urllib3
pip3 install gps --break-system-packages 2>/dev/null || pip3 install gps

# Install systemd service for auto-start
echo "[6/6] Installing systemd service..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/dagshell"
sudo mkdir -p "$INSTALL_DIR"
sudo cp "$SCRIPT_DIR/dagshell_companion.py" "$INSTALL_DIR/"
sudo cp "$SCRIPT_DIR/dagshell-companion.service" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable dagshell-companion.service
echo "  Installed to $INSTALL_DIR"
echo "  Service installed and enabled!"

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "CONFIGURATION NEEDED:"
echo ""
echo "1. GPS Setup (for U-Blox7):"
echo "   sudo nano /etc/default/gpsd"
echo "   Set: DEVICES=\"/dev/ttyACM0\" (or /dev/ttyUSB0)"
echo "   Set: GPSD_OPTIONS=\"-n\""
echo "   Then: sudo systemctl restart gpsd"
echo ""
echo "2. Bluetooth:"
echo "   sudo hciconfig hci0 up"
echo "   sudo hcitool lescan  # Test scan"
echo ""
echo "3. WiFi Monitor Mode (AC600):"
echo "   Find your interface: iwconfig"
echo "   Enable monitor: sudo airmon-ng start wlan1"
echo ""
echo "4. Connect to Orbic WiFi:"
echo "   sudo nmcli device wifi connect YOUR_SSID password YOUR_PASSWORD"
echo ""
echo "AUTO-START:"
echo "   The scanner will now start automatically on boot!"
echo "   To start now:   sudo systemctl start dagshell-companion"
echo "   To view logs:   sudo journalctl -u dagshell-companion -f"
echo "   To disable:     sudo systemctl disable dagshell-companion"
echo ""

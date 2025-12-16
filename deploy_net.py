
import http.server
import socketserver
import threading
import socket
import time
import os
import argparse
from pathlib import Path

# Auto-detect firmware directory relative to this script
SCRIPT_DIR = Path(__file__).parent.absolute()
FIRMWARE_DIR = SCRIPT_DIR / "orbic_fw_c"
FIRMWARE_FILE = "orbic_app"

# Persistent locations on device (survives reboot)
REMOTE_FILE = "/data/orbic_app"
STARTUP_SCRIPT = "/data/dagshell_autostart.sh"

def start_server(host_port):
    os.chdir(FIRMWARE_DIR)
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", host_port), handler) as httpd:
        print(f"Serving at port {host_port}")
        httpd.serve_forever()

def send_cmd(sock, cmd):
    print(f"Sending: {cmd}")
    sock.sendall(cmd.encode() + b"\n")
    time.sleep(1)
    try:
        data = sock.recv(4096).decode('utf-8', errors='ignore')
        print(f"Response: {data}")
        return data
    except socket.timeout:
        print("Timeout receiving response (might be expected for blocking commands)")
        return ""

def setup_autostart(sock):
    """Create autostart script to run firmware on boot"""
    print("Setting up autostart...")
    
    # Create the startup script
    send_cmd(sock, f"echo '#!/system/bin/sh' > {STARTUP_SCRIPT}")
    send_cmd(sock, f"echo '# DagShell Autostart Script' >> {STARTUP_SCRIPT}")
    send_cmd(sock, f"echo 'sleep 15' >> {STARTUP_SCRIPT}")  # Wait for system to stabilize
    send_cmd(sock, f"echo '{REMOTE_FILE} &' >> {STARTUP_SCRIPT}")
    send_cmd(sock, f"chmod +x {STARTUP_SCRIPT}")
    
    # Try multiple autostart methods (device-specific)
    # Method 1: Add to rc.local if it exists
    send_cmd(sock, f"grep -q '{STARTUP_SCRIPT}' /data/rc.local 2>/dev/null || echo '{STARTUP_SCRIPT}' >> /data/rc.local")
    
    # Method 2: Create init.d script if supported
    send_cmd(sock, f"mkdir -p /data/local/init.d")
    send_cmd(sock, f"echo '#!/system/bin/sh' > /data/local/init.d/99dagshell")
    send_cmd(sock, f"echo '{STARTUP_SCRIPT}' >> /data/local/init.d/99dagshell")
    send_cmd(sock, f"chmod +x /data/local/init.d/99dagshell")
    
    print("Autostart configured!")

def deploy(host_ip, host_port, target_ip, target_port):
    # Start HTTP Server in background
    thread = threading.Thread(target=start_server, args=(host_port,))
    thread.daemon = True
    thread.start()
    time.sleep(2)  # Wait for startup

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((target_ip, target_port))
            print("Connected to Orbic shell!")
            
            # Kill old process first
            print("Killing old process...")
            send_cmd(s, "pkill -f orbic_app")
            
            # 1. Download to persistent location
            cmd_download = f"wget -O {REMOTE_FILE} http://{host_ip}:{host_port}/{FIRMWARE_FILE}"
            send_cmd(s, cmd_download)
            
            # 2. Chmod
            send_cmd(s, f"chmod +x {REMOTE_FILE}")
            
            # 3. Setup autostart for persistence across reboots
            setup_autostart(s)
            
            # 4. Run in background
            print("Running firmware...")
            output = send_cmd(s, f"{REMOTE_FILE} &")
            print("--- FIRMWARE OUTPUT ---")
            print(output)
            print("-----------------------")
            print("\n✓ Firmware deployed to /data/ (persistent)")
            print("✓ Autostart configured for boot persistence")

    except Exception as e:
        print(f"Deploy Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy DagShell firmware to Orbic device via HTTP download")
    parser.add_argument("--host-ip", default="192.168.1.143", help="Your PC's IP on RNDIS interface (default: 192.168.1.143)")
    parser.add_argument("--host-port", type=int, default=8000, help="HTTP server port (default: 8000)")
    parser.add_argument("--target-ip", default="192.168.1.1", help="Orbic device IP (default: 192.168.1.1)")
    parser.add_argument("--target-port", type=int, default=24, help="Orbic shell port (default: 24)")
    args = parser.parse_args()
    
    deploy(args.host_ip, args.host_port, args.target_ip, args.target_port)


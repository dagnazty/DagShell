
import socket
import time
import base64
import argparse
from pathlib import Path

# Auto-detect firmware directory relative to this script
SCRIPT_DIR = Path(__file__).parent.absolute()
FIRMWARE_DIR = SCRIPT_DIR / "orbic_fw_c"
FIRMWARE_FILE = "orbic_app"
FILESYSTEM_PATH = FIRMWARE_DIR / FIRMWARE_FILE

# Persistent locations on device (survives reboot)
REMOTE_FILE_B64 = "/data/orbic_app.b64"
REMOTE_FILE = "/data/orbic_app"
STARTUP_SCRIPT = "/data/dagshell_autostart.sh"

def send_cmd(sock, cmd, wait=0.2):
    sock.sendall(cmd.encode() + b"\n")
    time.sleep(wait)
    # Don't read recv every time to speed up, just let it buffer

def read_response(sock):
    try:
        sock.settimeout(2)
        return sock.recv(16384).decode('utf-8', errors='ignore')
    except:
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

def deploy(target_ip, target_port):
    # 1. Read and Encode
    print(f"Reading {FILESYSTEM_PATH}...")
    with open(FILESYSTEM_PATH, "rb") as f:
        data = f.read()
    
    b64_data = base64.b64encode(data).decode('utf-8')
    print(f"Encoded size: {len(b64_data)} bytes")
    
    chunks = [b64_data[i:i+1000] for i in range(0, len(b64_data), 1000)]
    print(f"Chunks: {len(chunks)}")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((target_ip, target_port))
            print("Connected.")
            
            # Kill old process
            print("Killing old process...")
            send_cmd(s, "pkill -f orbic_app")
            time.sleep(1)

            # Clean up old files
            send_cmd(s, f"rm -f {REMOTE_FILE} {REMOTE_FILE_B64}")
            
            # Send chunks
            print("Sending chunks...")
            for i, chunk in enumerate(chunks):
                if i % 10 == 0:
                    print(f"Sending chunk {i}/{len(chunks)}...")
                # echo "chunk" >> file
                send_cmd(s, f"echo -n '{chunk}' >> {REMOTE_FILE_B64}", wait=0.05)
            
            print("Decoding...")
            send_cmd(s, f"base64 -d {REMOTE_FILE_B64} > {REMOTE_FILE}", wait=1)
            
            print("Chmoding...")
            send_cmd(s, f"chmod +x {REMOTE_FILE}", wait=0.5)
            
            # Setup autostart for persistence across reboots
            setup_autostart(s)
            
            print("Running...")
            send_cmd(s, f"{REMOTE_FILE} &", wait=1)  # Run in background
            
            time.sleep(2)
            print("--- OUTPUT ---")
            print(read_response(s))
            print("--------------")
            print("\n✓ Firmware deployed to /data/ (persistent)")
            print("✓ Autostart configured for boot persistence")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy DagShell firmware to Orbic device via base64")
    parser.add_argument("--target-ip", default="192.168.1.1", help="Orbic device IP (default: 192.168.1.1)")
    parser.add_argument("--target-port", type=int, default=24, help="Orbic shell port (default: 24)")
    args = parser.parse_args()
    
    deploy(args.target_ip, args.target_port)

#!/usr/bin/env python3
"""
DagShell ADB Deployment Script
Deploys orbic_app to the Orbic RCL400 via ADB
"""

import subprocess
import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BINARY_PATH = os.path.join(SCRIPT_DIR, "orbic_fw_c", "orbic_app")
REMOTE_PATH = "/data/local/tmp/orbic_app"
PORT = 8081

# Use local platform-tools
ADB = os.path.join(SCRIPT_DIR, "platform-tools", "adb.exe")
if not os.path.exists(ADB):
    ADB = "adb"  # Fallback to PATH

def run_cmd(cmd, check=True):
    """Run a command and return output"""
    print(f"$ {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"Error: {result.stderr}")
        return None
    return result.stdout.strip()

def main():
    # Check if binary exists
    if not os.path.exists(BINARY_PATH):
        print(f"Error: Binary not found at {BINARY_PATH}")
        print("Run build.ps1 first!")
        sys.exit(1)
    
    print(f"Binary: {BINARY_PATH} ({os.path.getsize(BINARY_PATH):,} bytes)")
    
    # Check ADB connection
    print("\n[1/5] Checking ADB connection...")
    devices = run_cmd([ADB, "devices"])
    if not devices or "device" not in devices.split('\n')[-1]:
        print("Error: No ADB device connected!")
        print("Make sure:")
        print("  1. USB cable is connected")
        print("  2. ADB is enabled on device")
        print("  3. Run: adb devices")
        sys.exit(1)
    print("Device connected!")
    
    # Kill old process
    print("\n[2/5] Killing old orbic_app process...")
    run_cmd([ADB, "shell", "pkill", "-f", "orbic_app"], check=False)
    
    # Push binary
    print("\n[3/5] Pushing binary to device...")
    result = run_cmd([ADB, "push", BINARY_PATH, REMOTE_PATH])
    if result is None:
        sys.exit(1)
    print(result)
    
    # Make executable
    print("\n[4/5] Setting permissions...")
    run_cmd([ADB, "shell", "chmod", "+x", REMOTE_PATH])
    
    # Run in background
    print("\n[5/5] Starting orbic_app...")
    # Use nohup to keep it running after adb disconnects
    run_cmd([ADB, "shell", f"nohup {REMOTE_PATH} > /dev/null 2>&1 &"], check=False)
    
    print("\n" + "="*50)
    print("SUCCESS! DagShell is running!")
    print(f"Access at: http://192.168.1.1:{PORT}/")
    print("="*50)

if __name__ == "__main__":
    main()


import socket
import time
import base64
import os

FIRMWARE_DIR = r"d:\Scripts\orbic\orbic_fw_c"
FIRMWARE_FILE = "orbic_app"
FILESYSTEM_PATH = os.path.join(FIRMWARE_DIR, FIRMWARE_FILE)
REMOTE_FILE_B64 = "/tmp/orbic_app.b64"
REMOTE_FILE = "/tmp/orbic_app"

TARGET_IP = '192.168.1.1'
TARGET_PORT = 24

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

def deploy():
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
            s.connect((TARGET_IP, TARGET_PORT))
            print("Connected.")
            
            # Kill old process
            print("Killing old process...")
            send_cmd(s, "pkill -f orbic_app")
            time.sleep(1)

            # Clean up
            send_cmd(s, f"rm {REMOTE_FILE} {REMOTE_FILE_B64}")
            
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
            
            print("Running...")
            send_cmd(s, REMOTE_FILE, wait=1)
            
            time.sleep(2)
            print("--- OUTPUT ---")
            print(read_response(s))
            print("--------------")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    deploy()

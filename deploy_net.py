
import http.server
import socketserver
import threading
import socket
import time
import os

HOST = '192.168.1.143'  # Your PC IP on the RNDIS interface
PORT = 8000
FIRMWARE_DIR = r"d:\Scripts\orbic\orbic_fw_c"
FIRMWARE_FILE = "orbic_app"
REMOTE_FILE = "/tmp/orbic_app"

TARGET_IP = '192.168.1.1'
TARGET_PORT = 24

def start_server():
    os.chdir(FIRMWARE_DIR)
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        print(f"Serving at port {PORT}")
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

def deploy():
    # Start HTTP Server in background
    thread = threading.Thread(target=start_server)
    thread.daemon = True
    thread.start()
    time.sleep(2) # Wait for startup

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((TARGET_IP, TARGET_PORT))
            print("Connected to Orbic shell!")
            
            # 1. Download
            cmd_download = f"wget -O {REMOTE_FILE} http://{HOST}:{PORT}/{FIRMWARE_FILE}"
            send_cmd(s, cmd_download)
            
            # 2. Chmod
            send_cmd(s, f"chmod +x {REMOTE_FILE}")
            
            # 3. Run
            print("Running firmware...")
            output = send_cmd(s, REMOTE_FILE)
            print("--- FIRMWARE OUTPUT ---")
            print(output)
            print("-----------------------")

    except Exception as e:
        print(f"Deploy Error: {e}")

if __name__ == "__main__":
    deploy()

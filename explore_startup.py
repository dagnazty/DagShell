#!/usr/bin/env python3
"""
Check misc-daemon and how Rayhunter hooks into it
"""
import socket
import time

TARGET_IP = "192.168.1.1"
TARGET_PORT = 24

def send_cmd(sock, cmd):
    print(f"$ {cmd}")
    sock.sendall(cmd.encode() + b"\n")
    time.sleep(0.5)
    try:
        sock.settimeout(2)
        data = sock.recv(16384).decode('utf-8', errors='ignore')
        print(data)
        return data
    except:
        return ""

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.settimeout(10)
    s.connect((TARGET_IP, TARGET_PORT))
    print("Connected!\n")
    
    # Check what misc-daemon looks like
    send_cmd(s, "cat /etc/init.d/misc-daemon")
    
    # Check our dagshell init script
    send_cmd(s, "cat /etc/init.d/dagshell")
    
    # Check if dagshell autostart script exists
    send_cmd(s, "cat /data/dagshell_autostart.sh")
    
    # Try running our dagshell init script manually
    send_cmd(s, "/etc/init.d/dagshell start")

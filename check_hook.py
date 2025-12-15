#!/usr/bin/env python3
import socket
import time

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.settimeout(10)
    s.connect(("192.168.1.1", 24))
    s.sendall(b"grep dagshell /etc/init.d/misc-daemon\n")
    time.sleep(1)
    print(s.recv(4096).decode())

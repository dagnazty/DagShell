import socket
import time
import sys

s = socket.socket()
s.settimeout(10)
s.connect(('192.168.1.1', 24))
time.sleep(0.5)

cmd = sys.argv[1] if len(sys.argv) > 1 else 'ps | grep orbic'

s.send(f'{cmd}\n'.encode())
time.sleep(6)  # Wait longer for scan commands

data = b''
s.setblocking(False)
while True:
    try:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    except:
        break

print(data.decode(errors='ignore'))
s.close()

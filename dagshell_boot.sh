#!/bin/sh
# DagShell Autostart - Robust
# Note: Use /bin/sh for this device (Orbic RCL400/MDM9207)

# 1. Enable Shell (Port 24)
# Run in background, don't block
# We use busybox explicitly to avoid path issues
busybox nc -ll -p 24 -e /bin/sh &

# 2. Open HTTPS port (Port 8443)
iptables -I INPUT -p tcp --dport 8443 -j ACCEPT

# 3. Start DagShell (Port 8443 HTTPS)
# Give network a moment, then launch
sleep 5
/data/orbic_app &

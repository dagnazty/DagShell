#!/bin/sh
# DagShell Autostart - Robust
# Note: Use /bin/sh for this device (Orbic RCL400/MDM9207)

# 1. Enable Shell (Port 24)
# Run in background, don't block
# We use busybox explicitly to avoid path issues
busybox nc -ll -p 24 -e /bin/sh &

# 2. Start DagShell (Port 8081)
# Give network a moment, then launch
sleep 5
/data/orbic_app &

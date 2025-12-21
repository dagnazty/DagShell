#!/bin/sh
# DagShell Autostart - Robust
# Boot diagnostics go to SEPARATE file that won't be overwritten
BOOTLOG="/data/boot_diag.log"

# Clear and start fresh each boot
echo "=== BOOT $(date) ===" > $BOOTLOG

# 1. Enable Shell (Port 24)
busybox nc -ll -p 24 -e /bin/sh &
echo "[OK] Shell on port 24" >> $BOOTLOG

# 2. Open HTTPS port (Port 8443)
iptables -I INPUT -p tcp --dport 8443 -j ACCEPT
echo "[OK] Port 8443 open" >> $BOOTLOG

# 3. Configure DNS forwarding for dnsmasq
# CRITICAL: dnsmasq uses --dhcp-option-force=6,192.168.1.1 which makes
# clients use the Orbic as DNS. We need to tell dnsmasq to forward queries.
echo "server=8.8.8.8" > /data/dnsmasq.conf
echo "server=1.1.1.1" >> /data/dnsmasq.conf
killall -HUP dnsmasq 2>/dev/null
echo "[OK] dnsmasq configured to forward DNS to 8.8.8.8/1.1.1.1" >> $BOOTLOG

# 4. Enable NAT passthrough
# Note: WiFi hotspot is on bridge0, cellular is on rmnet_data0
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "[OK] ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)" >> $BOOTLOG

# NAT rules - use bridge0 (hotspot) not wlan0
# Note: There's already a MASQUERADE rule, but add specific ones to be safe
iptables -t nat -A POSTROUTING -o rmnet_data0 -j MASQUERADE 2>/dev/null
iptables -A FORWARD -i bridge0 -o rmnet_data0 -j ACCEPT 2>/dev/null
iptables -A FORWARD -i rmnet_data0 -o bridge0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
echo "[OK] NAT rules added for bridge0 -> rmnet_data0" >> $BOOTLOG

# 5. Log network state
echo "" >> $BOOTLOG
echo "--- INTERFACES ---" >> $BOOTLOG
ifconfig | grep -E '^[a-z]|inet ' >> $BOOTLOG 2>&1

echo "" >> $BOOTLOG
echo "--- ROUTING ---" >> $BOOTLOG
route -n >> $BOOTLOG 2>&1

echo "" >> $BOOTLOG
echo "--- NAT POSTROUTING ---" >> $BOOTLOG
iptables -t nat -L POSTROUTING -n >> $BOOTLOG 2>&1

# 6. Apply saved settings from config
CONFIG_FILE="/data/dagshell_config"
if [ -f "$CONFIG_FILE" ]; then
    echo "" >> $BOOTLOG
    echo "--- APPLYING SAVED SETTINGS ---" >> $BOOTLOG
    
    # Apply TTL if set
    TTL=$(grep "^default_ttl=" "$CONFIG_FILE" | cut -d= -f2)
    if [ -n "$TTL" ] && [ "$TTL" -gt 0 ] 2>/dev/null; then
        iptables -t mangle -I POSTROUTING 1 -j TTL --ttl-set $TTL
        echo "[OK] TTL set to $TTL" >> $BOOTLOG
    fi
    
    # Apply MAC spoof if set
    MAC=$(grep "^spoofed_mac=" "$CONFIG_FILE" | cut -d= -f2)
    if [ -n "$MAC" ] && [ ${#MAC} -ge 17 ]; then
        ifconfig wlan1 down
        ifconfig wlan1 hw ether $MAC
        ifconfig wlan1 up
        echo "[OK] MAC spoofed to $MAC" >> $BOOTLOG
    fi
fi

# 7. Start DagShell
sleep 5
/data/orbic_app &
echo "" >> $BOOTLOG
echo "[OK] orbic_app started PID=$!" >> $BOOTLOG
echo "=== BOOT COMPLETE ===" >> $BOOTLOG

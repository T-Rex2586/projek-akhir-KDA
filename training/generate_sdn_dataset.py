#!/usr/bin/env python3
"""Generate SDN-level training dataset from PCAP files.

Reads PCAP files from data/raw/, groups packets into 10-second time windows,
computes 5 SDN features (APf, ABf, GDP, NFi, NSi) per window with labels,
and saves to CSV for RF training.
"""

import argparse
import csv
import os
import sys
from collections import defaultdict
from scapy.all import rdpcap, IP, UDP, TCP, ICMP

TIME_WINDOW = 10
RAW_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "raw")
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "processed")
CSV_HEADER = ["APf", "ABf", "GDP", "NFi", "NSi", "label"]


def get_flow_key(pkt):
    """Extract 5-tuple flow key from a packet."""
    if not pkt.haslayer(IP):
        return None
    ip = pkt[IP]
    proto = ip.proto
    src = ip.src
    dst = ip.dst
    
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    else:
        sport = 0
        dport = 0
    
    return (src, dst, sport, dport, proto)


def extract_features_from_window(packets, window_start, window_end):
    """Compute 5 SDN features from a list of packets in a time window.

    SDN simulation: the first packet of each flow is forwarded via
    packet_out (not counted in flow stats), so we skip it here.
    """
    flows = defaultdict(lambda: {"packets": 0, "bytes": 0, "ports": set()})
    first_packet_seen = set()
    total_packets = 0
    total_bytes = 0
    
    for pkt in packets:
        key = get_flow_key(pkt)
        if key is None:
            continue
        # Track ports for GDP (info available even from first packet via packet_out)
        flows[key]["ports"].add(key[2])
        flows[key]["ports"].add(key[3])
        # Skip first packet of each flow (SDN: forwarded via packet_out, not in flow stats)
        if key not in first_packet_seen:
            first_packet_seen.add(key)
            continue
        flows[key]["packets"] += 1
        flows[key]["bytes"] += len(pkt)
        total_packets += 1
        total_bytes += len(pkt)
    
    if not flows:
        return None
    
    nfi = len(flows)
    apf = total_packets / nfi if nfi > 0 else 0
    abf = total_bytes / nfi if nfi > 0 else 0
    nsi = len(set(k[0] for k in flows.keys()))
    
    return {
        "APf": round(apf, 4),
        "ABf": round(abf, 4),
        "NFi": nfi,
        "NSi": nsi,
    }


def process_pcap(pcap_path, label):
    """Process a single PCAP file and return list of feature rows."""
    print(f"  Reading {pcap_path}...")
    packets = rdpcap(pcap_path)
    print(f"    Total packets: {len(packets)}")
    
    if len(packets) == 0:
        return []
    
    # Group packets by time window
    start_time = float(packets[0].time)
    windows = defaultdict(list)
    
    for pkt in packets:
        ts = float(pkt.time)
        window_idx = int((ts - start_time) // TIME_WINDOW)
        windows[window_idx].append(pkt)
    
    rows = []
    previous_ports = set()
    
    for idx in sorted(windows.keys()):
        ws = start_time + idx * TIME_WINDOW
        we = ws + TIME_WINDOW
        feat = extract_features_from_window(windows[idx], ws, we)
        if feat is None:
            continue
        
        # Compute GDP: new unique ports in this window
        current_ports = set()
        for pkt in windows[idx]:
            if pkt.haslayer(TCP):
                current_ports.add(pkt[TCP].sport)
                current_ports.add(pkt[TCP].dport)
            elif pkt.haslayer(UDP):
                current_ports.add(pkt[UDP].sport)
                current_ports.add(pkt[UDP].dport)
        
        new_ports = current_ports - previous_ports
        gdp = len(new_ports)
        previous_ports = current_ports
        
        rows.append({
            "APf": feat["APf"],
            "ABf": feat["ABf"],
            "GDP": gdp,
            "NFi": feat["NFi"],
            "NSi": feat["NSi"],
            "label": label,
        })
    
    return rows


def main():
    parser = argparse.ArgumentParser(description="Generate SDN dataset from PCAP files")
    parser.add_argument("--input", default=RAW_DIR, help="Input directory with PCAP files")
    parser.add_argument("--output", default=None, help="Output CSV path")
    args = parser.parse_args()
    
    if args.output:
        output_path = args.output
    else:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        output_path = os.path.join(OUTPUT_DIR, "sdn_training_data.csv")
    
    all_rows = []
    
    for fname in sorted(os.listdir(args.input)):
        if not fname.endswith(".pcap"):
            continue
        
        # Label: 1 (DDoS) for non-Benign files, 0 (Normal) for Benign
        label = 0 if "Benign" in fname else 1
        
        pcap_path = os.path.join(args.input, fname)
        rows = process_pcap(pcap_path, label)
        all_rows.extend(rows)
        
        ddos_count = sum(1 for r in rows if r["label"] == 1)
        normal_count = sum(1 for r in rows if r["label"] == 0)
        print(f"    → {len(rows)} windows ({normal_count} Normal, {ddos_count} DDoS)\n")
    
    if not all_rows:
        print("No data generated!")
        return
    
    # Add synthetic DDoS samples simulating random-src-IP attacks
    # Real-time SDN behavior: each unique src IP = new flow,
    # first packet per flow not counted → APf=0, ABf=0, NSi≈NFi
    import random
    random.seed(42)
    syn_ddos = []
    for _ in range(200):
        nfi = random.randint(50, 2000)
        nsi = random.randint(int(nfi * 0.8), nfi)
        gdp = random.randint(10, min(500, nfi))
        syn_ddos.append({"APf": 0, "ABf": 0, "GDP": gdp, "NFi": nfi, "NSi": nsi, "label": 1})
    all_rows.extend(syn_ddos)
    print(f"Added {len(syn_ddos)} synthetic DDoS samples (random-src-IP simulation)")
    
    # Add synthetic Normal samples (low NFi/NSi) so model doesn't just
    # classify APf=0 as DDoS
    syn_normal = []
    for _ in range(50):
        nfi = random.randint(1, 20)
        nsi = random.randint(1, nfi)
        gdp = random.randint(0, 10)
        syn_normal.append({"APf": 0, "ABf": 0, "GDP": gdp, "NFi": nfi, "NSi": nsi, "label": 0})
    all_rows.extend(syn_normal)
    print(f"Added {len(syn_normal)} synthetic Normal samples (low-flow APf=0)")
    
    # Write CSV
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
        writer.writeheader()
        writer.writerows(all_rows)
    
    total_ddos = sum(1 for r in all_rows if r["label"] == 1)
    total_normal = sum(1 for r in all_rows if r["label"] == 0)
    print(f"\n=== Saved to {output_path} ===")
    print(f"Total samples: {len(all_rows)} ({total_normal} Normal, {total_ddos} DDoS)")


if __name__ == "__main__":
    main()

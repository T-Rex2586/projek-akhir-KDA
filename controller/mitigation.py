# Copyright (c) 2024 - DDoS Detection Project
# Mitigation Module for SDN DDoS Detection

import time
import csv
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOGS_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")


class MitigationEngine:
    """DDoS Attack Mitigation Engine - installs OpenFlow drop rules."""

    def __init__(self, log_path=None, datapath=None):
        self.datapath = datapath
        self.blocked_ips = set()
        self.mitigation_log = []
        if log_path is None:
            os.makedirs(LOGS_FOLDER, exist_ok=True)
            self.log_path = os.path.join(LOGS_FOLDER, "attack_log.csv")
        else:
            self.log_path = log_path
        self._init_log_file()

    def _init_log_file(self):
        if not os.path.exists(self.log_path):
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
            with open(self.log_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'Source_IP', 'Destination_IP',
                    'Prediction', 'Confidence_Score', 'Detection_Time_ms',
                    'Mitigation_Time_ms', 'Action_Taken'])

    def mitigate(self, src_ip, dst_ip, confidence, detection_time_ms, priority=100, timeout=300):
        start_time = time.time()
        if self.datapath is not None:
            action = self._install_drop_rule(src_ip, priority, timeout)
        else:
            action = self._simulate_mitigation(src_ip, priority, timeout)
        mitigation_time = (time.time() - start_time) * 1000

        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip, 'dst_ip': dst_ip,
            'prediction': 'DDoS', 'confidence': confidence,
            'detection_time_ms': detection_time_ms,
            'mitigation_time_ms': mitigation_time, 'action': action
        }
        self.mitigation_log.append(log_entry)
        self._write_log(log_entry)
        return mitigation_time, action

    def _install_drop_rule(self, attacker_ip, priority=100, timeout=300):
        try:
            parser = self.datapath.ofproto_parser
            ofproto = self.datapath.ofproto
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
            actions = []
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=self.datapath, priority=priority,
                match=match, instructions=inst, hard_timeout=timeout)
            self.datapath.send_msg(mod)
            self.blocked_ips.add(attacker_ip)
            return f"DROP_RULE_INSTALLED(ip={attacker_ip}, priority={priority}, timeout={timeout}s)"
        except Exception as e:
            return f"MITIGATION_FAILED(ip={attacker_ip}, error={str(e)})"

    def _simulate_mitigation(self, attacker_ip, priority=100, timeout=300):
        self.blocked_ips.add(attacker_ip)
        time.sleep(0.001)
        return f"SIMULATED_DROP(ip={attacker_ip}, priority={priority}, timeout={timeout}s)"

    def _write_log(self, entry):
        with open(self.log_path, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([entry['timestamp'], entry['src_ip'], entry['dst_ip'],
                entry['prediction'], f"{entry['confidence']:.4f}",
                f"{entry['detection_time_ms']:.2f}", f"{entry['mitigation_time_ms']:.2f}",
                entry['action']])

    def is_blocked(self, ip):
        return ip in self.blocked_ips

    def get_blocked_ips(self):
        return self.blocked_ips.copy()

    def get_stats(self):
        total = len(self.mitigation_log)
        if total == 0:
            return {'total_mitigations': 0, 'blocked_ips': 0, 'avg_mitigation_time_ms': 0}
        avg_time = sum(e['mitigation_time_ms'] for e in self.mitigation_log) / total
        return {'total_mitigations': total, 'blocked_ips': len(self.blocked_ips),
                'avg_mitigation_time_ms': avg_time,
                'unique_attackers': len(set(e['src_ip'] for e in self.mitigation_log))}

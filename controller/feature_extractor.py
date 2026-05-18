# Copyright (c) 2024 - DDoS Detection Project
# Feature Extractor Module for SDN Controller
#
# Computes the 5 key features from flow statistics:
# - APf: Average Packets per Flow
# - ABf: Average Bytes per Flow
# - GDP: Growth of Different Ports
# - NFi: Number of Flow Entries per Interval
# - NSi: Number of Source IPs per Interval
#
# These features are used as input to the LUCID-based Random Forest model
# that uses packet-level features (timestamp, packet_length, highest_layer,
# IP_flags, protocols, TCP_length, TCP_ack, TCP_flags, TCP_window_size,
# UDP_length, ICMP_type).

import numpy as np
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.util_functions import feature_list, static_min_max, normalize_and_padding


class FeatureExtractor:
    """
    Extracts statistical features from SDN flow statistics.

    This class supports two modes:
    1. SDN Flow Stats Mode: Computes APf, ABf, GDP, NFi, NSi from
       OpenFlow flow statistics (for real-time SDN detection).
    2. LUCID Packet Mode: Processes packet-level features from
       the LUCID framework (for the trained RF model).
    """

    def __init__(self, time_window=10, max_flow_len=10):
        """
        Initialize the feature extractor.

        Args:
            time_window: Time window in seconds for flow grouping
            max_flow_len: Maximum number of packets per flow
        """
        self.time_window = time_window
        self.max_flow_len = max_flow_len
        self.feature_names = list(feature_list.keys())
        self.mins, self.maxs = static_min_max(time_window)
        self.flow_history = {}
        self.previous_ports = set()

    def extract_sdn_features(self, flow_stats):
        """
        Extract the 5 SDN-level features from OpenFlow flow statistics.

        Features (as defined in the paper):
        - APf: Average Packets per Flow = total_packets / total_flows
        - ABf: Average Bytes per Flow = total_bytes / total_flows
        - GDP: Growth of Different Ports (new unique ports in this interval)
        - NFi: Number of Flow entries in this interval
        - NSi: Number of unique Source IPs in this interval

        Args:
            flow_stats: List of dicts with keys:
                - 'packet_count': Number of packets in the flow
                - 'byte_count': Number of bytes in the flow
                - 'src_ip': Source IP address
                - 'dst_port': Destination port
                - 'src_port': Source port

        Returns:
            features: numpy array [APf, ABf, GDP, NFi, NSi]
        """
        if not flow_stats:
            return np.zeros(5)

        total_flows = len(flow_stats)
        total_packets = sum(f.get('packet_count', 0) for f in flow_stats)
        total_bytes = sum(f.get('byte_count', 0) for f in flow_stats)

        # APf: Average Packets per Flow
        apf = total_packets / total_flows if total_flows > 0 else 0

        # ABf: Average Bytes per Flow
        abf = total_bytes / total_flows if total_flows > 0 else 0

        # GDP: Growth of Different Ports
        current_ports = set()
        for f in flow_stats:
            current_ports.add(f.get('dst_port', 0))
            current_ports.add(f.get('src_port', 0))
        new_ports = current_ports - self.previous_ports
        gdp = len(new_ports)
        self.previous_ports = current_ports

        # NFi: Number of Flow entries
        nfi = total_flows

        # NSi: Number of unique Source IPs
        source_ips = set(f.get('src_ip', '') for f in flow_stats)
        nsi = len(source_ips)

        features = np.array([apf, abf, gdp, nfi, nsi])
        return features

    def extract_packet_features(self, samples, normalize=True):
        """
        Process LUCID-style packet samples for RF model prediction.

        Args:
            samples: List of flow samples (from LUCID dataset parser)
            normalize: Whether to normalize features

        Returns:
            X: numpy array suitable for RF prediction (flattened 2D)
            Y_true: Labels if available, else None
            keys: Flow identifiers
        """
        from src.lucid_dataset_parser import dataset_to_list_of_fragments

        X, Y_true, keys = dataset_to_list_of_fragments(samples)

        if normalize:
            X = np.array(normalize_and_padding(X, self.mins, self.maxs, self.max_flow_len))
        else:
            X = np.array(X)

        # Flatten for Random Forest (2D input)
        X = X.reshape(X.shape[0], -1)

        if Y_true:
            Y_true = np.array(Y_true)
        else:
            Y_true = None

        return X, Y_true, keys

    def get_feature_names(self):
        """Return the list of LUCID packet-level feature names."""
        return self.feature_names

    def get_sdn_feature_names(self):
        """Return the list of SDN-level feature names."""
        return ['APf', 'ABf', 'GDP', 'NFi', 'NSi']

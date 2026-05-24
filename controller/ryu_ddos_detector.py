# Copyright (c) 2024 - DDoS Detection Project
# Ryu SDN Controller Application for DDoS Detection
#
# Main Ryu application that performs:
# 1. L2 Learning Switch (packet forwarding)
# 2. Flow Monitoring
# 3. Feature Extraction
# 4. Random Forest Inference
# 5. Attack Classification
# 6. Automated Mitigation
# 7. Logging
#
# NOTE: This module requires the Ryu SDN framework and is designed
# to run in a Linux/SDN environment with Open vSwitch.
# It will not run on Windows without the Ryu controller.
#
# Usage (on Linux with Ryu installed):
#   ryu-manager controller/ryu_ddos_detector.py

import os
import sys
import time
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
    from ryu.ofproto import ofproto_v1_3
    from ryu.lib.packet import packet, ethernet, ipv4, ether_types
    from ryu.lib import hub
    RYU_AVAILABLE = True
except ImportError:
    RYU_AVAILABLE = False
    print("WARNING: Ryu framework not available. This module requires a Linux SDN environment.")

from controller.predictor import DDoSPredictor
from controller.feature_extractor import FeatureExtractor
from controller.mitigation import MitigationEngine

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "models", "rf_ddos_sdn_model.pkl")
MONITOR_INTERVAL = 10  # seconds


if RYU_AVAILABLE:
    class DDoSDetectorApp(app_manager.RyuApp):
        """Ryu SDN Controller App for real-time DDoS detection and mitigation.

        This app acts as both an L2 learning switch (forwarding packets)
        AND a DDoS detector (monitoring flow statistics and applying
        mitigation rules when attacks are detected).
        """

        OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.mac_to_port = {}
            self.predictor = DDoSPredictor(MODEL_PATH)
            self.feature_extractor = FeatureExtractor(time_window=MONITOR_INTERVAL)
            self.mitigation = MitigationEngine()
            self.datapaths = {}
            self.pkt_count = 0
            self.monitor_thread = hub.spawn(self._monitor)
            self.logger.info("DDoS Detector initialized with RF model")

        def _monitor(self):
            """Periodically request flow statistics from all switches."""
            while True:
                for dp_id, dp in self.datapaths.items():
                    self._request_stats(dp)
                hub.sleep(MONITOR_INTERVAL)

        def _request_stats(self, datapath):
            parser = datapath.ofproto_parser
            req = parser.OFPFlowStatsRequest(datapath)
            datapath.send_msg(req)

        @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
        def switch_features_handler(self, ev):
            datapath = ev.msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            self.datapaths[datapath.id] = datapath
            self.mitigation.datapath = datapath
            # Table-miss: send unknown packets to controller
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self._add_flow(datapath, 0, match, actions)
            self.logger.info(f"Switch {datapath.id} connected")

        def _add_flow(self, datapath, priority, match, actions, hard_timeout=0, idle_timeout=0):
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                match=match, instructions=inst,
                hard_timeout=hard_timeout, idle_timeout=idle_timeout)
            datapath.send_msg(mod)

        # ------------------------------------------------------------------
        # L2 Learning Switch — packet_in handler
        # ------------------------------------------------------------------
        # Without this handler, the switch sends every packet to the
        # controller (table-miss) but nothing is ever forwarded back.
        # This implements standard MAC learning + flow installation.
        # ------------------------------------------------------------------
        @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
        def packet_in_handler(self, ev):
            """Handle packet-in events — implement learning switch with L3 flows.

            Installs L3 (IPv4) flow rules so that flow stats contain
            ipv4_src/ipv4_dst fields, enabling DDoS detection in
            flow_stats_reply_handler.
            """
            msg = ev.msg
            datapath = msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            in_port = msg.match['in_port']

            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocols(ethernet.ethernet)[0]

            # Ignore LLDP and IPv6 multicast discovery packets
            if eth.ethertype == ether_types.ETH_TYPE_LLDP:
                return
            if eth.ethertype == ether_types.ETH_TYPE_IPV6:
                return

            dst = eth.dst
            src = eth.src
            dpid = datapath.id

            self.pkt_count += 1

            self.mac_to_port.setdefault(dpid, {})

            # Learn: associate source MAC with the ingress port
            self.mac_to_port[dpid][src] = in_port

            # Decide output port
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            # Install a flow rule so future packets don't hit the controller
            if out_port != ofproto.OFPP_FLOOD:
                ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
                if ipv4_pkt:
                    # L3 flow: match on IP src/dst so stats carry ipv4_src
                    if self.pkt_count % 100 == 0 or self.pkt_count == 1:
                        self.logger.info(f"  Installing L3 flow: {ipv4_pkt.src} -> {ipv4_pkt.dst}")
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=ipv4_pkt.src,
                        ipv4_dst=ipv4_pkt.dst,
                    )
                    self._add_flow(datapath, 1, match, actions, idle_timeout=30)
                # Non-IP traffic (ARP, etc.): don't install any flow
                # so they always go through the controller.
                # This prevents L2 flows from masking L3 traffic.
                elif self.pkt_count % 100 == 0 or self.pkt_count == 1:
                    self.logger.info(f"  Skipping flow install for non-IP (eth_type={eth.ethertype})")

            # Send the buffered/received packet out
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data
            )
            datapath.send_msg(out)

        # ------------------------------------------------------------------
        # DDoS Detection — flow stats handler
        # ------------------------------------------------------------------
        @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
        def flow_stats_reply_handler(self, ev):
            """Process flow statistics and detect DDoS attacks."""
            body = ev.msg.body
            datapath = ev.msg.datapath

            if not body:
                return

            flow_stats = []
            for stat in body:
                try:
                    src_ip = stat.match.get('ipv4_src', None)
                except Exception:
                    src_ip = None
                if src_ip is not None:
                    dst_port = stat.match.get('tcp_dst', stat.match.get('udp_dst', 0))
                    src_port = stat.match.get('tcp_src', stat.match.get('udp_src', 0))
                    flow_stats.append({
                        'src_ip': src_ip,
                        'packet_count': stat.packet_count,
                        'byte_count': stat.byte_count,
                        'dst_port': dst_port,
                        'src_port': src_port,
                    })

            if not flow_stats:
                return

            # Extract features and predict
            features = self.feature_extractor.extract_sdn_features(flow_stats)
            features_2d = features.reshape(1, -1)

            self.logger.info(f"  Features: {features}")
            predictions, confidence, det_time = self.predictor.predict(features_2d)
            self.logger.info(f"  Prediction: {predictions[0]}, Confidence: {confidence[0]:.4f}")

            if predictions[0] == 1:
                # DDoS detected! Find top attacker IP
                ip_counts = {}
                for f in flow_stats:
                    ip = f['src_ip']
                    ip_counts[ip] = ip_counts.get(ip, 0) + f['packet_count']

                top_attacker = max(ip_counts, key=ip_counts.get)
                self.logger.warning(
                    f"DDoS DETECTED! Attacker: {top_attacker}, Confidence: {confidence[0]:.4f}")

                if not self.mitigation.is_blocked(top_attacker):
                    mit_time, action = self.mitigation.mitigate(
                        src_ip=top_attacker, dst_ip="victim",
                        confidence=confidence[0], detection_time_ms=det_time * 1000)
                    self.logger.info(f"Mitigation: {action} (took {mit_time:.2f}ms)")
else:
    print("Ryu controller module loaded in simulation mode (no Ryu framework available)")

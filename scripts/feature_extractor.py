"""
NEXUS - High-Speed Packet Feature Extractor
Extracts normalized 12-dimensional feature vectors from Scapy packets in real time.
"""

import time
import os
import numpy as np
from scapy.all import IP, TCP, UDP, ICMP, Raw, Ether, wrpcap, rdpcap

FEATURE_NAMES = [
    "packet_len",          # 0: Normalized packet length (0-1500 MTU)
    "protocol",            # 1: Protocol category (TCP=0.6, UDP=0.17, ICMP=0.01, other=0.0)
    "src_port",            # 2: Normalized source port (0-65535)
    "dst_port",            # 3: Normalized destination port (0-65535)
    "is_syn",              # 4: Pure SYN packet flag (potential scan / SYN flood)
    "is_ack",              # 5: ACK packet flag
    "is_fin_rst",          # 6: FIN or RST packet flag (teardown or rejection)
    "payload_len",         # 7: Normalized raw payload size (0-1500)
    "tcp_window",          # 8: Normalized TCP window size (0-65535)
    "ip_ttl",              # 9: Normalized IP Time To Live (0-255)
    "inter_arrival_time",  # 10: Delta time since previous packet on interface
    "stream_rate",         # 11: Exponential moving average packet rate
]

NUM_FEATURES = len(FEATURE_NAMES)


class PacketFeatureExtractor:
    def __init__(self, ema_alpha: float = 0.2):
        self.last_timestamp = None
        self.ema_alpha = ema_alpha
        self.packet_rate_ema = 0.0

    def reset(self):
        self.last_timestamp = None
        self.packet_rate_ema = 0.0

    def extract(self, packet, current_time: float = None) -> np.ndarray:
        """
        Converts a single Scapy packet into a 12-dim float32 feature vector.
        """
        if current_time is None:
            # Use packet epoch time if present, else system clock
            current_time = float(getattr(packet, 'time', time.time()))

        # 0: Packet length normalized to standard MTU (1500 bytes)
        raw_len = len(packet)
        f_len = min(1.0, float(raw_len) / 1500.0)

        # 1, 9: IP Protocol and TTL
        f_proto = 0.0
        f_ttl = 0.5  # default baseline
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            f_ttl = float(ip_layer.ttl) / 255.0
            if ip_layer.proto == 6:     # TCP
                f_proto = 0.6
            elif ip_layer.proto == 17:  # UDP
                f_proto = 0.17
            elif ip_layer.proto == 1:   # ICMP
                f_proto = 0.01
            else:
                f_proto = float(ip_layer.proto % 100) / 100.0

        # 2, 3, 4, 5, 6, 8: Transport layer & flags
        f_sport = 0.0
        f_dport = 0.0
        f_syn = 0.0
        f_ack = 0.0
        f_fin_rst = 0.0
        f_window = 0.0

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            f_sport = float(tcp.sport) / 65535.0
            f_dport = float(tcp.dport) / 65535.0
            f_window = float(tcp.window) / 65535.0

            flags = int(tcp.flags)
            is_syn_flag = bool(flags & 0x02)
            is_ack_flag = bool(flags & 0x10)
            is_rst_flag = bool(flags & 0x04)
            is_fin_flag = bool(flags & 0x01)

            # SYN without ACK indicates initiation / port scan
            f_syn = 1.0 if (is_syn_flag and not is_ack_flag) else 0.0
            f_ack = 1.0 if is_ack_flag else 0.0
            f_fin_rst = 1.0 if (is_rst_flag or is_fin_flag) else 0.0

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            f_sport = float(udp.sport) / 65535.0
            f_dport = float(udp.dport) / 65535.0

        # 7: Payload length
        f_payload = 0.0
        if packet.haslayer(Raw):
            f_payload = min(1.0, float(len(packet[Raw].load)) / 1500.0)

        # 10, 11: Timing & Packet rate
        if self.last_timestamp is None:
            delta_t = 0.1
            instant_rate = 1.0
        else:
            delta_t = max(0.000001, current_time - self.last_timestamp)
            instant_rate = min(1000.0, 1.0 / delta_t)

        self.last_timestamp = current_time

        # Update EMA rate
        self.packet_rate_ema = (self.ema_alpha * instant_rate) + ((1.0 - self.ema_alpha) * self.packet_rate_ema)
        # Normalize delta_t (clip to 1.0 sec) and rate (clip to 200 pkt/sec)
        f_delta_t = min(1.0, delta_t)
        f_rate = min(1.0, self.packet_rate_ema / 200.0)

        return np.array([
            f_len, f_proto, f_sport, f_dport,
            f_syn, f_ack, f_fin_rst, f_payload,
            f_window, f_ttl, f_delta_t, f_rate
        ], dtype=np.float32)


def extract_from_pcap(pcap_file: str) -> np.ndarray:
    """Reads a PCAP file and returns an (N, 12) numpy matrix."""
    if not os.path.exists(pcap_file):
        raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
    packets = rdpcap(pcap_file)
    extractor = PacketFeatureExtractor()
    features = []
    for pkt in packets:
        features.append(extractor.extract(pkt))
    if not features:
        return np.empty((0, NUM_FEATURES), dtype=np.float32)
    return np.vstack(features)


def generate_synthetic_datasets(base_dir: str = "."):
    """
    Generates synthetic PCAPs for training and baseline verification:
    - Normal: Web browsing, DNS lookups, keep-alives, steady intervals.
    - Attack: Fast SYN floods, aggressive port scans, malformed payloads.
    """
    import random

    normal_dir = os.path.join(base_dir, "data", "normal_traffic")
    attack_dir = os.path.join(base_dir, "data", "attack_samples")
    os.makedirs(normal_dir, exist_ok=True)
    os.makedirs(attack_dir, exist_ok=True)

    normal_pcap = os.path.join(normal_dir, "baseline_traffic.pcap")
    attack_pcap = os.path.join(attack_dir, "synflood_portscan.pcap")

    print("[NEXUS Extractor] Synthesizing baseline normal network traffic...")
    normal_pkts = []
    cur_time = time.time()
    # 300 normal packets: DNS, HTTPS handshakes, ACK sequences, HTTP data
    for _ in range(300):
        cur_time += random.uniform(0.02, 0.25)
        proto_choice = random.random()
        if proto_choice < 0.6:
            # Established TCP conversation (ACK, PSH-ACK)
            p = Ether()/IP(src="192.168.1.50", dst="142.250.190.46", ttl=64)/\
                TCP(sport=random.randint(49152, 65535), dport=443, flags="PA", window=64240)/\
                Raw(load=b"X" * random.randint(50, 800))
        elif proto_choice < 0.85:
            # DNS query / reply
            p = Ether()/IP(src="192.168.1.50", dst="8.8.8.8", ttl=64)/\
                UDP(sport=random.randint(49152, 65535), dport=53)/\
                Raw(load=b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")
        else:
            # ICMP Ping echo request/reply
            p = Ether()/IP(src="192.168.1.50", dst="192.168.1.1", ttl=64)/\
                ICMP(type=8, code=0)/\
                Raw(load=b"abcdefghijklmnopqrstuvwabcdefghi")
        p.time = cur_time
        normal_pkts.append(p)
    wrpcap(normal_pcap, normal_pkts)
    print(f" -> Wrote {len(normal_pkts)} normal packets to {normal_pcap}")

    print("[NEXUS Extractor] Synthesizing malicious attack traffic...")
    attack_pkts = []
    cur_time = time.time()
    # 1. TCP Port Scan (Nmap-like SYN sweep across sequential target ports)
    for target_port in range(20, 150):
        cur_time += random.uniform(0.0005, 0.003)  # Rapid arrival
        p = Ether()/IP(src="10.0.0.99", dst="192.168.1.50", ttl=48)/\
            TCP(sport=random.randint(40000, 60000), dport=target_port, flags="S", window=1024)
        p.time = cur_time
        attack_pkts.append(p)

    # 2. High-Rate SYN Flood
    for _ in range(200):
        cur_time += random.uniform(0.0001, 0.001)
        spoofed_ip = f"172.16.{random.randint(1, 254)}.{random.randint(1, 254)}"
        p = Ether()/IP(src=spoofed_ip, dst="192.168.1.50", ttl=32)/\
            TCP(sport=random.randint(1024, 65535), dport=80, flags="S", window=512)
        p.time = cur_time
        attack_pkts.append(p)

    wrpcap(attack_pcap, attack_pkts)
    print(f" -> Wrote {len(attack_pkts)} attack packets to {attack_pcap}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="NEXUS Packet Feature Extractor")
    parser.add_argument("--generate-synthetic", action="store_true", help="Generate synthetic baseline & attack PCAPs")
    parser.add_argument("--pcap", type=str, help="Extract features from a specific PCAP file")
    args = parser.parse_args()

    if args.generate_synthetic:
        generate_synthetic_datasets(base_dir=".")
    elif args.pcap:
        feats = extract_from_pcap(args.pcap)
        print(f"Extracted feature matrix shape: {feats.shape}")
        if len(feats) > 0:
            print(f"Sample feature vector (packet #0):\n{feats[0]}")
    else:
        # Self-test with synthetic generation
        generate_synthetic_datasets(base_dir=".")

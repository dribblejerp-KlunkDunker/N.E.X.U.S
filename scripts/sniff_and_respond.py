"""
NEXUS - Real-Time Intrusion Detection & Defensive Flow Intelligence Engine
Combines the Capture, State, Detection, and Response planes:
- State Plane: Passive TCP flow tracking, sequence tracking, and RFC 5961 challenge-ACK validation.
- Detection Plane: NEAT champion neural network scoring and RST anomaly heuristics.
- Response Plane: Authorized firewall policy enforcement (Windows Firewall / iptables).
- Investigation Plane: Forensic timeline and evidence artifact dumps.
- Lab Mode: Opt-in simulation of forged Demonic Skull TCP RST for controlled environments.
"""

import sys
import os
import time
import pickle
import subprocess
import argparse
import logging
from datetime import datetime
import numpy as np
import neat
from scapy.all import sniff, send, IP, TCP, UDP, Raw, conf

# Add scripts directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import PacketFeatureExtractor
from passive_flow_tracker import PassiveTcpFlowTracker

# ====================================================================
# DEMONIC SKULL COUNTERMEASURE PAYLOAD (FOR LAB / SIMULATION USE)
# ====================================================================
DEMONIC_SKULL_ASCII = """
      (                 )
      |\\   _,,,---,,_   /|
      / /`--'        `--'\\ \\
     / /                  \\ \\
    | |    (o)      (o)    | |
    | |        /\\          | |
     \\ \\     \\______/     / /
      \\ \\                / /
       `--||||||||||||||--'
          |            |
          `------------'
=======================================
     I'VE ALREADY TASTED YOUR IP
=======================================
"""

DEMONIC_PAYLOAD_BYTES = DEMONIC_SKULL_ASCII.strip().encode("ascii", errors="ignore")

WHITELIST_IPS = {"127.0.0.1", "::1", "0.0.0.0"}
RELOAD_SIGNAL_FILE = "genomes/.reload_signal"


class NexusGuardian:
    def __init__(
        self,
        champion_path: str = "genomes/champion.pkl",
        threshold: float = 0.85,
        active_defense: bool = False,
        inject_simulated_rst: bool = False,
        log_file: str = "logs/nexus_events.log",
        evidence_dir: str = "logs/evidence"
    ):
        self.champion_path = champion_path
        self.threshold = threshold
        self.active_defense = active_defense
        self.inject_simulated_rst = inject_simulated_rst
        self.evidence_dir = evidence_dir
        self.blocked_ips = set()
        self.extractor = PacketFeatureExtractor()
        self.flow_tracker = PassiveTcpFlowTracker(timeout_seconds=120.0, history_size=8)
        self.last_reload_time = 0.0

        # Setup logging
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        os.makedirs(evidence_dir, exist_ok=True)
        self.logger = logging.getLogger("NEXUS")
        self.logger.setLevel(logging.INFO)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        formatter = logging.Formatter("[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        fh.setFormatter(formatter)
        if not self.logger.handlers:
            self.logger.addHandler(fh)
            ch = logging.StreamHandler(sys.stdout)
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)

        # Load champion genome
        self.load_champion(self.champion_path)

    def load_champion(self, champion_path: str):
        if not os.path.exists(champion_path):
            raise FileNotFoundError(f"Champion genome not found at: {champion_path}")
        with open(champion_path, "rb") as f:
            data = pickle.load(f)
        self.genome = data["genome"]
        self.config = data["config"]
        self.net = neat.nn.FeedForwardNetwork.create(self.genome, self.config)
        self.last_reload_time = time.time()
        self.logger.info(f"[NEXUS] Loaded champion genome from {champion_path} (Fitness: {getattr(self.genome, 'fitness', 'N/A')})")

    def check_for_hot_reload(self):
        """Zero-downtime hot-reloading when continuous loop produces a superior champion."""
        if os.path.exists(RELOAD_SIGNAL_FILE):
            try:
                sig_mtime = os.path.getmtime(RELOAD_SIGNAL_FILE)
                if sig_mtime > self.last_reload_time:
                    self.logger.info("[HOT-RELOAD] Reload signal detected. Swapping champion neural weights...")
                    self.load_champion(self.champion_path)
            except Exception as e:
                self.logger.error(f"[HOT-RELOAD ERROR] Could not hot-reload champion: {e}")

    def block_ip(self, attacker_ip: str):
        if attacker_ip in WHITELIST_IPS or attacker_ip in self.blocked_ips:
            return

        self.blocked_ips.add(attacker_ip)
        if not self.active_defense:
            self.logger.info(f"[DRY-RUN] Would block IP via firewall: {attacker_ip}")
            return

        # OS-specific firewall blocking (Authorized Control Plane)
        try:
            if sys.platform == "win32":
                rule_name = f"NEXUS_BLOCK_{attacker_ip.replace('.', '_')}"
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={attacker_ip}'
                subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.logger.info(f"[FIREWALL] Added Windows Firewall block rule for {attacker_ip}")
            else:
                cmd = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.logger.info(f"[FIREWALL] Added iptables drop rule for {attacker_ip}")
        except Exception as e:
            self.logger.error(f"[FIREWALL ERROR] Failed to add block rule for {attacker_ip}: {e}")

    def send_demonic_rst(self, pkt):
        """
        [OPT-IN LAB TEST FIXTURE]
        Crafts and sends a TCP RST countermeasure packet injected with the demonic skull.
        Note: Modern RFC 5961 stacks reject non-exact sequence resets and issue Challenge ACKs.
        """
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        seq = pkt[TCP].seq
        ack = pkt[TCP].ack

        has_ack = bool(pkt[TCP].flags & 0x10)
        is_syn = bool(pkt[TCP].flags & 0x02)
        is_fin = bool(pkt[TCP].flags & 0x01)
        payload_len = len(pkt[Raw].load) if pkt.haslayer(Raw) else 0
        consumed = 1 if (is_syn or is_fin) else max(1, payload_len)

        resp_ack = (seq + consumed) & 0xFFFFFFFF
        resp_seq = ack if has_ack else 0

        rst_pkt = IP(src=dst_ip, dst=src_ip) / \
                  TCP(sport=dport, dport=sport, flags="RA", seq=resp_seq, ack=resp_ack) / \
                  Raw(load=DEMONIC_PAYLOAD_BYTES)

        if self.active_defense:
            try:
                send(rst_pkt, verbose=False, count=2)
                self.logger.info(f"[LAB DEMONIC RST] Dispatched horned skull RST x2 to {src_ip}:{sport} -> \"I'VE ALREADY TASTED YOUR IP\"")
            except Exception as e:
                self.logger.error(f"[DEMONIC RST ERROR] Could not transmit RST packet: {e}")
        else:
            self.logger.info(f"[DRY-RUN] Demonic RST armed for {src_ip}:{sport} (seq={resp_seq}, ack={resp_ack}, {len(DEMONIC_PAYLOAD_BYTES)} bytes payload, count=2)")

    def process_packet(self, pkt):
        # 1. Hot-reload check
        self.check_for_hot_reload()

        if not pkt.haslayer(IP):
            return

        attacker_ip = pkt[IP].src
        if attacker_ip in WHITELIST_IPS:
            return

        # 2. State Plane Observation (RFC 5961 / Passive Tracking)
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
            state_event = self.flow_tracker.observe(
                src_ip=pkt[IP].src,
                src_port=tcp.sport,
                dst_ip=pkt[IP].dst,
                dst_port=tcp.dport,
                seq=tcp.seq,
                ack=tcp.ack if (tcp.flags & 0x10) else None,
                flags=str(tcp.flags),
                payload_len=len(payload),
                window=tcp.window,
                ttl=pkt[IP].ttl,
                ts=float(getattr(pkt, "time", time.time())),
            )

            # Check for RFC 5961 / Flow anomalies
            findings = state_event.get("findings", [])
            for finding in findings:
                f_type = finding.get("type")
                f_sev = finding.get("severity", "info").upper()
                f_note = finding.get("note", "")
                self.logger.warning(f"[FLOW ANOMALY] [{f_sev}] Type: {f_type} | {f_note}")
                # Export forensic evidence artifact
                ev_file = self.flow_tracker.export_evidence_json(state_event["flow"], output_dir=self.evidence_dir)
                if ev_file:
                    self.logger.info(f"[FORENSIC EVIDENCE] Preserved flow timeline artifact: {ev_file}")

        # 3. Detection Plane: NEAT Anomaly Scoring
        feats = self.extractor.extract(pkt)
        anomaly_score = float(self.net.activate(feats)[0])

        if anomaly_score >= self.threshold:
            summary = pkt.summary()
            self.logger.warning(
                f"[ANOMALY DETECTED] Threat Score: {anomaly_score:.4f} | Attacker IP: {attacker_ip} | Pkt: {summary}"
            )

            # 4. Response Plane: Authorized Firewall Enforcement
            self.block_ip(attacker_ip)

            # 5. Optional Lab Mode: Simulated Demonic RST
            if self.inject_simulated_rst:
                self.send_demonic_rst(pkt)

    def start_sniffing(self, iface=None, count=0):
        self.logger.info(f"[NEXUS] Guardian armed. Sniffing traffic (Threshold: {self.threshold}, Active Defense: {self.active_defense}, Lab RST: {self.inject_simulated_rst})...")
        try:
            sniff(
                iface=iface,
                prn=self.process_packet,
                store=0,
                count=count
            )
        except KeyboardInterrupt:
            self.logger.info("[NEXUS] Sniffer terminated by operator.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NEXUS Live Guardian & Defensive Flow Intelligence Engine")
    parser.add_argument("--champion", type=str, default="genomes/champion.pkl", help="Champion genome path")
    parser.add_argument("--threshold", type=float, default=0.85, help="Anomaly threshold [0.0 - 1.0]")
    parser.add_argument("--active-defense", action="store_true", help="Enable live firewall blocking via netsh/iptables")
    parser.add_argument("--inject-simulated-rst", action="store_true", help="Opt-in lab mode: dispatch forged TCP RST with demonic skull")
    parser.add_argument("--iface", type=str, default=None, help="Network interface to sniff on")
    parser.add_argument("--test-packet", action="store_true", help="Send a simulated attack packet to test pipeline")
    args = parser.parse_args()

    guardian = NexusGuardian(
        champion_path=args.champion,
        threshold=args.threshold,
        active_defense=args.active_defense,
        inject_simulated_rst=args.inject_simulated_rst
    )

    if args.test_packet:
        from scapy.all import Ether
        print("\n--- SIMULATING ATTACK PACKET INGESTION & PASSIVE TRACKING ---")
        sim_attack = Ether()/IP(src="198.51.100.77", dst="192.168.1.50")/\
                     TCP(sport=55555, dport=80, flags="S", seq=1000, ack=0)
        guardian.process_packet(sim_attack)
        print("--- TEST COMPLETE ---\n")
    else:
        guardian.start_sniffing(iface=args.iface)

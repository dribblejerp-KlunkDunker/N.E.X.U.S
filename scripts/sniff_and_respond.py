"""
NEXUS - Real-Time Intrusion Detection & Defensive Flow Intelligence Engine
Combines the Capture, State, Detection, and Response planes:
- State Plane: Passive TCP flow tracking, sequence tracking, and RFC 5961 challenge-ACK validation.
- Detection Plane: NEAT champion neural network scoring and RST anomaly heuristics.
- Response Plane: Authorized firewall policy enforcement with TTL auto-expiry and rate limiting.
- Investigation Plane: Forensic timeline and evidence artifact dumps.
- Lab Mode: Opt-in simulation of bidirectional Demonic Skull TCP RST for controlled environments.
"""

import sys
import os
import time
import pickle
import subprocess
import argparse
import logging
import threading
import json
import urllib.request
from collections import deque
from datetime import datetime
from typing import Dict, Set, Optional
import numpy as np
import neat
import onnxruntime as ort
from scapy.all import sniff, send, IP, TCP, UDP, Raw, Ether, conf

# Add scripts directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import PacketFeatureExtractor
from passive_flow_tracker import PassiveTcpFlowTracker
from council_arbiter import CouncilArbiter
from whitelist_manager import WhitelistManager

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
        heightened_threshold: float = 0.70,
        escalation_threshold: float = 0.75,
        use_council: bool = True,
        use_predictive: bool = True,
        predictive_model_path: str = "models/predictive_brain.onnx",
        active_defense: bool = False,
        inject_simulated_rst: bool = False,
        bidirectional_rst: bool = False,
        ban_duration_sec: int = 1800,  # 30-minute temporary ban
        cooldown_sec: float = 30.0,     # 30-second rate limit per IP
        webhook_url: Optional[str] = None,
        whitelist_path: str = "config/whitelist.json",
        log_file: str = "logs/nexus_events.log",
        evidence_dir: str = "logs/evidence"
    ):
        self.champion_path = champion_path
        self.threshold = threshold
        self.heightened_threshold = heightened_threshold
        self.escalation_threshold = escalation_threshold
        self.use_council = use_council
        self.use_predictive = use_predictive
        self.predictive_model_path = predictive_model_path
        self.active_defense = active_defense
        self.inject_simulated_rst = inject_simulated_rst
        self.bidirectional_rst = bidirectional_rst
        self.ban_duration_sec = ban_duration_sec
        self.cooldown_sec = cooldown_sec
        self.webhook_url = webhook_url or os.getenv("NEXUS_WEBHOOK_URL")
        self.evidence_dir = evidence_dir
        self.whitelist_path = whitelist_path
        self.whitelist_manager = WhitelistManager(whitelist_path)

        # State tracking: IP -> unban timestamp
        self.banned_ips: Dict[str, float] = {}
        # Rate limiting: IP -> last countermeasure timestamp
        self.last_action_time: Dict[str, float] = {}
        self.last_reap_time = time.time()

        self.extractor = PacketFeatureExtractor()
        self.flow_tracker = PassiveTcpFlowTracker(timeout_seconds=120.0, history_size=8)
        self.last_reload_time = 0.0
        self._heightened_logged = False

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

        # Load fallback champion genome
        self.load_champion(self.champion_path)

        # Initialize Specialist Council (MoE) Arbiter
        self.council_arbiter: Optional[CouncilArbiter] = None
        if self.use_council:
            try:
                self.council_arbiter = CouncilArbiter()
                self.logger.info(f"[NEXUS] Specialist Council (MoE) online. Active Mode: {self.council_arbiter.active_mode}")
            except Exception as e:
                self.logger.warning(f"[NEXUS] Specialist Council unavailable ({e}). Fallback to monolithic champion.")

        # Initialize ONNX Predictive Brain for temporal horizon forecasting
        self.predictive_session = None
        self.predictive_buffer = deque(maxlen=30)
        self.last_recon_prob = 0.0
        if self.use_predictive and os.path.exists(self.predictive_model_path):
            try:
                self.predictive_session = ort.InferenceSession(self.predictive_model_path)
                self.logger.info(f"[NEXUS] ONNX Predictive Brain loaded ({self.predictive_model_path}). Horizon pre-emption active.")
            except Exception as e:
                self.logger.warning(f"[NEXUS] ONNX Predictive Brain failed to load ({e}). Pre-emption disabled.")

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
                    self.logger.info("[HOT-RELOAD] Reload signal detected. Swapping neural weights...")
                    if self.use_council:
                        try:
                            self.council_arbiter = CouncilArbiter()
                            self.logger.info(f"[HOT-RELOAD] Reloaded Specialist Council (MoE). Mode: {self.council_arbiter.active_mode}")
                        except Exception as ce:
                            self.logger.warning(f"[HOT-RELOAD] Council reload error: {ce}")
                    self.load_champion(self.champion_path)
            except Exception as e:
                self.logger.error(f"[HOT-RELOAD ERROR] Could not hot-reload champion: {e}")

    def reap_expired_bans(self):
        """Background garbage collector for temporary TTL-based firewall bans."""
        now = time.time()
        if now - self.last_reap_time < 10.0:
            return  # Run at most every 10 seconds
        self.last_reap_time = now

        expired = [ip for ip, expire_ts in self.banned_ips.items() if now >= expire_ts]
        for ip in expired:
            del self.banned_ips[ip]
            if self.active_defense:
                try:
                    if sys.platform == "win32":
                        rule_name = f"NEXUS_BLOCK_{ip.replace('.', '_')}"
                        cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    else:
                        cmd = f"iptables -D INPUT -s {ip} -j DROP"
                        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self.logger.info(f"[FIREWALL] Expired temporary ban for {ip}. Firewall rule removed.")
                except Exception as e:
                    self.logger.error(f"[FIREWALL UNBLOCK ERROR] Failed to unblock {ip}: {e}")
            else:
                self.logger.info(f"[DRY-RUN] Expired temporary ban for {ip}.")

    def block_ip(self, attacker_ip: str):
        """Enforces temporary IP ban with TTL auto-expiry and rate limiting."""
        now = time.time()
        if attacker_ip in WHITELIST_IPS:
            return

        # Check rate limit cooldown
        last_action = self.last_action_time.get(attacker_ip, 0.0)
        if (now - last_action) < self.cooldown_sec:
            # Within cooldown, suppress duplicate firewall spam
            return

        self.last_action_time[attacker_ip] = now
        unban_time = now + self.ban_duration_sec
        is_already_banned = (attacker_ip in self.banned_ips)
        self.banned_ips[attacker_ip] = unban_time

        if not self.active_defense:
            self.logger.info(f"[DRY-RUN] Would block IP via firewall: {attacker_ip} (TTL: {self.ban_duration_sec}s)")
            return

        if not is_already_banned:
            try:
                if sys.platform == "win32":
                    rule_name = f"NEXUS_BLOCK_{attacker_ip.replace('.', '_')}"
                    cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={attacker_ip}'
                    subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self.logger.info(f"[FIREWALL] Added Windows Firewall block rule for {attacker_ip} (TTL: {self.ban_duration_sec}s)")
                else:
                    cmd = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                    subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self.logger.info(f"[FIREWALL] Added iptables drop rule for {attacker_ip} (TTL: {self.ban_duration_sec}s)")
            except Exception as e:
                self.logger.error(f"[FIREWALL ERROR] Failed to add block rule for {attacker_ip}: {e}")

    def send_webhook_alert(self, attacker_ip: str, score: float, summary: str):
        """Dispatches an asynchronous HTTP webhook notification (Discord/Slack/Generic)."""
        if not self.webhook_url:
            return

        def _worker():
            payload = {
                "username": "NEXUS Defense Guardian",
                "content": f"🚨 **NEXUS THREAT DETECTED**\n"
                           f"• **Attacker IP**: `{attacker_ip}`\n"
                           f"• **Threat Score**: `{score:.4f}`\n"
                           f"• **Packet**: `{summary}`\n"
                           f"• **Action**: Firewall Block (TTL: {self.ban_duration_sec}s)\n"
                           f"• **Timestamp**: `{datetime.utcnow().isoformat()}Z`"
            }
            try:
                data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    self.webhook_url,
                    data=data,
                    headers={"Content-Type": "application/json", "User-Agent": "NEXUS-Defense/1.0"}
                )
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    pass
            except Exception as e:
                self.logger.error(f"[WEBHOOK ERROR] Could not dispatch alert: {e}")

        threading.Thread(target=_worker, daemon=True).start()

    def send_demonic_rst(self, pkt):
        """
        [OPT-IN LAB TEST FIXTURE]
        Crafts and sends TCP RST countermeasure packet(s).
        If bidirectional_rst is enabled, resets both attacker and local socket.
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

        # 1. Packet to Attacker (with Demonic Skull)
        rst_attacker = IP(src=dst_ip, dst=src_ip) / \
                       TCP(sport=dport, dport=sport, flags="RA", seq=resp_seq, ack=resp_ack) / \
                       Raw(load=DEMONIC_PAYLOAD_BYTES)

        # 2. Optional Packet to Local Victim Endpoint (clean teardown)
        rst_victim = None
        if self.bidirectional_rst:
            rst_victim = IP(src=src_ip, dst=dst_ip) / \
                         TCP(sport=sport, dport=dport, flags="R", seq=seq)

        if self.active_defense:
            try:
                send(rst_attacker, verbose=False, count=2)
                self.logger.info(f"[LAB DEMONIC RST] Dispatched horned skull RST x2 to {src_ip}:{sport} -> \"I'VE ALREADY TASTED YOUR IP\"")
                if rst_victim:
                    send(rst_victim, verbose=False, count=1)
                    self.logger.info(f"[LAB BIDIRECTIONAL RST] Teardown RST sent to local socket {dst_ip}:{dport}")
            except Exception as e:
                self.logger.error(f"[DEMONIC RST ERROR] Could not transmit RST packet: {e}")
        else:
            note = "bidirectional" if self.bidirectional_rst else "single"
            self.logger.info(f"[DRY-RUN] Demonic RST armed for {src_ip}:{sport} ({note}, seq={resp_seq}, ack={resp_ack}, count=2)")

    def process_packet(self, pkt):
        # 1. Housekeeping: hot-reload check & ban expiration reaper
        self.check_for_hot_reload()
        self.reap_expired_bans()

        if not pkt.haslayer(IP):
            return

        attacker_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
        sport = int(pkt[TCP].sport) if pkt.haslayer(TCP) else (int(pkt[UDP].sport) if pkt.haslayer(UDP) else None)
        dport = int(pkt[TCP].dport) if pkt.haslayer(TCP) else (int(pkt[UDP].dport) if pkt.haslayer(UDP) else None)

        is_wl, wl_reason = self.whitelist_manager.is_whitelisted(
            src_ip=attacker_ip, dst_ip=dst_ip, src_mac=src_mac, sport=sport, dport=dport
        )
        if is_wl:
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
                ev_file = self.flow_tracker.export_evidence_json(state_event["flow"], output_dir=self.evidence_dir)
                if ev_file:
                    self.logger.info(f"[FORENSIC EVIDENCE] Preserved flow timeline artifact: {ev_file}")

        # 3. Detection Plane: Specialist Council (MoE) & Monolithic Fallback
        feats_20 = self.extractor.extract(pkt, extended=True)
        leading_expert = "MONOLITH"
        if self.use_council and self.council_arbiter:
            c_res = self.council_arbiter.evaluate(feats_20)
            anomaly_score = float(c_res["score"])
            leading_expert = c_res.get("leading_expert", "NONE")
        else:
            num_in = len(self.config.genome_config.input_keys) if hasattr(self, 'config') and self.config else 20
            feats = feats_20 if num_in == 20 else feats_20[:12]
            anomaly_score = float(self.net.activate(feats)[0])

        # 4. Predictive Plane: ONNX Temporal Sequence Horizon Forecasting
        p_recon = self.last_recon_prob
        if self.use_predictive and self.predictive_session:
            vec_13 = list(feats_20[:12]) + [anomaly_score]
            self.predictive_buffer.append(vec_13)
            # Pad window to 30 steps if warming up
            seq_list = list(self.predictive_buffer)
            if len(seq_list) < 30:
                pad = [seq_list[0]] * (30 - len(seq_list))
                seq_list = pad + seq_list
            tensor_in = np.array(seq_list, dtype=np.float32).reshape(1, 30, 13)
            try:
                preds = self.predictive_session.run(["recon_probability"], {"packet_sequence": tensor_in})
                p_recon = float(preds[0][0][0])
                self.last_recon_prob = p_recon
            except Exception:
                pass

        # Dynamic Posture Adjustment: Tighten threshold when attack horizon escalates
        is_heightened = (p_recon >= self.escalation_threshold)
        effective_threshold = self.heightened_threshold if is_heightened else self.threshold
        posture = f"HEIGHTENED_PREEMPTION ({self.heightened_threshold})" if is_heightened else f"STANDARD ({self.threshold})"

        if is_heightened and not getattr(self, "_heightened_logged", False):
            self.logger.warning(
                f"[PREDICTIVE ESCALATION] Recon Probability: {p_recon:.4f} >= {self.escalation_threshold:.2f}! "
                f"Defensive Posture dynamically tightened to {self.heightened_threshold:.2f}."
            )
            self._heightened_logged = True
        elif not is_heightened:
            self._heightened_logged = False

        if anomaly_score >= effective_threshold:
            summary = pkt.summary()
            self.logger.warning(
                f"[ANOMALY DETECTED] Threat Score: {anomaly_score:.4f} [{leading_expert}] | Posture: {posture} (P_recon={p_recon:.4f}) | Attacker IP: {attacker_ip} | Pkt: {summary}"
            )

            # 5. Response Plane: Rate-limited Temporary Firewall Block
            self.block_ip(attacker_ip)
            self.send_webhook_alert(attacker_ip, anomaly_score, summary)

            # 6. Optional Lab Mode: Simulated Demonic RST
            if self.inject_simulated_rst:
                self.send_demonic_rst(pkt)

    def start_sniffing(self, iface=None, count=0):
        council_status = f"ONLINE ({self.council_arbiter.active_mode})" if (self.use_council and self.council_arbiter) else "OFFLINE (Monolith)"
        predictive_status = "ONLINE (Dynamic Pre-emption)" if (self.use_predictive and self.predictive_session) else "OFFLINE"
        self.logger.info(
            f"[NEXUS] Guardian armed. Sniffing traffic:\n"
            f"  - Base Threshold:       {self.threshold} (Heightened: {self.heightened_threshold} at P >= {self.escalation_threshold})\n"
            f"  - Specialist Council:   {council_status}\n"
            f"  - ONNX Predictive Brain:{predictive_status}\n"
            f"  - Active Firewall:      {self.active_defense}\n"
            f"  - Lab Demonic RST:      {self.inject_simulated_rst} (Bidirectional: {self.bidirectional_rst})\n"
            f"  - Temporary Ban TTL:    {self.ban_duration_sec}s\n"
            f"  - Attacker Cooldown:    {self.cooldown_sec}s"
        )
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
    parser.add_argument("--heightened-threshold", type=float, default=0.70, help="Tightened threshold during predicted escalation")
    parser.add_argument("--escalation-threshold", type=float, default=0.75, help="Recon probability trigger for heightened defense")
    parser.add_argument("--no-council", action="store_true", help="Disable Specialist Council (MoE), force monolithic champion")
    parser.add_argument("--no-predictive", action="store_true", help="Disable ONNX predictive horizon forecaster")
    parser.add_argument("--predictive-model", type=str, default="models/predictive_brain.onnx", help="Path to ONNX predictive model")
    parser.add_argument("--active-defense", action="store_true", help="Enable live firewall blocking via netsh/iptables")
    parser.add_argument("--inject-simulated-rst", action="store_true", help="Opt-in lab mode: dispatch forged TCP RST with demonic skull")
    parser.add_argument("--bidirectional-rst", action="store_true", help="In lab mode: send RST to both endpoints simultaneously")
    parser.add_argument("--ban-duration", type=int, default=1800, help="Temporary IP ban duration in seconds (default: 1800s / 30 min)")
    parser.add_argument("--cooldown", type=float, default=30.0, help="Per-IP rate-limiting cooldown in seconds")
    parser.add_argument("--webhook-url", type=str, default=None, help="Discord / Slack / Generic webhook URL for alerts")
    parser.add_argument("--whitelist", type=str, default="config/whitelist.json", help="Path to trusted whitelist JSON config")
    parser.add_argument("--iface", type=str, default=None, help="Network interface to sniff on")
    parser.add_argument("--test-packet", action="store_true", help="Send a simulated attack packet to test pipeline")
    args = parser.parse_args()

    guardian = NexusGuardian(
        champion_path=args.champion,
        threshold=args.threshold,
        heightened_threshold=args.heightened_threshold,
        escalation_threshold=args.escalation_threshold,
        use_council=not args.no_council,
        use_predictive=not args.no_predictive,
        predictive_model_path=args.predictive_model,
        active_defense=args.active_defense,
        inject_simulated_rst=args.inject_simulated_rst,
        bidirectional_rst=args.bidirectional_rst,
        ban_duration_sec=args.ban_duration,
        cooldown_sec=args.cooldown,
        webhook_url=args.webhook_url,
        whitelist_path=args.whitelist
    )

    if args.test_packet:
        from scapy.all import Ether
        print("\n--- SIMULATING ATTACK PACKET INGESTION & DEFENSIVE MITIGATION ---")
        sim_attack = Ether()/IP(src="198.51.100.77", dst="192.168.1.50")/\
                     TCP(sport=55555, dport=80, flags="S", seq=1000, ack=0)
        guardian.process_packet(sim_attack)

        print("\n--- TESTING RATE LIMITER COOLDOWN (SECOND IMMEDIATE PACKET) ---")
        guardian.process_packet(sim_attack)
        print("--- TEST COMPLETE ---\n")
    else:
        guardian.start_sniffing(iface=args.iface)

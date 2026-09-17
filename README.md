# NEXUS: Defensive TCP Flow Intelligence & Autonomous Neuroevolutionary Defense

NEXUS is an enterprise-grade network intrusion observability and defensive response engine. It combines **Passive TCP Flow Tracking (RFC 5961 compliance & Challenge-ACK detection)** with **NEAT (NeuroEvolution of Augmenting Topologies)** for microsecond packet scoring and a **PyTorch LSTM Predictive Brain** for forecasting impending multi-packet reconnaissance horizons. Defense is strictly enforced via **authorized policy devices** (Windows Firewall / `nftables` / `iptables`), preserving forensic timeline artifacts without fragile third-party packet spoofing.

---

## 5-Plane Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. CAPTURE PLANE                                                            │
│    Reads live NIC packets or PCAPs via Scapy (with fast-path normalization) │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. STATE PLANE (scripts/passive_flow_tracker.py)                            │
│    • Canonical 4-tuple hashing: ((ip_a, port_a), (ip_b, port_b))            │
│    • Dual-Leg Directional State: Leg A→B and Leg B→A (rolling history k=8)  │
│    • Expected Sequence Math: next_seq = seq + len + 1_SYN + 1_FIN           │
│    • State Machine: SYN_SEEN, ESTABLISHED_CONFIRMED, MIDSTREAM, CLOSING, etc│
└──────────────────┬───────────────────────────────────────────┬──────────────┘
                   │ Flow context & features                   │
                   ▼                                           ▼
┌──────────────────────────────────────┐    ┌─────────────────────────────────┐
│ 3. DETECTION PLANE                   │    │ 5. INVESTIGATION PLANE          │
│    • RFC 5961 Challenge-ACK Detector │    │ • Forensic Timeline Exporter    │
│    • Suspected Forged-RST Scoring    │    │ • Flow Inspection CLI           │
│    • NEAT Real-Time Threat Scorer    │    │ • Structured JSON Evidence Dumps│
│    • PyTorch LSTM Horizon Predictor  │    │   (logs/evidence/*.json)        │
└──────────────────┬───────────────────┘    └─────────────────────────────────┘
                   │ Verified high-confidence threat
                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. RESPONSE PLANE                                                           │
│    Authorized Policy Enforcement:                                           │
│    • Windows Firewall (`netsh advfirewall firewall add rule ...`)           │
│    • Linux `nftables` / `iptables` drop rules                               │
│    • SIEM Audit Logging (logs/nexus_events.log)                             │
│    • [OPT-IN LAB MODE]: Simulated Demonic Skull TCP RST test fixture        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## The Neuroevolutionary Guardian Paradigm ("The Living Genome")

Traditional machine learning relies on rigid, static architectures trained on historical data, leaving them blind to novel zero-day attack patterns. NEXUS applies genetic algorithms to evolve neural networks dynamically:

1. **The Healthy Genome Pool**:
   - Captures baseline home server traffic (media streaming, web browsing, DNS queries, SSH sessions, local LAN file transfers).
   - Serves as the clean training baseline so the network learns the rhythm of your actual home network.
2. **Genetic Topology Mutation (NEAT-Python)**:
   - Genomes start minimal (12 inputs $\to$ 1 output) with zero hidden nodes.
   - Evolution organically mutates connections, node topologies, and activation functions over generations, growing complexity only where necessary.
3. **The "Fitness Function From Hell"**:
   - Ruthlessly weeds out genomes that trigger false alarms on legitimate home server traffic (Netflix binges, game updates, file shares).
   - Rewards high-confidence spikes on SYN floods, stealth port scans, and malformed probes.
4. **Autonomous Re-Evolution Loop**:
   - Continuously buffers newly observed normal and flagged traffic.
   - Periodically re-evolves genomes in the background seeded from the current champion, adapting like an immune system against new threat variants.
5. **Edge Deployment (Raspberry Pi / Cluster)**:
   - Deploy the lightweight winning champion (`champion.pkl`, <10KB) on a Raspberry Pi or home gateway for microsecond packet scoring.
   - Run heavy evolution cycles in the background or offload to workstation/Ray clusters.

---

## Directory Structure

```text
~/nexus/
├── config/
│   └── config-nexus.txt          # Validated NEAT configuration (12 inputs, 1 output)
├── data/
│   ├── normal_traffic/           # Clean traffic captures (.pcap)
│   ├── attack_samples/           # SYN flood, port scan captures (.pcap)
│   └── nexus_sequence.db         # SQLite multi-packet sequence store
├── genomes/
│   ├── champion.pkl              # Active deployed champion neural network
│   ├── candidate_champion.pkl    # Next-generation candidate
│   └── archive/                  # Historical champion checkpoints
├── models/
│   ├── predictive_brain.pt       # PyTorch LSTM predictive brain weights
│   └── predictive_brain.onnx     # Production ONNX optimized model
├── logs/
│   ├── nexus_events.log          # Security audit trail (IP, score, action)
│   ├── evidence/                 # Forensic flow timeline JSON artifacts
│   └── neat-checkpoint-*         # Evolution checkpoint files
├── scripts/
│   ├── passive_flow_tracker.py   # State plane: RFC 5961 & sequence correlation
│   ├── test_passive_tracker.py   # Unit test suite for State Plane
│   ├── feature_extractor.py      # Scapy 12-dimensional vector extractor
│   ├── evolve.py                 # NEAT evolutionary fitness engine
│   ├── sniff_and_respond.py      # Live guardian, hot-reloader & firewall enforcement
│   ├── continuous_loop.py        # Background evolution & promotion loop
│   ├── train_predictive.py       # Sequence dataset generator & LSTM trainer
│   ├── distributed_ray_evolve.py # Phase 4 Ray multi-core/cluster evolution
│   ├── launch_cluster_node.py    # Ray cluster head/worker node orchestrator
│   ├── dataset_downloader.py     # Real PCAP & NSL-KDD dataset ingester
│   └── dashboard.py              # FastAPI + SSE real-time web command server
├── web/
│   └── index.html                # Tactical command dashboard UI (Canvas + Tailwind)
└── README.md                     # Master operational runbook
```

---

## Phased Master Roadmap & Success Criteria

### Phase 0 – Foundation (Single Laptop)
- **Goal**: Everything runs on one machine.
- **Components**:
  - `config/config-nexus.txt`: Initialized with 12 input pins, 1 output pin, population size 100, sigmoid activation.
  - `scripts/feature_extractor.py`: Turns Scapy packets into normalized 12-D vectors: packet size, protocol, ports, SYN/ACK/FIN/RST flags, payload length, window size, TTL, inter-arrival time, and packet arrival rate.
  - `scripts/evolve.py`: Evolves NEAT population, rewarding high anomaly scores for attack packets and low scores for normal traffic, penalizing false positives. Saves `genomes/champion.pkl`.
- **Success Criterion**: Load champion and get anomaly scores from live/simulated packets. *(Status: COMPLETED - 0.0000 on normal vs 0.9885 on attacks)*.

### Phase 1 – Live Detection + Demonic Response
- **Goal**: Watches network interface and dispatches demonic skull TCP RST on detected threats.
- **Components**:
  - `scripts/sniff_and_respond.py`: Sniffs traffic with Scapy, extracts features, scores via champion genome.
  - Demonic payload: Dispatches TCP RST packet loaded with the horned skull ASCII banner:
    ```text
          (                 )
          |\   _,,,---,,_   /|
          / /`--'        `--'\ \
         / /                  \ \
        | |    (o)      (o)    | |
        | |        /\          | |
         \ \     \______/     / /
          \ \                / /
           `--||||||||||||||--'
              |            |
              `------------'
    =======================================
         I'VE ALREADY TASTED YOUR IP
    =======================================
    ```
  - Automated blocking: Windows Firewall (`netsh advfirewall`) or Linux `iptables`.
  - Comprehensive logging to `logs/nexus_events.log`.
  - **Packet Crafting Mechanics**:
    - **Layer Stacking**: Built via Scapy layer operator `/`: `IP(...) / TCP(...) / Raw(...)`.
    - **Flags (`RA`)**: Reset + Acknowledge, forcing target socket teardown.
    - **Sequence & Ack Math**: 
      - If incoming packet has `ACK`, response `seq = incoming.ack`; otherwise `seq = 0`.
      - Response `ack = incoming.seq + consumed` where `consumed = 1` for SYN/FIN or `len(payload)`.
    - **Reliability Double-Shot**: Transmits with `count=2` to ensure delivery through noisy networks.
- **Success Criterion**: Trigger packet, see NEXUS score it, and dispatch demonic countermeasure. *(Status: COMPLETED - Validated with dry-run and live hooks)*.

### Phase 2 – Continuous Evolution Loop
- **Goal**: Background engine that evolves without human intervention and hot-reloads without downtime.
- **Components**:
  - `scripts/continuous_loop.py`: Continuously monitors traffic pools, seeds evolution from current champion, promotes when fitness margin $\Delta \ge 0.001$, archives checkpoints, and signals live sniffer.
  - Zero-downtime hot-reload in `sniff_and_respond.py`.
- **Success Criterion**: Leave running and automatically deploy stronger champion without dropping connections. *(Status: COMPLETED)*.

### Phase 3 – Predictive Layer ("Psychotic" Brain)
- **Goal**: Move from reactive defense to predictive threat forecasting.
- **Components**:
  - `data/nexus_sequence.db`: SQLite temporal sequence store.
  - `scripts/train_predictive.py`: 2-layer PyTorch LSTM taking sliding window of $(T=30, D=13)$ to forecast impending attack probability.
  - Exported to ONNX runtime (`models/predictive_brain.onnx`).
- **Success Criterion**: Forecast multi-packet reconnaissance buildup before full attack saturation occurs. *(Status: COMPLETED)*.

### Phase 4 – Multi-Machine Scaling (Distributed Ray Evolution)
- **Goal**: Move beyond one machine to distributed cluster evolution.
- **Components**:
  - `scripts/distributed_ray_evolve.py`: Distributes NEAT genome evaluations across multiple machines or CPU cores using Ray and zero-copy shared memory plasma object store.
  - `scripts/launch_cluster_node.py`: Orchestrates multi-node clusters (Head Node on primary coordinator; Worker nodes on secondary laptops/desktops or Raspberry Pis).
  - Dedicated permanent guardian node on sensor gateway while other machines run evolution when idle.
- **Success Criterion**: Evolution speed increases roughly linearly with the number of machines/cores. *(Status: COMPLETED - Validated linear scaling from 1,054.5 evals/sec on 8 CPUs to 2,330.3 evals/sec on 16 CPUs)*.

---

## Quickstart Runbook

### 1. Environment Activation
```powershell
cd ~/nexus
.\venv\Scripts\Activate.ps1
```

### 2. Generate Synthetic Baseline Data
```powershell
python scripts/feature_extractor.py --generate-synthetic
```

### 3. Run NEAT Evolution
```powershell
python scripts/evolve.py --generations 20 --output genomes/champion.pkl
```

### 4. Test Live Sniffer & Demonic Response
```powershell
# Safe Dry-Run Simulation:
python scripts/sniff_and_respond.py --test-packet

# Live Arming (Requires Administrator Privileges for Raw Sockets / Firewall):
python scripts/sniff_and_respond.py --active-defense --threshold 0.85
```

### 5. Launch Autonomous Continuous Evolution Loop
```powershell
python scripts/continuous_loop.py --interval 300 --generations 10 --margin 0.005
```

### 6. Train the Predictive Brain (PyTorch + ONNX)
```powershell
python scripts/train_predictive.py --epochs 15 --window 30
```

### 7. Run State Plane & RFC 5961 Unit Tests
```powershell
python scripts/test_passive_tracker.py
```

### 8. Passively Inspect PCAPs & Export Evidence
```powershell
python scripts/passive_flow_tracker.py --pcap data/attack_samples/synflood_portscan.pcap --evidence
```

### 9. Run Phase 4 Distributed Ray Evolution
```powershell
# Multi-Core Local Parallelism (e.g. 16 workers):
python scripts/distributed_ray_evolve.py --generations 20 --cpus 16

# Multi-Machine Cluster Run:
# On Head Node (Workstation):
python scripts/launch_cluster_node.py --head --port 6379

# On Worker Node (Secondary laptop / Pi):
python scripts/launch_cluster_node.py --worker --head-ip <HEAD_IP> --port 6379

# Dispatch distributed job to cluster:
python scripts/distributed_ray_evolve.py --address ray://<HEAD_IP>:10001 --generations 50
```

### 10. Launch Tactical Command Web Dashboard (Phase 2 & Sprint 2)
```powershell
# Run FastAPI server on port 8000:
python scripts/dashboard.py --port 8000

# With active defense (enforces live Windows firewall blocks for flagged threats):
python scripts/dashboard.py --port 8000 --active-defense
```
Open `http://localhost:8000` in any web browser:
- **Live Anomaly Speedometer**: Real-time threat coefficient gauge ($0.0000 - 1.0000$) with dynamic green/yellow/crimson transitions.
- **Demonic Skull Alarm Banner**: Pulsing skull alert with audio chirp when threat score $\ge 0.85$.
- **Living NEAT Genome Canvas**: Live topology visualizer of the champion neural network's inputs, synapses, and output.
- **Real-Time Packet Stream & 20-D Feature Drawer**: Click any packet row to slide open all 20 normalized features (Shannon entropy, TTL divergence, flag anomalies, window ratio).
- **Active Ban Matrix & Live Countdown**: Real-time TTL countdown with one-click manual unban API (`POST /api/bans/unban/{ip}`).
- **RFC 5961 State Plane Feed**: Live feed for challenge-ACKs, out-of-window RSTs, and forensic dumps.
- **One-Click Simulation Triggers**: Test `⚡ SIMULATE SYN FLOOD` and `+ SIMULATE CLEAN WEB` directly from the top navigation bar.

---

## Prioritized High-Impact Improvements Roadmap

Ranked by **Value vs. Effort** for upcoming sprints:

### Top Priority (Sprint 1 - Immediate Focus)
1. **Real Training Data Ingestion** (Medium / Very High): Ingest real-world attack captures (CIC-IDS2017, NSL-KDD, Stratosphere CTU-13) alongside local home server PCAPs.
2. **Enhanced Feature Set** (Low-Medium / High): Expand from 12 to 20+ features (Shannon payload entropy, TTL variance, anomalous TCP flag combinations, window scaling ratios).
3. **Temporary IP Ban List (TTL Auto-Expiry)** (Low / High): Automatically unblock attacker IPs after 10–60 minutes to prevent firewall rule clutter.
4. **Response Cooldown & Rate Limiting** (Very Low / Medium-High): Token bucket rate-limiting per attacker IP (max 1 countermeasure / alert per 30–60s).
5. **Real-time Logging & Webhook Alerts** (Low / High): Alert dispatcher streaming to Discord/Telegram/Slack webhooks and structured JSON audit logs.
6. **Bidirectional RST (Lab Mode)** (Low / Medium): In simulation mode, dispatch RST packets to both client and server simultaneously.

### Strong Medium-Term Upgrades (Sprint 2)
- **Automatic Champion Promotion + Rollback**: Automatically revert to the previous champion if a candidate exhibits higher false alarm rates on validation data.
- **Live Web Dashboard**: FastAPI / WebSocket dashboard showing real-time threat scores, active flows, and firewall blocks.
- **Trusted Device & Subnet Whitelist**: Dedicated CIDR/IP/MAC configuration to safeguard local streaming, gaming, and development.
- **Predictive LSTM Integration**: Proactively adjust alert sensitivity before packet saturation occurs.


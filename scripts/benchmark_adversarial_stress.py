"""
NEXUS Adversarial Stress Benchmark Suite
Pits the Monolithic Champion and the Specialist Council (MoE) against
5 progressive tiers of adversarial evasion:
- Tier 0: Unmutated Standard Attacks
- Tier 1: Timing & Rate Shaping (Low-and-Slow Jitter)
- Tier 2: TTL Masquerading & OS Camouflage
- Tier 3: Entropy Flattening (Steganographic Padding)
- Tier 4: Blended Full-Spectrum Camouflage (Combined Evasions)
"""

import os
import sys
import time
import json
import pickle
import random
from datetime import datetime
from typing import Dict, List, Tuple
import numpy as np

# Add scripts directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import PacketFeatureExtractor
from council_arbiter import CouncilArbiter
from evasion_engine import AdversarialEvasionEngine
from benchmark_moe_vs_monolith import generate_benchmark_test_suites

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def run_adversarial_stress_benchmark():
    print(f"{BOLD}{CYAN}================================================================{RESET}")
    print(f"{BOLD}{CYAN}      NEXUS ADVERSARIAL STRESS TEST: MONOLITH vs. COUNCIL (MoE) {RESET}")
    print(f"{BOLD}{CYAN}================================================================{RESET}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # 1. Load Defenders
    import neat
    monolith_path = "genomes/champion.pkl"
    if not os.path.exists(monolith_path):
        print(f"{RED}Error: Monolithic champion not found at {monolith_path}{RESET}")
        return

    with open(monolith_path, "rb") as f:
        m_data = pickle.load(f)
    m_genome = m_data["genome"]
    m_cfg = m_data["config"]
    m_net = neat.nn.FeedForwardNetwork.create(m_genome, m_cfg)
    m_num_in = len(m_cfg.genome_config.input_keys)

    arbiter = CouncilArbiter()
    print(f"Defenders Online:")
    print(f"  - Monolithic Champion (20-D): Fitness {getattr(m_genome, 'fitness', 0.0):.4f}")
    print(f"  - Specialist Council (MoE):   Mode {arbiter.active_mode}")

    # 2. Prepare Base Attack Pool (Extract attack vectors from standard benchmark suites)
    engine = AdversarialEvasionEngine()
    test_suites = generate_benchmark_test_suites()

    attack_vectors = []
    for name, (feats, category) in test_suites.items():
        if category == "ATTACK":
            attack_vectors.extend(feats)
    attack_vectors = np.array(attack_vectors, dtype=np.float32)
    print(f"\n[Sparring Arena] Assembled Base Attack Pool: {len(attack_vectors)} intrusion vectors.")

    # 3. Define 5 Adversarial Stress Tiers
    tiers = [
        ("Tier 0: Standard Unmutated Baseline", "none", 0.0),
        ("Tier 1: Timing Jitter & Rate Shaping", "jitter", 0.85),
        ("Tier 2: TTL Masquerading & OS Camouflage", "ttl", 1.0),
        ("Tier 3: Entropy Flattening & JSON Padding", "entropy", 0.80),
        ("Tier 4: Blended Full-Spectrum Evasion", "full", 0.90)
    ]

    print(f"\n{BOLD}{CYAN}--- Tiered Adversarial Sparring Evaluation ---{RESET}")
    header = f"{'Evasion Tier':<42} | {'Monolith Det':<14} | {'MoE Council Det':<16} | {'Council Attribution':<22}"
    print(BOLD + header + RESET)
    print("-" * len(header))

    benchmark_summary = []

    for tier_name, strategy, intensity in tiers:
        # Generate perturbed vectors for this tier
        if strategy == "none":
            perturbed_pool = attack_vectors
        else:
            perturbed_pool = np.array([
                engine.mutate_vector(v, strategy=strategy, intensity=intensity)
                for v in attack_vectors
            ])

        n_samples = len(perturbed_pool)

        # Monolith Evaluation
        m_detected = 0
        for x in perturbed_pool:
            inp = x if m_num_in == 20 else x[:12]
            score = float(m_net.activate(inp)[0])
            if score >= 0.85:
                m_detected += 1
        m_rate = (m_detected / n_samples) * 100.0

        # MoE Council Evaluation
        moe_detected = 0
        expert_votes = {}
        for x in perturbed_pool:
            res = arbiter.evaluate(x)
            if res["is_threat"]:
                moe_detected += 1
            lead = res["leading_expert"]
            expert_votes[lead] = expert_votes.get(lead, 0) + 1
        moe_rate = (moe_detected / n_samples) * 100.0

        dominant_expert = max(expert_votes, key=expert_votes.get) if expert_votes else "NONE"

        # Display results
        color_moe = GREEN if moe_rate >= 90.0 else (YELLOW if moe_rate >= 75.0 else RED)
        color_m = GREEN if m_rate >= 90.0 else (YELLOW if m_rate >= 75.0 else RED)

        print(f"{tier_name:<42} | {color_m}{m_rate:>5.1f}% Det{RESET}       | {color_moe}{moe_rate:>5.1f}% Det{RESET}         | {dominant_expert:<22}")

        benchmark_summary.append({
            "tier": tier_name,
            "strategy": strategy,
            "intensity": intensity,
            "monolith_detection": round(m_rate, 2),
            "moe_detection": round(moe_rate, 2),
            "dominant_expert": dominant_expert
        })

    print("-" * len(header))

    # Calculate Degradation Delta
    m_base = benchmark_summary[0]["monolith_detection"]
    m_worst = benchmark_summary[4]["monolith_detection"]
    moe_base = benchmark_summary[0]["moe_detection"]
    moe_worst = benchmark_summary[4]["moe_detection"]

    m_drop = m_base - m_worst
    moe_drop = moe_base - moe_worst

    print(f"\n{BOLD}Adversarial Resilience Summary:{RESET}")
    print(f"  - Monolith Detection Drop (Tier 0 -> Tier 4):    -{m_drop:.1f}%")
    print(f"  - MoE Council Detection Drop (Tier 0 -> Tier 4): -{moe_drop:.1f}%")
    if moe_drop < m_drop:
        advantage = m_drop - moe_drop
        print(f"  {GREEN}{BOLD}VERDICT: Specialist Council exhibited +{advantage:.1f}% superior evasion resilience!{RESET}")

    # Save to disk
    os.makedirs("logs", exist_ok=True)
    out_file = "logs/adversarial_stress_results.json"
    with open(out_file, "w") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "tiers": benchmark_summary,
            "monolith_drop": round(m_drop, 2),
            "moe_drop": round(moe_drop, 2)
        }, f, indent=2)
    print(f"\nDetailed stress results saved to: {out_file}\n")


if __name__ == "__main__":
    run_adversarial_stress_benchmark()

"""
NEXUS Specialist Council Arbiter (Mixture of Experts - MoE)
Coordinates three hyper-specialized NEAT champions:
1. Volumetric Vanguard (Inputs 0, 1, 4, 7, 10, 11, 18)
2. Recon Inquisitor (Inputs 2, 3, 4, 5, 6, 9, 13, 14, 15, 19)
3. Deep-Payload Analyst (Inputs 1, 3, 7, 10, 12, 16, 17)

Applies probabilistic disjunction and priority-veto consensus logic with
automatic zero-downtime fallback to the monolithic champion.
"""

import os
import time
import json
import pickle
from typing import Dict, Any, Optional, Tuple
import numpy as np

# Sensory slices into the 20-D feature vector
VOLUMETRIC_INDICES = [0, 1, 4, 7, 10, 11, 18]        # 7 features
RECON_INDICES = [2, 3, 4, 5, 6, 9, 13, 14, 15, 19]   # 10 features
PAYLOAD_INDICES = [1, 3, 7, 10, 12, 16, 17]          # 7 features

DEFAULT_PATHS = {
    "volumetric": "genomes/council_volumetric.pkl",
    "recon": "genomes/council_recon.pkl",
    "payload": "genomes/council_payload.pkl",
    "manifest": "genomes/council_manifest.json",
    "monolith": "genomes/champion.pkl"
}


class CouncilArbiter:
    """
    Arbitrates multi-expert neural evaluations and synthesizes a unified threat score.
    """
    def __init__(self, base_dir: str = "."):
        self.base_dir = base_dir
        self.paths = {k: os.path.join(base_dir, v) for k, v in DEFAULT_PATHS.items()}
        self.specialists: Dict[str, Any] = {}
        self.specialist_configs: Dict[str, Any] = {}
        self.specialist_fitnesses: Dict[str, float] = {}
        self.monolith_net = None
        self.monolith_config = None
        self.last_load_time = 0.0
        self.active_mode = "UNINITIALIZED"

        self.load_models()

    def load_models(self):
        """Loads all specialist champion models or falls back to monolithic model."""
        import neat
        loaded_count = 0
        self.specialists.clear()
        self.specialist_configs.clear()
        self.specialist_fitnesses.clear()

        # Attempt loading each specialist
        for role in ["volumetric", "recon", "payload"]:
            path = self.paths[role]
            if os.path.exists(path):
                try:
                    with open(path, "rb") as f:
                        data = pickle.load(f)
                    genome = data["genome"]
                    cfg = data["config"]
                    net = neat.nn.FeedForwardNetwork.create(genome, cfg)
                    self.specialists[role] = net
                    self.specialist_configs[role] = cfg
                    self.specialist_fitnesses[role] = float(getattr(genome, "fitness", 0.95))
                    loaded_count += 1
                except Exception as e:
                    print(f"[Council Arbiter] Error loading {role} specialist: {e}")

        # Load monolithic champion as backup/baseline
        if os.path.exists(self.paths["monolith"]):
            try:
                with open(self.paths["monolith"], "rb") as f:
                    m_data = pickle.load(f)
                m_genome = m_data["genome"]
                self.monolith_config = m_data["config"]
                self.monolith_net = neat.nn.FeedForwardNetwork.create(m_genome, self.monolith_config)
            except Exception as e:
                print(f"[Council Arbiter] Error loading fallback monolith: {e}")

        if loaded_count == 3:
            self.active_mode = "MOE_COUNCIL"
            print(f"[Council Arbiter] Full Specialist Council Loaded (3/3 Champions Online):")
            print(f"  - Volumetric Vanguard: {self.specialist_fitnesses.get('volumetric', 0.0):.4f}")
            print(f"  - Recon Inquisitor:    {self.specialist_fitnesses.get('recon', 0.0):.4f}")
            print(f"  - Deep-Payload Analyst: {self.specialist_fitnesses.get('payload', 0.0):.4f}")
        elif self.monolith_net is not None:
            self.active_mode = "MONOLITHIC_FALLBACK"
            print(f"[Council Arbiter] Partial/Missing Council ({loaded_count}/3). Operating in MONOLITHIC_FALLBACK mode.")
        else:
            self.active_mode = "HEURISTIC_ONLY"
            print("[Council Arbiter] Warning: No models available. Operating in HEURISTIC mode.")

        self.last_load_time = time.time()

    def reload_if_needed(self):
        """Checks for updated champion files or signal and hot-reloads."""
        signal_file = os.path.join(self.base_dir, "genomes", ".reload_signal")
        if os.path.exists(signal_file):
            try:
                mtime = os.path.getmtime(signal_file)
                if mtime > self.last_load_time:
                    print("[Council Arbiter] Reload signal detected. Refreshing Council models...")
                    self.load_models()
            except Exception:
                pass

    def evaluate(self, feats_20: np.ndarray) -> Dict[str, Any]:
        """
        Evaluates a 20-D packet vector across all council members.
        Returns unified threat verdict, individual scores, and attribution.
        """
        self.reload_if_needed()

        if self.active_mode == "MOE_COUNCIL":
            # 1. Slice features for each specialist
            v_in = feats_20[VOLUMETRIC_INDICES]
            r_in = feats_20[RECON_INDICES]
            p_in = feats_20[PAYLOAD_INDICES]

            # 2. Activate neural networks
            s_vol = float(self.specialists["volumetric"].activate(v_in)[0])
            s_rec = float(self.specialists["recon"].activate(r_in)[0])
            s_pay = float(self.specialists["payload"].activate(p_in)[0])

            # Bound between 0.0 and 1.0
            s_vol = max(0.0, min(1.0, s_vol))
            s_rec = max(0.0, min(1.0, s_rec))
            s_pay = max(0.0, min(1.0, s_pay))
            # 2b. Calibrate confidence: NEAT decision boundary is 0.50.
            # Map [0.0, 0.5) to [0.0, 0.35) and [0.5, 1.0] to [0.85, 0.99]
            def _calibrate(raw_s: float) -> float:
                if raw_s < 0.50:
                    return raw_s * 0.70
                return min(0.995, 0.85 + 0.145 * min(1.0, (raw_s - 0.50) / 0.35))

            c_vol = _calibrate(s_vol)
            c_rec = _calibrate(s_rec)
            c_pay = _calibrate(s_pay)

            scores = {
                "VOLUMETRIC_VANGUARD": c_vol,
                "RECON_INQUISITOR": c_rec,
                "DEEP_PAYLOAD_ANALYST": c_pay
            }

            leading_expert = max(scores, key=scores.get)
            leading_score = scores[leading_expert]

            # 3. Consensus Decision Rule
            # Priority Veto: If any specialist crosses threat threshold (>= 0.85),
            # trigger immediate alert with zero dilution.
            if leading_score >= 0.85:
                final_score = leading_score
                consensus_rule = "PRIORITY_VETO"
            else:
                # Probabilistic Disjunction on calibrated non-threat scores
                final_score = 1.0 - ((1.0 - c_vol) * (1.0 - c_rec) * (1.0 - c_pay))
                consensus_rule = "PROBABILISTIC_DISJUNCTION"

            return {
                "score": float(final_score),
                "is_threat": bool(final_score >= 0.85),
                "leading_expert": leading_expert,
                "leading_score": float(leading_score),
                "breakdown": {
                    "volumetric": round(s_vol, 4),
                    "recon": round(s_rec, 4),
                    "payload": round(s_pay, 4)
                },
                "calibrated": {
                    "volumetric": round(c_vol, 4),
                    "recon": round(c_rec, 4),
                    "payload": round(c_pay, 4)
                },
                "consensus_rule": consensus_rule,
                "mode": "MOE_COUNCIL"
            }

        elif self.active_mode == "MONOLITHIC_FALLBACK" and self.monolith_net is not None:
            num_in = len(self.monolith_config.genome_config.input_keys) if self.monolith_config else 20
            inp = feats_20 if num_in == 20 else feats_20[:12]
            score = float(self.monolith_net.activate(inp)[0])
            score = max(0.0, min(1.0, score))

            # Approximate attribution based on prominent feature groups
            if feats_20[11] > 0.6 or feats_20[0] > 0.8:
                leading = "VOLUMETRIC_VANGUARD"
            elif feats_20[13] > 0.5 or feats_20[14] > 0.5 or feats_20[15] > 0.5:
                leading = "RECON_INQUISITOR"
            elif feats_20[12] > 0.7:
                leading = "DEEP_PAYLOAD_ANALYST"
            else:
                leading = "GENERAL_MONOLITH"

            return {
                "score": float(score),
                "is_threat": bool(score >= 0.85),
                "leading_expert": leading,
                "leading_score": float(score),
                "breakdown": {
                    "volumetric": round(score if leading == "VOLUMETRIC_VANGUARD" else score * 0.5, 4),
                    "recon": round(score if leading == "RECON_INQUISITOR" else score * 0.5, 4),
                    "payload": round(score if leading == "DEEP_PAYLOAD_ANALYST" else score * 0.5, 4)
                },
                "consensus_rule": "MONOLITHIC_FALLBACK",
                "mode": "MONOLITHIC_FALLBACK"
            }

        else:
            # Heuristic Baseline
            heuristic_score = 0.0
            if feats_20[13] > 0.5 or feats_20[14] > 0.5:  # NULL or XMAS
                heuristic_score = 0.95
                leading = "RECON_INQUISITOR"
            elif feats_20[12] > 0.85:                     # High entropy
                heuristic_score = 0.90
                leading = "DEEP_PAYLOAD_ANALYST"
            elif feats_20[11] > 0.8:                      # High packet rate
                heuristic_score = 0.88
                leading = "VOLUMETRIC_VANGUARD"
            else:
                leading = "NONE"

            return {
                "score": float(heuristic_score),
                "is_threat": bool(heuristic_score >= 0.85),
                "leading_expert": leading,
                "leading_score": float(heuristic_score),
                "breakdown": {
                    "volumetric": float(feats_20[11]),
                    "recon": float(max(feats_20[13], feats_20[14])),
                    "payload": float(feats_20[12])
                },
                "consensus_rule": "HEURISTIC_RULE",
                "mode": "HEURISTIC_ONLY"
            }


if __name__ == "__main__":
    # Self-test
    arbiter = CouncilArbiter()
    dummy_feat = np.zeros(20, dtype=np.float32)
    dummy_feat[14] = 1.0  # XMAS scan flag
    res = arbiter.evaluate(dummy_feat)
    print("\nSelf-Test Sample Evaluation:")
    print(json.dumps(res, indent=2))

"""
NEXUS - NeuroEvolution Engine (NEAT)
Evolves lightweight, high-speed neural networks to detect network anomalies and attacks.
"""

import os
import glob
import pickle
import argparse
import numpy as np
import neat
from feature_extractor import extract_from_pcap, NUM_FEATURES

def load_or_extract_dataset(base_dir: str = "."):
    """
    Loads all .pcap files from normal_traffic and attack_samples,
    extracting and aggregating 12-dim feature vectors.
    """
    normal_pcaps = glob.glob(os.path.join(base_dir, "data", "normal_traffic", "*.pcap"))
    attack_pcaps = glob.glob(os.path.join(base_dir, "data", "attack_samples", "*.pcap"))

    if not normal_pcaps or not attack_pcaps:
        print("[NEXUS Evolve] Missing dataset PCAPs. Generating baseline synthetic datasets...")
        from feature_extractor import generate_synthetic_datasets
        generate_synthetic_datasets(base_dir=base_dir)
        normal_pcaps = glob.glob(os.path.join(base_dir, "data", "normal_traffic", "*.pcap"))
        attack_pcaps = glob.glob(os.path.join(base_dir, "data", "attack_samples", "*.pcap"))

    normal_list = []
    for pcap in normal_pcaps:
        feats = extract_from_pcap(pcap)
        if len(feats) > 0:
            normal_list.append(feats)

    attack_list = []
    for pcap in attack_pcaps:
        feats = extract_from_pcap(pcap)
        if len(feats) > 0:
            attack_list.append(feats)

    X_norm = np.vstack(normal_list) if normal_list else np.empty((0, NUM_FEATURES))
    X_atk = np.vstack(attack_list) if attack_list else np.empty((0, NUM_FEATURES))

    print(f"[NEXUS Evolve] Loaded {len(X_norm)} normal samples, {len(X_atk)} attack samples.")
    return X_norm, X_atk


def eval_genomes(genomes, config, X_norm, X_atk):
    """
    Evaluates fitness across the entire population.
    Fitness rewards high anomaly score for attacks, low score for normal traffic,
    and severely penalizes false positives.
    """
    for genome_id, genome in genomes:
        net = neat.nn.FeedForwardNetwork.create(genome, config)

        # 1. Normal traffic evaluation (target = 0.0)
        norm_scores = np.array([net.activate(x)[0] for x in X_norm], dtype=np.float32)
        # False positives: normal packets scored > 0.5
        fp_rate = float(np.mean(norm_scores > 0.5))
        # Normal MSE loss
        norm_loss = float(np.mean(norm_scores ** 2))

        # 2. Attack traffic evaluation (target = 1.0)
        atk_scores = np.array([net.activate(x)[0] for x in X_atk], dtype=np.float32)
        # False negatives: attack packets scored < 0.5
        fn_rate = float(np.mean(atk_scores < 0.5))
        # Attack MSE loss
        atk_loss = float(np.mean((1.0 - atk_scores) ** 2))

        # Combined fitness in [0.0, 1.0]
        # Max score is 1.0 when loss is 0.0
        base_fitness = 1.0 - np.sqrt(0.5 * norm_loss + 0.5 * atk_loss)
        penalty = (0.3 * fp_rate) + (0.2 * fn_rate)
        genome.fitness = max(0.0, float(base_fitness - penalty))


def run_evolution(config_file: str, generations: int = 25, output_file: str = "genomes/champion.pkl", seed_champion: str = None):
    """
    Executes the NEAT evolution cycle.
    """
    print(f"[NEXUS Evolve] Loading config: {config_file}")
    config = neat.Config(
        neat.DefaultGenome,
        neat.DefaultReproduction,
        neat.DefaultSpeciesSet,
        neat.DefaultStagnation,
        config_file
    )

    X_norm, X_atk = load_or_extract_dataset(base_dir=".")

    # Subsample for speed if datasets are very large (keep max 1000 each per eval)
    if len(X_norm) > 1000:
        idx_n = np.random.choice(len(X_norm), 1000, replace=False)
        X_norm = X_norm[idx_n]
    if len(X_atk) > 1000:
        idx_a = np.random.choice(len(X_atk), 1000, replace=False)
        X_atk = X_atk[idx_a]

    # Initialize population
    p = neat.Population(config)

    # If seeding from an existing champion:
    if seed_champion and os.path.exists(seed_champion):
        try:
            with open(seed_champion, "rb") as f:
                saved = pickle.load(f)
                seed_genome = saved["genome"] if isinstance(saved, dict) else saved
                p.population[1] = seed_genome
                print(f"[NEXUS Evolve] Successfully seeded population with {seed_champion}")
        except Exception as e:
            print(f"[NEXUS Evolve] Warning: Could not seed champion: {e}")

    # Reporters
    p.add_reporter(neat.StdOutReporter(True))
    stats = neat.StatisticsReporter()
    p.add_reporter(stats)

    os.makedirs("logs", exist_ok=True)
    p.add_reporter(neat.Checkpointer(5, filename_prefix="logs/neat-checkpoint-"))

    # Evolutionary loop
    def eval_wrapper(genomes, cfg):
        eval_genomes(genomes, cfg, X_norm, X_atk)

    winner = p.run(eval_wrapper, generations)

    # Save champion
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    payload = {
        "genome": winner,
        "fitness": winner.fitness,
        "config": config,
        "num_inputs": config.genome_config.num_inputs,
        "num_outputs": config.genome_config.num_outputs
    }
    with open(output_file, "wb") as f:
        pickle.dump(payload, f)

    print(f"\n[NEXUS Evolve] EVOLUTION COMPLETE!")
    print(f" -> Best Genome Fitness: {winner.fitness:.4f}")
    print(f" -> Champion saved to: {output_file}")
    return winner, config


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NEXUS NEAT Evolution Engine")
    parser.add_argument("--config", type=str, default="config/config-nexus.txt", help="Path to NEAT config")
    parser.add_argument("--generations", type=int, default=20, help="Number of evolution generations")
    parser.add_argument("--output", type=str, default="genomes/champion.pkl", help="Output path for champion genome")
    parser.add_argument("--seed", type=str, default=None, help="Path to champion genome to seed from")
    args = parser.parse_args()

    run_evolution(
        config_file=args.config,
        generations=args.generations,
        output_file=args.output,
        seed_champion=args.seed
    )

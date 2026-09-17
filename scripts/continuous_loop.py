"""
NEXUS - Continuous Evolution & Hot-Reload Loop
Orchestrates autonomous background evolution cycles, seeds from the current champion,
promotes superior genomes when fitness exceeds margin, and triggers hot-reloads.
"""

import os
import sys
import time
import shutil
import pickle
import argparse
import logging
from datetime import datetime

# Add scripts directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evolve import run_evolution

logger = logging.getLogger("NEXUS_EVOLVE_LOOP")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("[%(asctime)s] [CONTINUOUS LOOP] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(formatter)
logger.addHandler(ch)

RELOAD_SIGNAL_FILE = "genomes/.reload_signal"
ARCHIVE_DIR = "genomes/archive"


def get_current_champion_fitness(champion_file: str) -> float:
    if not os.path.exists(champion_file):
        return -1.0
    try:
        with open(champion_file, "rb") as f:
            data = pickle.load(f)
            return float(data.get("fitness", -1.0))
    except Exception:
        return -1.0


def trigger_hot_reload():
    os.makedirs(os.path.dirname(RELOAD_SIGNAL_FILE), exist_ok=True)
    with open(RELOAD_SIGNAL_FILE, "w") as f:
        f.write(str(time.time()))


def run_continuous_evolution(
    config_file: str = "config/config-nexus.txt",
    champion_file: str = "genomes/champion.pkl",
    cycle_interval: int = 300,
    generations_per_cycle: int = 10,
    promotion_margin: float = 0.005,
    max_cycles: int = 0  # 0 means infinite
):
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    cycle = 0

    logger.info("Initializing NEXUS Autonomous Continuous Evolution Loop...")
    logger.info(f"Cycle Interval: {cycle_interval}s | Gen/Cycle: {generations_per_cycle} | Margin: {promotion_margin}")

    while True:
        cycle += 1
        logger.info(f"\n========== BEGINNING EVOLUTION CYCLE #{cycle} ==========")

        current_fitness = get_current_champion_fitness(champion_file)
        logger.info(f"Current Active Champion Fitness: {current_fitness:.4f}")

        # Candidate champion path
        candidate_file = "genomes/candidate_champion.pkl"

        try:
            winner, config = run_evolution(
                config_file=config_file,
                generations=generations_per_cycle,
                output_file=candidate_file,
                seed_champion=champion_file if os.path.exists(champion_file) else None
            )

            new_fitness = float(winner.fitness)
            logger.info(f"Candidate Genome Evolved with Fitness: {new_fitness:.4f}")

            # Check promotion criteria
            if (new_fitness - current_fitness) >= promotion_margin or current_fitness < 0:
                logger.info(f"*** PROMOTION CRITERIA MET! (+{new_fitness - current_fitness:.4f} improvement) ***")

                # Archive existing champion
                if os.path.exists(champion_file):
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    archive_path = os.path.join(ARCHIVE_DIR, f"champion_cycle{cycle}_{ts}.pkl")
                    shutil.copy2(champion_file, archive_path)
                    logger.info(f"Archived previous champion to: {archive_path}")

                # Promote candidate
                shutil.copy2(candidate_file, champion_file)
                trigger_hot_reload()
                logger.info(f"PROMOTED NEW CHAMPION -> {champion_file}")
                logger.info("Signaled live sniffer for hot-reload.")
            else:
                logger.info(f"Candidate did not exceed promotion margin (+{promotion_margin:.4f}). Champion retained.")

        except Exception as e:
            logger.error(f"Error during evolution cycle #{cycle}: {e}")

        if max_cycles > 0 and cycle >= max_cycles:
            logger.info(f"Completed requested {max_cycles} evolution cycles. Exiting loop.")
            break

        logger.info(f"Sleeping for {cycle_interval}s until next evolution cycle...")
        time.sleep(cycle_interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NEXUS Continuous Evolution Loop")
    parser.add_argument("--config", type=str, default="config/config-nexus.txt", help="NEAT config file")
    parser.add_argument("--champion", type=str, default="genomes/champion.pkl", help="Champion genome file")
    parser.add_argument("--interval", type=int, default=60, help="Interval in seconds between cycles")
    parser.add_argument("--generations", type=int, default=5, help="Generations per cycle")
    parser.add_argument("--margin", type=float, default=0.001, help="Fitness margin required to promote")
    parser.add_argument("--cycles", type=int, default=1, help="Number of cycles to run (0=infinite)")
    args = parser.parse_args()

    run_continuous_evolution(
        config_file=args.config,
        champion_file=args.champion,
        cycle_interval=args.interval,
        generations_per_cycle=args.generations,
        promotion_margin=args.margin,
        max_cycles=args.cycles
    )

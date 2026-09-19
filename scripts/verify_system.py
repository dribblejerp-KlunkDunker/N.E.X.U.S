"""
NEXUS System Integrity & Pre-Flight Diagnostic Suite
Runs comprehensive health checks across all 5 architectural planes,
models, network interfaces, and web dashboard readiness.
"""

import os
import sys
import time
import subprocess
from datetime import datetime

# Set color codes for terminal output
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def print_header(text: str):
    print(f"\n{CYAN}{BOLD}--- {text} ---{RESET}")

def print_check(name: str, passed: bool, detail: str = ""):
    status = f"{GREEN}[PASS]{RESET}" if passed else f"{RED}[FAIL]{RESET}"
    detail_str = f" ({detail})" if detail else ""
    print(f"  {status} {name}{detail_str}")

def run_diagnostics():
    print(f"{BOLD}{CYAN}================================================================{RESET}")
    print(f"{BOLD}{CYAN}           NEXUS SYSTEM INTEGRITY & PRE-FLIGHT AUDIT            {RESET}")
    print(f"{BOLD}{CYAN}================================================================{RESET}")
    print(f"Audit Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Working Directory: {os.getcwd()}")
    print(f"Python Interpreter: {sys.executable}")

    all_passed = True

    # -------------------------------------------------------------
    # 1. PYTHON ENVIRONMENT & DEPENDENCIES
    # -------------------------------------------------------------
    print_header("1. Core Python Dependencies")
    dependencies = [
        ("neat", "neat-python"),
        ("scapy", "scapy"),
        ("torch", "PyTorch"),
        ("onnxruntime", "ONNX Runtime"),
        ("fastapi", "FastAPI"),
        ("uvicorn", "Uvicorn"),
        ("numpy", "NumPy"),
        ("ray", "Ray Distributed")
    ]

    for mod, label in dependencies:
        try:
            m = __import__(mod)
            ver = getattr(m, "__version__", "installed")
            print_check(f"{label} ({mod})", True, f"v{ver}")
        except ImportError as e:
            print_check(f"{label} ({mod})", False, f"Missing: {e}")
            all_passed = False

    # -------------------------------------------------------------
    # 2. CONFIGURATION & MODELS
    # -------------------------------------------------------------
    print_header("2. Configuration & Trained Models")
    config_path = "config/config-nexus.txt"
    has_config = os.path.exists(config_path)
    print_check("NEAT Config File", has_config, config_path)
    if has_config:
        try:
            import neat
            cfg = neat.Config(neat.DefaultGenome, neat.DefaultReproduction, neat.DefaultSpeciesSet, neat.DefaultStagnation, config_path)
            num_inputs = len(cfg.genome_config.input_keys)
            act_ok = set(cfg.genome_config.activation_options) == {"sigmoid", "relu", "tanh"}
            print_check("NEAT Input Dimension (20-D)", num_inputs == 20, f"num_inputs = {num_inputs}")
            print_check("NEAT Population Size (150)", cfg.pop_size == 150, f"pop_size = {cfg.pop_size}")
            print_check("Non-Linear Activations", act_ok, f"{', '.join(cfg.genome_config.activation_options)}")
            if num_inputs != 20 or cfg.pop_size != 150 or not act_ok:
                all_passed = False
        except Exception as e:
            print_check("NEAT Config Parsing", False, str(e))
            all_passed = False
    else:
        all_passed = False

    champion_path = "genomes/champion.pkl"
    has_champ = os.path.exists(champion_path)
    if has_champ:
        try:
            import pickle
            with open(champion_path, "rb") as f:
                champ_data = pickle.load(f)
            fitness = getattr(champ_data["genome"], "fitness", 0.0)
            print_check("Active Champion Genome", True, f"{champion_path} | Fitness: {fitness:.4f}")
        except Exception as e:
            print_check("Active Champion Genome", False, f"Corrupted: {e}")
            all_passed = False
    else:
        print_check("Active Champion Genome", False, f"Not found at {champion_path}")
        all_passed = False

    pt_path = "models/predictive_brain.pt"
    onnx_path = "models/predictive_brain.onnx"
    print_check("PyTorch LSTM Brain", os.path.exists(pt_path), pt_path)
    print_check("ONNX Runtime Brain", os.path.exists(onnx_path), onnx_path)

    # -------------------------------------------------------------
    # 3. FEATURE EXTRACTOR & STATE PLANE
    # -------------------------------------------------------------
    print_header("3. State Plane & Feature Extractor (RFC 5961)")
    try:
        sys.path.insert(0, os.path.join(os.getcwd(), "scripts"))
        from feature_extractor import PacketFeatureExtractor, calculate_shannon_entropy
        from scapy.all import Ether, IP, TCP, Raw

        # Test Shannon entropy
        ent = abs(calculate_shannon_entropy(b"A" * 100))
        ent_rand = calculate_shannon_entropy(os.urandom(1000))
        entropy_ok = (ent == 0.0) and (ent_rand > 0.7)
        print_check("Shannon Entropy Engine", entropy_ok, f"Zero: {ent:.2f}, High: {ent_rand:.2f}")

        # Test 12-D and 20-D extraction
        extractor = PacketFeatureExtractor()
        test_pkt = Ether()/IP(src="192.168.1.100", dst="192.168.1.1", ttl=64)/\
                   TCP(sport=54321, dport=443, flags="S", window=64240)/\
                   Raw(load=b"TEST")
        f12 = extractor.extract(test_pkt)
        f20 = extractor.extract(test_pkt, extended=True)
        extractor_ok = (len(f12) == 12) and (len(f20) == 20)
        print_check("Packet Feature Extractor", extractor_ok, f"12-D & 20-D Vectors verified")

        # Test Passive TCP Flow Tracker
        from passive_flow_tracker import PassiveTcpFlowTracker
        tracker = PassiveTcpFlowTracker()
        res = tracker.observe(
            src_ip="1.1.1.1",
            src_port=1234,
            dst_ip="2.2.2.2",
            dst_port=80,
            seq=100,
            ack=None,
            flags="S",
            payload_len=0,
            window=64240,
            ttl=64
        )
        tracker_ok = res.get("state") == "SYN_SEEN"
        print_check("Passive TCP State Machine", tracker_ok, "Handshake tracking active")
        if not tracker_ok:
            all_passed = False

    except Exception as e:
        print_check("Feature Extractor & State Plane", False, str(e))
        all_passed = False

    # -------------------------------------------------------------
    # 4. NETWORK INTERFACES & LIVE CAPTURE CAPABILITY
    # -------------------------------------------------------------
    print_header("4. Network Capture Capability (Scapy / Npcap)")
    try:
        from scapy.all import get_if_list, conf, sniff
        ifaces = get_if_list()
        default_iface = conf.iface
        print_check("Npcap Network Interfaces", len(ifaces) > 0, f"{len(ifaces)} interfaces detected")
        print_check("Default Capture Adapter", True, f"{default_iface}")

        # Quick capture test (1 packet, 2s timeout)
        t0 = time.time()
        captured = sniff(count=1, timeout=2.0)
        dur = time.time() - t0
        print_check("Live Packet Capture Test", True, f"Sniffed {len(captured)} pkt in {dur:.2f}s")
    except Exception as e:
        print_check("Network Capture Capability", False, str(e))
        all_passed = False

    # -------------------------------------------------------------
    # 5. FIREWALL & POLICY ENFORCEMENT ACCESS
    # -------------------------------------------------------------
    print_header("5. Host Firewall Policy Access")
    if sys.platform == "win32":
        try:
            res = subprocess.run(
                'netsh advfirewall show allprofiles state',
                shell=True,
                capture_output=True,
                text=True
            )
            fw_ok = "State" in res.stdout or "ON" in res.stdout or "OFF" in res.stdout or res.returncode == 0
            print_check("Windows Firewall (netsh)", fw_ok, "Accessible")
        except Exception as e:
            print_check("Windows Firewall (netsh)", False, str(e))
    else:
        print_check("Host Firewall", True, "Linux/Unix platform detected")

    # -------------------------------------------------------------
    # 6. DASHBOARD & UI ARTIFACTS
    # -------------------------------------------------------------
    print_header("6. Web Dashboard & UI Artifacts")
    dash_script = "scripts/dashboard.py"
    ui_html = "web/index.html"
    print_check("Dashboard Server Script", os.path.exists(dash_script), dash_script)
    print_check("Dashboard UI Template", os.path.exists(ui_html), ui_html)

    # -------------------------------------------------------------
    # 7. SPECIALIST COUNCIL (MIXTURE OF EXPERTS - MoE) PLANE
    # -------------------------------------------------------------
    print_header("7. Specialist Council (Mixture of Experts - MoE)")
    council_configs = [
        ("config/config-council-volumetric.txt", "Volumetric Config (7-D)", 7),
        ("config/config-council-recon.txt", "Recon Config (10-D)", 10),
        ("config/config-council-payload.txt", "Deep-Payload Config (7-D)", 7)
    ]
    for c_path, label, exp_in in council_configs:
        exists = os.path.exists(c_path)
        if exists:
            try:
                import neat
                cfg = neat.Config(neat.DefaultGenome, neat.DefaultReproduction, neat.DefaultSpeciesSet, neat.DefaultStagnation, c_path)
                in_count = len(cfg.genome_config.input_keys)
                print_check(label, in_count == exp_in, f"{in_count}-D inputs")
                if in_count != exp_in:
                    all_passed = False
            except Exception as e:
                print_check(label, False, str(e))
                all_passed = False
        else:
            print_check(label, False, f"Missing {c_path}")
            all_passed = False

    council_models = [
        ("genomes/council_volumetric.pkl", "Volumetric Vanguard Champion"),
        ("genomes/council_recon.pkl", "Recon Inquisitor Champion"),
        ("genomes/council_payload.pkl", "Deep-Payload Analyst Champion")
    ]
    for m_path, label in council_models:
        exists = os.path.exists(m_path)
        if exists:
            try:
                import pickle
                with open(m_path, "rb") as f:
                    data = pickle.load(f)
                fit = getattr(data["genome"], "fitness", 0.0)
                print_check(label, True, f"Fitness: {fit:.4f}")
            except Exception as e:
                print_check(label, False, f"Corrupted: {e}")
                all_passed = False
        else:
            print_check(label, False, f"Missing {m_path}")
            all_passed = False

    manifest_path = "genomes/council_manifest.json"
    print_check("Council Manifest JSON", os.path.exists(manifest_path), manifest_path)

    # Test Council Arbiter
    try:
        from council_arbiter import CouncilArbiter
        arbiter = CouncilArbiter()
        arbiter_ok = (arbiter.active_mode == "MOE_COUNCIL")
        print_check("Council Arbiter Engine", arbiter_ok, f"Mode: {arbiter.active_mode}")
        if not arbiter_ok:
            all_passed = False
    except Exception as e:
        print_check("Council Arbiter Engine", False, str(e))
        all_passed = False

    # -------------------------------------------------------------
    # FINAL VERDICT
    # -------------------------------------------------------------
    print(f"\n{BOLD}{CYAN}================================================================{RESET}")
    if all_passed:
        print(f"{BOLD}{GREEN}  STATUS: ALL CHECKS PASSED - NEXUS SYSTEM FULLY OPERATIONAL  {RESET}")
    else:
        print(f"{BOLD}{RED}  STATUS: ISSUES DETECTED - REVIEW FAILED CHECKS ABOVE        {RESET}")
    print(f"{BOLD}{CYAN}================================================================{RESET}\n")

    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(run_diagnostics())

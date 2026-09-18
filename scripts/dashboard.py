"""
NEXUS - Real-Time Cyber-Guardian Web Dashboard
FastAPI + Server-Sent Events (SSE) backend serving the tactical command interface,
streaming live packet evaluations, firewall bans, and RFC 5961 forensic events.
Supports both live network interface sniffing and on-demand threat simulation.
"""

import os
import sys
import time
import json
import asyncio
import pickle
import threading
import argparse
import subprocess
from typing import Dict, List, Optional, Set
from datetime import datetime

from contextlib import asynccontextmanager
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from pydantic import BaseModel

# Add scripts directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import PacketFeatureExtractor, FEATURE_NAMES_20
from passive_flow_tracker import PassiveTcpFlowTracker

@asynccontextmanager
async def lifespan(app: FastAPI):
    global EVENT_LOOP
    EVENT_LOOP = asyncio.get_running_loop()
    yield
    stop_sniffer()

app = FastAPI(title="NEXUS Tactical Command API", lifespan=lifespan)

# Global event loop & subscriber set for multi-client SSE
EVENT_LOOP: Optional[asyncio.AbstractEventLoop] = None
EVENT_SUBSCRIBERS: Set[asyncio.Queue] = set()

# Shared operational state
SHARED_STATE = {
    "packets_evaluated": 0,
    "threats_flagged": 0,
    "bans": {},  # ip -> expire_ts
    "champion_fitness": 0.9980,
    "last_score": 0.0,
    "active_defense": False,
    "champion_path": "genomes/champion.pkl",
    "live_sniffing": False
}

# Live sniffer control
SNIFFER_RUNNING = False
SNIFFER_THREAD: Optional[threading.Thread] = None

# Load champion genome
NET = None
CONFIG = None
try:
    if os.path.exists("genomes/champion.pkl"):
        import neat
        with open("genomes/champion.pkl", "rb") as f:
            data = pickle.load(f)
        genome = data["genome"]
        CONFIG = data["config"]
        NET = neat.nn.FeedForwardNetwork.create(genome, CONFIG)
        SHARED_STATE["champion_fitness"] = float(getattr(genome, "fitness", 0.9980))
        print(f"[NEXUS Dashboard] Champion genome loaded (Fitness: {SHARED_STATE['champion_fitness']:.4f})")
except Exception as e:
    print(f"[NEXUS Dashboard] Warning: Could not load champion genome: {e}")

EXTRACTOR = PacketFeatureExtractor()
TRACKER = PassiveTcpFlowTracker(timeout_seconds=120.0, history_size=8)


def broadcast_event(event_type: str, data: dict):
    """Thread-safe event broadcast to all connected SSE clients."""
    payload = {"type": event_type, "data": data}

    def _deliver():
        dead = []
        for q in list(EVENT_SUBSCRIBERS):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass
            except Exception:
                dead.append(q)
        for q in dead:
            EVENT_SUBSCRIBERS.discard(q)

    if EVENT_LOOP and EVENT_LOOP.is_running():
        EVENT_LOOP.call_soon_threadsafe(_deliver)


def process_packet(pkt):
    """
    Unified packet evaluation engine:
    1. Extracts 12-D base and 20-D extended features
    2. Runs NEAT champion neural network scoring
    3. Triggers automated firewall policy enforcement upon threat detection
    4. Updates Passive State Plane (RFC 5961 heuristics)
    5. Dispatches real-time SSE telemetry to the web dashboard
    """
    from scapy.all import IP, TCP, Raw

    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return None

    cur_time = datetime.now().strftime("%H:%M:%S")
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    sport = int(pkt[TCP].sport)
    dport = int(pkt[TCP].dport)
    flags_str = str(pkt[TCP].flags)
    payload_len = len(pkt[Raw].load) if pkt.haslayer(Raw) else 0
    seq = int(pkt[TCP].seq)
    ack = int(pkt[TCP].ack) if (pkt[TCP].flags & 0x10) else None
    window = int(pkt[TCP].window)
    ttl = int(pkt[IP].ttl)

    # 1. Feature extraction (single pass preserves accurate delta_t and rate EMA)
    feats_20 = EXTRACTOR.extract(pkt, extended=True)
    feats_12 = feats_20[:12]

    # 2. Score with champion neural net
    if NET:
        score = float(NET.activate(feats_12)[0])
    else:
        score = 0.0

    SHARED_STATE["packets_evaluated"] += 1
    SHARED_STATE["last_score"] = score

    # 3. Policy Enforcement upon Threat Detection
    if score >= 0.85 and src_ip not in {"127.0.0.1", "::1", "0.0.0.0"}:
        SHARED_STATE["threats_flagged"] += 1
        ban_expire = time.time() + 1800  # 30-min TTL
        SHARED_STATE["bans"][src_ip] = ban_expire

        if SHARED_STATE["active_defense"] and sys.platform == "win32":
            rule_name = f"NEXUS_BLOCK_{src_ip.replace('.', '_')}"
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={src_ip}'
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        broadcast_event("bans", SHARED_STATE["bans"])

    # 4. State Plane RFC 5961 tracking
    state_event = TRACKER.observe(
        src_ip=src_ip,
        src_port=sport,
        dst_ip=dst_ip,
        dst_port=dport,
        seq=seq,
        ack=ack,
        flags=flags_str,
        payload_len=payload_len,
        window=window,
        ttl=ttl
    )

    for finding in state_event.get("findings", []):
        broadcast_event("rfc_event", finding)

    # 5. Broadcast packet telemetry
    feat_dict = {name: float(val) for name, val in zip(FEATURE_NAMES_20, feats_20)}
    packet_data = {
        "time": cur_time,
        "src": f"{src_ip}:{sport}",
        "dst": f"{dst_ip}:{dport}",
        "proto": "TCP",
        "flags": flags_str,
        "score": score,
        "features": feat_dict
    }
    broadcast_event("packet", packet_data)
    return packet_data


# --------------------------------------------------------------------
# LIVE CAPTURE BACKGROUND WORKER
# --------------------------------------------------------------------
def _sniffer_worker(iface=None):
    global SNIFFER_RUNNING
    from scapy.all import sniff, conf, IP, TCP

    target_iface = iface or conf.iface
    print(f"[NEXUS Sniffer] Background sniffer active on: {target_iface}")
    SHARED_STATE["live_sniffing"] = True

    def _pkt_callback(pkt):
        if not SNIFFER_RUNNING:
            return
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            try:
                process_packet(pkt)
            except Exception:
                pass

    try:
        sniff(
            iface=target_iface,
            prn=_pkt_callback,
            store=0,
            stop_filter=lambda p: not SNIFFER_RUNNING
        )
    except Exception as e:
        print(f"[NEXUS Sniffer] Sniffer stopped: {e}")
    finally:
        SNIFFER_RUNNING = False
        SHARED_STATE["live_sniffing"] = False
        print("[NEXUS Sniffer] Background capture thread terminated.")


def start_sniffer(iface=None):
    global SNIFFER_RUNNING, SNIFFER_THREAD
    if SNIFFER_RUNNING:
        return
    SNIFFER_RUNNING = True
    SNIFFER_THREAD = threading.Thread(target=_sniffer_worker, args=(iface,), daemon=True)
    SNIFFER_THREAD.start()


def stop_sniffer():
    global SNIFFER_RUNNING
    SNIFFER_RUNNING = False
    SHARED_STATE["live_sniffing"] = False


# --------------------------------------------------------------------
# FASTAPI ROUTES
# --------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web", "index.html")
    if not os.path.exists(index_path):
        return HTMLResponse("<h3>Error: web/index.html not found</h3>", status_code=404)
    return FileResponse(index_path)


@app.get("/api/status")
async def get_status():
    return {
        "status": "ARMED" if SHARED_STATE["active_defense"] else "ARMED (SIMULATION)",
        "fitness": SHARED_STATE["champion_fitness"],
        "total_packets": SHARED_STATE["packets_evaluated"],
        "total_threats": SHARED_STATE["threats_flagged"],
        "bans": SHARED_STATE["bans"],
        "last_score": SHARED_STATE["last_score"],
        "live_sniffing": SNIFFER_RUNNING
    }


@app.get("/api/genome")
async def get_genome():
    """Returns the nodes and synapses of the active champion."""
    try:
        with open("genomes/champion.pkl", "rb") as f:
            data = pickle.load(f)
        genome = data["genome"]
        nodes = list(genome.nodes.keys())
        conns = []
        for key, cg in genome.connections.items():
            if cg.enabled:
                conns.append({
                    "in": key[0],
                    "out": key[1],
                    "weight": cg.weight
                })
        return {"nodes": nodes, "connections": conns}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/bans/unban/{ip}")
async def unban_ip(ip: str):
    if ip in SHARED_STATE["bans"]:
        del SHARED_STATE["bans"][ip]
        if sys.platform == "win32":
            rule_name = f"NEXUS_BLOCK_{ip.replace('.', '_')}"
            subprocess.run(
                f'netsh advfirewall firewall delete rule name="{rule_name}"',
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        broadcast_event("bans", SHARED_STATE["bans"])
        return {"status": "unbanned", "ip": ip}
    return {"status": "not_found", "ip": ip}


@app.get("/api/sniff/status")
async def get_sniff_status():
    return {"running": SNIFFER_RUNNING}


@app.post("/api/sniff/toggle")
async def toggle_sniff():
    if SNIFFER_RUNNING:
        stop_sniffer()
    else:
        start_sniffer()
    return {"running": SNIFFER_RUNNING}


@app.post("/api/simulate/{attack_type}")
async def simulate_attack(attack_type: str):
    """Simulates real-time packet arrival and pushes through neural net & state plane."""
    from scapy.all import Ether, IP, TCP, Raw
    import random

    if attack_type == "synflood":
        src_ip = f"198.51.100.{random.randint(10, 99)}"
        dst_port = random.choice([80, 443, 22, 3389])
        pkt = Ether()/IP(src=src_ip, dst="192.168.1.50", ttl=32)/\
              TCP(sport=random.randint(1024, 65535), dport=dst_port, flags="S", seq=random.randint(1000, 9999), ack=0)
    elif attack_type == "clean":
        src_ip = "192.168.1.50"
        pkt = Ether()/IP(src=src_ip, dst="142.250.190.46", ttl=64)/\
              TCP(sport=random.randint(49152, 65535), dport=443, flags="PA", window=64240)/\
              Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    else:
        src_ip = "10.0.0.66"
        pkt = Ether()/IP(src=src_ip, dst="192.168.1.50", ttl=40)/\
              TCP(sport=random.randint(40000, 60000), dport=445, flags="FPU", window=0)

    data = process_packet(pkt)
    return {"status": "ok", "score": data["score"], "src": src_ip}


@app.get("/api/stream")
async def event_stream(request: Request):
    """Per-client Server-Sent Events endpoint streaming real-time alerts and packet updates."""
    client_queue = asyncio.Queue(maxsize=100)
    EVENT_SUBSCRIBERS.add(client_queue)

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(client_queue.get(), timeout=2.0)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            EVENT_SUBSCRIBERS.discard(client_queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


def run_dashboard(host: str = "127.0.0.1", port: int = 8000, sniff_live: bool = False, active_defense: bool = False, iface: Optional[str] = None):
    SHARED_STATE["active_defense"] = active_defense
    if sniff_live:
        start_sniffer(iface=iface)

    print("\n=======================================================")
    print(f"  NEXUS TACTICAL COMMAND DASHBOARD INITIALIZED")
    print(f"  Dashboard URL:  http://localhost:{port}")
    print(f"  Live Sniffing:  {'ENABLED' if sniff_live else 'OFF (Use Simulation or Toggle in UI)'}")
    print(f"  Defense Mode:   {'ARMED (LIVE FIREWALL)' if active_defense else 'SIMULATION / LAB'}")
    print("=======================================================\n")

    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NEXUS Cyber-Guardian Live Web Dashboard")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host binding IP")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    parser.add_argument("--sniff", action="store_true", help="Start with live network packet capture enabled")
    parser.add_argument("--iface", type=str, default=None, help="Network interface for live capture")
    parser.add_argument("--active-defense", action="store_true", help="Arm live Windows firewall blocking")
    args = parser.parse_args()

    run_dashboard(
        host=args.host,
        port=args.port,
        sniff_live=args.sniff,
        active_defense=args.active_defense,
        iface=args.iface
    )

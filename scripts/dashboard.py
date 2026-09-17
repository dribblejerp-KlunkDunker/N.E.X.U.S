"""
NEXUS - Real-Time Cyber-Guardian Web Dashboard
FastAPI + Server-Sent Events (SSE) backend serving the tactical command interface,
streaming live packet evaluations, firewall bans, and RFC 5961 forensic events.
"""

import os
import sys
import time
import json
import asyncio
import pickle
import threading
import argparse
from typing import Dict, List, Optional
from datetime import datetime

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from pydantic import BaseModel

# Add scripts directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import PacketFeatureExtractor
from passive_flow_tracker import PassiveTcpFlowTracker

app = FastAPI(title="NEXUS Tactical Command API")

# Global event broadcast queue for Server-Sent Events (SSE)
EVENT_SUBSCRIBERS = set()
BROADCAST_QUEUE = asyncio.Queue()

# Shared state
SHARED_STATE = {
    "packets_evaluated": 0,
    "threats_flagged": 0,
    "bans": {},  # ip -> expire_ts
    "champion_fitness": 0.9980,
    "last_score": 0.0,
    "active_defense": False,
    "champion_path": "genomes/champion.pkl"
}

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
except Exception as e:
    print(f"[NEXUS Dashboard] Warning: Could not load champion genome: {e}")

EXTRACTOR = PacketFeatureExtractor()
TRACKER = PassiveTcpFlowTracker()


def broadcast_event(event_type: str, data: dict):
    """Pushes an event to all connected SSE clients."""
    loop = None
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        pass

    payload = {"type": event_type, "data": data}
    if loop and loop.is_running():
        loop.create_task(BROADCAST_QUEUE.put(payload))


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
        "last_score": SHARED_STATE["last_score"]
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
        # Remove firewall rule if active
        if sys.platform == "win32":
            import subprocess
            rule_name = f"NEXUS_BLOCK_{ip.replace('.', '_')}"
            subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name}"', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        await BROADCAST_QUEUE.put({"type": "bans", "data": SHARED_STATE["bans"]})
        return {"status": "unbanned", "ip": ip}
    return {"status": "not_found", "ip": ip}


@app.post("/api/simulate/{attack_type}")
async def simulate_attack(attack_type: str):
    """Simulates real-time packet arrival and pushes through neural net & state plane."""
    from scapy.all import Ether, IP, TCP, Raw
    import random

    cur_time = datetime.now().strftime("%H:%M:%S")

    if attack_type == "synflood":
        src_ip = f"198.51.100.{random.randint(10, 99)}"
        dst_port = random.choice([80, 443, 22, 3389])
        pkt = Ether()/IP(src=src_ip, dst="192.168.1.50", ttl=32)/\
              TCP(sport=random.randint(1024, 65535), dport=dst_port, flags="S", seq=random.randint(1000, 9999), ack=0)
        proto = "TCP"
        flags = "S"
    elif attack_type == "clean":
        src_ip = "192.168.1.50"
        pkt = Ether()/IP(src=src_ip, dst="142.250.190.46", ttl=64)/\
              TCP(sport=random.randint(49152, 65535), dport=443, flags="PA", window=64240)/\
              Raw(load=b"X" * random.randint(100, 500))
        proto = "TCP"
        flags = "PA"
    else:
        src_ip = "10.0.0.66"
        pkt = Ether()/IP(src=src_ip, dst="192.168.1.50", ttl=40)/\
              TCP(sport=random.randint(40000, 60000), dport=445, flags="FPU", window=0)
        proto = "TCP"
        flags = "FPU"

    # Evaluate with neural net
    feats_12 = EXTRACTOR.extract(pkt)
    feats_20 = EXTRACTOR.extract(pkt, extended=True)

    if NET:
        score = float(NET.activate(feats_12)[0])
    else:
        score = 0.98 if attack_type != "clean" else 0.001

    SHARED_STATE["packets_evaluated"] += 1
    SHARED_STATE["last_score"] = score

    # If anomaly, add temporary ban
    if score >= 0.85:
        SHARED_STATE["threats_flagged"] += 1
        ban_expire = time.time() + 1800  # 30 min
        SHARED_STATE["bans"][src_ip] = ban_expire
        await BROADCAST_QUEUE.put({"type": "bans", "data": SHARED_STATE["bans"]})

    # State plane event
    state_event = TRACKER.observe(
        src_ip=src_ip,
        src_port=pkt[TCP].sport,
        dst_ip=pkt[IP].dst,
        dst_port=pkt[TCP].dport,
        seq=pkt[TCP].seq,
        ack=pkt[TCP].ack if (pkt[TCP].flags & 0x10) else None,
        flags=flags,
        payload_len=len(pkt[Raw].load) if pkt.haslayer(Raw) else 0,
        window=pkt[TCP].window,
        ttl=pkt[IP].ttl
    )

    for finding in state_event.get("findings", []):
        await BROADCAST_QUEUE.put({"type": "rfc_event", "data": finding})

    # Prepare feature dictionary
    from feature_extractor import FEATURE_NAMES_20
    feat_dict = {name: float(val) for name, val in zip(FEATURE_NAMES_20, feats_20)}

    packet_data = {
        "time": cur_time,
        "src": f"{src_ip}:{pkt[TCP].sport}",
        "dst": f"{pkt[IP].dst}:{pkt[TCP].dport}",
        "proto": proto,
        "flags": flags,
        "score": score,
        "features": feat_dict
    }

    await BROADCAST_QUEUE.put({"type": "packet", "data": packet_data})
    return {"status": "ok", "score": score, "src": src_ip}


@app.get("/api/stream")
async def event_stream(request: Request):
    """Server-Sent Events endpoint streaming real-time alerts and packet updates."""
    async def event_generator():
        while True:
            if await request.is_disconnected():
                break
            try:
                # Wait for next event with a timeout for keep-alive
                event = await asyncio.wait_for(BROADCAST_QUEUE.get(), timeout=2.0)
                yield f"data: {json.dumps(event)}\n\n"
            except asyncio.TimeoutError:
                # Keep-alive ping
                yield ": keep-alive\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


def run_dashboard(host: str = "127.0.0.1", port: int = 8000):
    print("\n=======================================================")
    print(f"  NEXUS TACTICAL COMMAND DASHBOARD INITIALIZED")
    print(f"  Open your browser at: http://localhost:{port}")
    print("=======================================================\n")
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NEXUS Cyber-Guardian Live Web Dashboard")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host binding IP")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    args = parser.parse_args()

    run_dashboard(host=args.host, port=args.port)

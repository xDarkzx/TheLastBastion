#!/usr/bin/env python3
"""
Bastion Protocol Bench -- proof-of-work CLI.

Boots real agents (separate OS processes if you want) that actually talk to
each other over a real TCP connection, and reports MEASURED numbers, not
claims: handshake latency (fresh vs resumed), throughput, round-trip
latency percentiles, CPU/memory during the run, and an honest baseline
comparison against plain JSON-over-TCP (same transport, different wire
format -- isolates exactly what changed).

Zero external infrastructure required: no Postgres, no Redis, no Docker.
Just this repo's sdk/ installed (`pip install -e sdk/`).

Usage:
    # Terminal 1 -- the receiving side
    python scripts/bastion_bench.py serve --port 9100

    # Terminal 2 -- the sending side (same machine or a different one)
    python scripts/bastion_bench.py bench --host localhost --port 9100

    # Across two real machines on different networks: just point --host at
    # the other machine's reachable address. Nothing else changes -- the
    # same code path that proves correctness on localhost is what you run
    # cross-network the moment you have a second box.

Every number printed is measured during THIS run, not estimated. The JSON
report (--report, default bastion_bench_report.json) captures a structured
event log (every frame/message with timestamp and size) for the visual demo
report in scripts/bastion_report.py.
"""
import argparse
import asyncio
import json
import os
import statistics
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))

from lastbastion.crypto import load_or_create_keypair
from lastbastion.protocol.trust_store import PeerTrustStore
from lastbastion.protocol.socket import DirectAgentSocket

_HERE = os.path.dirname(os.path.abspath(__file__))

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

try:
    import pynvml
    pynvml.nvmlInit()
    _HAS_GPU = True
except Exception:
    _HAS_GPU = False


# ---------------------------------------------------------------------------
# Resource monitoring
# ---------------------------------------------------------------------------

@dataclass
class ResourceSample:
    t: float
    cpu_percent: float
    memory_mb: float
    gpu_percent: Optional[float] = None


class ResourceMonitor:
    """Samples this process's CPU/memory (and GPU, if available) in the background."""

    def __init__(self, interval_seconds: float = 0.2):
        self.interval = interval_seconds
        self.samples: List[ResourceSample] = []
        self._task: Optional[asyncio.Task] = None
        self._process = psutil.Process() if _HAS_PSUTIL else None
        if self._process:
            self._process.cpu_percent()  # prime the internal counter

    async def _run(self):
        while True:
            self.samples.append(self._sample())
            await asyncio.sleep(self.interval)

    def _sample(self) -> ResourceSample:
        if not self._process:
            return ResourceSample(t=time.time(), cpu_percent=-1.0, memory_mb=-1.0)
        cpu = self._process.cpu_percent()
        mem = self._process.memory_info().rss / (1024 * 1024)
        gpu = None
        if _HAS_GPU:
            try:
                handle = pynvml.nvmlDeviceGetHandleByIndex(0)
                gpu = pynvml.nvmlDeviceGetUtilizationRates(handle).gpu
            except Exception:
                gpu = None
        return ResourceSample(t=time.time(), cpu_percent=cpu, memory_mb=mem, gpu_percent=gpu)

    def start(self):
        if _HAS_PSUTIL:
            self._task = asyncio.ensure_future(self._run())

    def stop(self) -> Dict[str, Any]:
        if self._task:
            self._task.cancel()
        if not self.samples:
            return {"available": _HAS_PSUTIL, "note": "no samples captured"}
        cpu_vals = [s.cpu_percent for s in self.samples if s.cpu_percent >= 0]
        mem_vals = [s.memory_mb for s in self.samples]
        gpu_vals = [s.gpu_percent for s in self.samples if s.gpu_percent is not None]
        return {
            "available": _HAS_PSUTIL,
            "gpu_available": _HAS_GPU,
            "gpu_note": None if _HAS_GPU else (
                "No GPU/pynvml detected -- expected: this protocol is pure "
                "crypto + networking, it has no GPU workload"
            ),
            "samples": len(self.samples),
            "cpu_percent": _minmaxavg(cpu_vals),
            "memory_mb": _minmaxavg(mem_vals),
            "gpu_percent": _minmaxavg(gpu_vals) if gpu_vals else None,
        }


def _minmaxavg(vals: List[float]) -> Dict[str, float]:
    if not vals:
        return {"min": 0.0, "avg": 0.0, "max": 0.0}
    return {"min": round(min(vals), 2), "avg": round(sum(vals) / len(vals), 2), "max": round(max(vals), 2)}


def _percentiles(vals_ms: List[float]) -> Dict[str, float]:
    if not vals_ms:
        return {"min": 0.0, "avg": 0.0, "p50": 0.0, "p95": 0.0, "max": 0.0}
    s = sorted(vals_ms)
    return {
        "min": round(s[0], 3),
        "avg": round(sum(s) / len(s), 3),
        "p50": round(statistics.median(s), 3),
        "p95": round(s[int(len(s) * 0.95) - 1] if len(s) > 1 else s[0], 3),
        "max": round(s[-1], 3),
    }


# ---------------------------------------------------------------------------
# Event log -- feeds the visual demo report
# ---------------------------------------------------------------------------

@dataclass
class EventLog:
    events: List[Dict[str, Any]] = field(default_factory=list)

    def record(self, phase: str, event: str, **kwargs):
        self.events.append({"t": time.time(), "phase": phase, "event": event, **kwargs})


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------

async def cmd_serve(args):
    pub, priv = load_or_create_keypair(os.path.join(_HERE, ".bench_server.keys.json"))
    trust_store = PeerTrustStore(os.path.join(_HERE, ".bench_server_trust.json"))
    ticket_key = os.urandom(32)

    stats = {"connections": 0, "messages": 0, "bytes": 0}

    async def handle(conn):
        stats["connections"] += 1
        try:
            while True:
                msg = await conn.recv()
                stats["messages"] += 1
                stats["bytes"] += len(json.dumps(msg).encode())
                await conn.send({"echo": msg})
        except Exception:
            pass

    server = DirectAgentSocket.listen(
        agent_id=args.agent_id, public_key=pub, signing_key=priv,
        trust_store=trust_store, host=args.bind, port=args.port,
        ticket_key=ticket_key,
    )
    server.on_connect(handle)

    print(f"Bastion Bench server -- agent_id={args.agent_id!r}")
    print(f"Listening on {args.bind}:{args.port} (DIRECT mode, resumption enabled)")
    print(f"Public key: {pub}")
    print("Waiting for connections... (Ctrl+C to stop)")
    print(f"Stats every 5s: connections / messages / bytes received")

    async def report_loop():
        while True:
            await asyncio.sleep(5)
            print(f"  [{time.strftime('%H:%M:%S')}] "
                  f"connections={stats['connections']} messages={stats['messages']} "
                  f"bytes={stats['bytes']} active={server.active_connections}")

    asyncio.ensure_future(report_loop())
    await server.start()


# ---------------------------------------------------------------------------
# bench
# ---------------------------------------------------------------------------

async def cmd_bench(args):
    log = EventLog()
    monitor = ResourceMonitor()
    monitor.start()

    pub, priv = load_or_create_keypair(os.path.join(_HERE, ".bench_client.keys.json"))
    trust_store = PeerTrustStore(os.path.join(_HERE, ".bench_client_trust.json"))

    print(f"Bastion Bench -- connecting to {args.host}:{args.port}")
    print(f"Client agent_id={args.agent_id!r}, target agent_id={args.target_agent_id!r}\n")

    report: Dict[str, Any] = {
        "target": f"{args.host}:{args.port}",
        "started_at": time.time(),
    }

    # --- Phase 1: fresh handshake latency (N repetitions) ---
    print(f"[1/4] Fresh DIRECT-mode handshakes x{args.handshakes} ...")
    fresh_latencies = []
    last_ticket = None
    last_secret = None
    for i in range(args.handshakes):
        t0 = time.perf_counter()
        conn, ticket, secret = await DirectAgentSocket.connect(
            args.host, agent_id=args.agent_id, public_key=pub, signing_key=priv,
            trust_store=trust_store, port=args.port,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000
        fresh_latencies.append(elapsed_ms)
        log.record("handshake_fresh", "complete", index=i, latency_ms=elapsed_ms)
        last_ticket, last_secret = ticket, secret
        await conn.close()
    report["fresh_handshake_ms"] = _percentiles(fresh_latencies)
    print(f"      {report['fresh_handshake_ms']}")

    # --- Phase 2: resumed handshake latency (N repetitions, chained tickets) ---
    resumed_latencies = []
    if last_ticket is not None:
        print(f"[2/4] Resumed handshakes x{args.handshakes} ...")
        for i in range(args.handshakes):
            t0 = time.perf_counter()
            conn, next_ticket, secret2 = await DirectAgentSocket.connect(
                args.host, agent_id=args.agent_id, public_key=pub, signing_key=priv,
                trust_store=trust_store, port=args.port,
                resume_ticket=last_ticket, resumption_secret=last_secret,
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000
            resumed_latencies.append(elapsed_ms)
            log.record("handshake_resumed", "complete", index=i, latency_ms=elapsed_ms,
                        was_resumed=(conn.peer.verdict == "RESUMED"))
            last_ticket = next_ticket
            await conn.close()
        report["resumed_handshake_ms"] = _percentiles(resumed_latencies)
        print(f"      {report['resumed_handshake_ms']}")
        if fresh_latencies and resumed_latencies:
            speedup = statistics.mean(fresh_latencies) / max(statistics.mean(resumed_latencies), 0.001)
            report["measured_resumption_speedup_x"] = round(speedup, 2)
            print(f"      measured speedup: {speedup:.2f}x (fresh avg / resumed avg)")
    else:
        print("[2/4] Skipped -- server did not offer a resumption ticket")
        report["resumed_handshake_ms"] = None

    # --- Phase 3: throughput over an established connection ---
    print(f"[3/4] Throughput: {args.messages} messages x {args.size} bytes ...")
    conn, _t, _s = await DirectAgentSocket.connect(
        args.host, agent_id=args.agent_id, public_key=pub, signing_key=priv,
        trust_store=trust_store, port=args.port,
    )
    payload_blob = os.urandom(args.size).hex()
    rtts = []
    t_start = time.perf_counter()
    for i in range(args.messages):
        t0 = time.perf_counter()
        await conn.send({"seq": i, "data": payload_blob})
        resp = await conn.recv()
        rtt_ms = (time.perf_counter() - t0) * 1000
        rtts.append(rtt_ms)
        log.record("bastion_data", "round_trip", index=i, rtt_ms=rtt_ms, size_bytes=args.size)
    total_s = time.perf_counter() - t_start
    await conn.close()

    total_bytes = args.messages * args.size * 2  # request + echoed response
    report["bastion_throughput"] = {
        "messages": args.messages,
        "message_size_bytes": args.size,
        "total_seconds": round(total_s, 4),
        "messages_per_sec": round(args.messages / total_s, 1),
        "mb_per_sec": round((total_bytes / (1024 * 1024)) / total_s, 3),
        "round_trip_ms": _percentiles(rtts),
    }
    print(f"      {report['bastion_throughput']['messages_per_sec']} msg/s, "
          f"{report['bastion_throughput']['mb_per_sec']} MB/s, "
          f"round-trip {report['bastion_throughput']['round_trip_ms']}")

    # --- Phase 4: honest baseline -- plain JSON-over-TCP, same transport pattern ---
    print(f"[4/4] Baseline: plain JSON-over-TCP x{args.messages} (same payload, no crypto) ...")
    baseline = await _run_json_baseline(args, payload_blob, log)
    report["json_baseline_throughput"] = baseline
    print(f"      {baseline['messages_per_sec']} msg/s, {baseline['mb_per_sec']} MB/s, "
          f"round-trip {baseline['round_trip_ms']}")
    if baseline["messages_per_sec"] > 0:
        rt_speedup = baseline["round_trip_ms"]["avg"] / max(report["bastion_throughput"]["round_trip_ms"]["avg"], 0.001)
        report["measured_data_speedup_x"] = round(rt_speedup, 2)
        print(f"      measured Bastion vs plain-JSON round-trip speedup: {rt_speedup:.2f}x")

    report["resources"] = monitor.stop()
    report["completed_at"] = time.time()
    report["events"] = log.events

    print("\n--- Resource usage during this run ---")
    print(json.dumps(report["resources"], indent=2))

    with open(args.report, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nFull report written to {args.report}")
    print("Note: these are real measured numbers from THIS run/machine/network. "
          "Re-run on your actual deployment target for numbers that matter for it.")


async def _run_json_baseline(args, payload_blob: str, log: EventLog) -> Dict[str, Any]:
    """
    Plain length-prefixed JSON over a raw TCP socket -- deliberately NOT full
    HTTP/A2A, to isolate exactly one variable (binary+msgpack+crypto vs
    text+JSON+no crypto) rather than also mixing in a specific HTTP server
    implementation's overhead. Spins up its own tiny echo server on a
    separate port for the duration of this phase.
    """
    port = args.port + 1000

    async def handle(reader, writer):
        try:
            while True:
                length_bytes = await reader.readexactly(4)
                length = int.from_bytes(length_bytes, "big")
                data = await reader.readexactly(length)
                msg = json.loads(data)
                resp = json.dumps({"echo": msg}).encode()
                writer.write(len(resp).to_bytes(4, "big") + resp)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass

    server = await asyncio.start_server(handle, args.host if args.host != "localhost" else "0.0.0.0", port)
    async with server:
        reader, writer = await asyncio.open_connection(args.host, port)
        rtts = []
        t_start = time.perf_counter()
        for i in range(args.messages):
            t0 = time.perf_counter()
            msg = json.dumps({"seq": i, "data": payload_blob}).encode()
            writer.write(len(msg).to_bytes(4, "big") + msg)
            await writer.drain()
            length_bytes = await reader.readexactly(4)
            length = int.from_bytes(length_bytes, "big")
            await reader.readexactly(length)
            rtt_ms = (time.perf_counter() - t0) * 1000
            rtts.append(rtt_ms)
            log.record("json_baseline", "round_trip", index=i, rtt_ms=rtt_ms, size_bytes=args.size)
        total_s = time.perf_counter() - t_start
        writer.close()

        total_bytes = args.messages * args.size * 2
        return {
            "messages": args.messages,
            "total_seconds": round(total_s, 4),
            "messages_per_sec": round(args.messages / total_s, 1),
            "mb_per_sec": round((total_bytes / (1024 * 1024)) / total_s, 3),
            "round_trip_ms": _percentiles(rtts),
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Bastion Protocol proof-of-work bench -- real agents, real measured numbers."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_serve = sub.add_parser("serve", help="Run the receiving side")
    p_serve.add_argument("--bind", default="0.0.0.0")
    p_serve.add_argument("--port", type=int, default=9100)
    p_serve.add_argument("--agent-id", default="bench-server")

    p_bench = sub.add_parser("bench", help="Run the sending side and measure everything")
    p_bench.add_argument("--host", required=True, help="Server host/IP (use the serve side's reachable address)")
    p_bench.add_argument("--port", type=int, default=9100)
    p_bench.add_argument("--agent-id", default="bench-client")
    p_bench.add_argument("--target-agent-id", default="bench-server")
    p_bench.add_argument("--handshakes", type=int, default=20, help="Repetitions for handshake latency stats")
    p_bench.add_argument("--messages", type=int, default=200, help="Messages for throughput test")
    p_bench.add_argument("--size", type=int, default=1024, help="Payload size in bytes per message")
    p_bench.add_argument("--report", default="bastion_bench_report.json")

    args = parser.parse_args()

    if not _HAS_PSUTIL:
        print("Note: psutil not installed -- CPU/memory stats will be unavailable "
              "(pip install psutil). GPU stats need pynvml on top of that.")

    if args.command == "serve":
        asyncio.run(cmd_serve(args))
    elif args.command == "bench":
        asyncio.run(cmd_bench(args))


if __name__ == "__main__":
    main()

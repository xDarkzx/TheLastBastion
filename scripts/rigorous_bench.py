#!/usr/bin/env python3
"""
Rigorous Bastion Protocol vs. JSON-over-TCP benchmark.

This is NOT bastion_bench.py's single-shot numbers repackaged. It exists
because single ad-hoc runs are not an adequate basis for a performance claim
that anyone -- especially a skeptical reviewer -- should be able to trust:

  - Each trial launches a FRESH server process and a FRESH client process.
    No shared warm-up state, no OS-level socket/connection caching carried
    between trials, no risk of one trial's JIT/cache warmth contaminating
    the next.
  - Runs N independent trials (default 10) and reports mean/median/stdev/
    min/max across trials, not a single number from a single run.
  - Records the exact test environment (OS, kernel, Python, library
    versions) alongside the results, because a number with no environment
    attached is not reproducible and should not be trusted.
  - Writes everything -- methodology, environment, every trial's raw data,
    and the aggregate statistics -- to a single Markdown report. Nothing is
    cherry-picked; every trial that ran is in the report, favorable or not.

Usage:
    python scripts/rigorous_bench.py --trials 10 --messages 500 \\
        --bulk-messages 20000 --size 512 --output BENCHMARK_RESULTS.md

Requirements: same as bastion_bench.py (this repo's SDK, psutil optional).
No Docker, no Postgres, no Redis.
"""
import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
_PYTHON = sys.executable


def _pkg_version(name: str) -> str:
    try:
        import importlib.metadata as md
        return md.version(name)
    except Exception:
        return "not installed"


def _collect_environment() -> Dict[str, Any]:
    env = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "processor": platform.processor() or "unknown",
        "cpu_count": os.cpu_count(),
        "pynacl_version": _pkg_version("pynacl"),
        "msgpack_version": _pkg_version("msgpack"),
        "psutil_version": _pkg_version("psutil"),
    }
    if platform.system() == "Linux":
        try:
            uname = subprocess.run(["uname", "-a"], capture_output=True, text=True, timeout=5)
            env["uname"] = uname.stdout.strip()
        except Exception:
            pass
        # WSL detection
        try:
            with open("/proc/version") as f:
                version_str = f.read()
            env["is_wsl"] = "microsoft" in version_str.lower() or "wsl" in version_str.lower()
            if env["is_wsl"]:
                env["proc_version"] = version_str.strip()
        except Exception:
            env["is_wsl"] = "unknown"
    return env


def _run_one_trial(
    trial_num: int, host: str, port: int, messages: int, bulk_messages: int,
    handshakes: int, size: int, report_path: str, trusted_transport: bool = False,
    use_uvloop: bool = False,
) -> Optional[Dict[str, Any]]:
    """Launches a fresh server subprocess and a fresh client subprocess for one trial."""
    serve_cmd = [_PYTHON, os.path.join(_HERE, "bastion_bench.py"), "serve", "--port", str(port)]
    if trusted_transport:
        serve_cmd.append("--trusted-transport")
    if use_uvloop:
        serve_cmd.append("--uvloop")
    server_proc = subprocess.Popen(
        serve_cmd,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(1.2)  # let the server bind and start accepting

        bench_cmd = [
            _PYTHON, os.path.join(_HERE, "bastion_bench.py"), "bench",
            "--host", host, "--port", str(port),
            "--handshakes", str(handshakes), "--messages", str(messages),
            "--bulk-messages", str(bulk_messages), "--size", str(size),
            "--report", report_path,
        ]
        if trusted_transport:
            bench_cmd.append("--trusted-transport")
        if use_uvloop:
            bench_cmd.append("--uvloop")
        client_proc = subprocess.run(
            bench_cmd,
            capture_output=True, text=True, timeout=120,
        )
        if client_proc.returncode != 0:
            print(f"  Trial {trial_num}: FAILED (exit {client_proc.returncode})")
            print(f"    stderr: {client_proc.stderr[-500:]}")
            return None

        with open(report_path) as f:
            result = json.load(f)
        # bastion_bench.py's report includes a full per-message event log
        # (one entry per round-trip/bulk message -- tens of thousands of
        # entries per trial). That's useful for bastion_bench.py's own
        # visual-report tooling, but multiplied across 10 trials it turns
        # this script's Markdown report into multi-megabyte files with no
        # value for the aggregate statistics this report actually makes --
        # strip it here, keep everything else.
        result.pop("events", None)
        return result
    finally:
        server_proc.terminate()
        try:
            server_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_proc.kill()


def _stats(values: List[float]) -> Dict[str, float]:
    if not values:
        return {}
    return {
        "n": len(values),
        "mean": round(statistics.mean(values), 2),
        "median": round(statistics.median(values), 2),
        "stdev": round(statistics.stdev(values), 2) if len(values) > 1 else 0.0,
        "min": round(min(values), 2),
        "max": round(max(values), 2),
    }


def main():
    parser = argparse.ArgumentParser(description="Rigorous, multi-trial Bastion vs JSON benchmark")
    parser.add_argument("--trials", type=int, default=10, help="Independent trials (fresh processes each)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19900)
    parser.add_argument("--handshakes", type=int, default=15)
    parser.add_argument("--messages", type=int, default=500)
    parser.add_argument("--bulk-messages", type=int, default=20000)
    parser.add_argument("--size", type=int, default=512)
    parser.add_argument("--output", default="BENCHMARK_RESULTS.md")
    parser.add_argument(
        "--trusted-transport", dest="trusted_transport", action="store_true",
        help="Benchmark the trusted_transport=True path (no NaCl encryption on DATA "
             "frames) instead of the default fully-encrypted path.",
    )
    parser.add_argument(
        "--uvloop", dest="use_uvloop", action="store_true",
        help="Benchmark with uvloop instead of the default asyncio event loop "
             "(Linux/Mac only -- both serve and bench subprocesses use it).",
    )
    args = parser.parse_args()

    print(f"Rigorous benchmark: {args.trials} independent trials, fresh server+client process each")
    print(f"Environment: {platform.platform()}, Python {platform.python_version()}\n")

    env = _collect_environment()
    env["trusted_transport"] = args.trusted_transport
    env["use_uvloop"] = args.use_uvloop
    if args.use_uvloop:
        env["uvloop_version"] = _pkg_version("uvloop")
    trials: List[Dict[str, Any]] = []
    failed = 0

    for i in range(args.trials):
        print(f"Trial {i+1}/{args.trials} ...")
        report_path = os.path.join(_HERE, f".rigorous_trial_{i}.json")
        result = _run_one_trial(
            i + 1, args.host, args.port + (i % 50), args.messages, args.bulk_messages,
            args.handshakes, args.size, report_path, args.trusted_transport, args.use_uvloop,
        )
        if result is None:
            failed += 1
            continue
        trials.append(result)
        try:
            os.remove(report_path)
        except OSError:
            pass
        time.sleep(0.3)

    if not trials:
        print("ERROR: all trials failed, nothing to report")
        sys.exit(1)

    # --- Aggregate ---
    def extract(path_fn):
        vals = []
        for t in trials:
            try:
                vals.append(path_fn(t))
            except (KeyError, TypeError):
                pass
        return vals

    agg = {
        "fresh_handshake_ms_mean": extract(lambda t: t["fresh_handshake_ms"]["avg"]),
        "resumed_handshake_ms_mean": extract(lambda t: t["resumed_handshake_ms"]["avg"] if t.get("resumed_handshake_ms") else None),
        "resumption_speedup_x": extract(lambda t: t["measured_resumption_speedup_x"]),
        "bastion_roundtrip_msg_per_sec": extract(lambda t: t["bastion_throughput"]["messages_per_sec"]),
        "json_roundtrip_msg_per_sec": extract(lambda t: t["json_baseline_throughput"]["messages_per_sec"]),
        "roundtrip_speedup_x": extract(lambda t: t["measured_data_speedup_x"]),
        "bastion_pipelined_msg_per_sec": extract(lambda t: t["bastion_pipelined_throughput"]["messages_per_sec"]),
        "bastion_pipelined_mb_per_sec": extract(lambda t: t["bastion_pipelined_throughput"]["mb_per_sec"]),
        "json_pipelined_msg_per_sec": extract(lambda t: t["json_pipelined_throughput"]["messages_per_sec"]),
        "pipelined_speedup_x": extract(lambda t: t["measured_pipelined_speedup_x"]),
    }
    agg = {k: v for k, v in agg.items() if v}  # drop empty (e.g. no resumption ticket offered)
    stats = {k: _stats(v) for k, v in agg.items()}

    # --- Write report ---
    lines = []
    lines.append("# Bastion Protocol vs. JSON-over-TCP — Benchmark Results\n")
    lines.append(f"Generated: {env['timestamp_utc']}\n")
    lines.append("## Methodology\n")
    lines.append(
        f"- **{len(trials)} independent trials** completed ({failed} failed and excluded), "
        f"each launching a fresh server process and a fresh client process — no shared "
        f"warm-up state, connection caching, or JIT/cache warmth carried between trials.\n"
        f"- Each trial: {args.handshakes} handshake repetitions, {args.messages} round-trip "
        f"messages, {args.bulk_messages} pipelined bulk-send messages, {args.size}-byte payloads.\n"
        "- Every trial's raw data is included below — none excluded except outright process failures.\n"
        "- **This is not a security-equivalent comparison.** The JSON baseline has zero "
        "encryption, zero authentication, zero replay protection, and zero framing validation. "
        "Bastion Protocol does all of that. The comparison isolates wire-format/session cost, "
        "not \"equivalent security posture at different speeds\" — there is no equivalent-security "
        "JSON baseline being claimed here.\n"
        "- Reproduce with: `python scripts/rigorous_bench.py --trials "
        f"{args.trials} --messages {args.messages} --bulk-messages {args.bulk_messages} "
        f"--size {args.size}`\n"
    )
    lines.append("## Environment\n")
    lines.append("```json")
    lines.append(json.dumps(env, indent=2))
    lines.append("```\n")

    lines.append("## Aggregate results (across all trials)\n")
    lines.append("| Metric | Trials (n) | Mean | Median | Stdev | Min | Max |")
    lines.append("|---|---|---|---|---|---|---|")
    label_map = {
        "fresh_handshake_ms_mean": "Fresh handshake latency (ms)",
        "resumed_handshake_ms_mean": "Resumed handshake latency (ms)",
        "resumption_speedup_x": "Resumption speedup (x, fresh/resumed)",
        "bastion_roundtrip_msg_per_sec": "Bastion round-trip throughput (msg/s)",
        "json_roundtrip_msg_per_sec": "JSON baseline round-trip throughput (msg/s)",
        "roundtrip_speedup_x": "Bastion vs JSON round-trip ratio (x)",
        "bastion_pipelined_msg_per_sec": "Bastion pipelined bulk-send (msg/s)",
        "bastion_pipelined_mb_per_sec": "Bastion pipelined bulk-send (MB/s)",
        "json_pipelined_msg_per_sec": "JSON baseline pipelined bulk-send (msg/s)",
        "pipelined_speedup_x": "Bastion vs JSON pipelined ratio (x)",
    }
    for key, label in label_map.items():
        if key not in stats:
            continue
        s = stats[key]
        lines.append(
            f"| {label} | {s['n']} | {s['mean']} | {s['median']} | {s['stdev']} | {s['min']} | {s['max']} |"
        )
    lines.append("")

    lines.append("## Honest interpretation\n")
    if "roundtrip_speedup_x" in stats:
        rt = stats["roundtrip_speedup_x"]["mean"]
        verdict = "SLOWER than" if rt < 1 else "FASTER than"
        lines.append(
            f"- **Round-trip (request-response) throughput: Bastion is {verdict} the plain-JSON "
            f"baseline**, at {rt}x across {stats['roundtrip_speedup_x']['n']} trials "
            f"(stdev {stats['roundtrip_speedup_x']['stdev']}). This is NOT parity, and this "
            f"report does not claim it is.\n"
        )
    if "resumption_speedup_x" in stats:
        rs = stats["resumption_speedup_x"]["mean"]
        lines.append(
            f"- **Session resumption** (skipping the full handshake on reconnect) shows a real, "
            f"repeated, measured speedup of {rs}x over a fresh handshake "
            f"(stdev {stats['resumption_speedup_x']['stdev']}, {stats['resumption_speedup_x']['n']} trials).\n"
        )
    if "bastion_pipelined_msg_per_sec" in stats:
        lines.append(
            f"- **Pipelined bulk-send** (the pattern an actual bulk transfer uses -- not "
            f"waiting for a per-message ack): {stats['bastion_pipelined_msg_per_sec']['mean']} msg/s "
            f"mean ({stats['bastion_pipelined_msg_per_sec']['stdev']} stdev). This is the number "
            f"relevant to \"send N messages of data,\" not round-trip request-response latency.\n"
        )
    if "pipelined_speedup_x" in stats:
        ps = stats["pipelined_speedup_x"]["mean"]
        verdict = "SLOWER than" if ps < 1 else "FASTER than"
        lines.append(
            f"- **Pipelined bulk-send: Bastion is {verdict} the plain-JSON pipelined baseline**, "
            f"at {ps}x across {stats['pipelined_speedup_x']['n']} trials "
            f"(stdev {stats['pipelined_speedup_x']['stdev']}). This is the direct, fair comparison "
            f"for the pipelined pattern -- both sides fire-and-forget, neither waits per-message.\n"
        )
    lines.append(
        "\n## Raw per-trial data\n\n"
        "Every completed trial, unfiltered:\n"
    )
    lines.append("```json")
    lines.append(json.dumps(trials, indent=2))
    lines.append("```\n")

    report_text = "\n".join(lines)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report_text)

    print(f"\n{len(trials)}/{args.trials} trials completed successfully.")
    print(f"Full report written to {args.output}")


if __name__ == "__main__":
    main()

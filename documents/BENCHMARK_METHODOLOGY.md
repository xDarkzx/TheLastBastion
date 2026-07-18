# Benchmark Methodology & Cross-Platform Summary

This document exists because a performance claim without a reproducible,
documented methodology behind it is not a claim worth making. It is the
index for two full benchmark reports and the tool that produced them.

## Reports

- [`BENCHMARK_RESULTS_WINDOWS.md`](BENCHMARK_RESULTS_WINDOWS.md) — 10 independent trials, Windows 10
- [`BENCHMARK_RESULTS_LINUX_WSL2.md`](BENCHMARK_RESULTS_LINUX_WSL2.md) — 10 independent trials, WSL2 Ubuntu 22.04 (Linux kernel)

Both were produced by the same tool (`scripts/rigorous_bench.py`, which
drives `scripts/bastion_bench.py`) with identical parameters, so the two
reports are directly comparable to each other.

## How this differs from an ad-hoc benchmark run

Every number in the two linked reports comes from **10 independent trials**,
where each trial launches a brand-new server process and a brand-new client
process — not 10 loop iterations inside one warm process. This matters
because a single long-running process can have JIT/cache warmth, OS-level
socket buffer state, or connection reuse effects that make one measurement
non-representative of a cold start. Independent process-level trials don't
have that problem.

For each metric, the reports show **mean, median, standard deviation, min,
and max across the 10 trials** — not a single number. The full raw JSON for
every trial is included in each report, unfiltered, so the aggregate numbers
can be checked against the underlying data.

## Reproducing these results

```bash
pip install -e sdk/
python scripts/rigorous_bench.py --trials 10 --handshakes 15 --messages 500 \
    --bulk-messages 20000 --size 512 --output documents/BENCHMARK_RESULTS_WINDOWS.md
```

Run the identical command on Linux/WSL2 for the Linux report. No Docker,
Postgres, or Redis required — this benchmarks the protocol layer in
isolation.

## What is being measured, and what is deliberately NOT a fair comparison

Two patterns are measured, because they answer different questions:

1. **Round-trip (request-response)**: send a message, wait for the reply,
   repeat. This is the cost per turn of a synchronous exchange.
2. **Pipelined (fire-and-forget) bulk send**: fire N messages back-to-back
   without waiting for an ack after each one. This is the pattern an actual
   bulk transfer (e.g. "send 200k records") uses, and it is a fundamentally
   different throughput number from round-trip — pipelining removes the
   network round-trip latency from the critical path.

Both patterns are benchmarked against a plain length-prefixed JSON-over-TCP
baseline with **zero encryption, zero authentication, zero replay
protection, and zero framing validation**. Bastion Protocol does all of
that (Ed25519 identity, X25519 ECDH handshake, NaCl SecretBox session
encryption, replay/nonce protection). The comparison isolates wire-format
and session cost — it is explicitly **not** a claim that these are
equivalent-security baselines running at different speeds. There is no
zero-security JSON deployment this project would recommend; the baseline
exists only to answer "what does the crypto and framing cost, concretely."

## Honest summary of findings (as of these runs)

Bastion Protocol is **slower than plain JSON** on both platforms, on both
patterns tested:

| Pattern | Windows | Linux (WSL2) |
|---|---|---|
| Round-trip throughput ratio (Bastion / JSON) | 0.45x | 0.22x |
| Pipelined bulk-send ratio (Bastion / JSON) | 0.22x | 0.21x |

This is not parity, and no claim of parity or improvement is made anywhere
in this repository. Session resumption (skipping a full handshake on
reconnect) does show a real, repeatedly-measured ~1.9–2.1x speedup over a
fresh handshake on both platforms — that is a genuine, narrower win, not a
substitute for the round-trip/pipelined numbers above.

The gap is attributable to the actual cost of Ed25519 signing, X25519 ECDH,
and NaCl SecretBox encrypt/decrypt per message, plus msgpack framing versus
Python's C-accelerated `json` module — costs plain JSON-over-TCP does not
pay because it does none of that work. Closing this gap, if it's worth
closing, requires either reducing per-message crypto operations (e.g.
batching, or amortizing signature cost across a session rather than
per-frame) or accepting that a secure protocol will not be as fast as an
insecure one and choosing where that tradeoff is acceptable.

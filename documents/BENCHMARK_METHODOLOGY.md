# Benchmark Methodology & Cross-Platform Summary

This document exists because a performance claim without a reproducible,
documented methodology behind it is not a claim worth making. It is the
index for two full benchmark reports and the tool that produced them.

## Reports

Fully-encrypted DIRECT mode (default: NaCl SecretBox encryption on every DATA frame):
- [`BENCHMARK_RESULTS_WINDOWS.md`](BENCHMARK_RESULTS_WINDOWS.md) — 10 independent trials, Windows 10
- [`BENCHMARK_RESULTS_LINUX_WSL2.md`](BENCHMARK_RESULTS_LINUX_WSL2.md) — 10 independent trials, WSL2 Ubuntu 22.04 (Linux kernel)

`trusted_transport=True` (no encryption — only appropriate for a connection
you control end-to-end, see `sdk/lastbastion/protocol/socket.py`'s
`AgentConnection` docstring):
- [`BENCHMARK_RESULTS_WINDOWS_TRUSTED.md`](BENCHMARK_RESULTS_WINDOWS_TRUSTED.md) — 10 independent trials, Windows 10
- [`BENCHMARK_RESULTS_LINUX_WSL2_TRUSTED.md`](BENCHMARK_RESULTS_LINUX_WSL2_TRUSTED.md) — 10 independent trials, WSL2 Ubuntu 22.04

All four were produced by the same tool (`scripts/rigorous_bench.py`, which
drives `scripts/bastion_bench.py`) with identical parameters (only
`--trusted-transport` differs), so all four reports are directly comparable.

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
patterns tested, in both configurations:

| Pattern | Windows (encrypted) | Windows (trusted_transport) | Linux (encrypted) | Linux (trusted_transport) |
|---|---|---|---|---|
| Round-trip throughput ratio (Bastion / JSON) | 0.45x | 0.62x | 0.22x | 0.28x |
| Pipelined bulk-send ratio (Bastion / JSON) | 0.22x | 0.29x | 0.21x | 0.34x |

This is not parity, and no claim of parity or improvement is made anywhere
in this repository. Session resumption (skipping a full handshake on
reconnect) does show a real, repeatedly-measured ~1.9–2.1x speedup over a
fresh handshake on both platforms — that is a genuine, narrower win, not a
substitute for the round-trip/pipelined numbers above.

**Removing encryption (`trusted_transport=True`) closes part of the gap,
consistently, on both platforms — but not most of it.** Round-trip
improved 38% on Windows (0.45x → 0.62x) and 27% on Linux (0.22x → 0.28x);
pipelined improved similarly. That's a real, repeatable, statistically
solid result (see the `_TRUSTED` reports above for full trial data) — and
it is nowhere near "as fast as JSON."

### Where the remaining gap actually is (profiled, not guessed)

After encryption is removed, isolated CPU-only microbenchmarks of just the
encode/decode path (msgpack pack/unpack, frame header struct.pack/unpack,
sequence/freshness validation) showed costs small enough that they didn't
explain the observed throughput gap on their own — so rather than trust
that estimate, the actual live round-trip path was profiled directly with
`cProfile` against a real running server, and compared line-for-line against
an identically-profiled JSON baseline over the same connection pattern.

Result: **both protocols pay nearly identical raw socket I/O cost** — same
number of `WSASend`/`WSARecvInto`/event-loop-poll calls, since both use the
same length-prefixed read/write pattern. The gap comes from Bastion's own
structural overhead on top of that shared I/O cost: frame header
packing/unpacking (`struct.pack`/`struct.unpack`), sequence-number and
freshness/timestamp validation, and the extra Python-level call chain
(`send()` → `_write_frame()` → `_write_frame_raw()`, and the equivalent on
the read side) versus JSON's flatter, more direct `writer.write()` /
`reader.readexactly()` calls. None of this is wasted computation --
it's what a binary framed protocol with replay/freshness protection
actually costs beyond a bare socket write, and msgpack itself is faster
than `json` in isolation (measured ~0.74us vs ~3.53us per message for
pack+unpack combined) — the serialization format was never the problem.

**What this means practically:** closing the remaining gap further would
require removing more of what makes this a real protocol -- sequence
numbers (replay protection), timestamps (freshness/replay-window
enforcement), or the structured typed-frame header (versioning,
parseability) -- not more crypto or serialization tuning, since those are
no longer the dominant cost. There is a real, marginal amount of headroom
left in flattening the call chain and reducing per-frame dataclass
construction, but based on the profiling above that would close single-digit
percentage points, not the remaining multiple-x gap to parity.

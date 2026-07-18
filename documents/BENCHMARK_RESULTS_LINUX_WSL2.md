# Bastion Protocol vs. JSON-over-TCP — Benchmark Results

Generated: 2026-07-18T23:53:20.283152+00:00

## Methodology

- **10 independent trials** completed (0 failed and excluded), each launching a fresh server process and a fresh client process — no shared warm-up state, connection caching, or JIT/cache warmth carried between trials.
- Each trial: 15 handshake repetitions, 500 round-trip messages, 20000 pipelined bulk-send messages, 512-byte payloads.
- Every trial's raw data is included below — none excluded except outright process failures.
- **This is not a security-equivalent comparison.** The JSON baseline has zero encryption, zero authentication, zero replay protection, and zero framing validation. Bastion Protocol does all of that. The comparison isolates wire-format/session cost, not "equivalent security posture at different speeds" — there is no equivalent-security JSON baseline being claimed here.
- Reproduce with: `python scripts/rigorous_bench.py --trials 10 --messages 500 --bulk-messages 20000 --size 512`

## Environment

```json
{
  "timestamp_utc": "2026-07-18T23:53:20.283152+00:00",
  "platform": "Linux-6.6.87.2-microsoft-standard-WSL2-x86_64-with-glibc2.35",
  "python_version": "3.10.12",
  "python_implementation": "CPython",
  "processor": "x86_64",
  "cpu_count": 10,
  "pynacl_version": "1.6.2",
  "msgpack_version": "1.2.1",
  "psutil_version": "7.2.2",
  "uname": "Linux GGPC 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux",
  "is_wsl": true,
  "proc_version": "Linux version 6.6.87.2-microsoft-standard-WSL2 (root@439a258ad544) (gcc (GCC) 11.2.0, GNU ld (GNU Binutils) 2.37) #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025"
}
```

## Aggregate results (across all trials)

| Metric | Trials (n) | Mean | Median | Stdev | Min | Max |
|---|---|---|---|---|---|---|
| Fresh handshake latency (ms) | 10 | 0.93 | 0.93 | 0.08 | 0.74 | 1.02 |
| Resumed handshake latency (ms) | 10 | 0.48 | 0.46 | 0.1 | 0.4 | 0.77 |
| Resumption speedup (x, fresh/resumed) | 10 | 2.0 | 2.12 | 0.34 | 1.21 | 2.33 |
| Bastion round-trip throughput (msg/s) | 10 | 5204.22 | 5228.15 | 529.83 | 4625.2 | 6279.0 |
| JSON baseline round-trip throughput (msg/s) | 10 | 27291.44 | 29264.4 | 4347.12 | 20579.5 | 32311.6 |
| Bastion vs JSON round-trip ratio (x) | 10 | 0.19 | 0.18 | 0.05 | 0.14 | 0.3 |
| Bastion pipelined bulk-send (msg/s) | 10 | 112594.71 | 111859.65 | 6066.95 | 105680.6 | 120876.6 |
| Bastion pipelined bulk-send (MB/s) | 10 | 54.98 | 54.62 | 2.96 | 51.6 | 59.02 |
| JSON baseline pipelined bulk-send (msg/s) | 10 | 536054.59 | 546844.7 | 22004.52 | 491028.3 | 558678.2 |
| Bastion vs JSON pipelined ratio (x) | 10 | 0.21 | 0.21 | 0.01 | 0.19 | 0.22 |

## Honest interpretation

- **Round-trip (request-response) throughput: Bastion is SLOWER than the plain-JSON baseline**, at 0.19x across 10 trials (stdev 0.05). This is NOT parity, and this report does not claim it is.

- **Session resumption** (skipping the full handshake on reconnect) shows a real, repeated, measured speedup of 2.0x over a fresh handshake (stdev 0.34, 10 trials).

- **Pipelined bulk-send** (the pattern an actual bulk transfer uses -- not waiting for a per-message ack): 112594.71 msg/s mean (6066.95 stdev). This is the number relevant to "send N messages of data," not round-trip request-response latency.

- **Pipelined bulk-send: Bastion is SLOWER than the plain-JSON pipelined baseline**, at 0.21x across 10 trials (stdev 0.01). This is the direct, fair comparison for the pipelined pattern -- both sides fire-and-forget, neither waits per-message.


## Raw per-trial data

Every completed trial, unfiltered:

```json
[
  {
    "target": "127.0.0.1:19950",
    "trusted_transport": false,
    "started_at": 1784418801.8331234,
    "fresh_handshake_ms": {
      "min": 0.682,
      "avg": 0.929,
      "p50": 0.788,
      "p95": 0.934,
      "max": 2.82
    },
    "resumed_handshake_ms": {
      "min": 0.295,
      "avg": 0.438,
      "p50": 0.336,
      "p95": 0.527,
      "max": 1.551
    },
    "measured_resumption_speedup_x": 2.12,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.097,
      "messages_per_sec": 5153.2,
      "mb_per_sec": 5.032,
      "round_trip_ms": {
        "min": 0.105,
        "avg": 0.192,
        "p50": 0.186,
        "p95": 0.288,
        "max": 0.551
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0216,
      "messages_per_sec": 23097.8,
      "mb_per_sec": 22.556,
      "round_trip_ms": {
        "min": 0.026,
        "avg": 0.042,
        "p50": 0.034,
        "p95": 0.061,
        "max": 0.368
      }
    },
    "measured_data_speedup_x": 0.22,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.1712,
      "messages_per_sec": 116811.8,
      "mb_per_sec": 57.037
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0363,
      "messages_per_sec": 550657.1,
      "mb_per_sec": 268.876
    },
    "measured_pipelined_speedup_x": 0.21,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 39.95,
        "max": 79.9
      },
      "memory_mb": {
        "min": 34.71,
        "avg": 35.27,
        "max": 35.83
      },
      "gpu_percent": null
    },
    "completed_at": 1784418802.2624621
  },
  {
    "target": "127.0.0.1:19951",
    "trusted_transport": false,
    "started_at": 1784418804.1081583,
    "fresh_handshake_ms": {
      "min": 0.782,
      "avg": 1.002,
      "p50": 0.899,
      "p95": 1.504,
      "max": 1.626
    },
    "resumed_handshake_ms": {
      "min": 0.36,
      "avg": 0.451,
      "p50": 0.408,
      "p95": 0.644,
      "max": 0.699
    },
    "measured_resumption_speedup_x": 2.22,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0935,
      "messages_per_sec": 5348.5,
      "mb_per_sec": 5.223,
      "round_trip_ms": {
        "min": 0.104,
        "avg": 0.185,
        "p50": 0.173,
        "p95": 0.294,
        "max": 0.514
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0213,
      "messages_per_sec": 23454.3,
      "mb_per_sec": 22.905,
      "round_trip_ms": {
        "min": 0.025,
        "avg": 0.041,
        "p50": 0.03,
        "p95": 0.065,
        "max": 0.314
      }
    },
    "measured_data_speedup_x": 0.22,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.1892,
      "messages_per_sec": 105680.6,
      "mb_per_sec": 51.602
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0377,
      "messages_per_sec": 530724.2,
      "mb_per_sec": 259.143
    },
    "measured_pipelined_speedup_x": 0.2,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 41.0,
        "max": 82.0
      },
      "memory_mb": {
        "min": 34.7,
        "avg": 35.26,
        "max": 35.82
      },
      "gpu_percent": null
    },
    "completed_at": 1784418804.541368
  },
  {
    "target": "127.0.0.1:19952",
    "trusted_transport": false,
    "started_at": 1784418806.4073615,
    "fresh_handshake_ms": {
      "min": 0.588,
      "avg": 0.74,
      "p50": 0.69,
      "p95": 0.851,
      "max": 1.379
    },
    "resumed_handshake_ms": {
      "min": 0.267,
      "avg": 0.474,
      "p50": 0.416,
      "p95": 0.923,
      "max": 0.936
    },
    "measured_resumption_speedup_x": 1.56,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0796,
      "messages_per_sec": 6279.0,
      "mb_per_sec": 6.132,
      "round_trip_ms": {
        "min": 0.099,
        "avg": 0.158,
        "p50": 0.132,
        "p95": 0.275,
        "max": 0.464
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0243,
      "messages_per_sec": 20579.5,
      "mb_per_sec": 20.097,
      "round_trip_ms": {
        "min": 0.026,
        "avg": 0.047,
        "p50": 0.037,
        "p95": 0.087,
        "max": 0.513
      }
    },
    "measured_data_speedup_x": 0.3,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.1727,
      "messages_per_sec": 115774.3,
      "mb_per_sec": 56.53
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0367,
      "messages_per_sec": 545043.4,
      "mb_per_sec": 266.134
    },
    "measured_pipelined_speedup_x": 0.21,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 40.35,
        "max": 80.7
      },
      "memory_mb": {
        "min": 34.58,
        "avg": 35.14,
        "max": 35.7
      },
      "gpu_percent": null
    },
    "completed_at": 1784418806.8034775
  },
  {
    "target": "127.0.0.1:19953",
    "trusted_transport": false,
    "started_at": 1784418808.6507747,
    "fresh_handshake_ms": {
      "min": 0.631,
      "avg": 0.875,
      "p50": 0.791,
      "p95": 1.248,
      "max": 1.657
    },
    "resumed_handshake_ms": {
      "min": 0.323,
      "avg": 0.429,
      "p50": 0.409,
      "p95": 0.647,
      "max": 0.713
    },
    "measured_resumption_speedup_x": 2.04,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0943,
      "messages_per_sec": 5303.1,
      "mb_per_sec": 5.179,
      "round_trip_ms": {
        "min": 0.102,
        "avg": 0.187,
        "p50": 0.18,
        "p95": 0.268,
        "max": 1.119
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0166,
      "messages_per_sec": 30036.1,
      "mb_per_sec": 29.332,
      "round_trip_ms": {
        "min": 0.026,
        "avg": 0.032,
        "p50": 0.029,
        "p95": 0.042,
        "max": 0.333
      }
    },
    "measured_data_speedup_x": 0.17,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.1857,
      "messages_per_sec": 107701.7,
      "mb_per_sec": 52.589
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0364,
      "messages_per_sec": 549368.5,
      "mb_per_sec": 268.246
    },
    "measured_pipelined_speedup_x": 0.2,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 40.7,
        "max": 81.4
      },
      "memory_mb": {
        "min": 34.57,
        "avg": 35.01,
        "max": 35.45
      },
      "gpu_percent": null
    },
    "completed_at": 1784418809.0491567
  },
  {
    "target": "127.0.0.1:19954",
    "trusted_transport": false,
    "started_at": 1784418810.924029,
    "fresh_handshake_ms": {
      "min": 0.605,
      "avg": 0.935,
      "p50": 0.813,
      "p95": 1.218,
      "max": 2.044
    },
    "resumed_handshake_ms": {
      "min": 0.268,
      "avg": 0.401,
      "p50": 0.349,
      "p95": 0.645,
      "max": 0.759
    },
    "measured_resumption_speedup_x": 2.33,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.089,
      "messages_per_sec": 5617.1,
      "mb_per_sec": 5.485,
      "round_trip_ms": {
        "min": 0.099,
        "avg": 0.176,
        "p50": 0.17,
        "p95": 0.276,
        "max": 0.512
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0169,
      "messages_per_sec": 29515.2,
      "mb_per_sec": 28.823,
      "round_trip_ms": {
        "min": 0.026,
        "avg": 0.033,
        "p50": 0.029,
        "p95": 0.051,
        "max": 0.231
      }
    },
    "measured_data_speedup_x": 0.19,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.1655,
      "messages_per_sec": 120876.6,
      "mb_per_sec": 59.022
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0358,
      "messages_per_sec": 558678.2,
      "mb_per_sec": 272.792
    },
    "measured_pipelined_speedup_x": 0.22,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 40.85,
        "max": 81.7
      },
      "memory_mb": {
        "min": 34.64,
        "avg": 35.14,
        "max": 35.64
      },
      "gpu_percent": null
    },
    "completed_at": 1784418811.346761
  },
  {
    "target": "127.0.0.1:19955",
    "trusted_transport": false,
    "started_at": 1784418813.2085695,
    "fresh_handshake_ms": {
      "min": 0.659,
      "avg": 0.929,
      "p50": 0.847,
      "p95": 1.119,
      "max": 2.031
    },
    "resumed_handshake_ms": {
      "min": 0.375,
      "avg": 0.768,
      "p50": 0.529,
      "p95": 1.641,
      "max": 2.672
    },
    "measured_resumption_speedup_x": 1.21,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.1068,
      "messages_per_sec": 4680.6,
      "mb_per_sec": 4.571,
      "round_trip_ms": {
        "min": 0.104,
        "avg": 0.212,
        "p50": 0.212,
        "p95": 0.322,
        "max": 0.63
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0172,
      "messages_per_sec": 29013.6,
      "mb_per_sec": 28.334,
      "round_trip_ms": {
        "min": 0.025,
        "avg": 0.033,
        "p50": 0.03,
        "p95": 0.048,
        "max": 0.42
      }
    },
    "measured_data_speedup_x": 0.16,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.1859,
      "messages_per_sec": 107594.7,
      "mb_per_sec": 52.536
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0393,
      "messages_per_sec": 509363.2,
      "mb_per_sec": 248.712
    },
    "measured_pipelined_speedup_x": 0.21,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 39.7,
        "max": 79.4
      },
      "memory_mb": {
        "min": 34.5,
        "avg": 35.06,
        "max": 35.62
      },
      "gpu_percent": null
    },
    "completed_at": 1784418813.663298
  },
  {
    "target": "127.0.0.1:19956",
    "trusted_transport": false,
    "started_at": 1784418815.563473,
    "fresh_handshake_ms": {
      "min": 0.731,
      "avg": 1.019,
      "p50": 0.975,
      "p95": 1.335,
      "max": 1.828
    },
    "resumed_handshake_ms": {
      "min": 0.387,
      "avg": 0.467,
      "p50": 0.441,
      "p95": 0.56,
      "max": 0.646
    },
    "measured_resumption_speedup_x": 2.18,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.1081,
      "messages_per_sec": 4625.2,
      "mb_per_sec": 4.517,
      "round_trip_ms": {
        "min": 0.107,
        "avg": 0.214,
        "p50": 0.204,
        "p95": 0.329,
        "max": 0.835
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0161,
      "messages_per_sec": 31011.6,
      "mb_per_sec": 30.285,
      "round_trip_ms": {
        "min": 0.025,
        "avg": 0.031,
        "p50": 0.029,
        "p95": 0.048,
        "max": 0.166
      }
    },
    "measured_data_speedup_x": 0.14,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.166,
      "messages_per_sec": 120467.4,
      "mb_per_sec": 58.822
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0365,
      "messages_per_sec": 548646.0,
      "mb_per_sec": 267.894
    },
    "measured_pipelined_speedup_x": 0.22,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 41.05,
        "max": 82.1
      },
      "memory_mb": {
        "min": 34.7,
        "avg": 35.26,
        "max": 35.82
      },
      "gpu_percent": null
    },
    "completed_at": 1784418815.988579
  },
  {
    "target": "127.0.0.1:19957",
    "trusted_transport": false,
    "started_at": 1784418817.8353758,
    "fresh_handshake_ms": {
      "min": 0.647,
      "avg": 0.895,
      "p50": 0.802,
      "p95": 0.953,
      "max": 2.067
    },
    "resumed_handshake_ms": {
      "min": 0.339,
      "avg": 0.422,
      "p50": 0.389,
      "p95": 0.547,
      "max": 0.557
    },
    "measured_resumption_speedup_x": 2.12,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.09,
      "messages_per_sec": 5557.8,
      "mb_per_sec": 5.428,
      "round_trip_ms": {
        "min": 0.104,
        "avg": 0.178,
        "p50": 0.172,
        "p95": 0.264,
        "max": 0.473
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.016,
      "messages_per_sec": 31305.9,
      "mb_per_sec": 30.572,
      "round_trip_ms": {
        "min": 0.025,
        "avg": 0.031,
        "p50": 0.028,
        "p95": 0.043,
        "max": 0.253
      }
    },
    "measured_data_speedup_x": 0.17,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.1853,
      "messages_per_sec": 107945.0,
      "mb_per_sec": 52.708
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0407,
      "messages_per_sec": 491028.3,
      "mb_per_sec": 239.76
    },
    "measured_pipelined_speedup_x": 0.22,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 3,
      "cpu_percent": {
        "min": 0.0,
        "avg": 31.97,
        "max": 76.0
      },
      "memory_mb": {
        "min": 34.39,
        "avg": 35.26,
        "max": 35.75
      },
      "gpu_percent": null
    },
    "completed_at": 1784418818.3576891
  },
  {
    "target": "127.0.0.1:19958",
    "trusted_transport": false,
    "started_at": 1784418820.2295215,
    "fresh_handshake_ms": {
      "min": 0.732,
      "avg": 0.988,
      "p50": 0.879,
      "p95": 1.215,
      "max": 1.968
    },
    "resumed_handshake_ms": {
      "min": 0.309,
      "avg": 0.468,
      "p50": 0.423,
      "p95": 0.615,
      "max": 0.759
    },
    "measured_resumption_speedup_x": 2.11,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.1054,
      "messages_per_sec": 4742.0,
      "mb_per_sec": 4.631,
      "round_trip_ms": {
        "min": 0.103,
        "avg": 0.209,
        "p50": 0.169,
        "p95": 0.321,
        "max": 6.979
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0155,
      "messages_per_sec": 32311.6,
      "mb_per_sec": 31.554,
      "round_trip_ms": {
        "min": 0.025,
        "avg": 0.03,
        "p50": 0.028,
        "p95": 0.04,
        "max": 0.177
      }
    },
    "measured_data_speedup_x": 0.14,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.1879,
      "messages_per_sec": 106436.3,
      "mb_per_sec": 51.971
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0361,
      "messages_per_sec": 553279.5,
      "mb_per_sec": 270.156
    },
    "measured_pipelined_speedup_x": 0.19,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 78.1,
        "avg": 134.5,
        "max": 190.9
      },
      "memory_mb": {
        "min": 34.58,
        "avg": 35.2,
        "max": 35.83
      },
      "gpu_percent": null
    },
    "completed_at": 1784418820.680865
  },
  {
    "target": "127.0.0.1:19959",
    "trusted_transport": false,
    "started_at": 1784418822.532924,
    "fresh_handshake_ms": {
      "min": 0.701,
      "avg": 0.966,
      "p50": 0.949,
      "p95": 1.273,
      "max": 1.499
    },
    "resumed_handshake_ms": {
      "min": 0.343,
      "avg": 0.47,
      "p50": 0.454,
      "p95": 0.691,
      "max": 0.693
    },
    "measured_resumption_speedup_x": 2.06,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.1056,
      "messages_per_sec": 4735.7,
      "mb_per_sec": 4.625,
      "round_trip_ms": {
        "min": 0.104,
        "avg": 0.209,
        "p50": 0.203,
        "p95": 0.313,
        "max": 0.567
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0221,
      "messages_per_sec": 22588.8,
      "mb_per_sec": 22.059,
      "round_trip_ms": {
        "min": 0.026,
        "avg": 0.043,
        "p50": 0.033,
        "p95": 0.065,
        "max": 0.535
      }
    },
    "measured_data_speedup_x": 0.21,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.1714,
      "messages_per_sec": 116658.7,
      "mb_per_sec": 56.962
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0382,
      "messages_per_sec": 523757.5,
      "mb_per_sec": 255.741
    },
    "measured_pipelined_speedup_x": 0.22,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 77.1,
        "avg": 114.55,
        "max": 152.0
      },
      "memory_mb": {
        "min": 34.27,
        "avg": 34.77,
        "max": 35.27
      },
      "gpu_percent": null
    },
    "completed_at": 1784418822.9665368
  }
]
```

# Bastion Protocol vs. JSON-over-TCP — Benchmark Results

Generated: 2026-07-19T04:29:54.329243+00:00

## Methodology

- **10 independent trials** completed (0 failed and excluded), each launching a fresh server process and a fresh client process — no shared warm-up state, connection caching, or JIT/cache warmth carried between trials.
- Each trial: 15 handshake repetitions, 500 round-trip messages, 20000 pipelined bulk-send messages, 512-byte payloads.
- Every trial's raw data is included below — none excluded except outright process failures.
- **This is not a security-equivalent comparison.** The JSON baseline has zero encryption, zero authentication, zero replay protection, and zero framing validation. Bastion Protocol does all of that. The comparison isolates wire-format/session cost, not "equivalent security posture at different speeds" — there is no equivalent-security JSON baseline being claimed here.
- Reproduce with: `python scripts/rigorous_bench.py --trials 10 --messages 500 --bulk-messages 20000 --size 512`

## Environment

```json
{
  "timestamp_utc": "2026-07-19T04:29:54.329243+00:00",
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
| Fresh handshake latency (ms) | 10 | 0.81 | 0.79 | 0.1 | 0.7 | 0.99 |
| Resumed handshake latency (ms) | 10 | 0.39 | 0.37 | 0.07 | 0.32 | 0.54 |
| Resumption speedup (x, fresh/resumed) | 10 | 2.07 | 2.08 | 0.16 | 1.84 | 2.3 |
| Bastion round-trip throughput (msg/s) | 10 | 8367.94 | 8346.4 | 1563.49 | 5588.5 | 10356.4 |
| JSON baseline round-trip throughput (msg/s) | 10 | 29051.2 | 30379.05 | 3007.57 | 23390.3 | 32089.1 |
| Bastion vs JSON round-trip ratio (x) | 10 | 0.28 | 0.29 | 0.03 | 0.23 | 0.33 |
| Bastion pipelined bulk-send (msg/s) | 10 | 193883.83 | 199279.6 | 16526.74 | 160542.8 | 215241.2 |
| Bastion pipelined bulk-send (MB/s) | 10 | 94.67 | 97.3 | 8.07 | 78.39 | 105.1 |
| JSON baseline pipelined bulk-send (msg/s) | 10 | 572500.6 | 574458.55 | 27943.89 | 519942.4 | 604846.2 |
| Bastion vs JSON pipelined ratio (x) | 10 | 0.34 | 0.34 | 0.02 | 0.31 | 0.37 |

## Honest interpretation

- **Round-trip (request-response) throughput: Bastion is SLOWER than the plain-JSON baseline**, at 0.28x across 10 trials (stdev 0.03). This is NOT parity, and this report does not claim it is.

- **Session resumption** (skipping the full handshake on reconnect) shows a real, repeated, measured speedup of 2.07x over a fresh handshake (stdev 0.16, 10 trials).

- **Pipelined bulk-send** (the pattern an actual bulk transfer uses -- not waiting for a per-message ack): 193883.83 msg/s mean (16526.74 stdev). This is the number relevant to "send N messages of data," not round-trip request-response latency.

- **Pipelined bulk-send: Bastion is SLOWER than the plain-JSON pipelined baseline**, at 0.34x across 10 trials (stdev 0.02). This is the direct, fair comparison for the pipelined pattern -- both sides fire-and-forget, neither waits per-message.


## Raw per-trial data

Every completed trial, unfiltered:

```json
[
  {
    "target": "127.0.0.1:19990",
    "trusted_transport": true,
    "started_at": 1784435395.9330904,
    "fresh_handshake_ms": {
      "min": 0.646,
      "avg": 0.99,
      "p50": 0.868,
      "p95": 1.145,
      "max": 3.041
    },
    "resumed_handshake_ms": {
      "min": 0.398,
      "avg": 0.536,
      "p50": 0.52,
      "p95": 0.703,
      "max": 0.748
    },
    "measured_resumption_speedup_x": 1.85,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0895,
      "messages_per_sec": 5588.5,
      "mb_per_sec": 5.458,
      "round_trip_ms": {
        "min": 0.083,
        "avg": 0.177,
        "p50": 0.158,
        "p95": 0.277,
        "max": 1.238
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0214,
      "messages_per_sec": 23390.3,
      "mb_per_sec": 22.842,
      "round_trip_ms": {
        "min": 0.026,
        "avg": 0.041,
        "p50": 0.032,
        "p95": 0.069,
        "max": 1.151
      }
    },
    "measured_data_speedup_x": 0.23,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.1112,
      "messages_per_sec": 179794.8,
      "mb_per_sec": 87.79
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0356,
      "messages_per_sec": 561116.9,
      "mb_per_sec": 273.983
    },
    "measured_pipelined_speedup_x": 0.32,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 36.5,
        "max": 73.0
      },
      "memory_mb": {
        "min": 34.58,
        "avg": 35.08,
        "max": 35.58
      },
      "gpu_percent": null
    },
    "completed_at": 1784435396.2643209
  },
  {
    "target": "127.0.0.1:19991",
    "trusted_transport": true,
    "started_at": 1784435398.0435975,
    "fresh_handshake_ms": {
      "min": 0.691,
      "avg": 0.886,
      "p50": 0.816,
      "p95": 1.146,
      "max": 1.711
    },
    "resumed_handshake_ms": {
      "min": 0.309,
      "avg": 0.424,
      "p50": 0.409,
      "p95": 0.557,
      "max": 0.74
    },
    "measured_resumption_speedup_x": 2.09,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0641,
      "messages_per_sec": 7804.2,
      "mb_per_sec": 7.621,
      "round_trip_ms": {
        "min": 0.09,
        "avg": 0.127,
        "p50": 0.112,
        "p95": 0.216,
        "max": 0.463
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0195,
      "messages_per_sec": 25636.9,
      "mb_per_sec": 25.036,
      "round_trip_ms": {
        "min": 0.026,
        "avg": 0.038,
        "p50": 0.033,
        "p95": 0.058,
        "max": 0.265
      }
    },
    "measured_data_speedup_x": 0.3,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.1246,
      "messages_per_sec": 160542.8,
      "mb_per_sec": 78.39
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0385,
      "messages_per_sec": 519942.4,
      "mb_per_sec": 253.878
    },
    "measured_pipelined_speedup_x": 0.31,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 79.2,
        "avg": 154.6,
        "max": 230.0
      },
      "memory_mb": {
        "min": 34.83,
        "avg": 35.27,
        "max": 35.7
      },
      "gpu_percent": null
    },
    "completed_at": 1784435398.3716998
  },
  {
    "target": "127.0.0.1:19992",
    "trusted_transport": true,
    "started_at": 1784435400.1791859,
    "fresh_handshake_ms": {
      "min": 0.602,
      "avg": 0.713,
      "p50": 0.662,
      "p95": 0.746,
      "max": 1.468
    },
    "resumed_handshake_ms": {
      "min": 0.268,
      "avg": 0.367,
      "p50": 0.303,
      "p95": 0.611,
      "max": 0.699
    },
    "measured_resumption_speedup_x": 1.94,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0521,
      "messages_per_sec": 9605.6,
      "mb_per_sec": 9.38,
      "round_trip_ms": {
        "min": 0.072,
        "avg": 0.103,
        "p50": 0.084,
        "p95": 0.193,
        "max": 0.55
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0156,
      "messages_per_sec": 32089.1,
      "mb_per_sec": 31.337,
      "round_trip_ms": {
        "min": 0.025,
        "avg": 0.03,
        "p50": 0.028,
        "p95": 0.039,
        "max": 0.216
      }
    },
    "measured_data_speedup_x": 0.29,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0929,
      "messages_per_sec": 215241.2,
      "mb_per_sec": 105.098
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0344,
      "messages_per_sec": 581527.9,
      "mb_per_sec": 283.949
    },
    "measured_pipelined_speedup_x": 0.37,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 34.85,
        "max": 69.7
      },
      "memory_mb": {
        "min": 34.71,
        "avg": 35.33,
        "max": 35.96
      },
      "gpu_percent": null
    },
    "completed_at": 1784435400.4652505
  },
  {
    "target": "127.0.0.1:19993",
    "trusted_transport": true,
    "started_at": 1784435402.2418146,
    "fresh_handshake_ms": {
      "min": 0.592,
      "avg": 0.738,
      "p50": 0.707,
      "p95": 0.921,
      "max": 1.322
    },
    "resumed_handshake_ms": {
      "min": 0.254,
      "avg": 0.324,
      "p50": 0.314,
      "p95": 0.378,
      "max": 0.429
    },
    "measured_resumption_speedup_x": 2.28,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0632,
      "messages_per_sec": 7910.8,
      "mb_per_sec": 7.725,
      "round_trip_ms": {
        "min": 0.077,
        "avg": 0.125,
        "p50": 0.106,
        "p95": 0.227,
        "max": 0.583
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0173,
      "messages_per_sec": 28979.6,
      "mb_per_sec": 28.3,
      "round_trip_ms": {
        "min": 0.025,
        "avg": 0.033,
        "p50": 0.03,
        "p95": 0.05,
        "max": 0.107
      }
    },
    "measured_data_speedup_x": 0.26,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.1067,
      "messages_per_sec": 187498.3,
      "mb_per_sec": 91.552
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0358,
      "messages_per_sec": 558190.3,
      "mb_per_sec": 272.554
    },
    "measured_pipelined_speedup_x": 0.34,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 33.7,
        "max": 67.4
      },
      "memory_mb": {
        "min": 34.7,
        "avg": 35.27,
        "max": 35.83
      },
      "gpu_percent": null
    },
    "completed_at": 1784435402.545308
  },
  {
    "target": "127.0.0.1:19994",
    "trusted_transport": true,
    "started_at": 1784435404.352251,
    "fresh_handshake_ms": {
      "min": 0.637,
      "avg": 0.813,
      "p50": 0.766,
      "p95": 0.931,
      "max": 1.633
    },
    "resumed_handshake_ms": {
      "min": 0.279,
      "avg": 0.375,
      "p50": 0.363,
      "p95": 0.509,
      "max": 0.546
    },
    "measured_resumption_speedup_x": 2.17,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0631,
      "messages_per_sec": 7923.6,
      "mb_per_sec": 7.738,
      "round_trip_ms": {
        "min": 0.078,
        "avg": 0.125,
        "p50": 0.111,
        "p95": 0.21,
        "max": 0.397
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0159,
      "messages_per_sec": 31500.4,
      "mb_per_sec": 30.762,
      "round_trip_ms": {
        "min": 0.025,
        "avg": 0.031,
        "p50": 0.029,
        "p95": 0.039,
        "max": 0.246
      }
    },
    "measured_data_speedup_x": 0.25,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0978,
      "messages_per_sec": 204568.1,
      "mb_per_sec": 99.887
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0331,
      "messages_per_sec": 604467.4,
      "mb_per_sec": 295.15
    },
    "measured_pipelined_speedup_x": 0.34,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 36.1,
        "max": 72.2
      },
      "memory_mb": {
        "min": 34.33,
        "avg": 34.89,
        "max": 35.46
      },
      "gpu_percent": null
    },
    "completed_at": 1784435404.651827
  },
  {
    "target": "127.0.0.1:19995",
    "trusted_transport": true,
    "started_at": 1784435406.437329,
    "fresh_handshake_ms": {
      "min": 0.602,
      "avg": 0.765,
      "p50": 0.688,
      "p95": 0.954,
      "max": 1.464
    },
    "resumed_handshake_ms": {
      "min": 0.258,
      "avg": 0.333,
      "p50": 0.335,
      "p95": 0.395,
      "max": 0.449
    },
    "measured_resumption_speedup_x": 2.3,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0545,
      "messages_per_sec": 9182.7,
      "mb_per_sec": 8.967,
      "round_trip_ms": {
        "min": 0.076,
        "avg": 0.108,
        "p50": 0.086,
        "p95": 0.178,
        "max": 1.17
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0162,
      "messages_per_sec": 30941.5,
      "mb_per_sec": 30.216,
      "round_trip_ms": {
        "min": 0.025,
        "avg": 0.031,
        "p50": 0.029,
        "p95": 0.045,
        "max": 0.197
      }
    },
    "measured_data_speedup_x": 0.29,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0962,
      "messages_per_sec": 207940.3,
      "mb_per_sec": 101.533
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0331,
      "messages_per_sec": 604846.2,
      "mb_per_sec": 295.335
    },
    "measured_pipelined_speedup_x": 0.34,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 79.7,
        "avg": 161.45,
        "max": 243.2
      },
      "memory_mb": {
        "min": 34.7,
        "avg": 35.27,
        "max": 35.83
      },
      "gpu_percent": null
    },
    "completed_at": 1784435406.725356
  },
  {
    "target": "127.0.0.1:19996",
    "trusted_transport": true,
    "started_at": 1784435408.506256,
    "fresh_handshake_ms": {
      "min": 0.581,
      "avg": 0.729,
      "p50": 0.686,
      "p95": 0.877,
      "max": 1.321
    },
    "resumed_handshake_ms": {
      "min": 0.272,
      "avg": 0.363,
      "p50": 0.343,
      "p95": 0.495,
      "max": 0.503
    },
    "measured_resumption_speedup_x": 2.01,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0492,
      "messages_per_sec": 10169.3,
      "mb_per_sec": 9.931,
      "round_trip_ms": {
        "min": 0.076,
        "avg": 0.097,
        "p50": 0.083,
        "p95": 0.16,
        "max": 0.434
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0161,
      "messages_per_sec": 31072.9,
      "mb_per_sec": 30.345,
      "round_trip_ms": {
        "min": 0.026,
        "avg": 0.031,
        "p50": 0.028,
        "p95": 0.045,
        "max": 0.174
      }
    },
    "measured_data_speedup_x": 0.32,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.1011,
      "messages_per_sec": 197911.1,
      "mb_per_sec": 96.636
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0332,
      "messages_per_sec": 602774.9,
      "mb_per_sec": 294.324
    },
    "measured_pipelined_speedup_x": 0.33,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 39.9,
        "max": 79.8
      },
      "memory_mb": {
        "min": 34.58,
        "avg": 35.14,
        "max": 35.7
      },
      "gpu_percent": null
    },
    "completed_at": 1784435408.7752457
  },
  {
    "target": "127.0.0.1:19997",
    "trusted_transport": true,
    "started_at": 1784435410.5498295,
    "fresh_handshake_ms": {
      "min": 0.59,
      "avg": 0.7,
      "p50": 0.628,
      "p95": 0.741,
      "max": 1.475
    },
    "resumed_handshake_ms": {
      "min": 0.256,
      "avg": 0.338,
      "p50": 0.281,
      "p95": 0.422,
      "max": 0.58
    },
    "measured_resumption_speedup_x": 2.07,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0483,
      "messages_per_sec": 10356.4,
      "mb_per_sec": 10.114,
      "round_trip_ms": {
        "min": 0.076,
        "avg": 0.095,
        "p50": 0.08,
        "p95": 0.169,
        "max": 1.426
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.016,
      "messages_per_sec": 31160.5,
      "mb_per_sec": 30.43,
      "round_trip_ms": {
        "min": 0.025,
        "avg": 0.031,
        "p50": 0.029,
        "p95": 0.039,
        "max": 0.286
      }
    },
    "measured_data_speedup_x": 0.33,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.098,
      "messages_per_sec": 204024.2,
      "mb_per_sec": 99.621
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0348,
      "messages_per_sec": 574352.7,
      "mb_per_sec": 280.446
    },
    "measured_pipelined_speedup_x": 0.36,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 32.35,
        "max": 64.7
      },
      "memory_mb": {
        "min": 34.7,
        "avg": 35.27,
        "max": 35.83
      },
      "gpu_percent": null
    },
    "completed_at": 1784435410.8208475
  },
  {
    "target": "127.0.0.1:19998",
    "trusted_transport": true,
    "started_at": 1784435412.2957125,
    "fresh_handshake_ms": {
      "min": 0.667,
      "avg": 0.898,
      "p50": 0.841,
      "p95": 1.061,
      "max": 1.876
    },
    "resumed_handshake_ms": {
      "min": 0.316,
      "avg": 0.489,
      "p50": 0.486,
      "p95": 0.716,
      "max": 0.73
    },
    "measured_resumption_speedup_x": 1.84,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0785,
      "messages_per_sec": 6369.1,
      "mb_per_sec": 6.22,
      "round_trip_ms": {
        "min": 0.082,
        "avg": 0.155,
        "p50": 0.14,
        "p95": 0.248,
        "max": 0.438
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0193,
      "messages_per_sec": 25924.2,
      "mb_per_sec": 25.317,
      "round_trip_ms": {
        "min": 0.027,
        "avg": 0.037,
        "p50": 0.03,
        "p95": 0.053,
        "max": 1.584
      }
    },
    "measured_data_speedup_x": 0.24,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.1107,
      "messages_per_sec": 180669.4,
      "mb_per_sec": 88.218
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0368,
      "messages_per_sec": 543222.9,
      "mb_per_sec": 265.246
    },
    "measured_pipelined_speedup_x": 0.33,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 35.1,
        "max": 70.2
      },
      "memory_mb": {
        "min": 34.7,
        "avg": 35.27,
        "max": 35.83
      },
      "gpu_percent": null
    },
    "completed_at": 1784435412.6109338
  },
  {
    "target": "127.0.0.1:19999",
    "trusted_transport": true,
    "started_at": 1784435414.4374073,
    "fresh_handshake_ms": {
      "min": 0.634,
      "avg": 0.83,
      "p50": 0.767,
      "p95": 1.281,
      "max": 1.496
    },
    "resumed_handshake_ms": {
      "min": 0.271,
      "avg": 0.387,
      "p50": 0.346,
      "p95": 0.652,
      "max": 0.812
    },
    "measured_resumption_speedup_x": 2.15,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.057,
      "messages_per_sec": 8769.2,
      "mb_per_sec": 8.564,
      "round_trip_ms": {
        "min": 0.079,
        "avg": 0.113,
        "p50": 0.095,
        "p95": 0.191,
        "max": 1.324
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0168,
      "messages_per_sec": 29816.6,
      "mb_per_sec": 29.118,
      "round_trip_ms": {
        "min": 0.026,
        "avg": 0.032,
        "p50": 0.03,
        "p95": 0.043,
        "max": 0.224
      }
    },
    "measured_data_speedup_x": 0.28,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0997,
      "messages_per_sec": 200648.1,
      "mb_per_sec": 97.973
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0348,
      "messages_per_sec": 574564.4,
      "mb_per_sec": 280.549
    },
    "measured_pipelined_speedup_x": 0.35,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 34.9,
        "max": 69.8
      },
      "memory_mb": {
        "min": 34.7,
        "avg": 35.33,
        "max": 35.95
      },
      "gpu_percent": null
    },
    "completed_at": 1784435414.727239
  }
]
```

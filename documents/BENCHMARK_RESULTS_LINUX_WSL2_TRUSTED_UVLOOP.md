# Bastion Protocol vs. JSON-over-TCP — Benchmark Results

Generated: 2026-07-19T07:55:42.218814+00:00

## Methodology

- **10 independent trials** completed (0 failed and excluded), each launching a fresh server process and a fresh client process — no shared warm-up state, connection caching, or JIT/cache warmth carried between trials.
- Each trial: 15 handshake repetitions, 500 round-trip messages, 20000 pipelined bulk-send messages, 512-byte payloads.
- Every trial's raw data is included below — none excluded except outright process failures.
- **This is not a security-equivalent comparison.** The JSON baseline has zero encryption, zero authentication, zero replay protection, and zero framing validation. Bastion Protocol does all of that. The comparison isolates wire-format/session cost, not "equivalent security posture at different speeds" — there is no equivalent-security JSON baseline being claimed here.
- Reproduce with: `python scripts/rigorous_bench.py --trials 10 --messages 500 --bulk-messages 20000 --size 512`

## Environment

```json
{
  "timestamp_utc": "2026-07-19T07:55:42.218814+00:00",
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
  "proc_version": "Linux version 6.6.87.2-microsoft-standard-WSL2 (root@439a258ad544) (gcc (GCC) 11.2.0, GNU ld (GNU Binutils) 2.37) #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025",
  "trusted_transport": true,
  "use_uvloop": true,
  "uvloop_version": "0.22.1"
}
```

## Aggregate results (across all trials)

| Metric | Trials (n) | Mean | Median | Stdev | Min | Max |
|---|---|---|---|---|---|---|
| Fresh handshake latency (ms) | 10 | 3.45 | 3.4 | 0.18 | 3.32 | 3.95 |
| Resumed handshake latency (ms) | 10 | 0.36 | 0.36 | 0.04 | 0.32 | 0.43 |
| Resumption speedup (x, fresh/resumed) | 10 | 9.58 | 9.36 | 1.06 | 8.07 | 11.16 |
| Bastion round-trip throughput (msg/s) | 10 | 7823.01 | 7787.8 | 538.61 | 6963.2 | 9133.8 |
| JSON baseline round-trip throughput (msg/s) | 10 | 43628.43 | 48404.45 | 10665.28 | 23561.5 | 53005.9 |
| Bastion vs JSON round-trip ratio (x) | 10 | 0.19 | 0.17 | 0.06 | 0.14 | 0.33 |
| Bastion pipelined bulk-send (msg/s) | 10 | 203449.54 | 205191.35 | 10221.23 | 180023.3 | 216796.2 |
| Bastion pipelined bulk-send (MB/s) | 10 | 99.34 | 100.19 | 4.99 | 87.9 | 105.86 |
| JSON baseline pipelined bulk-send (msg/s) | 10 | 725371.75 | 743516.55 | 88074.66 | 550438.3 | 849015.0 |
| Bastion vs JSON pipelined ratio (x) | 10 | 0.29 | 0.28 | 0.05 | 0.23 | 0.39 |

## Honest interpretation

- **Round-trip (request-response) throughput: Bastion is SLOWER than the plain-JSON baseline**, at 0.19x across 10 trials (stdev 0.06). This is NOT parity, and this report does not claim it is.

- **Session resumption** (skipping the full handshake on reconnect) shows a real, repeated, measured speedup of 9.58x over a fresh handshake (stdev 1.06, 10 trials).

- **Pipelined bulk-send** (the pattern an actual bulk transfer uses -- not waiting for a per-message ack): 203449.54 msg/s mean (10221.23 stdev). This is the number relevant to "send N messages of data," not round-trip request-response latency.

- **Pipelined bulk-send: Bastion is SLOWER than the plain-JSON pipelined baseline**, at 0.29x across 10 trials (stdev 0.05). This is the direct, fair comparison for the pipelined pattern -- both sides fire-and-forget, neither waits per-message.


## Raw per-trial data

Every completed trial, unfiltered:

```json
[
  {
    "target": "127.0.0.1:20000",
    "trusted_transport": true,
    "started_at": 1784447743.7936282,
    "fresh_handshake_ms": {
      "min": 2.834,
      "avg": 3.363,
      "p50": 3.389,
      "p95": 3.913,
      "max": 3.922
    },
    "resumed_handshake_ms": {
      "min": 0.252,
      "avg": 0.358,
      "p50": 0.367,
      "p95": 0.422,
      "max": 0.422
    },
    "measured_resumption_speedup_x": 9.4,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0643,
      "messages_per_sec": 7774.0,
      "mb_per_sec": 7.592,
      "round_trip_ms": {
        "min": 0.075,
        "avg": 0.127,
        "p50": 0.115,
        "p95": 0.212,
        "max": 0.437
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0096,
      "messages_per_sec": 51877.7,
      "mb_per_sec": 50.662,
      "round_trip_ms": {
        "min": 0.016,
        "avg": 0.019,
        "p50": 0.017,
        "p95": 0.023,
        "max": 0.125
      }
    },
    "measured_data_speedup_x": 0.15,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0982,
      "messages_per_sec": 203730.4,
      "mb_per_sec": 99.478
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0283,
      "messages_per_sec": 707851.0,
      "mb_per_sec": 345.63
    },
    "measured_pipelined_speedup_x": 0.29,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 26.7,
        "max": 53.4
      },
      "memory_mb": {
        "min": 36.39,
        "avg": 37.08,
        "max": 37.77
      },
      "gpu_percent": null
    },
    "completed_at": 1784447744.1373682
  },
  {
    "target": "127.0.0.1:20001",
    "trusted_transport": true,
    "started_at": 1784447746.034501,
    "fresh_handshake_ms": {
      "min": 3.063,
      "avg": 3.946,
      "p50": 3.868,
      "p95": 4.459,
      "max": 5.152
    },
    "resumed_handshake_ms": {
      "min": 0.238,
      "avg": 0.353,
      "p50": 0.329,
      "p95": 0.45,
      "max": 0.59
    },
    "measured_resumption_speedup_x": 11.16,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0718,
      "messages_per_sec": 6963.2,
      "mb_per_sec": 6.8,
      "round_trip_ms": {
        "min": 0.078,
        "avg": 0.142,
        "p50": 0.132,
        "p95": 0.218,
        "max": 0.52
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.017,
      "messages_per_sec": 29436.2,
      "mb_per_sec": 28.746,
      "round_trip_ms": {
        "min": 0.016,
        "avg": 0.033,
        "p50": 0.024,
        "p95": 0.059,
        "max": 0.543
      }
    },
    "measured_data_speedup_x": 0.23,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0968,
      "messages_per_sec": 206652.3,
      "mb_per_sec": 100.904
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0292,
      "messages_per_sec": 685837.3,
      "mb_per_sec": 334.881
    },
    "measured_pipelined_speedup_x": 0.3,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 26.6,
        "max": 53.2
      },
      "memory_mb": {
        "min": 36.52,
        "avg": 37.14,
        "max": 37.77
      },
      "gpu_percent": null
    },
    "completed_at": 1784447746.3990364
  },
  {
    "target": "127.0.0.1:20002",
    "trusted_transport": true,
    "started_at": 1784447748.2778122,
    "fresh_handshake_ms": {
      "min": 2.717,
      "avg": 3.337,
      "p50": 3.151,
      "p95": 4.263,
      "max": 4.505
    },
    "resumed_handshake_ms": {
      "min": 0.234,
      "avg": 0.334,
      "p50": 0.285,
      "p95": 0.498,
      "max": 0.611
    },
    "measured_resumption_speedup_x": 10.0,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0634,
      "messages_per_sec": 7891.6,
      "mb_per_sec": 7.707,
      "round_trip_ms": {
        "min": 0.074,
        "avg": 0.125,
        "p50": 0.119,
        "p95": 0.188,
        "max": 0.499
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0104,
      "messages_per_sec": 48065.0,
      "mb_per_sec": 46.938,
      "round_trip_ms": {
        "min": 0.015,
        "avg": 0.02,
        "p50": 0.017,
        "p95": 0.027,
        "max": 0.4
      }
    },
    "measured_data_speedup_x": 0.16,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.1005,
      "messages_per_sec": 198934.1,
      "mb_per_sec": 97.136
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.025,
      "messages_per_sec": 798466.7,
      "mb_per_sec": 389.876
    },
    "measured_pipelined_speedup_x": 0.25,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 26.15,
        "max": 52.3
      },
      "memory_mb": {
        "min": 36.86,
        "avg": 37.48,
        "max": 38.11
      },
      "gpu_percent": null
    },
    "completed_at": 1784447748.6148856
  },
  {
    "target": "127.0.0.1:20003",
    "trusted_transport": true,
    "started_at": 1784447750.4669816,
    "fresh_handshake_ms": {
      "min": 2.806,
      "avg": 3.399,
      "p50": 3.263,
      "p95": 4.106,
      "max": 5.102
    },
    "resumed_handshake_ms": {
      "min": 0.241,
      "avg": 0.365,
      "p50": 0.346,
      "p95": 0.478,
      "max": 0.545
    },
    "measured_resumption_speedup_x": 9.31,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0547,
      "messages_per_sec": 9133.8,
      "mb_per_sec": 8.92,
      "round_trip_ms": {
        "min": 0.073,
        "avg": 0.108,
        "p50": 0.093,
        "p95": 0.18,
        "max": 0.279
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0103,
      "messages_per_sec": 48743.9,
      "mb_per_sec": 47.601,
      "round_trip_ms": {
        "min": 0.015,
        "avg": 0.02,
        "p50": 0.017,
        "p95": 0.027,
        "max": 0.364
      }
    },
    "measured_data_speedup_x": 0.19,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.1111,
      "messages_per_sec": 180023.3,
      "mb_per_sec": 87.902
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.026,
      "messages_per_sec": 769431.9,
      "mb_per_sec": 375.699
    },
    "measured_pipelined_speedup_x": 0.23,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 23.8,
        "max": 47.6
      },
      "memory_mb": {
        "min": 36.86,
        "avg": 37.48,
        "max": 38.11
      },
      "gpu_percent": null
    },
    "completed_at": 1784447750.798039
  },
  {
    "target": "127.0.0.1:20004",
    "trusted_transport": true,
    "started_at": 1784447752.6614938,
    "fresh_handshake_ms": {
      "min": 2.846,
      "avg": 3.443,
      "p50": 3.438,
      "p95": 4.115,
      "max": 4.217
    },
    "resumed_handshake_ms": {
      "min": 0.29,
      "avg": 0.427,
      "p50": 0.4,
      "p95": 0.581,
      "max": 0.615
    },
    "measured_resumption_speedup_x": 8.07,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.065,
      "messages_per_sec": 7688.4,
      "mb_per_sec": 7.508,
      "round_trip_ms": {
        "min": 0.076,
        "avg": 0.128,
        "p50": 0.124,
        "p95": 0.189,
        "max": 0.34
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0094,
      "messages_per_sec": 53005.9,
      "mb_per_sec": 51.764,
      "round_trip_ms": {
        "min": 0.016,
        "avg": 0.018,
        "p50": 0.017,
        "p95": 0.022,
        "max": 0.095
      }
    },
    "measured_data_speedup_x": 0.14,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.095,
      "messages_per_sec": 210477.0,
      "mb_per_sec": 102.772
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0263,
      "messages_per_sec": 759722.9,
      "mb_per_sec": 370.958
    },
    "measured_pipelined_speedup_x": 0.28,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 27.35,
        "max": 54.7
      },
      "memory_mb": {
        "min": 36.71,
        "avg": 37.34,
        "max": 37.96
      },
      "gpu_percent": null
    },
    "completed_at": 1784447753.001504
  },
  {
    "target": "127.0.0.1:20005",
    "trusted_transport": true,
    "started_at": 1784447754.8411918,
    "fresh_handshake_ms": {
      "min": 2.881,
      "avg": 3.449,
      "p50": 3.382,
      "p95": 4.237,
      "max": 4.406
    },
    "resumed_handshake_ms": {
      "min": 0.24,
      "avg": 0.392,
      "p50": 0.373,
      "p95": 0.552,
      "max": 0.602
    },
    "measured_resumption_speedup_x": 8.8,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0662,
      "messages_per_sec": 7553.0,
      "mb_per_sec": 7.376,
      "round_trip_ms": {
        "min": 0.079,
        "avg": 0.13,
        "p50": 0.121,
        "p95": 0.19,
        "max": 0.431
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0095,
      "messages_per_sec": 52635.6,
      "mb_per_sec": 51.402,
      "round_trip_ms": {
        "min": 0.015,
        "avg": 0.018,
        "p50": 0.017,
        "p95": 0.023,
        "max": 0.07
      }
    },
    "measured_data_speedup_x": 0.14,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0944,
      "messages_per_sec": 211971.2,
      "mb_per_sec": 103.502
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0256,
      "messages_per_sec": 782100.4,
      "mb_per_sec": 381.885
    },
    "measured_pipelined_speedup_x": 0.27,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 26.2,
        "max": 52.4
      },
      "memory_mb": {
        "min": 36.73,
        "avg": 37.23,
        "max": 37.73
      },
      "gpu_percent": null
    },
    "completed_at": 1784447755.1846797
  },
  {
    "target": "127.0.0.1:20006",
    "trusted_transport": true,
    "started_at": 1784447757.0249963,
    "fresh_handshake_ms": {
      "min": 2.624,
      "avg": 3.395,
      "p50": 3.202,
      "p95": 4.479,
      "max": 5.864
    },
    "resumed_handshake_ms": {
      "min": 0.247,
      "avg": 0.319,
      "p50": 0.318,
      "p95": 0.401,
      "max": 0.411
    },
    "measured_resumption_speedup_x": 10.63,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0656,
      "messages_per_sec": 7619.3,
      "mb_per_sec": 7.441,
      "round_trip_ms": {
        "min": 0.075,
        "avg": 0.13,
        "p50": 0.121,
        "p95": 0.199,
        "max": 0.464
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0131,
      "messages_per_sec": 38185.4,
      "mb_per_sec": 37.29,
      "round_trip_ms": {
        "min": 0.016,
        "avg": 0.025,
        "p50": 0.017,
        "p95": 0.043,
        "max": 0.533
      }
    },
    "measured_data_speedup_x": 0.19,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0987,
      "messages_per_sec": 202672.3,
      "mb_per_sec": 98.961
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0275,
      "messages_per_sec": 727310.2,
      "mb_per_sec": 355.132
    },
    "measured_pipelined_speedup_x": 0.28,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 27.35,
        "max": 54.7
      },
      "memory_mb": {
        "min": 36.83,
        "avg": 37.45,
        "max": 38.08
      },
      "gpu_percent": null
    },
    "completed_at": 1784447757.3734555
  },
  {
    "target": "127.0.0.1:20007",
    "trusted_transport": true,
    "started_at": 1784447759.2100348,
    "fresh_handshake_ms": {
      "min": 2.7,
      "avg": 3.321,
      "p50": 3.191,
      "p95": 4.201,
      "max": 4.291
    },
    "resumed_handshake_ms": {
      "min": 0.234,
      "avg": 0.356,
      "p50": 0.323,
      "p95": 0.55,
      "max": 0.575
    },
    "measured_resumption_speedup_x": 9.32,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0641,
      "messages_per_sec": 7801.6,
      "mb_per_sec": 7.619,
      "round_trip_ms": {
        "min": 0.075,
        "avg": 0.126,
        "p50": 0.115,
        "p95": 0.202,
        "max": 0.415
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0131,
      "messages_per_sec": 38285.3,
      "mb_per_sec": 37.388,
      "round_trip_ms": {
        "min": 0.016,
        "avg": 0.025,
        "p50": 0.018,
        "p95": 0.043,
        "max": 0.569
      }
    },
    "measured_data_speedup_x": 0.2,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0967,
      "messages_per_sec": 206782.0,
      "mb_per_sec": 100.968
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0321,
      "messages_per_sec": 623543.8,
      "mb_per_sec": 304.465
    },
    "measured_pipelined_speedup_x": 0.33,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 30.65,
        "max": 61.3
      },
      "memory_mb": {
        "min": 36.68,
        "avg": 37.24,
        "max": 37.8
      },
      "gpu_percent": null
    },
    "completed_at": 1784447759.5485594
  },
  {
    "target": "127.0.0.1:20008",
    "trusted_transport": true,
    "started_at": 1784447761.4023507,
    "fresh_handshake_ms": {
      "min": 2.609,
      "avg": 3.482,
      "p50": 3.36,
      "p95": 4.364,
      "max": 4.527
    },
    "resumed_handshake_ms": {
      "min": 0.231,
      "avg": 0.321,
      "p50": 0.319,
      "p95": 0.384,
      "max": 0.418
    },
    "measured_resumption_speedup_x": 10.83,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0634,
      "messages_per_sec": 7884.2,
      "mb_per_sec": 7.699,
      "round_trip_ms": {
        "min": 0.075,
        "avg": 0.125,
        "p50": 0.118,
        "p95": 0.201,
        "max": 0.336
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0212,
      "messages_per_sec": 23561.5,
      "mb_per_sec": 23.009,
      "round_trip_ms": {
        "min": 0.016,
        "avg": 0.041,
        "p50": 0.035,
        "p95": 0.104,
        "max": 0.279
      }
    },
    "measured_data_speedup_x": 0.33,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0923,
      "messages_per_sec": 216796.2,
      "mb_per_sec": 105.858
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0363,
      "messages_per_sec": 550438.3,
      "mb_per_sec": 268.769
    },
    "measured_pipelined_speedup_x": 0.39,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 26.55,
        "max": 53.1
      },
      "memory_mb": {
        "min": 36.86,
        "avg": 37.48,
        "max": 38.11
      },
      "gpu_percent": null
    },
    "completed_at": 1784447761.7679033
  },
  {
    "target": "127.0.0.1:20009",
    "trusted_transport": true,
    "started_at": 1784447763.5976493,
    "fresh_handshake_ms": {
      "min": 2.839,
      "avg": 3.358,
      "p50": 3.286,
      "p95": 4.098,
      "max": 4.425
    },
    "resumed_handshake_ms": {
      "min": 0.293,
      "avg": 0.406,
      "p50": 0.394,
      "p95": 0.579,
      "max": 0.58
    },
    "measured_resumption_speedup_x": 8.27,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0631,
      "messages_per_sec": 7921.0,
      "mb_per_sec": 7.735,
      "round_trip_ms": {
        "min": 0.072,
        "avg": 0.125,
        "p50": 0.117,
        "p95": 0.183,
        "max": 0.465
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0095,
      "messages_per_sec": 52487.8,
      "mb_per_sec": 51.258,
      "round_trip_ms": {
        "min": 0.014,
        "avg": 0.018,
        "p50": 0.016,
        "p95": 0.025,
        "max": 0.215
      }
    },
    "measured_data_speedup_x": 0.14,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.1018,
      "messages_per_sec": 196456.6,
      "mb_per_sec": 95.926
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0236,
      "messages_per_sec": 849015.0,
      "mb_per_sec": 414.558
    },
    "measured_pipelined_speedup_x": 0.23,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 2,
      "cpu_percent": {
        "min": 0.0,
        "avg": 28.7,
        "max": 57.4
      },
      "memory_mb": {
        "min": 36.74,
        "avg": 37.37,
        "max": 37.99
      },
      "gpu_percent": null
    },
    "completed_at": 1784447763.9439569
  }
]
```

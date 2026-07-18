# Bastion Protocol vs. JSON-over-TCP — Benchmark Results

Generated: 2026-07-18T23:52:43.943767+00:00

## Methodology

- **10 independent trials** completed (0 failed and excluded), each launching a fresh server process and a fresh client process — no shared warm-up state, connection caching, or JIT/cache warmth carried between trials.
- Each trial: 15 handshake repetitions, 500 round-trip messages, 20000 pipelined bulk-send messages, 512-byte payloads.
- Every trial's raw data is included below — none excluded except outright process failures.
- **This is not a security-equivalent comparison.** The JSON baseline has zero encryption, zero authentication, zero replay protection, and zero framing validation. Bastion Protocol does all of that. The comparison isolates wire-format/session cost, not "equivalent security posture at different speeds" — there is no equivalent-security JSON baseline being claimed here.
- Reproduce with: `python scripts/rigorous_bench.py --trials 10 --messages 500 --bulk-messages 20000 --size 512`

## Environment

```json
{
  "timestamp_utc": "2026-07-18T23:52:43.943767+00:00",
  "platform": "Windows-10-10.0.26200-SP0",
  "python_version": "3.11.9",
  "python_implementation": "CPython",
  "processor": "Intel64 Family 6 Model 198 Stepping 2, GenuineIntel",
  "cpu_count": 10,
  "pynacl_version": "1.6.2",
  "msgpack_version": "1.1.2",
  "psutil_version": "7.2.2"
}
```

## Aggregate results (across all trials)

| Metric | Trials (n) | Mean | Median | Stdev | Min | Max |
|---|---|---|---|---|---|---|
| Fresh handshake latency (ms) | 10 | 1.67 | 1.67 | 0.08 | 1.53 | 1.76 |
| Resumed handshake latency (ms) | 10 | 1.04 | 1.04 | 0.04 | 0.96 | 1.1 |
| Resumption speedup (x, fresh/resumed) | 10 | 1.6 | 1.62 | 0.1 | 1.46 | 1.72 |
| Bastion round-trip throughput (msg/s) | 10 | 6283.75 | 6303.05 | 615.6 | 5076.7 | 7052.6 |
| JSON baseline round-trip throughput (msg/s) | 10 | 17526.05 | 17578.1 | 538.34 | 16374.8 | 18134.2 |
| Bastion vs JSON round-trip ratio (x) | 10 | 0.35 | 0.35 | 0.04 | 0.29 | 0.41 |
| Bastion pipelined bulk-send (msg/s) | 10 | 76082.04 | 75412.65 | 4117.27 | 71152.4 | 82139.8 |
| Bastion pipelined bulk-send (MB/s) | 10 | 37.15 | 36.82 | 2.01 | 34.74 | 40.11 |
| JSON baseline pipelined bulk-send (msg/s) | 10 | 306970.52 | 311782.65 | 28486.1 | 236139.5 | 333510.1 |
| Bastion vs JSON pipelined ratio (x) | 10 | 0.25 | 0.24 | 0.04 | 0.21 | 0.33 |

## Honest interpretation

- **Round-trip (request-response) throughput: Bastion is SLOWER than the plain-JSON baseline**, at 0.35x across 10 trials (stdev 0.04). This is NOT parity, and this report does not claim it is.

- **Session resumption** (skipping the full handshake on reconnect) shows a real, repeated, measured speedup of 1.6x over a fresh handshake (stdev 0.1, 10 trials).

- **Pipelined bulk-send** (the pattern an actual bulk transfer uses -- not waiting for a per-message ack): 76082.04 msg/s mean (4117.27 stdev). This is the number relevant to "send N messages of data," not round-trip request-response latency.

- **Pipelined bulk-send: Bastion is SLOWER than the plain-JSON pipelined baseline**, at 0.25x across 10 trials (stdev 0.04). This is the direct, fair comparison for the pipelined pattern -- both sides fire-and-forget, neither waits per-message.


## Raw per-trial data

Every completed trial, unfiltered:

```json
[
  {
    "target": "127.0.0.1:19940",
    "trusted_transport": false,
    "started_at": 1784418765.587589,
    "fresh_handshake_ms": {
      "min": 1.362,
      "avg": 1.765,
      "p50": 1.765,
      "p95": 2.496,
      "max": 2.564
    },
    "resumed_handshake_ms": {
      "min": 0.837,
      "avg": 1.06,
      "p50": 1.101,
      "p95": 1.234,
      "max": 1.373
    },
    "measured_resumption_speedup_x": 1.67,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0781,
      "messages_per_sec": 6405.6,
      "mb_per_sec": 6.256,
      "round_trip_ms": {
        "min": 0.093,
        "avg": 0.155,
        "p50": 0.151,
        "p95": 0.23,
        "max": 0.434
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0285,
      "messages_per_sec": 17536.4,
      "mb_per_sec": 17.125,
      "round_trip_ms": {
        "min": 0.048,
        "avg": 0.056,
        "p50": 0.052,
        "p95": 0.071,
        "max": 0.268
      }
    },
    "measured_data_speedup_x": 0.36,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.2536,
      "messages_per_sec": 78870.8,
      "mb_per_sec": 38.511
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0847,
      "messages_per_sec": 236139.5,
      "mb_per_sec": 115.302
    },
    "measured_pipelined_speedup_x": 0.33,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 3,
      "cpu_percent": {
        "min": 0.0,
        "avg": 47.2,
        "max": 74.8
      },
      "memory_mb": {
        "min": 51.14,
        "avg": 52.0,
        "max": 52.43
      },
      "gpu_percent": null
    },
    "completed_at": 1784418766.0922759
  },
  {
    "target": "127.0.0.1:19941",
    "trusted_transport": false,
    "started_at": 1784418768.122056,
    "fresh_handshake_ms": {
      "min": 1.284,
      "avg": 1.531,
      "p50": 1.442,
      "p95": 1.982,
      "max": 2.346
    },
    "resumed_handshake_ms": {
      "min": 0.791,
      "avg": 1.047,
      "p50": 1.026,
      "p95": 1.455,
      "max": 1.503
    },
    "measured_resumption_speedup_x": 1.46,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0756,
      "messages_per_sec": 6610.7,
      "mb_per_sec": 6.456,
      "round_trip_ms": {
        "min": 0.092,
        "avg": 0.15,
        "p50": 0.14,
        "p95": 0.221,
        "max": 0.831
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0276,
      "messages_per_sec": 18134.2,
      "mb_per_sec": 17.709,
      "round_trip_ms": {
        "min": 0.047,
        "avg": 0.054,
        "p50": 0.051,
        "p95": 0.068,
        "max": 0.186
      }
    },
    "measured_data_speedup_x": 0.36,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.2811,
      "messages_per_sec": 71152.4,
      "mb_per_sec": 34.742
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0642,
      "messages_per_sec": 311759.1,
      "mb_per_sec": 152.226
    },
    "measured_pipelined_speedup_x": 0.23,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 3,
      "cpu_percent": {
        "min": 0.0,
        "avg": 41.67,
        "max": 66.5
      },
      "memory_mb": {
        "min": 51.27,
        "avg": 52.05,
        "max": 52.44
      },
      "gpu_percent": null
    },
    "completed_at": 1784418768.6257956
  },
  {
    "target": "127.0.0.1:19942",
    "trusted_transport": false,
    "started_at": 1784418770.6041572,
    "fresh_handshake_ms": {
      "min": 1.471,
      "avg": 1.729,
      "p50": 1.639,
      "p95": 2.124,
      "max": 2.454
    },
    "resumed_handshake_ms": {
      "min": 0.911,
      "avg": 1.069,
      "p50": 1.02,
      "p95": 1.211,
      "max": 1.543
    },
    "measured_resumption_speedup_x": 1.62,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0985,
      "messages_per_sec": 5076.7,
      "mb_per_sec": 4.958,
      "round_trip_ms": {
        "min": 0.113,
        "avg": 0.195,
        "p50": 0.193,
        "p95": 0.257,
        "max": 0.537
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0291,
      "messages_per_sec": 17156.2,
      "mb_per_sec": 16.754,
      "round_trip_ms": {
        "min": 0.047,
        "avg": 0.057,
        "p50": 0.052,
        "p95": 0.073,
        "max": 0.238
      }
    },
    "measured_data_speedup_x": 0.29,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.2543,
      "messages_per_sec": 78659.7,
      "mb_per_sec": 38.408
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0648,
      "messages_per_sec": 308664.8,
      "mb_per_sec": 150.715
    },
    "measured_pipelined_speedup_x": 0.25,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 3,
      "cpu_percent": {
        "min": 0.0,
        "avg": 41.7,
        "max": 75.2
      },
      "memory_mb": {
        "min": 51.35,
        "avg": 52.11,
        "max": 52.53
      },
      "gpu_percent": null
    },
    "completed_at": 1784418771.1105795
  },
  {
    "target": "127.0.0.1:19943",
    "trusted_transport": false,
    "started_at": 1784418773.0992122,
    "fresh_handshake_ms": {
      "min": 1.256,
      "avg": 1.743,
      "p50": 1.68,
      "p95": 2.238,
      "max": 2.96
    },
    "resumed_handshake_ms": {
      "min": 0.833,
      "avg": 1.038,
      "p50": 0.969,
      "p95": 1.344,
      "max": 1.45
    },
    "measured_resumption_speedup_x": 1.68,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.074,
      "messages_per_sec": 6754.2,
      "mb_per_sec": 6.596,
      "round_trip_ms": {
        "min": 0.093,
        "avg": 0.147,
        "p50": 0.14,
        "p95": 0.212,
        "max": 0.264
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0305,
      "messages_per_sec": 16374.8,
      "mb_per_sec": 15.991,
      "round_trip_ms": {
        "min": 0.048,
        "avg": 0.06,
        "p50": 0.055,
        "p95": 0.075,
        "max": 0.298
      }
    },
    "measured_data_speedup_x": 0.41,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.2435,
      "messages_per_sec": 82139.8,
      "mb_per_sec": 40.107
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0689,
      "messages_per_sec": 290261.4,
      "mb_per_sec": 141.729
    },
    "measured_pipelined_speedup_x": 0.28,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 3,
      "cpu_percent": {
        "min": 0.0,
        "avg": 36.13,
        "max": 66.8
      },
      "memory_mb": {
        "min": 51.31,
        "avg": 52.16,
        "max": 52.59
      },
      "gpu_percent": null
    },
    "completed_at": 1784418773.5754654
  },
  {
    "target": "127.0.0.1:19944",
    "trusted_transport": false,
    "started_at": 1784418775.5530803,
    "fresh_handshake_ms": {
      "min": 1.323,
      "avg": 1.69,
      "p50": 1.623,
      "p95": 2.218,
      "max": 2.614
    },
    "resumed_handshake_ms": {
      "min": 0.85,
      "avg": 0.991,
      "p50": 0.939,
      "p95": 1.164,
      "max": 1.184
    },
    "measured_resumption_speedup_x": 1.71,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0844,
      "messages_per_sec": 5921.7,
      "mb_per_sec": 5.783,
      "round_trip_ms": {
        "min": 0.092,
        "avg": 0.167,
        "p50": 0.162,
        "p95": 0.229,
        "max": 0.36
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0277,
      "messages_per_sec": 18050.0,
      "mb_per_sec": 17.627,
      "round_trip_ms": {
        "min": 0.046,
        "avg": 0.054,
        "p50": 0.051,
        "p95": 0.065,
        "max": 0.249
      }
    },
    "measured_data_speedup_x": 0.32,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.2669,
      "messages_per_sec": 74926.1,
      "mb_per_sec": 36.585
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0621,
      "messages_per_sec": 321877.2,
      "mb_per_sec": 157.167
    },
    "measured_pipelined_speedup_x": 0.23,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 3,
      "cpu_percent": {
        "min": 0.0,
        "avg": 30.57,
        "max": 58.5
      },
      "memory_mb": {
        "min": 51.27,
        "avg": 52.12,
        "max": 52.54
      },
      "gpu_percent": null
    },
    "completed_at": 1784418776.050108
  },
  {
    "target": "127.0.0.1:19945",
    "trusted_transport": false,
    "started_at": 1784418778.0872376,
    "fresh_handshake_ms": {
      "min": 1.383,
      "avg": 1.611,
      "p50": 1.528,
      "p95": 1.832,
      "max": 2.358
    },
    "resumed_handshake_ms": {
      "min": 0.949,
      "avg": 1.1,
      "p50": 1.073,
      "p95": 1.35,
      "max": 1.411
    },
    "measured_resumption_speedup_x": 1.46,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0806,
      "messages_per_sec": 6200.5,
      "mb_per_sec": 6.055,
      "round_trip_ms": {
        "min": 0.094,
        "avg": 0.16,
        "p50": 0.154,
        "p95": 0.232,
        "max": 0.314
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0279,
      "messages_per_sec": 17901.0,
      "mb_per_sec": 17.481,
      "round_trip_ms": {
        "min": 0.047,
        "avg": 0.055,
        "p50": 0.051,
        "p95": 0.069,
        "max": 0.195
      }
    },
    "measured_data_speedup_x": 0.34,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.2444,
      "messages_per_sec": 81844.4,
      "mb_per_sec": 39.963
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0641,
      "messages_per_sec": 311806.2,
      "mb_per_sec": 152.249
    },
    "measured_pipelined_speedup_x": 0.26,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 3,
      "cpu_percent": {
        "min": 0.0,
        "avg": 38.9,
        "max": 58.5
      },
      "memory_mb": {
        "min": 51.31,
        "avg": 52.1,
        "max": 52.5
      },
      "gpu_percent": null
    },
    "completed_at": 1784418778.5616531
  },
  {
    "target": "127.0.0.1:19946",
    "trusted_transport": false,
    "started_at": 1784418780.5294414,
    "fresh_handshake_ms": {
      "min": 1.233,
      "avg": 1.642,
      "p50": 1.546,
      "p95": 2.154,
      "max": 2.926
    },
    "resumed_handshake_ms": {
      "min": 0.839,
      "avg": 1.012,
      "p50": 0.946,
      "p95": 1.227,
      "max": 1.405
    },
    "measured_resumption_speedup_x": 1.62,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0714,
      "messages_per_sec": 7001.8,
      "mb_per_sec": 6.838,
      "round_trip_ms": {
        "min": 0.091,
        "avg": 0.142,
        "p50": 0.131,
        "p95": 0.215,
        "max": 0.495
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0289,
      "messages_per_sec": 17293.2,
      "mb_per_sec": 16.888,
      "round_trip_ms": {
        "min": 0.048,
        "avg": 0.057,
        "p50": 0.052,
        "p95": 0.078,
        "max": 0.207
      }
    },
    "measured_data_speedup_x": 0.4,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.2774,
      "messages_per_sec": 72103.1,
      "mb_per_sec": 35.207
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0606,
      "messages_per_sec": 330057.0,
      "mb_per_sec": 161.161
    },
    "measured_pipelined_speedup_x": 0.22,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 3,
      "cpu_percent": {
        "min": 0.0,
        "avg": 47.17,
        "max": 91.4
      },
      "memory_mb": {
        "min": 51.41,
        "avg": 52.17,
        "max": 52.54
      },
      "gpu_percent": null
    },
    "completed_at": 1784418781.0256295
  },
  {
    "target": "127.0.0.1:19947",
    "trusted_transport": false,
    "started_at": 1784418783.0070696,
    "fresh_handshake_ms": {
      "min": 1.477,
      "avg": 1.729,
      "p50": 1.615,
      "p95": 2.287,
      "max": 2.466
    },
    "resumed_handshake_ms": {
      "min": 0.882,
      "avg": 1.082,
      "p50": 1.013,
      "p95": 1.45,
      "max": 1.527
    },
    "measured_resumption_speedup_x": 1.6,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0818,
      "messages_per_sec": 6109.1,
      "mb_per_sec": 5.966,
      "round_trip_ms": {
        "min": 0.092,
        "avg": 0.162,
        "p50": 0.156,
        "p95": 0.254,
        "max": 0.519
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0284,
      "messages_per_sec": 17619.8,
      "mb_per_sec": 17.207,
      "round_trip_ms": {
        "min": 0.047,
        "avg": 0.056,
        "p50": 0.051,
        "p95": 0.069,
        "max": 0.343
      }
    },
    "measured_data_speedup_x": 0.35,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.2635,
      "messages_per_sec": 75899.2,
      "mb_per_sec": 37.06
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0611,
      "messages_per_sec": 327475.3,
      "mb_per_sec": 159.9
    },
    "measured_pipelined_speedup_x": 0.23,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 3,
      "cpu_percent": {
        "min": 0.0,
        "avg": 47.17,
        "max": 99.7
      },
      "memory_mb": {
        "min": 51.01,
        "avg": 51.89,
        "max": 52.32
      },
      "gpu_percent": null
    },
    "completed_at": 1784418783.5014179
  },
  {
    "target": "127.0.0.1:19948",
    "trusted_transport": false,
    "started_at": 1784418785.4819062,
    "fresh_handshake_ms": {
      "min": 1.317,
      "avg": 1.563,
      "p50": 1.473,
      "p95": 1.745,
      "max": 2.653
    },
    "resumed_handshake_ms": {
      "min": 0.809,
      "avg": 1.033,
      "p50": 1.018,
      "p95": 1.329,
      "max": 1.346
    },
    "measured_resumption_speedup_x": 1.51,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0876,
      "messages_per_sec": 5704.6,
      "mb_per_sec": 5.571,
      "round_trip_ms": {
        "min": 0.095,
        "avg": 0.174,
        "p50": 0.17,
        "p95": 0.234,
        "max": 0.376
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.029,
      "messages_per_sec": 17218.1,
      "mb_per_sec": 16.815,
      "round_trip_ms": {
        "min": 0.047,
        "avg": 0.057,
        "p50": 0.051,
        "p95": 0.083,
        "max": 0.332
      }
    },
    "measured_data_speedup_x": 0.33,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.2711,
      "messages_per_sec": 73766.8,
      "mb_per_sec": 36.019
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0671,
      "messages_per_sec": 298154.6,
      "mb_per_sec": 145.583
    },
    "measured_pipelined_speedup_x": 0.25,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 3,
      "cpu_percent": {
        "min": 0.0,
        "avg": 41.67,
        "max": 66.8
      },
      "memory_mb": {
        "min": 51.14,
        "avg": 52.0,
        "max": 52.43
      },
      "gpu_percent": null
    },
    "completed_at": 1784418785.9949563
  },
  {
    "target": "127.0.0.1:19949",
    "trusted_transport": false,
    "started_at": 1784418788.0421345,
    "fresh_handshake_ms": {
      "min": 1.335,
      "avg": 1.65,
      "p50": 1.555,
      "p95": 2.123,
      "max": 2.724
    },
    "resumed_handshake_ms": {
      "min": 0.758,
      "avg": 0.96,
      "p50": 0.949,
      "p95": 1.209,
      "max": 1.226
    },
    "measured_resumption_speedup_x": 1.72,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0709,
      "messages_per_sec": 7052.6,
      "mb_per_sec": 6.887,
      "round_trip_ms": {
        "min": 0.089,
        "avg": 0.141,
        "p50": 0.135,
        "p95": 0.225,
        "max": 0.354
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0278,
      "messages_per_sec": 17976.8,
      "mb_per_sec": 17.555,
      "round_trip_ms": {
        "min": 0.048,
        "avg": 0.055,
        "p50": 0.051,
        "p95": 0.068,
        "max": 0.189
      }
    },
    "measured_data_speedup_x": 0.39,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.2799,
      "messages_per_sec": 71458.1,
      "mb_per_sec": 34.892
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.06,
      "messages_per_sec": 333510.1,
      "mb_per_sec": 162.847
    },
    "measured_pipelined_speedup_x": 0.21,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 3,
      "cpu_percent": {
        "min": 0.0,
        "avg": 41.7,
        "max": 75.2
      },
      "memory_mb": {
        "min": 51.29,
        "avg": 52.03,
        "max": 52.4
      },
      "gpu_percent": null
    },
    "completed_at": 1784418788.5355127
  }
]
```

# Bastion Protocol vs. JSON-over-TCP — Benchmark Results

Generated: 2026-07-19T04:25:46.578198+00:00

## Methodology

- **10 independent trials** completed (0 failed and excluded), each launching a fresh server process and a fresh client process — no shared warm-up state, connection caching, or JIT/cache warmth carried between trials.
- Each trial: 15 handshake repetitions, 500 round-trip messages, 20000 pipelined bulk-send messages, 512-byte payloads.
- Every trial's raw data is included below — none excluded except outright process failures.
- **This is not a security-equivalent comparison.** The JSON baseline has zero encryption, zero authentication, zero replay protection, and zero framing validation. Bastion Protocol does all of that. The comparison isolates wire-format/session cost, not "equivalent security posture at different speeds" — there is no equivalent-security JSON baseline being claimed here.
- Reproduce with: `python scripts/rigorous_bench.py --trials 10 --messages 500 --bulk-messages 20000 --size 512`

## Environment

```json
{
  "timestamp_utc": "2026-07-19T04:25:46.578198+00:00",
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
| Fresh handshake latency (ms) | 10 | 1.25 | 1.25 | 0.13 | 1.09 | 1.44 |
| Resumed handshake latency (ms) | 10 | 0.63 | 0.66 | 0.07 | 0.52 | 0.72 |
| Resumption speedup (x, fresh/resumed) | 10 | 1.98 | 1.94 | 0.23 | 1.63 | 2.4 |
| Bastion round-trip throughput (msg/s) | 10 | 9003.61 | 8865.4 | 491.78 | 8514.9 | 10131.4 |
| JSON baseline round-trip throughput (msg/s) | 10 | 14529.18 | 14033.1 | 1691.2 | 12580.3 | 17585.0 |
| Bastion vs JSON round-trip ratio (x) | 10 | 0.62 | 0.64 | 0.08 | 0.5 | 0.71 |
| Bastion pipelined bulk-send (msg/s) | 10 | 89718.57 | 89608.35 | 5801.69 | 81862.7 | 102392.8 |
| Bastion pipelined bulk-send (MB/s) | 10 | 43.81 | 43.75 | 2.83 | 39.97 | 50.0 |
| JSON baseline pipelined bulk-send (msg/s) | 10 | 305583.59 | 305057.15 | 14587.95 | 284537.1 | 324317.3 |
| Bastion vs JSON pipelined ratio (x) | 10 | 0.29 | 0.29 | 0.02 | 0.26 | 0.33 |

## Honest interpretation

- **Round-trip (request-response) throughput: Bastion is SLOWER than the plain-JSON baseline**, at 0.62x across 10 trials (stdev 0.08). This is NOT parity, and this report does not claim it is.

- **Session resumption** (skipping the full handshake on reconnect) shows a real, repeated, measured speedup of 1.98x over a fresh handshake (stdev 0.23, 10 trials).

- **Pipelined bulk-send** (the pattern an actual bulk transfer uses -- not waiting for a per-message ack): 89718.57 msg/s mean (5801.69 stdev). This is the number relevant to "send N messages of data," not round-trip request-response latency.

- **Pipelined bulk-send: Bastion is SLOWER than the plain-JSON pipelined baseline**, at 0.29x across 10 trials (stdev 0.02). This is the direct, fair comparison for the pipelined pattern -- both sides fire-and-forget, neither waits per-message.


## Raw per-trial data

Every completed trial, unfiltered:

```json
[
  {
    "target": "127.0.0.1:19970",
    "trusted_transport": true,
    "started_at": 1784435152.217391,
    "fresh_handshake_ms": {
      "min": 1.109,
      "avg": 1.441,
      "p50": 1.409,
      "p95": 1.715,
      "max": 2.107
    },
    "resumed_handshake_ms": {
      "min": 0.561,
      "avg": 0.693,
      "p50": 0.678,
      "p95": 0.839,
      "max": 0.975
    },
    "measured_resumption_speedup_x": 2.08,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0562,
      "messages_per_sec": 8895.5,
      "mb_per_sec": 8.687,
      "round_trip_ms": {
        "min": 0.095,
        "avg": 0.111,
        "p50": 0.099,
        "p95": 0.19,
        "max": 0.399
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0397,
      "messages_per_sec": 12580.3,
      "mb_per_sec": 12.285,
      "round_trip_ms": {
        "min": 0.048,
        "avg": 0.078,
        "p50": 0.074,
        "p95": 0.097,
        "max": 0.309
      }
    },
    "measured_data_speedup_x": 0.7,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.2238,
      "messages_per_sec": 89356.1,
      "mb_per_sec": 43.631
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0703,
      "messages_per_sec": 284631.9,
      "mb_per_sec": 138.98
    },
    "measured_pipelined_speedup_x": 0.31,
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
        "min": 51.2,
        "avg": 52.01,
        "max": 52.42
      },
      "gpu_percent": null
    },
    "completed_at": 1784435152.6589186
  },
  {
    "target": "127.0.0.1:19971",
    "trusted_transport": true,
    "started_at": 1784435158.6673527,
    "fresh_handshake_ms": {
      "min": 0.872,
      "avg": 1.308,
      "p50": 1.008,
      "p95": 1.722,
      "max": 4.526
    },
    "resumed_handshake_ms": {
      "min": 0.461,
      "avg": 0.689,
      "p50": 0.56,
      "p95": 1.385,
      "max": 1.464
    },
    "measured_resumption_speedup_x": 1.9,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0581,
      "messages_per_sec": 8610.0,
      "mb_per_sec": 8.408,
      "round_trip_ms": {
        "min": 0.071,
        "avg": 0.115,
        "p50": 0.087,
        "p95": 0.254,
        "max": 0.728
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0344,
      "messages_per_sec": 14553.3,
      "mb_per_sec": 14.212,
      "round_trip_ms": {
        "min": 0.047,
        "avg": 0.068,
        "p50": 0.055,
        "p95": 0.124,
        "max": 0.428
      }
    },
    "measured_data_speedup_x": 0.59,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.2224,
      "messages_per_sec": 89922.1,
      "mb_per_sec": 43.907
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0643,
      "messages_per_sec": 310937.1,
      "mb_per_sec": 151.825
    },
    "measured_pipelined_speedup_x": 0.29,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 3,
      "cpu_percent": {
        "min": 0.0,
        "avg": 55.53,
        "max": 91.4
      },
      "memory_mb": {
        "min": 51.1,
        "avg": 51.97,
        "max": 52.48
      },
      "gpu_percent": null
    },
    "completed_at": 1784435159.0893412
  },
  {
    "target": "127.0.0.1:19972",
    "trusted_transport": true,
    "started_at": 1784435165.0923712,
    "fresh_handshake_ms": {
      "min": 0.893,
      "avg": 1.13,
      "p50": 1.026,
      "p95": 1.539,
      "max": 2.143
    },
    "resumed_handshake_ms": {
      "min": 0.445,
      "avg": 0.519,
      "p50": 0.504,
      "p95": 0.612,
      "max": 0.635
    },
    "measured_resumption_speedup_x": 2.18,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0575,
      "messages_per_sec": 8692.5,
      "mb_per_sec": 8.489,
      "round_trip_ms": {
        "min": 0.073,
        "avg": 0.114,
        "p50": 0.088,
        "p95": 0.25,
        "max": 0.635
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0291,
      "messages_per_sec": 17158.5,
      "mb_per_sec": 16.756,
      "round_trip_ms": {
        "min": 0.048,
        "avg": 0.057,
        "p50": 0.052,
        "p95": 0.074,
        "max": 0.332
      }
    },
    "measured_data_speedup_x": 0.5,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.2124,
      "messages_per_sec": 94170.5,
      "mb_per_sec": 45.982
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0617,
      "messages_per_sec": 324317.3,
      "mb_per_sec": 158.358
    },
    "measured_pipelined_speedup_x": 0.29,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 3,
      "cpu_percent": {
        "min": 0.0,
        "avg": 38.9,
        "max": 66.8
      },
      "memory_mb": {
        "min": 51.05,
        "avg": 52.0,
        "max": 52.6
      },
      "gpu_percent": null
    },
    "completed_at": 1784435165.4955437
  },
  {
    "target": "127.0.0.1:19973",
    "trusted_transport": true,
    "started_at": 1784435171.4785206,
    "fresh_handshake_ms": {
      "min": 0.882,
      "avg": 1.333,
      "p50": 1.103,
      "p95": 1.87,
      "max": 3.869
    },
    "resumed_handshake_ms": {
      "min": 0.454,
      "avg": 0.554,
      "p50": 0.533,
      "p95": 0.684,
      "max": 0.748
    },
    "measured_resumption_speedup_x": 2.4,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0529,
      "messages_per_sec": 9444.1,
      "mb_per_sec": 9.223,
      "round_trip_ms": {
        "min": 0.067,
        "avg": 0.105,
        "p50": 0.085,
        "p95": 0.2,
        "max": 0.931
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.036,
      "messages_per_sec": 13905.6,
      "mb_per_sec": 13.58,
      "round_trip_ms": {
        "min": 0.048,
        "avg": 0.071,
        "p50": 0.073,
        "p95": 0.098,
        "max": 0.295
      }
    },
    "measured_data_speedup_x": 0.68,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.1953,
      "messages_per_sec": 102392.8,
      "mb_per_sec": 49.996
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0653,
      "messages_per_sec": 306095.9,
      "mb_per_sec": 149.461
    },
    "measured_pipelined_speedup_x": 0.33,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 3,
      "cpu_percent": {
        "min": 0.0,
        "avg": 36.1,
        "max": 66.5
      },
      "memory_mb": {
        "min": 51.15,
        "avg": 52.03,
        "max": 52.58
      },
      "gpu_percent": null
    },
    "completed_at": 1784435171.8707252
  },
  {
    "target": "127.0.0.1:19974",
    "trusted_transport": true,
    "started_at": 1784435177.849676,
    "fresh_handshake_ms": {
      "min": 0.877,
      "avg": 1.095,
      "p50": 0.987,
      "p95": 1.173,
      "max": 2.182
    },
    "resumed_handshake_ms": {
      "min": 0.448,
      "avg": 0.557,
      "p50": 0.51,
      "p95": 0.714,
      "max": 0.857
    },
    "measured_resumption_speedup_x": 1.96,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0558,
      "messages_per_sec": 8967.4,
      "mb_per_sec": 8.757,
      "round_trip_ms": {
        "min": 0.068,
        "avg": 0.11,
        "p50": 0.086,
        "p95": 0.23,
        "max": 0.911
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0284,
      "messages_per_sec": 17585.0,
      "mb_per_sec": 17.173,
      "round_trip_ms": {
        "min": 0.047,
        "avg": 0.056,
        "p50": 0.051,
        "p95": 0.069,
        "max": 0.462
      }
    },
    "measured_data_speedup_x": 0.51,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.2347,
      "messages_per_sec": 85232.2,
      "mb_per_sec": 41.617
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.062,
      "messages_per_sec": 322598.9,
      "mb_per_sec": 157.519
    },
    "measured_pipelined_speedup_x": 0.26,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 3,
      "cpu_percent": {
        "min": 0.0,
        "avg": 44.43,
        "max": 66.8
      },
      "memory_mb": {
        "min": 51.23,
        "avg": 51.98,
        "max": 52.39
      },
      "gpu_percent": null
    },
    "completed_at": 1784435178.2687004
  },
  {
    "target": "127.0.0.1:19975",
    "trusted_transport": true,
    "started_at": 1784435184.2425542,
    "fresh_handshake_ms": {
      "min": 0.903,
      "avg": 1.336,
      "p50": 1.121,
      "p95": 2.198,
      "max": 2.554
    },
    "resumed_handshake_ms": {
      "min": 0.527,
      "avg": 0.706,
      "p50": 0.561,
      "p95": 0.936,
      "max": 2.149
    },
    "measured_resumption_speedup_x": 1.89,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0576,
      "messages_per_sec": 8675.1,
      "mb_per_sec": 8.472,
      "round_trip_ms": {
        "min": 0.067,
        "avg": 0.114,
        "p50": 0.084,
        "p95": 0.287,
        "max": 0.657
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0376,
      "messages_per_sec": 13305.2,
      "mb_per_sec": 12.993,
      "round_trip_ms": {
        "min": 0.047,
        "avg": 0.074,
        "p50": 0.062,
        "p95": 0.137,
        "max": 0.767
      }
    },
    "measured_data_speedup_x": 0.65,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.2303,
      "messages_per_sec": 86838.9,
      "mb_per_sec": 42.402
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0703,
      "messages_per_sec": 284537.1,
      "mb_per_sec": 138.934
    },
    "measured_pipelined_speedup_x": 0.31,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 3,
      "cpu_percent": {
        "min": 0.0,
        "avg": 33.37,
        "max": 58.5
      },
      "memory_mb": {
        "min": 51.63,
        "avg": 52.34,
        "max": 52.7
      },
      "gpu_percent": null
    },
    "completed_at": 1784435184.6891367
  },
  {
    "target": "127.0.0.1:19976",
    "trusted_transport": true,
    "started_at": 1784435190.702484,
    "fresh_handshake_ms": {
      "min": 0.882,
      "avg": 1.182,
      "p50": 1.013,
      "p95": 2.046,
      "max": 2.215
    },
    "resumed_handshake_ms": {
      "min": 0.461,
      "avg": 0.725,
      "p50": 0.565,
      "p95": 1.164,
      "max": 2.544
    },
    "measured_resumption_speedup_x": 1.63,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0587,
      "messages_per_sec": 8514.9,
      "mb_per_sec": 8.315,
      "round_trip_ms": {
        "min": 0.069,
        "avg": 0.116,
        "p50": 0.098,
        "p95": 0.21,
        "max": 1.04
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0368,
      "messages_per_sec": 13581.1,
      "mb_per_sec": 13.263,
      "round_trip_ms": {
        "min": 0.047,
        "avg": 0.073,
        "p50": 0.073,
        "p95": 0.088,
        "max": 0.236
      }
    },
    "measured_data_speedup_x": 0.63,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.2226,
      "messages_per_sec": 89860.6,
      "mb_per_sec": 43.877
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0659,
      "messages_per_sec": 303686.9,
      "mb_per_sec": 148.285
    },
    "measured_pipelined_speedup_x": 0.3,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 3,
      "cpu_percent": {
        "min": 0.0,
        "avg": 27.77,
        "max": 58.2
      },
      "memory_mb": {
        "min": 51.09,
        "avg": 51.88,
        "max": 52.36
      },
      "gpu_percent": null
    },
    "completed_at": 1784435191.1288028
  },
  {
    "target": "127.0.0.1:19977",
    "trusted_transport": true,
    "started_at": 1784435197.1042047,
    "fresh_handshake_ms": {
      "min": 0.876,
      "avg": 1.418,
      "p50": 1.119,
      "p95": 2.25,
      "max": 3.694
    },
    "resumed_handshake_ms": {
      "min": 0.442,
      "avg": 0.655,
      "p50": 0.524,
      "p95": 0.955,
      "max": 2.042
    },
    "measured_resumption_speedup_x": 2.17,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0494,
      "messages_per_sec": 10131.4,
      "mb_per_sec": 9.894,
      "round_trip_ms": {
        "min": 0.067,
        "avg": 0.098,
        "p50": 0.072,
        "p95": 0.218,
        "max": 0.613
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0353,
      "messages_per_sec": 14160.6,
      "mb_per_sec": 13.829,
      "round_trip_ms": {
        "min": 0.047,
        "avg": 0.07,
        "p50": 0.074,
        "p95": 0.088,
        "max": 0.311
      }
    },
    "measured_data_speedup_x": 0.71,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.2443,
      "messages_per_sec": 81862.7,
      "mb_per_sec": 39.972
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0624,
      "messages_per_sec": 320744.6,
      "mb_per_sec": 156.614
    },
    "measured_pipelined_speedup_x": 0.26,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 3,
      "cpu_percent": {
        "min": 0.0,
        "avg": 50.03,
        "max": 83.6
      },
      "memory_mb": {
        "min": 51.3,
        "avg": 51.99,
        "max": 52.34
      },
      "gpu_percent": null
    },
    "completed_at": 1784435197.541267
  },
  {
    "target": "127.0.0.1:19978",
    "trusted_transport": true,
    "started_at": 1784435203.5305364,
    "fresh_handshake_ms": {
      "min": 0.859,
      "avg": 1.118,
      "p50": 0.987,
      "p95": 1.652,
      "max": 2.167
    },
    "resumed_handshake_ms": {
      "min": 0.44,
      "avg": 0.662,
      "p50": 0.479,
      "p95": 1.704,
      "max": 1.807
    },
    "measured_resumption_speedup_x": 1.69,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0539,
      "messages_per_sec": 9269.9,
      "mb_per_sec": 9.053,
      "round_trip_ms": {
        "min": 0.068,
        "avg": 0.107,
        "p50": 0.086,
        "p95": 0.231,
        "max": 0.48
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0382,
      "messages_per_sec": 13092.7,
      "mb_per_sec": 12.786,
      "round_trip_ms": {
        "min": 0.048,
        "avg": 0.075,
        "p50": 0.074,
        "p95": 0.117,
        "max": 0.677
      }
    },
    "measured_data_speedup_x": 0.7,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.2158,
      "messages_per_sec": 92671.8,
      "mb_per_sec": 45.25
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.068,
      "messages_per_sec": 294267.8,
      "mb_per_sec": 143.685
    },
    "measured_pipelined_speedup_x": 0.31,
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
        "min": 51.37,
        "avg": 52.19,
        "max": 52.64
      },
      "gpu_percent": null
    },
    "completed_at": 1784435203.9494913
  },
  {
    "target": "127.0.0.1:19979",
    "trusted_transport": true,
    "started_at": 1784435209.9394944,
    "fresh_handshake_ms": {
      "min": 0.945,
      "avg": 1.13,
      "p50": 1.051,
      "p95": 1.34,
      "max": 1.876
    },
    "resumed_handshake_ms": {
      "min": 0.476,
      "avg": 0.587,
      "p50": 0.542,
      "p95": 0.743,
      "max": 0.864
    },
    "measured_resumption_speedup_x": 1.93,
    "bastion_throughput": {
      "messages": 500,
      "message_size_bytes": 512,
      "total_seconds": 0.0566,
      "messages_per_sec": 8835.3,
      "mb_per_sec": 8.628,
      "round_trip_ms": {
        "min": 0.076,
        "avg": 0.112,
        "p50": 0.101,
        "p95": 0.188,
        "max": 0.305
      }
    },
    "json_baseline_throughput": {
      "messages": 500,
      "total_seconds": 0.0325,
      "messages_per_sec": 15369.5,
      "mb_per_sec": 15.009,
      "round_trip_ms": {
        "min": 0.047,
        "avg": 0.064,
        "p50": 0.053,
        "p95": 0.094,
        "max": 0.369
      }
    },
    "measured_data_speedup_x": 0.57,
    "bastion_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.2356,
      "messages_per_sec": 84878.0,
      "mb_per_sec": 41.444
    },
    "json_pipelined_throughput": {
      "messages": 20000,
      "total_seconds": 0.0658,
      "messages_per_sec": 304018.4,
      "mb_per_sec": 148.446
    },
    "measured_pipelined_speedup_x": 0.28,
    "resources": {
      "available": true,
      "gpu_available": false,
      "gpu_note": "No GPU/pynvml detected -- expected: this protocol is pure crypto + networking, it has no GPU workload",
      "samples": 3,
      "cpu_percent": {
        "min": 0.0,
        "avg": 22.2,
        "max": 49.9
      },
      "memory_mb": {
        "min": 51.4,
        "avg": 52.13,
        "max": 52.5
      },
      "gpu_percent": null
    },
    "completed_at": 1784435210.3765824
  }
]
```

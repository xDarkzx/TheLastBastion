# M2M Simulation Ecosystem — Design Blueprint

## Overview

A containerised mini-economy where **simulated agents** trade data,
request verification from The Registry Base, and transfer results to each other.
The goal is to stress-test the entire M2M stack as close to real life
as possible *before* going live.

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                Docker Network                   │
│                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ Agent A  │  │ Agent B  │  │ Agent C  │       │
│  │ (Energy) │  │ (Invoice)│  │ (Market) │       │
│  │          │  │          │  │          │       │
│  │ Collects │  │ Submits  │  │ Buys +   │       │
│  │ NZ power │  │ invoice  │  │ compares │       │
│  │ pricing  │  │ scans    │  │ data     │       │
│  └────┬─────┘  └─────┬────┘  └────┬─────┘       │
│       │              │            │             │
│       ▼              ▼            ▼             │
│  ┌──────────────────────────────────────┐       │
│  │        THe Last Bastion Gateway      │       │
│  │   (regional_core.py + M2M Router )   │       │
│  │                                      │       │
│  │  /m2m/register  /m2m/quote           │       │
│  │  /m2m/submit    /m2m/result          │       │
│  │  /refinery/submit                    │       │
│  │                                      │       │
│  │  Verification Stack (5 layers)       │       │
│  │  Proof Ledger (hash chain)           │       │
│  └──────────────────────────────────────┘       │
│       │               │            │            │
│       ▼               ▼            ▼            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ Postgres │  │  Redis   │  │  Logs    │       │
│  │          │  │ Conveyor │  │ (stdout) │       │
│  └──────────┘  └──────────┘  └──────────┘       │
└─────────────────────────────────────────────────┘
```

---

## Simulated Agent Types

### Agent A — "Energy Harvester"
- **Role**: DATA_PROVIDER
- Collects NZ electricity pricing (generated from realistic templates)
- Submits raw pricing data to `/refinery/submit`
- Periodically sends fresh data every 30 seconds
- Some submissions are **intentionally wrong** (bad arithmetic, stale dates)
- Tests: ingestion, schema validation, consistency checks

### Agent B — "Invoice Scanner"
- **Role**: DATA_PROVIDER
- Submits invoice-like payloads (company, quantity, price, total)
- Some invoices have arithmetic errors (100 × 50 ≠ 4500)
- Some have anomalous magnitudes ($2.80/kWh instead of $0.28)
- Tests: consistency analyzer, magnitude detection, verification pipeline

### Agent C — "Market Consumer"
- **Role**: DATA_CONSUMER
- Registers with The Registry Base and gets API key
- Discovers services via `/m2m/discover`
- Requests quotes and submits tasks
- Retrieves verified results
- Tests: full M2M flow (register → quote → submit → result)

### Agent D — "Adversarial Bot" (Optional)
- **Role**: DATA_PROVIDER
- Submits deliberately falsified data
- Replays old submissions
- Sends unsigned messages
- Tests: replay protection, auth rejection, adversarial challenges

---

## Simulation Scenarios

### Scenario 1: Happy Path
1. Agent A submits 5 valid energy pricing records
2. The Registry Base ingests, verifies → all get VERIFIED
3. Agent C discovers energy services, gets a quote, submits a task
4. The Registry Base returns verified data to Agent C
5. **Success**: All records verified, proof hashes generated

### Scenario 2: Bad Data Detection
1. Agent B submits 3 invoices: 2 valid, 1 with arithmetic error
2. The Registry Base catches the bad invoice → REJECTED
3. Agent B submits same invoice again → duplicate detected
4. **Success**: Bad data rejected, duplicate flagged

### Scenario 3: Cross-Agent Data Transfer
1. Agent A submits pricing data → VERIFIED
2. Agent C requests that specific data via task
3. The Registry Base returns data with proof hash
4. Agent C receives data + proof hash
5. Agent C validates proof hash via `/m2m/verify/{hash}`
6. **Success**: Data transferred with cryptographic proof

### Scenario 4: Security Stress Test
1. Agent D sends request with no auth → 401
2. Agent D replays old signed message → replay rejected
3. Agent D requests with expired API key → rejected
4. Agent D submits task without sufficient credits → 402
5. **Success**: All attacks blocked

---

## Docker Compose Structure

```yaml
# docker-compose.simulation.yml
version: '3.8'

services:
  registry-base:
    build: .
    ports: ["8000:8000"]
    environment:
      DATABASE_URL: postgresql://swarm:swarm@db:5432/registry_base
      REDIS_URL: redis://redis:6379
    depends_on: [db, redis]

  db:
    image: postgres:16
    environment:
      POSTGRES_USER: swarm
      POSTGRES_PASSWORD: swarm
      POSTGRES_DB: registry_base

  redis:
    image: redis:7-alpine

  agent-energy:
    build:
      context: .
      dockerfile: sim/Dockerfile.agent
    environment:
      AGENT_TYPE: energy_harvester
      REGISTRY_BASE_URL: http://registry-base:8000
      SUBMIT_INTERVAL: 30

  agent-invoice:
    build:
      context: .
      dockerfile: sim/Dockerfile.agent
    environment:
      AGENT_TYPE: invoice_scanner
      REGISTRY_BASE_URL: http://registry-base:8000
      ERROR_RATE: 0.3

  agent-consumer:
    build:
      context: .
      dockerfile: sim/Dockerfile.agent
    environment:
      AGENT_TYPE: market_consumer
      REGISTRY_BASE_URL: http://registry-base:8000
      POLL_INTERVAL: 15
```

---

## Implementation Steps

1. **Create `sim/` directory** with simulation agent scripts
2. **`sim/agent_runner.py`** — Generic agent that does:
   - Register with The Registry Base
   - Execute scenario based on AGENT_TYPE env var
   - Log all interactions + verdicts
3. **`sim/scenarios.py`** — The scenario logic (happy path, bad data, etc.)
4. **`sim/data_templates.py`** — Realistic data generators (NZ energy prices, invoices)
5. **`sim/Dockerfile.agent`** — Minimal Python container
6. **`docker-compose.simulation.yml`** — Spins up the entire ecosystem
7. **`sim/report.py`** — Collects results and generates pass/fail summary

---

## Success Criteria

| Metric | Target |
|---|---|
| Valid data → VERIFIED | 100% |
| Bad arithmetic → REJECTED | 100% |
| Duplicate submissions flagged | 100% |
| Unauthenticated requests → 401 | 100% |
| Replay attacks → blocked | 100% |
| Insufficient credits → 402 | 100% |
| Proof hashes verifiable | 100% |
| Cross-agent data transfer | Works end-to-end |

---

> [!NOTE]
> This simulation runs entirely locally via Docker Compose.
> No external APIs or blockchain needed. Build this AFTER
> the M2M API surface is tested and stable.

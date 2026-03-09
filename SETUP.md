# Setup Guide

Get The Last Bastion running in under 5 minutes. Everything runs in Docker — nothing gets installed on your system.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [1. Clone the Repository](#1-clone-the-repository)
- [2. Configure Environment](#2-configure-environment)
- [3. Launch](#3-launch)
- [4. Verify Everything Works](#4-verify-everything-works)
- [5. Run the Test Suite](#5-run-the-test-suite)
- [Stopping & Restarting](#stopping--restarting)
- [Optional: Local LLM (Offline Mode)](#optional-local-llm-offline-mode)
- [Optional: Blockchain Anchoring](#optional-blockchain-anchoring)
- [Advanced: Local Development (No Docker)](#advanced-local-development-no-docker)
- [Troubleshooting](#troubleshooting)
- [Project Structure](#project-structure)

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| **Docker** | 20+ | [docker.com/get-docker](https://docs.docker.com/get-docker/) |
| **Docker Compose** | v2+ | Included with Docker Desktop |
| **Git** | any | [git-scm.com](https://git-scm.com/) |

You also need a **free Groq API key** — this powers the LLM reasoning layer. No credit card required.

**Get your Groq key:** [console.groq.com](https://console.groq.com)

That's it. No Python, no Node.js, no package managers. Docker handles everything.

---

## 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/the-last-bastion.git
cd the-last-bastion
```

---

## 2. Configure Environment

```bash
cp .env.example .env
```

Open `.env` in any text editor and set your Groq API key:

```bash
GROQ_API_KEY=gsk_your_actual_groq_key_here
```

This is the **only required change**. Everything else has working defaults.

---

## 3. Launch

```bash
docker-compose up --build
```

First run takes a few minutes to build the images. After that, subsequent starts are fast.

Once you see the services reporting healthy, everything is live:

| Service | URL | What it does |
|---------|-----|-------------|
| **Dashboard** | [http://localhost:5173](http://localhost:5173) | React UI — monitoring, sandbox, protocol feed |
| **API** | [http://localhost:8000](http://localhost:8000) | FastAPI backend |
| **API Docs** | [http://localhost:8000/docs](http://localhost:8000/docs) | Interactive Swagger documentation |
| **PostgreSQL** | localhost:5432 | Database (auto-configured) |
| **Redis** | localhost:6379 | Queuing + pub/sub (auto-configured) |

### What starts

| Container | Role |
|-----------|------|
| `db` | PostgreSQL — persistent data vault |
| `redis` | Redis — real-time queuing, heartbeats, pub/sub |
| `api` | FastAPI backend — all endpoints, agent network, trust decay |
| `frontend` | React dashboard on port 5173 |

---

## 4. Verify Everything Works

```bash
# Check system health
curl http://localhost:8000/health

# Check M2M dashboard stats
curl http://localhost:8000/m2m/dashboard/stats

# Open the interactive API docs
# http://localhost:8000/docs
```

Open [http://localhost:5173](http://localhost:5173) and you should see The Last Bastion dashboard with:
- System overview and agent status
- Verification pipeline activity
- Protocol message feed
- Sandbox controls

---

## 5. Run the Test Suite

The test suite runs 19 sequential phases covering every system component. Run it inside the API container:

```bash
docker-compose exec api python scripts/run_backend_test.py
```

This tests: database, LLM, Redis, consensus, proof-of-task, verification stack, M2M protocol, ingestion pipeline, forensic analyzers, and more.

---

## Stopping & Restarting

```bash
# Stop everything (preserves data)
docker-compose down

# Stop and wipe all data (fresh start)
docker-compose down -v

# Restart
docker-compose up

# Rebuild after code changes
docker-compose up --build
```

Your database data persists in a Docker volume between restarts. Only `docker-compose down -v` wipes it.

---

## Optional: Local LLM (Offline Mode)

For fully offline operation, install [Ollama](https://ollama.com) on your host machine and pull a model:

```bash
ollama pull qwen2.5:7b-instruct
```

The system automatically routes between:
- **Local (Ollama)** — fast, private, used for routine decisions
- **Groq (cloud)** — powerful 70B model, used for strategic decisions

If both are configured, each request goes to the right tier. If only Groq is configured, everything uses Groq (the free tier is plenty).

---

## Optional: Blockchain Anchoring

The verification system works entirely without blockchain — proofs are recorded in a tamper-evident Merkle-chain locally. To also anchor proofs on Polygon:

1. Get testnet POL from the [Polygon Faucet](https://faucet.polygon.technology)
2. Uncomment and fill in the blockchain section in your `.env`:

```bash
BLOCKCHAIN_RPC_URL=https://rpc-amoy.polygon.technology
BLOCKCHAIN_PRIVATE_KEY=0xyour_private_key
PROOF_REGISTRY_ADDRESS=0x110affBAC98FCC6b86Da499550B1fC0aCA22e946
AGENT_REGISTRY_ADDRESS=0xc9177baBF86FF16794AABd1a2169f898986a0D7D
```

3. Restart: `docker-compose up --build`

### Deploying your own contract instances

```bash
cd contracts
cp .env.example .env
# Fill in your deployer key and Polygonscan API key
npm install
npx hardhat run scripts/deploy.js --network amoy
npx hardhat run scripts/deploy-agent-registry.js --network amoy
```

---

## Advanced: Local Development (No Docker)

If you want to run the backend and frontend directly on your machine (for development):

### Requirements

| Tool | Version |
|------|---------|
| Python | 3.10+ |
| Node.js | 18+ |
| Docker | For PostgreSQL + Redis only |

### Steps

```bash
# 1. Start just the database and Redis
docker-compose up db redis -d

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Start the backend
uvicorn regional_core:app --reload --port 8000

# 4. In a new terminal — start the frontend
cd frontend
npm install
npm run dev
```

This gives you hot-reload on both backend and frontend for faster development iteration.

---

## Troubleshooting

### Docker containers won't start

```bash
# Check what's happening
docker-compose logs

# Check a specific service
docker-compose logs api
docker-compose logs db

# Nuclear option — fresh start
docker-compose down -v
docker-compose up --build
```

### Port already in use

Another process is using port 8000, 5173, 5432, or 6379. Either stop that process or change the port mapping in `docker-compose.yml`.

```bash
# Find what's using a port (Linux/Mac)
lsof -i :8000

# Windows
netstat -ano | findstr :8000
```

### Database connection refused

```bash
# Check if db container is healthy
docker-compose ps

# Check db logs
docker-compose logs db
```

### LLM not responding

- **Groq**: Verify your API key at [console.groq.com](https://console.groq.com). Free tier has rate limits — the system retries automatically.
- **Ollama** (optional): Make sure it's running on your host (`ollama serve`) and accessible from Docker via `host.docker.internal`.

### Frontend shows "Network desync"

The frontend can't reach the API. Check that the `api` container is running:

```bash
docker-compose ps
docker-compose logs api
```

### Build fails

```bash
# Clear Docker build cache and rebuild
docker-compose build --no-cache
docker-compose up
```

---

## Project Structure

```
the-last-bastion/
├── regional_core.py          # FastAPI entrypoint
├── core/                     # Backend logic
│   ├── database.py           # All models + DB helpers
│   ├── m2m_router.py         # M2M + refinery API endpoints
│   ├── agent_verifier.py     # 10-check trust pipeline
│   ├── agent_simulator.py    # A2A agent network
│   ├── verification/         # 5-layer verification stack
│   │   ├── pipeline.py       # Verification entry point
│   │   ├── schema_gatekeeper.py
│   │   ├── consistency.py
│   │   ├── forensic_integrity.py
│   │   ├── logic_triangulation.py
│   │   ├── attestation.py
│   │   └── adversarial.py
│   └── attacks/              # Sandbox attack framework
├── agents/                   # Agent workers
│   └── a2a/                  # A2A protocol agents
├── sdk/                      # Python SDK
│   └── lastbastion/          # Client, gateway, MCP tools
├── contracts/                # Solidity smart contracts
│   └── src/                  # SwarmProofRegistry, SwarmAgentRegistry
├── frontend/                 # React dashboard
│   └── src/
├── documents/                # Architecture & research docs
├── tests/                    # Test modules
├── docker-compose.yml        # Full stack orchestration
├── .env.example              # Environment template
├── SETUP.md                  # This file
└── README.md                 # Project overview
```

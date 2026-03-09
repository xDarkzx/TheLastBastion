# NIST AI Agent Security — Research & Strategy

## Why This Matters to The Last Bastion

NIST is the U.S. government standards body. They're actively asking industry for input on how to secure AI agents. Our system already addresses 7 of their 10 identified gaps. Getting on their radar means credibility, legitimacy, and being part of the standard — not competing against it.

---

## Key NIST Documents & Deadlines

| Document | What It Is | Deadline | Link |
|---|---|---|---|
| RFI NIST-2025-0035 | "Security Considerations for AI Agents" — asking industry what threats are unique to agents | March 9, 2026 (passed) | [Federal Register](https://www.federalregister.gov/documents/2026/01/08/2026-00206/request-for-information-regarding-security-considerations-for-artificial-intelligence-agents) |
| NCCoE Concept Paper | "Accelerating the Adoption of Software and AI Agent Identity and Authorization" | **April 2, 2026** | [CSRC](https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd) |
| AI Agent Standards Initiative | Three-pillar program: standards, open-source protocols, security research | Ongoing — listening sessions April 2026 | [NIST](https://www.nist.gov/caisi/ai-agent-standards-initiative) |

---

## NIST's Three Pillars (AI Agent Standards Initiative)

Launched February 17, 2026 by CAISI (Center for AI Standards and Innovation).

1. **Industry-led Standards** — NIST hosts technical convenings, produces voluntary guidelines
2. **Community-led Open-Source Protocols** — NSF investment in interoperable agent protocols
3. **Research in Security and Identity** — fundamental research into agent authentication infrastructure

### Four Technical Focus Areas

| Area | What NIST Wants |
|---|---|
| Security & Risk Management | Safeguards against misuse, compromise, privilege escalation, unintended autonomous actions |
| Identity & Authorization | Authenticating agents, defining permissions, scoping and monitoring |
| Interoperability | Protocols for reliable multi-agent, multi-vendor, multi-platform interaction |
| Testing & Assurance | Evaluating performance, resilience, security posture, compliance |

---

## NIST's 10 Identified Gaps

These are the specific problems NIST says nobody has solved yet:

| # | Gap | Detail | Our System |
|---|---|---|---|
| 1 | No agent identity standard | Agents lack unique, verifiable identities distinguishable from humans | **Ed25519 challenge-response, trust passports, anti-Sybil detection** |
| 2 | Trusted/untrusted data mixing | LLM architectures combine developer instructions with untrusted data in same context | **Verification pipeline separates intelligence from authorization** |
| 3 | No authorization framework for agents | OAuth/OIDC designed for humans, not machine-speed agent actions | **Credit-based access, role scoping, M2M auth pipeline** |
| 4 | Prompt injection unsolved | NIST's own tests: 11% baseline → 81% with novel attacks | **SchemaGatekeeper injection detection, adversarial challenge** |
| 5 | No interoperability standards | Agents from different vendors can't securely interact | **Built on A2A protocol (Linux Foundation governed)** |
| 6 | No audit/non-repudiation | Can't reliably trace which agent took which action | **Merkle-chain proof ledger, blockchain stamps, SHA-256 proof-of-task** |
| 7 | Human oversight doesn't scale | Agents operate autonomously; approval gates create bottlenecks | **Quarantine review, calibration dashboard** |
| 8 | No rollback mechanisms | Agents that take destructive actions need undo capability | **Not yet built** |
| 9 | Cross-platform trust | No standard way for agents to establish trust across organizational boundaries | **Vendor-neutral 10-check verification, blockchain-stamped verdicts** |
| 10 | No security evaluation methods | No established methodology to test/certify agent security posture | **10-check trust pipeline with weighted scoring** |

**Score: 7/10 gaps addressed with working code. 2 partial. 1 not yet built.**

---

## NIST RFI Questions (NIST-2025-0035)

### Topic 1: Security Threats (Questions 1a, 1c, 1d)
- What security threats are UNIQUE to AI agents vs traditional software?
- How do threats vary by model capability, scaffold software, tool use?
- How do threats change based on deployment method (internal vs external)?

### Topic 2: Security Practices (Questions 2a, 2e)
- What practices work at model, system, and human oversight levels?
- What defenses actually work?

### Topic 3: Assessment (Questions 3a, 3b)
- How do you quantify agent security?
- What methods work for risk anticipation during development?

### Topic 4: Deployment Environments (Questions 4a, 4b, 4d)
- How to constrain agent access within deployment environments?
- How to monitor agents?
- How to implement rollback/undo?

### Topic 5: Standards & Policy
- What standards, disclosures, research, and policy coordination are needed?

---

## NCCoE Concept Paper — Agent Identity & Authorization

This is the one to respond to (deadline April 2, 2026).

### Their Four Focus Areas

| Area | What They Want | What We Have |
|---|---|---|
| **Identification** | Distinguishing AI agents from human users; managing metadata to control agent actions | Agent Cards (A2A protocol), unique agent_id, public key identity |
| **Authorization** | OAuth 2.0/2.1 extensions; policy-based access control for agent rights | M2M auth pipeline (6-step), credit-based access, role-based scoping |
| **Access Delegation** | Linking user identities to agent operations for accountability | Agent registration with owner identity, trust passport chain |
| **Logging & Transparency** | Linking specific agent actions to their non-human entity | Protocol bus logging, Merkle-chain proof ledger, blockchain stamps |

### Standards They're Looking At

- Model Context Protocol (MCP)
- OAuth 2.0/2.1 and extensions
- OpenID Connect
- SPIFFE/SPIRE (workload identity)
- SCIM (cross-domain identity management)
- NIST SP 800-207 (Zero Trust Architecture)
- NIST SP 800-63-4 (Digital Identity Guidelines)

### Their Planned Output

A **practice guide** with example implementation details, built in NCCoE laboratories. They are building reference implementations — we could be one.

---

## The Core Principle: Separation of Intelligence from Authorization

Not a formal NIST term, but the principle running through everything they publish:

> The AI agent's reasoning layer (the LLM) must be architecturally separated from its authorization layer (what it's allowed to do). The LLM should not be the arbiter of its own permissions.

**Evidence from NIST's own research:**
- RFI identifies root cause: "the architecture of many LLM agents requires combining trusted instructions with untrusted data in the same context"
- Agent hijacking tests: agents "decided independently that authentication in one direction was sufficient" — bypassing designed security
- Conclusion: security orchestration must be in deterministic components, not LLM-driven

**How our sandbox demonstrates this:**
- Verification verdicts are deterministic (cryptographic checks, DB queries, behavioral analysis)
- LLM intelligence is used for reasoning, but verdicts come from the pipeline
- Trust scores are computed by weighted algorithm, not by asking an LLM "is this agent trustworthy?"
- Blockchain stamps are immutable — even we can't alter a verdict after the fact

---

## Agent Hijacking — NIST's Own Test Results

Source: [NIST Technical Blog](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations)

CAISI tested three attack categories using the AgentDojo framework:

| Attack | What Happens |
|---|---|
| Remote Code Execution | Agent tricked into downloading and executing untrusted programs |
| Database Exfiltration | Malicious instructions cause agent to mass-export sensitive user data |
| Automated Phishing | Hijacked agent sends customized deceptive emails with attacker links |

**Key finding:** Attack success jumped from **11% baseline to 81%** with novel red team attacks. With 25 attempts, average success went from 57% to 80%. Probabilistic LLM behavior gives persistent attackers an advantage.

---

## W3C DIDs and Agent Identity

NIST doesn't directly reference W3C DIDs, but the NCCoE references SPIFFE/SPIRE (similar properties for machine identities).

The Decentralized Identity Foundation is actively building:
- **KYAPay Protocol** — agents present JWT combining verified identity + payment authorization + scope-limited permissions
- **MCP-I Extension** — built on DIDs and Verifiable Credentials, real-time capability verification

Research paper (ArXiv: 2511.02841) tested DIDs for agent identity:
- Ed25519 signatures (same as our system)
- Zero-trust mutual presentation
- Critical finding: LLMs orchestrating security had 20-95% variable success → must use deterministic components

---

## Related NIST Documents

| Document | Relevance |
|---|---|
| NIST AI 100-2 E2025 | Adversarial ML taxonomy — covers indirect prompt injection, agent hijacking |
| SP 800-207 | Zero Trust Architecture — applied to agent deployment |
| SP 800-63-4 | Digital Identity Guidelines — applied to agent identity |
| NISTIR 8587 | Protecting Tokens/Assertions from forgery, theft, misuse |
| AI RMF | AI Risk Management Framework — parent framework |

---

## Payload Integrity Research

### The Gap
Nobody has published a deployed system for verifying structured data payloads exchanged between agents in real-time. Most integrity work focuses on training data and model-level security.

### Key Sources

**Multi-agent payload attacks:**
- [Multi-Agent Systems Execute Arbitrary Malicious Code](https://arxiv.org/abs/2503.12188) — arXiv March 2025. Attack success 58-90% with GPT-4o. Payloads compromise multi-agent systems even when individual agents refuse harmful actions.
- [Open Challenges in Multi-Agent Security](https://arxiv.org/abs/2505.02077) — arXiv May 2025. Agents can establish secret collusion channels through steganographic communication. Proposes tamper-evident logs and immutable identifiers.
- [From Prompt Injections to Protocol Exploits](https://arxiv.org/abs/2506.23260) — ScienceDirect Dec 2025. First unified end-to-end threat model for LLM-agent ecosystems. 30+ attack techniques cataloged.

**Indirect prompt injection via payloads (documented in the wild):**
- [Palo Alto Unit 42: Web-Based Indirect Prompt Injection](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/) — March 2026. 12 real-world cases, 22 distinct techniques. Includes zero font-size text, CSS suppression, Base64 encoding, invisible Unicode, homoglyphs.
- [OWASP LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) — attacks embedded in documents through invisible text, metadata fields, steganographic instructions in images.

**Government guidance on AI data integrity:**
- [NSA/CISA/FBI: AI Data Security](https://media.defense.gov/2025/May/22/2003720601/-1/-1/0/CSI_AI_DATA_SECURITY.PDF) — May 2025. Recommends: digital signatures, cryptographic hashes, data lineage tracking, immutable logging.
- [NSA/CISA: Strengthening Multimedia Integrity](https://media.defense.gov/2025/Jan/29/2003634788/-1/-1/0/CSI-CONTENT-CREDENTIALS.PDF) — Jan 2025. US government endorses C2PA Content Credentials.

**Content provenance standards:**
- [C2PA AI/ML Guidance v2.2](https://spec.c2pa.org/specifications/specifications/2.2/ai-ml/ai_ml.html) — supports AI output provenance, `c2pa.trainedAlgorithmicData` designation. Not yet applied to agent-to-agent structured data.
- [C2PA response to NIST RFI](https://downloads.regulations.gov/NIST-2024-0001-0030/attachment_1.pdf) — proposed integrating provenance standard into AI governance frameworks.

**Cryptographic verification frameworks:**
- [Framework for Cryptographic Verifiability of End-to-End AI Pipelines](https://arxiv.org/abs/2503.22573) — ACM IWSPA 2025. Closest to tool output verification. Proposes cryptographic proofs accompanying AI outputs.
- [DAO-Agent: Zero Knowledge-Verified Incentives](https://arxiv.org/pdf/2512.20973) — arXiv Dec 2025. Off-chain execution with on-chain cryptographic verification.

**OWASP Top 10 for LLMs (2025)** — [genai.owasp.org/llm-top-10](https://genai.owasp.org/llm-top-10/)
- LLM01: Prompt Injection (including indirect via external data)
- LLM03: Supply Chain Vulnerabilities
- LLM04: Data and Model Poisoning
- LLM05: Improper Output Handling
- LLM08: Vector and Embedding Weaknesses

---

## Sources

- [NIST RFI Federal Register](https://www.federalregister.gov/documents/2026/01/08/2026-00206/request-for-information-regarding-security-considerations-for-artificial-intelligence-agents)
- [Regulations.gov Docket](https://www.regulations.gov/docket/NIST-2025-0035)
- [NIST CAISI RFI Announcement](https://www.nist.gov/news-events/news/2026/01/caisi-issues-request-information-about-securing-ai-agent-systems)
- [NIST AI Agent Standards Initiative](https://www.nist.gov/caisi/ai-agent-standards-initiative)
- [NIST Initiative Announcement](https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure)
- [NCCoE Concept Paper](https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd)
- [NCCoE Project Page](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization)
- [NIST AI 100-2 E2025](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
- [NIST Agent Hijacking Blog](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations)
- [ArXiv: AI Agents with DIDs and VCs](https://arxiv.org/abs/2511.02841)
- [DIF: Building the Agentic Economy](https://blog.identity.foundation/building-the-agentic-economy/)
- [W3C DIDs v1.1](https://www.w3.org/TR/did-1.1/)

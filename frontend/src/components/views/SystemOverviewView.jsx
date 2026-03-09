import React, { useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
    Shield, ShieldCheck, Fingerprint, Eye, Lock,
    Bot, Network, Activity, CheckCircle, XCircle,
    ArrowRight, AlertTriangle, Layers, Globe,
    Server, Database, LinkIcon, ExternalLink, FileWarning,
    UserCheck, Ban
} from 'lucide-react';

/* ─── Live Stat Pill ─── */
const LiveStat = ({ label, value, icon: Icon }) => (
    <div className="flex items-center gap-3 px-4 py-3 bg-white border border-slate-200 rounded-sm">
        <Icon size={15} className="text-slate-400 shrink-0" />
        <span className="text-[10px] font-bold uppercase tracking-widest text-slate-400">{label}</span>
        <span className="text-sm font-black font-mono text-slate-900 ml-auto">{value}</span>
    </div>
);

/* ─── Pipeline Step ─── */
const PipelineStep = ({ number, total, title, description, detail, icon: Icon, color = 'slate' }) => {
    const colorMap = {
        emerald: 'bg-slate-50 border-slate-300 text-slate-700',
        amber: 'bg-slate-50 border-slate-300 text-slate-700',
        rose: 'bg-slate-50 border-slate-300 text-slate-700',
        indigo: 'bg-slate-50 border-slate-300 text-slate-700',
        slate: 'bg-slate-50 border-slate-200 text-slate-700',
        cyan: 'bg-slate-50 border-slate-300 text-slate-700',
    };
    return (
        <div className="flex gap-4">
            <div className="flex flex-col items-center">
                <div className={`w-8 h-8 rounded-full border flex items-center justify-center text-xs font-black ${colorMap[color]}`}>
                    {number}
                </div>
                {number < total && <div className="w-px flex-1 bg-slate-200 mt-1" />}
            </div>
            <div className="pb-6">
                <div className="flex items-center gap-2 mb-1">
                    <Icon size={14} className="text-slate-500" />
                    <h4 className="text-xs font-bold uppercase tracking-wide text-slate-800">{title}</h4>
                </div>
                <p className="text-[11px] text-slate-500 leading-relaxed max-w-md">{description}</p>
                {detail && (
                    <p className="text-[10px] font-mono text-slate-400 mt-1.5">{detail}</p>
                )}
            </div>
        </div>
    );
};

/* ─── Verdict Badge ─── */
const VerdictBadge = ({ verdict, count, description }) => {
    const styles = {
        gold: 'bg-slate-200 border-slate-400 text-slate-900',
        verified: 'bg-slate-100 border-slate-300 text-slate-700',
        quarantine: 'bg-slate-100 border-slate-300 text-slate-600',
        rejected: 'bg-slate-50 border-slate-200 text-slate-400',
    };
    const labels = {
        gold: 'Gold Standard',
        verified: 'Verified',
        quarantine: 'Quarantine',
        rejected: 'Rejected',
    };
    return (
        <div className={`px-3 py-2 rounded-sm border ${styles[verdict]}`}>
            <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold uppercase tracking-widest">{labels[verdict]}</span>
                <span className="text-sm font-black font-mono">{count}</span>
            </div>
            {description && <p className="text-[9px] opacity-70 mt-0.5">{description}</p>}
        </div>
    );
};

/* ─── Industry Concern Card ─── */
const ConcernCard = ({ concern, finding, source, sourceLabel, approach }) => (
    <div className="bg-white border border-slate-200 rounded-sm p-5">
        <div className="flex items-start gap-3 mb-3">
            <FileWarning size={14} className="text-slate-500 mt-0.5 shrink-0" />
            <div>
                <h4 className="text-xs font-bold text-slate-800 leading-snug">{concern}</h4>
                <a href={source} target="_blank" rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-[10px] text-slate-400 hover:text-slate-700 transition-colors mt-1 font-mono">
                    {sourceLabel} <ExternalLink size={8} />
                </a>
            </div>
        </div>
        <p className="text-[11px] text-slate-500 leading-relaxed mb-3 border-l-2 border-slate-200 pl-3">
            {finding}
        </p>
        <div className="flex items-start gap-2">
            <ShieldCheck size={12} className="text-slate-600 mt-0.5 shrink-0" />
            <p className="text-[11px] text-slate-600 leading-relaxed">
                {approach}
            </p>
        </div>
    </div>
);

/* ─── Health Dot ─── */
const HealthDot = ({ label, status }) => {
    const isUp = status === 'connected' || status === 'healthy' || status === true;
    return (
        <div className="flex items-center gap-2">
            <div className={`w-1.5 h-1.5 rounded-full ${isUp ? 'bg-slate-600' : 'bg-slate-300'}`} />
            <span className="text-[10px] font-mono text-slate-500 uppercase">{label}</span>
        </div>
    );
};


const SystemOverviewView = ({ stats, health, refineryStats, activity = [] }) => {
    const verdicts = refineryStats?.verdicts || {};
    const totalVerdicts = Object.values(verdicts).reduce((a, b) => a + b, 0);

    return (
        <div className="p-8 max-w-6xl mx-auto space-y-8 animate-fade-in">

            {/* ═══ Mission Header ═══ */}
            <header className="border-b border-slate-200 pb-8 mb-4">
                <div className="flex items-center gap-3 mb-3">
                    <img src="/TheRegistryBase.png" alt="The Last Bastion" className="w-12 h-12 object-contain" />
                    <div>
                        <h1 className="text-2xl font-black tracking-tight text-slate-900">The Last Bastion</h1>
                        <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Independent Agent Identity Verification &amp; Payload Integrity Platform</p>
                    </div>
                    <div className="ml-auto flex items-center gap-2">
                        <div className={`w-2 h-2 rounded-full ${health?.database === 'connected' ? 'bg-slate-600 animate-pulse' : 'bg-slate-300'}`} />
                        <span className={`text-[10px] font-bold uppercase tracking-widest font-mono ${health?.database === 'connected' ? 'text-slate-700' : 'text-slate-400'}`}>
                            {health?.database === 'connected' ? 'Systems Online' : 'Offline'}
                        </span>
                    </div>
                </div>
                <p className="text-sm text-slate-600 leading-relaxed max-w-3xl mt-4">
                    There is currently no industry standard for verifying the identity of an AI agent, or for proving
                    that the data an agent carries has not been fabricated, tampered with, or injected with adversarial content.
                    The Last Bastion is a vendor-neutral verification platform that subjects agents to cryptographic identity challenges,
                    runs their payloads through a multi-layer inspection pipeline, and produces tamper-evident proof records
                    that any third party can independently verify — without trusting this platform.
                </p>
            </header>

            {/* ═══ Three Pillars — Specific ═══ */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-white border border-slate-200 rounded-sm p-5">
                    <div className="flex items-center gap-2 mb-3">
                        <Fingerprint size={16} className="text-slate-600" />
                        <h3 className="text-xs font-bold uppercase tracking-wide text-slate-800">Cryptographic Identity Verification</h3>
                    </div>
                    <p className="text-[11px] text-slate-500 leading-relaxed mb-3">
                        10-check pipeline: Ed25519 challenge-response (agent must sign a nonce with its private key),
                        X25519 ephemeral key exchange with forward secrecy, runtime environment fingerprinting (OS + hostname hash),
                        source IP cross-check against passport claim, anti-Sybil analysis, and behavioral consistency scoring.
                    </p>
                    <p className="text-[11px] text-slate-500 leading-relaxed mb-3">
                        Cloned agents fail the runtime fingerprint check. Spoofed agents fail the challenge-response.
                        Stolen credentials fail the IP cross-check. Each check produces a weighted score; the composite
                        determines the trust verdict.
                    </p>
                    <div className="text-[10px] font-mono text-slate-400 space-y-0.5">
                        <div className="flex items-center gap-1.5"><Lock size={9} /> Ed25519 (identity) + X25519 (key exchange)</div>
                        <div className="flex items-center gap-1.5"><Lock size={9} /> XSalsa20-Poly1305 (per-frame encryption)</div>
                        <div className="flex items-center gap-1.5"><Lock size={9} /> SHA-256 passport integrity hash</div>
                    </div>
                </div>

                <div className="bg-white border border-slate-200 rounded-sm p-5">
                    <div className="flex items-center gap-2 mb-3">
                        <Eye size={16} className="text-slate-600" />
                        <h3 className="text-xs font-bold uppercase tracking-wide text-slate-800">5-Layer Payload Verification</h3>
                    </div>
                    <p className="text-[11px] text-slate-500 leading-relaxed mb-3">
                        Every data payload submitted by an agent passes through five independent verification layers, in order:
                    </p>
                    <div className="text-[11px] text-slate-500 space-y-1.5 mb-3">
                        <p><span className="font-bold text-slate-700">Gate 1:</span> Schema validation — type checking, required fields, value ranges, injection pattern detection (script tags, SQL, Python eval)</p>
                        <p><span className="font-bold text-slate-700">Gate 2:</span> Consistency analysis — arithmetic cross-checks (quantity x price = total, within 1% tolerance), statistical anomaly detection</p>
                        <p><span className="font-bold text-slate-700">Pillar 1:</span> Forensic integrity — 7 analyzers: Error Level Analysis, noise pattern, copy-move detection, lighting consistency, EXIF metadata, file structure, PDF forensics</p>
                        <p><span className="font-bold text-slate-700">Pillar 2:</span> Logic triangulation — cross-reference against known sources, temporal plausibility, domain-specific logic rules</p>
                        <p><span className="font-bold text-slate-700">Pillar 3:</span> Adversarial challenge — contradiction hunting, boundary testing, prompt injection probing, confidence calibration</p>
                    </div>
                    <div className="text-[10px] font-mono text-slate-400">
                        Gates 1-2 have veto authority (force score to 0.10)
                    </div>
                </div>

                <div className="bg-white border border-slate-200 rounded-sm p-5">
                    <div className="flex items-center gap-2 mb-3">
                        <Globe size={16} className="text-slate-600" />
                        <h3 className="text-xs font-bold uppercase tracking-wide text-slate-800">Tamper-Evident Proof Chain</h3>
                    </div>
                    <p className="text-[11px] text-slate-500 leading-relaxed mb-3">
                        Every verification verdict produces a ProofRecord containing: SHA-256 of the original payload,
                        SHA-256 of the serialized evidence chain, per-pillar scores, adversarial penalty, and the hash of the previous record.
                        The combined block hash is SHA-256(record_id | timestamp | payload_hash | verdict | score | evidence_hash | provenance_hash | previous_hash).
                    </p>
                    <p className="text-[11px] text-slate-500 leading-relaxed mb-3">
                        Modifying any single field in any record invalidates all subsequent hashes in the chain.
                        Chain integrity is independently verifiable by recomputing every hash from the genesis record forward.
                    </p>
                    <div className="text-[10px] font-mono text-slate-400 space-y-0.5">
                        <div>Merkle chain — append-only JSONL ledger</div>
                        <div>Blockchain anchor — Polygon smart contract (optional, human-approved)</div>
                    </div>
                </div>
            </div>

            {/* ═══ Human-in-the-Loop Blockchain Anchoring ═══ */}
            <div className="bg-white border-2 border-slate-300 rounded-sm p-6">
                <div className="flex items-start gap-4">
                    <div className="w-10 h-10 rounded-sm bg-slate-100 border border-slate-300 flex items-center justify-center shrink-0">
                        <UserCheck size={20} className="text-slate-700" />
                    </div>
                    <div className="flex-1">
                        <h2 className="text-xs font-bold uppercase tracking-wide text-slate-800 mb-2">Human-in-the-Loop Blockchain Anchoring</h2>
                        <p className="text-[11px] text-slate-600 leading-relaxed mb-3">
                            No verification verdict is written to the blockchain automatically.
                            The automated pipeline produces a verdict and seals it into the local Merkle chain — but on-chain
                            anchoring requires explicit human operator approval. Every proof record enters a review queue where an
                            operator inspects the verdict, the composite score, the per-pillar breakdown, and the evidence chain before
                            authorizing the irreversible on-chain transaction.
                        </p>
                        <p className="text-[11px] text-slate-600 leading-relaxed mb-4">
                            This is a deliberate architectural decision. AI agent verification is an emerging discipline with no established
                            accuracy benchmarks. Automated anchoring without human oversight would produce immutable on-chain records of
                            potentially incorrect verdicts — creating a false sense of trust that undermines the purpose of the system.
                            The human review gate remains in place until the pipeline demonstrates sustained accuracy across a statistically
                            significant volume of real-world verifications.
                        </p>
                        <div className="flex flex-wrap gap-3 text-[10px] font-mono">
                            <span className="px-2 py-1 bg-slate-50 border border-slate-200 rounded text-slate-500">Pipeline verdict (automated)</span>
                            <ArrowRight size={12} className="text-slate-300 self-center" />
                            <span className="px-2 py-1 bg-slate-100 border border-slate-300 rounded text-slate-600">Review queue (pending)</span>
                            <ArrowRight size={12} className="text-slate-300 self-center" />
                            <span className="px-2 py-1 bg-slate-200 border border-slate-400 rounded text-slate-700">Human approves</span>
                            <ArrowRight size={12} className="text-slate-300 self-center" />
                            <span className="px-2 py-1 bg-slate-800 border border-slate-900 rounded text-white">On-chain anchor (immutable)</span>
                        </div>
                    </div>
                </div>
            </div>

            {/* ═══ Documented Gaps — Why This Matters ═══ */}
            <div>
                <div className="mb-4">
                    <h2 className="text-xs font-bold uppercase tracking-wide text-slate-800 mb-1">Documented Gaps in AI Agent Security</h2>
                    <p className="text-[11px] text-slate-500 leading-relaxed max-w-3xl">
                        The following are specific, documented findings from government agencies, standards bodies, and security researchers.
                        Each links to the primary source. We are not claiming to have fully solved these problems — we are building
                        working implementations that address them directly, and testing them in the open.
                    </p>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <ConcernCard
                        concern="No Standard for AI Agent Identity"
                        finding={`NIST's AI Agent Standards Initiative identifies four technical focus areas. The first: "Identity & Authorization — authenticating agents, defining permissions, scoping and monitoring." Current frameworks (OAuth 2.0, OIDC) were designed for human users making occasional requests, not autonomous agents executing thousands of actions per minute.`}
                        source="https://www.nist.gov/caisi/ai-agent-standards-initiative"
                        sourceLabel="NIST CAISI, Feb 2026"
                        approach="Implementation: Ed25519 challenge-response where the agent must sign a random nonce with its private key. Runtime fingerprint (SHA-256 of OS + hostname + machine) compared against passport claim. Source IP cross-checked against declared geo_ip. 10 checks, weighted composite score."
                    />
                    <ConcernCard
                        concern="Agent Hijacking: 11% Baseline to 81% With Novel Attacks"
                        finding={`NIST CAISI tested agent hijacking using the AgentDojo framework across three attack categories: remote code execution, database exfiltration, and automated phishing. Baseline attack success: 11%. With novel red team techniques: 81%. With 25 persistent attempts: 80% average. Root cause: "the architecture of many LLM agents requires combining trusted instructions with untrusted data in the same context."`}
                        source="https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations"
                        sourceLabel="NIST Technical Blog, Jan 2025"
                        approach="Implementation: Security decisions (trust verdicts, blockchain anchoring, access control) are made by deterministic pipeline components — cryptographic checks, database queries, weighted algorithms. The LLM is used for reasoning and analysis, but never arbitrates its own permissions or security state."
                    />
                    <ConcernCard
                        concern="No Tamper-Evident Audit Trail for Agent Actions"
                        finding={`The NCCoE concept paper on agent identity identifies "Logging & Transparency" as a critical gap: there is no standard mechanism to create non-repudiable records linking specific actions to specific non-human entities, or to prove that audit logs have not been modified after the fact.`}
                        source="https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd"
                        sourceLabel="NIST NCCoE, Feb 2026"
                        approach="Implementation: Append-only Merkle chain where each record's block_hash = SHA-256(record_id | timestamp | payload_hash | verdict | score | evidence_hash | provenance_hash | previous_hash). Modifying any record breaks all subsequent hashes. verify_chain_integrity() walks the full chain and recomputes every hash."
                    />
                    <ConcernCard
                        concern="Indirect Prompt Injection via Agent Payloads"
                        finding={`12 real-world cases documented with 22 distinct attack techniques embedded in documents that agents process: zero font-size text, CSS display:none suppression, Base64-encoded instructions, invisible Unicode characters (U+200B, U+FEFF), homoglyph substitution, and steganographic content in image metadata.`}
                        source="https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/"
                        sourceLabel="Palo Alto Unit 42, Mar 2026"
                        approach={`Implementation: SchemaGatekeeper (Gate 1) scans for injection patterns: <script>, SQL keywords (DROP, UNION SELECT), Python eval/exec, template literals, Unicode zero-width characters. Gate 1 has veto authority — a detected injection forces the composite score to 0.10 regardless of other pillar results.`}
                    />
                    <ConcernCard
                        concern="Multi-Agent Payload Attacks (58-90% Success)"
                        finding={`Research demonstrates that payloads can compromise multi-agent systems even when individual agents refuse harmful actions. Coordinated attacks across agent workflows achieved 58-90% success rates with GPT-4o. Agents can establish covert communication channels through steganographic content in shared data.`}
                        source="https://arxiv.org/abs/2503.12188"
                        sourceLabel="arXiv:2503.12188, Mar 2025"
                        approach="Implementation: Payloads are verified through 5 independent layers with separate scoring. No single layer trusts another's output. Forensic integrity (7 analyzers), logic triangulation, and adversarial challenge each contribute independently to the composite score. Pillar weights: forensic 0.30-0.40, triangulation 0.45-0.60, attestation 0.25."
                    />
                    <ConcernCard
                        concern="Government Guidance: Digital Signatures and Immutable Logging"
                        finding={`Joint advisory recommends four foundational controls for AI systems handling sensitive data: digital signatures on all data exchanges, cryptographic hash chains for data lineage, immutable logging that cannot be retroactively modified, and provenance tracking from origin to consumption.`}
                        source="https://media.defense.gov/2025/May/22/2003720601/-1/-1/0/CSI_AI_DATA_SECURITY.PDF"
                        sourceLabel="NSA / CISA / FBI, May 2025"
                        approach="Implementation: Ed25519 signatures on every Bastion Protocol wire frame. SHA-256 proof hashes for each verdict. Merkle chain with previous_hash linking. Optional blockchain anchor to Polygon smart contract (human-approved) for permanent, independently verifiable public proof."
                    />
                </div>
            </div>

            {/* ═══ Live Network Stats ═══ */}
            <div>
                <h2 className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-3">Live Network Telemetry</h2>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <LiveStat label="Connected Agents" value={stats?.active_agents || 0} icon={Bot} />
                    <LiveStat label="Verifications Run" value={stats?.total_extractions || 0} icon={ShieldCheck} />
                    <LiveStat label="Proof Records" value={stats?.total_proofs_generated || 0} icon={Database} />
                    <LiveStat label="Anchored On-Chain" value={stats?.proofs_anchored_on_chain || 0} icon={Activity} />
                </div>
            </div>

            {/* ═══ How It Works + Verdicts ═══ */}
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">

                {/* Pipeline — left 3 cols */}
                <div className="lg:col-span-3 bg-white border border-slate-200 rounded-sm p-6">
                    <h2 className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-5">Verification Pipeline — Step by Step</h2>
                    <PipelineStep
                        number={1} total={7}
                        title="Agent Connects via Bastion Protocol"
                        description="The agent opens a TCP connection and sends a HELLO frame containing its signed passport envelope and an ephemeral X25519 public key. The Bastion Protocol is a binary wire format with 116-byte fixed overhead — every frame is signed with Ed25519 and carries a full SHA-256 passport hash."
                        detail="Wire: [Ver:1B][Type:1B][Flags:2B][PassportHash:32B][Seq:4B][Time:8B][Len:4B][Payload][Sig:64B]"
                        icon={Bot}
                        color="slate"
                    />
                    <PipelineStep
                        number={2} total={7}
                        title="Cryptographic Identity Challenge"
                        description="A random nonce is sent to the agent. The agent must sign it with the Ed25519 private key matching the public key in its passport — proving it holds the real key, not a copy. The runtime fingerprint (OS + hostname hash) is compared against the passport claim to detect cloned agents. Source IP is cross-checked to catch spoofed locations."
                        detail="Fail: wrong signature (stolen key), fingerprint mismatch (clone), IP mismatch (spoof)"
                        icon={Fingerprint}
                        color="indigo"
                    />
                    <PipelineStep
                        number={3} total={7}
                        title="Payload Inspection (5 Layers)"
                        description="Gate 1: Schema validation — type checks, required fields, injection detection (SQL, XSS, eval). Gate 2: Consistency — arithmetic cross-checks (does quantity × price = total?). Pillar 1: Forensic integrity — 7 analyzers on images/documents (ELA, noise, copy-move, metadata). Pillar 2: Logic triangulation — cross-reference against known sources. Pillar 3: Adversarial challenge — contradiction hunting, boundary probing."
                        detail="Gates can veto (force score to 0.10) | Pillars produce weighted composite score"
                        icon={Eye}
                        color="amber"
                    />
                    <PipelineStep
                        number={4} total={7}
                        title="Composite Score + Verdict"
                        description="Pillar scores are combined with configurable weights — then the adversarial penalty is applied. The final composite score determines the verdict: Rejected (below 0.40), Quarantine (0.40–0.70, held for human review), Verified (0.70–0.90), or Gold (0.90+ with forensic score at least 0.80)."
                        icon={ShieldCheck}
                        color="emerald"
                    />
                    <PipelineStep
                        number={5} total={7}
                        title="Proof Record Sealed in Merkle Chain"
                        description="Every verdict produces a tamper-evident proof record: SHA-256 of the payload, the evidence chain, per-pillar scores, and — critically — the hash of the previous record. This creates a Merkle chain where modifying any single record invalidates everything after it."
                        detail="Independently verifiable: recompute every hash from genesis to detect any tampering"
                        icon={Database}
                        color="slate"
                    />
                    <PipelineStep
                        number={6} total={7}
                        title="Human Review Queue"
                        description="Nothing goes on-chain automatically. A human operator reviews the verdict, score breakdown, evidence chain, and risk flags before deciding whether to approve blockchain anchoring. This is deliberate — automated stamping of potentially wrong verdicts would create false trust."
                        detail="Queue: pending verdicts await human approval before irreversible on-chain write"
                        icon={UserCheck}
                        color="cyan"
                    />
                    <PipelineStep
                        number={7} total={7}
                        title="Blockchain Anchor (Human-Approved)"
                        description="After operator approval, the proof hash is submitted to a smart contract on Polygon. The on-chain record stores payload hash, evidence hash, verdict, score, and timestamp. Anyone can call verifyProof() to check a record — it's a free read, no gas cost, no API key, no trust in this platform required."
                        detail="Contract: SwarmProofRegistry.sol — anchorProof() (write) / verifyProof() (free read)"
                        icon={Globe}
                        color="indigo"
                    />
                </div>

                {/* Verdicts — right 2 cols */}
                <div className="lg:col-span-2 space-y-4">
                    <div className="bg-white border border-slate-200 rounded-sm p-5">
                        <h2 className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-4">Verdict Classification</h2>
                        {totalVerdicts > 0 ? (
                            <div className="space-y-2">
                                <VerdictBadge verdict="gold" count={verdicts.gold || 0} description="Score >= 0.90, forensic >= 0.80, attestation or triangulation >= 0.85" />
                                <VerdictBadge verdict="verified" count={verdicts.verified || 0} description="Score 0.70 - 0.90, stored with blockchain stamp" />
                                <VerdictBadge verdict="quarantine" count={verdicts.quarantine || 0} description="Score 0.40 - 0.70, held for human review" />
                                <VerdictBadge verdict="rejected" count={verdicts.rejected || 0} description="Score < 0.40, discarded, agent flagged" />
                                <div className="flex items-center justify-between pt-3 mt-2 border-t border-slate-100">
                                    <span className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Total Processed</span>
                                    <span className="text-lg font-black font-mono text-slate-900">{totalVerdicts}</span>
                                </div>
                            </div>
                        ) : (
                            <div className="py-6 text-center">
                                <Shield size={28} className="mx-auto mb-3 text-slate-200" />
                                <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">No Verdicts Issued</p>
                                <p className="text-[10px] text-slate-400 mt-1">Verdicts appear when agents submit payloads for verification</p>
                            </div>
                        )}
                    </div>

                    {/* Infrastructure health */}
                    <div className="bg-white border border-slate-200 rounded-sm p-5">
                        <h2 className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-4">Infrastructure Status</h2>
                        <div className="space-y-2.5">
                            <HealthDot label="PostgreSQL (primary store)" status={health?.database} />
                            <HealthDot label="Redis (message queue)" status={health?.redis} />
                            <HealthDot label="Blockchain RPC (Polygon)" status={stats?.blockchain_connected ? 'connected' : 'disconnected'} />
                            <HealthDot label="Hive Supervisor" status={health?.supervisor_running} />
                            <HealthDot label="Scheduler" status={health?.scheduler_running} />
                        </div>
                    </div>

                    {/* Quick navigation */}
                    <div className="bg-white border border-slate-200 rounded-sm p-5">
                        <h2 className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-3">Subsystems</h2>
                        <div className="space-y-1.5">
                            <Link to="/dashboard/agents" className="flex items-center justify-between px-3 py-2 rounded-sm hover:bg-slate-50 transition-colors group">
                                <span className="text-xs font-bold text-slate-700 group-hover:text-slate-900">Agent Directory</span>
                                <ArrowRight size={12} className="text-slate-300 group-hover:text-slate-500" />
                            </Link>
                            <Link to="/dashboard/bastion-protocol" className="flex items-center justify-between px-3 py-2 rounded-sm hover:bg-slate-50 transition-colors group">
                                <span className="text-xs font-bold text-slate-700 group-hover:text-slate-900">Bastion Protocol Monitor</span>
                                <ArrowRight size={12} className="text-slate-300 group-hover:text-slate-500" />
                            </Link>
                            <Link to="/dashboard/verification" className="flex items-center justify-between px-3 py-2 rounded-sm hover:bg-slate-50 transition-colors group">
                                <span className="text-xs font-bold text-slate-700 group-hover:text-slate-900">Verification Pipeline</span>
                                <ArrowRight size={12} className="text-slate-300 group-hover:text-slate-500" />
                            </Link>
                            <Link to="/dashboard/blockchain" className="flex items-center justify-between px-3 py-2 rounded-sm hover:bg-slate-50 transition-colors group">
                                <span className="text-xs font-bold text-slate-700 group-hover:text-slate-900">Blockchain Proof Registry</span>
                                <ArrowRight size={12} className="text-slate-300 group-hover:text-slate-500" />
                            </Link>
                        </div>
                    </div>
                </div>
            </div>

            {/* ═══ Latest Activity Feed ═══ */}
            {activity.length > 0 && (
                <div className="bg-white border border-slate-200 rounded-sm p-6">
                    <div className="flex items-center justify-between mb-4 border-b border-slate-100 pb-3">
                        <h2 className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Recent Activity</h2>
                    </div>
                    <div className="space-y-2">
                        {activity.slice(0, 4).map((evt, i) => (
                            <div key={i} className="flex items-center gap-4 px-4 py-2.5 bg-slate-50 rounded-sm border border-slate-100">
                                <span className="text-[10px] font-mono text-slate-400 w-16 shrink-0">
                                    {evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '-'}
                                </span>
                                <span className="text-xs font-bold text-slate-700">{evt.from_agent}</span>
                                {evt.to_agent && (
                                    <>
                                        <span className="text-slate-300">&#8594;</span>
                                        <span className="text-xs font-mono text-slate-500">{evt.to_agent}</span>
                                    </>
                                )}
                                <span className="text-xs text-slate-500 ml-auto truncate max-w-xs">{evt.action}</span>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
};

export default SystemOverviewView;

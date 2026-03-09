import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Network, Server, Shield, Activity, ArrowRight, Box, Cpu, HardDrive, Cloud, Info, Lock, Search, CheckCircle, AlertTriangle, XCircle } from 'lucide-react';

const verdictColors = {
    TRUSTED: 'text-slate-700 bg-slate-100 border-slate-300',
    SUSPICIOUS: 'text-slate-500 bg-slate-100 border-slate-300',
    MALICIOUS: 'text-slate-400 bg-slate-50 border-slate-200',
};

const roleColors = {
    DATA_PROVIDER: 'text-slate-700 bg-slate-100 border-slate-300',
    DATA_CONSUMER: 'text-slate-600 bg-slate-50 border-slate-200',
    VERIFIER: 'text-slate-700 bg-slate-100 border-slate-300',
    BROKER: 'text-slate-600 bg-slate-50 border-slate-200',
    OBSERVER: 'text-slate-500 bg-slate-50 border-slate-200',
    ORCHESTRATOR: 'text-slate-800 bg-slate-100 border-slate-300',
    supply_chain: 'text-slate-600 bg-slate-50 border-slate-200',
};

const roleDescriptions = {
    DATA_PROVIDER: 'Generates and submits structured data (batch records, sensor readings, certificates)',
    DATA_CONSUMER: 'Receives and cross-verifies data from other agents in the network',
    VERIFIER: 'Validates compliance, certifications, and regulatory standards',
    BROKER: 'Coordinates handoffs between agents and routes tasks',
    OBSERVER: 'Monitors network activity without submitting data',
    ORCHESTRATOR: 'Manages multi-agent workflows and supply chain sequencing',
    supply_chain: 'Participates in end-to-end supply chain verification',
};

// Classify an agent's endpoint based on its URL/port
const classifyEndpoint = (url, port) => {
    if (!url && !port) return { label: 'Unknown', type: 'unknown', color: 'text-slate-300', bgColor: 'bg-slate-50 border-slate-200' };

    const raw = url || '';
    const stripped = raw.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const hostPart = stripped.split(':')[0] || '';
    const portPart = stripped.split(':')[1] || port || '';

    // Localhost / 127.x.x.x
    if (hostPart === 'localhost' || hostPart === '127.0.0.1' || hostPart.startsWith('127.')) {
        return { label: 'Local', host: hostPart, port: portPart, type: 'local', color: 'text-slate-600', bgColor: 'bg-slate-50 border-slate-200', desc: 'Same machine' };
    }
    // Docker internal hostnames (no dots, not an IP)
    if (hostPart && !hostPart.includes('.') && !/^\d+\.\d+\.\d+\.\d+$/.test(hostPart)) {
        return { label: 'Docker', host: hostPart, port: portPart, type: 'docker', color: 'text-slate-700', bgColor: 'bg-slate-100 border-slate-300', desc: 'Container network' };
    }
    // Private LAN ranges: 10.x, 172.16-31.x, 192.168.x
    if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(hostPart)) {
        return { label: 'LAN', host: hostPart, port: portPart, type: 'lan', color: 'text-slate-600', bgColor: 'bg-slate-50 border-slate-200', desc: 'Local network' };
    }
    // Public IP or domain
    if (hostPart) {
        return { label: 'Public', host: hostPart, port: portPart, type: 'public', color: 'text-slate-800', bgColor: 'bg-slate-100 border-slate-300', desc: 'Internet-facing' };
    }
    // Port only (no URL)
    if (port) {
        return { label: 'Local', host: '', port, type: 'local', color: 'text-slate-600', bgColor: 'bg-slate-50 border-slate-200', desc: 'Same machine' };
    }
    return { label: 'Unknown', type: 'unknown', color: 'text-slate-300', bgColor: 'bg-slate-50 border-slate-200' };
};

const AgentDirectoryView = ({ agents, stats }) => {
    const navigate = useNavigate();

    // Deduplicate agents by name (not just ID) — same logical agent may have protocol + dashboard entries
    const deduped = React.useMemo(() => {
        if (!agents) return [];
        const seen = new Map();
        for (const agent of agents) {
            const key = (agent.name || agent.agent_id).toLowerCase().replace(/[-_\s]/g, '');
            if (!seen.has(key)) {
                seen.set(key, agent);
            } else {
                const existing = seen.get(key);
                if ((agent.skills?.length || 0) > (existing.skills?.length || 0) || agent.url) {
                    seen.set(key, { ...existing, ...agent });
                }
            }
        }
        return Array.from(seen.values());
    }, [agents]);

    const trustedCount = deduped.filter(a => (a.reputation_score ?? 0.0) >= 0.7).length;
    const suspiciousCount = deduped.filter(a => {
        const s = a.reputation_score ?? 0.0;
        return s >= 0.4 && s < 0.7;
    }).length;
    const maliciousCount = deduped.filter(a => (a.reputation_score ?? 0.0) < 0.4).length;

    return (
        <div className="p-8 max-w-7xl mx-auto space-y-6 animate-fade-in">
            {/* Header */}
            <header className="border-b-2 border-slate-900 pb-6">
                <div className="flex items-end justify-between">
                    <div>
                        <div className="flex items-center gap-3 mb-2">
                            <Network className="text-slate-700" size={28} />
                            <h1 className="text-3xl font-black tracking-tight text-slate-900 uppercase">Agent Directory</h1>
                        </div>
                        <p className="text-xs text-slate-500 mt-1 max-w-3xl leading-relaxed normal-case">
                            Every agent listed here has connected to The Last Bastion and announced itself via the
                            {' '}<span className="font-bold text-slate-700">A2A protocol</span> (Agent-to-Agent, Linux Foundation standard).
                            Each agent runs as an independent process — it could be a Docker container on this machine,
                            a service on a Raspberry Pi, a cloud function, or a bot running on someone else's infrastructure entirely.
                            The point is: <span className="font-bold text-slate-700">we don't control them, and we don't trust them by default</span>.
                        </p>
                    </div>
                    <div className="flex gap-6 text-right shrink-0">
                        <div>
                            <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Total</div>
                            <div className="text-2xl font-black font-mono text-slate-900">{deduped.length}</div>
                        </div>
                        <div>
                            <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Active</div>
                            <div className="text-2xl font-black font-mono text-slate-700 flex items-center gap-2 justify-end">
                                <Activity size={18} className="animate-pulse" />
                                {stats?.active_agents || 0}
                            </div>
                        </div>
                    </div>
                </div>
            </header>

            {/* What This Proves — info cards */}
            <div className="grid grid-cols-3 gap-4">
                <div className="bg-white border border-slate-200 rounded-sm p-5">
                    <div className="flex items-center gap-2 mb-3">
                        <div className="w-8 h-8 bg-slate-100 border border-slate-300 rounded-sm flex items-center justify-center">
                            <Lock size={16} className="text-slate-700" />
                        </div>
                        <h3 className="text-[10px] font-black text-slate-900 uppercase tracking-widest">Identity Verification</h3>
                    </div>
                    <p className="text-[11px] text-slate-500 leading-relaxed">
                        Each agent holds an <span className="font-bold text-slate-700">Ed25519 keypair</span>. When it connects,
                        we challenge it to prove it holds the private key — not a copy, not a replay. This is the same
                        cryptographic standard used in SSH and secure messaging.
                    </p>
                </div>
                <div className="bg-white border border-slate-200 rounded-sm p-5">
                    <div className="flex items-center gap-2 mb-3">
                        <div className="w-8 h-8 bg-slate-100 border border-slate-300 rounded-sm flex items-center justify-center">
                            <Search size={16} className="text-slate-700" />
                        </div>
                        <h3 className="text-[10px] font-black text-slate-900 uppercase tracking-widest">10-Check Pipeline</h3>
                    </div>
                    <p className="text-[11px] text-slate-500 leading-relaxed">
                        Trust isn't binary. Each agent is scored across <span className="font-bold text-slate-700">10 independent checks</span>:
                        crypto validation, behavioral analysis, anti-Sybil detection, payload quality, network probing,
                        reputation history, and more. Click any agent to see the full breakdown.
                    </p>
                </div>
                <div className="bg-white border border-slate-200 rounded-sm p-5">
                    <div className="flex items-center gap-2 mb-3">
                        <div className="w-8 h-8 bg-slate-100 border border-slate-300 rounded-sm flex items-center justify-center">
                            <Shield size={16} className="text-slate-700" />
                        </div>
                        <h3 className="text-[10px] font-black text-slate-900 uppercase tracking-widest">Trust Verdict</h3>
                    </div>
                    <p className="text-[11px] text-slate-500 leading-relaxed">
                        After verification, each agent receives a verdict:
                        {' '}<span className="font-bold text-slate-800">TRUSTED</span>,
                        {' '}<span className="font-bold text-slate-600">SUSPICIOUS</span>, or
                        {' '}<span className="font-bold text-slate-400">MALICIOUS</span>.
                        This verdict is recorded in a tamper-evident Merkle chain and optionally stamped on-chain (Polygon).
                    </p>
                </div>
            </div>

            {/* Where Agents Run — infrastructure context */}
            <div className="bg-slate-50 border border-slate-200 rounded-sm p-5">
                <div className="flex items-center gap-2 mb-3">
                    <Info size={14} className="text-slate-400" />
                    <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Where These Agents Run</h3>
                </div>
                <div className="grid grid-cols-4 gap-4">
                    <div className="flex items-start gap-3">
                        <Box size={18} className="text-slate-500 mt-0.5 shrink-0" />
                        <div>
                            <div className="text-[10px] font-bold text-slate-700 uppercase tracking-wider">Docker Containers</div>
                            <p className="text-[10px] text-slate-400 mt-0.5 leading-relaxed">Isolated containers on the same host or across a cluster. Each agent is a separate service with its own network identity.</p>
                        </div>
                    </div>
                    <div className="flex items-start gap-3">
                        <Cpu size={18} className="text-slate-500 mt-0.5 shrink-0" />
                        <div>
                            <div className="text-[10px] font-bold text-slate-700 uppercase tracking-wider">Edge Devices</div>
                            <p className="text-[10px] text-slate-400 mt-0.5 leading-relaxed">Raspberry Pi, IoT gateways, or embedded systems running lightweight agent processes at the network edge.</p>
                        </div>
                    </div>
                    <div className="flex items-start gap-3">
                        <Cloud size={18} className="text-slate-500 mt-0.5 shrink-0" />
                        <div>
                            <div className="text-[10px] font-bold text-slate-700 uppercase tracking-wider">Cloud / Third-Party</div>
                            <p className="text-[10px] text-slate-400 mt-0.5 leading-relaxed">Agents running on external infrastructure — AWS, Azure, someone else's server. We verify them the same way regardless of origin.</p>
                        </div>
                    </div>
                    <div className="flex items-start gap-3">
                        <HardDrive size={18} className="text-slate-500 mt-0.5 shrink-0" />
                        <div>
                            <div className="text-[10px] font-bold text-slate-700 uppercase tracking-wider">Local Processes</div>
                            <p className="text-[10px] text-slate-400 mt-0.5 leading-relaxed">Standalone Python/Node scripts running on a developer's machine. Common during development and testing.</p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Trust Summary Bar */}
            <div className="flex items-center gap-4">
                <div className="flex items-center gap-1.5 bg-slate-100 border border-slate-300 rounded-sm px-3 py-1.5">
                    <CheckCircle size={12} className="text-slate-700" />
                    <span className="text-[10px] font-bold text-slate-700 uppercase tracking-wider">{trustedCount} Trusted</span>
                </div>
                <div className="flex items-center gap-1.5 bg-slate-100 border border-slate-300 rounded-sm px-3 py-1.5">
                    <AlertTriangle size={12} className="text-slate-500" />
                    <span className="text-[10px] font-bold text-slate-600 uppercase tracking-wider">{suspiciousCount} Suspicious</span>
                </div>
                <div className="flex items-center gap-1.5 bg-slate-50 border border-slate-200 rounded-sm px-3 py-1.5">
                    <XCircle size={12} className="text-slate-400" />
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">{maliciousCount} Malicious</span>
                </div>
                <div className="flex-1" />
                <p className="text-[10px] text-slate-400 italic">Click any row to inspect the full trust passport, submission history, and protocol activity</p>
            </div>

            {/* Agent Table */}
            <div className="bg-white border border-slate-200 rounded-sm overflow-hidden">
                {/* Column explanations */}
                <div className="bg-slate-50/80 border-b border-slate-200 px-5 py-2.5 flex items-center gap-1">
                    <Info size={11} className="text-slate-300" />
                    <p className="text-[9px] text-slate-400 leading-relaxed">
                        <span className="font-bold">Role</span> = what this agent does in the network.
                        <span className="font-bold ml-2">Trust</span> = composite score from the 10-check verification pipeline (higher is better).
                        <span className="font-bold ml-2">Skills</span> = capabilities the agent declared in its Agent Card (A2A standard).
                        <span className="font-bold ml-2">Endpoint</span> = where the agent is listening — classified as Local (same machine), LAN (e.g. Raspberry Pi on 192.168.x), Docker (container network), or Public (internet-facing).
                    </p>
                </div>
                {deduped.length > 0 ? (
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr className="bg-slate-50 border-b border-slate-200">
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-400 uppercase tracking-widest">Agent</th>
                                <th className="py-3 px-4 text-[10px] font-bold text-slate-400 uppercase tracking-widest">Role</th>
                                <th className="py-3 px-4 text-[10px] font-bold text-slate-400 uppercase tracking-widest">Status</th>
                                <th className="py-3 px-4 text-[10px] font-bold text-slate-400 uppercase tracking-widest">Trust</th>
                                <th className="py-3 px-4 text-[10px] font-bold text-slate-400 uppercase tracking-widest">Skills</th>
                                <th className="py-3 px-4 text-[10px] font-bold text-slate-400 uppercase tracking-widest">Endpoint</th>
                                <th className="py-3 px-4 text-[10px] font-bold text-slate-400 uppercase tracking-widest">Last Seen</th>
                                <th className="py-3 px-3"></th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                            {deduped.map((agent) => {
                                const repScore = agent.reputation_score ?? 0.0;
                                const displayName = agent.name || agent.agent_id;
                                const skills = agent.skills || [];
                                const capabilities = agent.capabilities || [];
                                const allSkills = skills.length > 0
                                    ? skills.map(s => s.name || s)
                                    : capabilities;
                                const rc = roleColors[agent.role] || roleColors.supply_chain;
                                const roleDesc = roleDescriptions[agent.role] || '';

                                return (
                                    <tr key={agent.agent_id} className="hover:bg-slate-50 transition-colors group cursor-pointer" onClick={() => navigate(`/dashboard/agents/${agent.agent_id}`)}>
                                        <td className="py-3 px-5">
                                            <div className="text-sm font-bold text-slate-900 group-hover:text-slate-700 transition-colors">{displayName}</div>
                                            <div className="text-[10px] font-mono text-slate-400 mt-0.5">{agent.agent_id}</div>
                                        </td>
                                        <td className="py-3 px-4">
                                            <div>
                                                <span className={`text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${rc}`}>
                                                    {agent.role?.replace('_', ' ')}
                                                </span>
                                                {roleDesc && (
                                                    <div className="text-[9px] text-slate-400 mt-1 max-w-[180px] leading-relaxed">{roleDesc}</div>
                                                )}
                                            </div>
                                        </td>
                                        <td className="py-3 px-4">
                                            {agent.status === 'online' ? (
                                                <span className="flex items-center gap-1.5 text-[10px] font-bold text-slate-700">
                                                    <span className="w-1.5 h-1.5 rounded-full bg-slate-600 animate-pulse" />
                                                    Online
                                                </span>
                                            ) : (
                                                <span className="text-[10px] font-bold text-slate-400">
                                                    {agent.status || 'Unknown'}
                                                </span>
                                            )}
                                        </td>
                                        <td className="py-3 px-4">
                                            <div className="flex items-center gap-2">
                                                <div className="w-16 h-1.5 bg-slate-100 rounded-full overflow-hidden">
                                                    <div
                                                        className={`h-full rounded-full ${repScore >= 0.7 ? 'bg-slate-700' : repScore >= 0.4 ? 'bg-slate-500' : 'bg-slate-300'}`}
                                                        style={{ width: `${Math.min(100, repScore * 100)}%` }}
                                                    />
                                                </div>
                                                <span className={`text-[11px] font-black font-mono ${repScore >= 0.7 ? 'text-slate-800' : repScore >= 0.4 ? 'text-slate-500' : 'text-slate-400'}`}>
                                                    {(repScore * 100).toFixed(0)}%
                                                </span>
                                            </div>
                                        </td>
                                        <td className="py-3 px-4">
                                            <div className="flex flex-wrap gap-1 max-w-[200px]">
                                                {allSkills.length > 0 ? allSkills.slice(0, 3).map((s, i) => (
                                                    <span key={i} className="px-1.5 py-0.5 bg-slate-100 text-slate-600 text-[9px] font-mono rounded border border-slate-200">
                                                        {typeof s === 'string' ? s : s}
                                                    </span>
                                                )) : (
                                                    <span className="text-[10px] text-slate-300">&mdash;</span>
                                                )}
                                                {allSkills.length > 3 && (
                                                    <span className="text-[9px] text-slate-400 font-mono">+{allSkills.length - 3}</span>
                                                )}
                                            </div>
                                        </td>
                                        <td className="py-3 px-4">
                                            {(() => {
                                                const ep = classifyEndpoint(agent.url, agent.port);
                                                if (ep.type === 'unknown') return <span className="text-[10px] text-slate-300">&mdash;</span>;
                                                return (
                                                    <div>
                                                        <div className="flex items-center gap-1.5 mb-0.5">
                                                            <span className={`text-[8px] font-black uppercase tracking-widest px-1.5 py-0.5 rounded border ${ep.bgColor}`}>
                                                                {ep.label}
                                                            </span>
                                                            <span className="text-[9px] text-slate-400">{ep.desc}</span>
                                                        </div>
                                                        <span className="text-[10px] font-mono text-slate-500">
                                                            {ep.host}{ep.port ? `:${ep.port}` : ''}
                                                        </span>
                                                    </div>
                                                );
                                            })()}
                                        </td>
                                        <td className="py-3 px-4">
                                            {agent.last_seen ? (
                                                <span className="text-[10px] font-mono text-slate-400">{new Date(agent.last_seen).toLocaleString()}</span>
                                            ) : (
                                                <span className="text-[10px] text-slate-300">&mdash;</span>
                                            )}
                                        </td>
                                        <td className="py-3 px-3">
                                            <ArrowRight size={14} className="text-slate-300 group-hover:text-slate-600 transition-colors" />
                                        </td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                ) : (
                    <div className="p-12 text-center">
                        <Server size={32} className="mx-auto mb-4 text-slate-300" />
                        <p className="text-sm font-bold text-slate-400 uppercase tracking-widest">No Agents Connected</p>
                        <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto leading-relaxed">
                            Agents will appear here after connecting via the A2A protocol and completing identity verification.
                            Any agent — from any infrastructure — can connect and be assessed.
                        </p>
                    </div>
                )}
            </div>

            {/* How Verification Works — bottom explainer */}
            <div className="bg-white border border-slate-200 rounded-sm p-6">
                <h3 className="text-[10px] font-black text-slate-900 uppercase tracking-widest mb-4">How Agent Verification Works</h3>
                <div className="grid grid-cols-4 gap-6">
                    <div>
                        <div className="flex items-center gap-2 mb-2">
                            <div className="w-6 h-6 bg-slate-900 text-white text-[10px] font-black flex items-center justify-center rounded-sm">1</div>
                            <span className="text-[10px] font-bold text-slate-700 uppercase tracking-wider">Connect</span>
                        </div>
                        <p className="text-[10px] text-slate-400 leading-relaxed">
                            An agent announces itself by publishing an Agent Card (A2A standard) containing its public key, capabilities, and endpoint URL.
                        </p>
                    </div>
                    <div>
                        <div className="flex items-center gap-2 mb-2">
                            <div className="w-6 h-6 bg-slate-900 text-white text-[10px] font-black flex items-center justify-center rounded-sm">2</div>
                            <span className="text-[10px] font-bold text-slate-700 uppercase tracking-wider">Challenge</span>
                        </div>
                        <p className="text-[10px] text-slate-400 leading-relaxed">
                            The Last Bastion challenges the agent to prove it holds its private key. It also probes the agent's endpoint, checks for Sybil patterns, and inspects its history.
                        </p>
                    </div>
                    <div>
                        <div className="flex items-center gap-2 mb-2">
                            <div className="w-6 h-6 bg-slate-900 text-white text-[10px] font-black flex items-center justify-center rounded-sm">3</div>
                            <span className="text-[10px] font-bold text-slate-700 uppercase tracking-wider">Score</span>
                        </div>
                        <p className="text-[10px] text-slate-400 leading-relaxed">
                            10 independent checks produce a composite trust score. Each check has veto power — a single critical failure (like a forged key) can override everything else.
                        </p>
                    </div>
                    <div>
                        <div className="flex items-center gap-2 mb-2">
                            <div className="w-6 h-6 bg-slate-900 text-white text-[10px] font-black flex items-center justify-center rounded-sm">4</div>
                            <span className="text-[10px] font-bold text-slate-700 uppercase tracking-wider">Record</span>
                        </div>
                        <p className="text-[10px] text-slate-400 leading-relaxed">
                            The verdict is written to a tamper-evident Merkle chain. Other agents can look up any agent's trust status — it's a public, verifiable record.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default AgentDirectoryView;

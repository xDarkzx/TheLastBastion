import React, { useMemo } from 'react';
import { Cpu, CheckCircle, Link as LinkIcon, Database, Shield, Activity, Hash } from 'lucide-react';
import {
    LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer
} from 'recharts';

const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
        return (
            <div className="bg-white border border-slate-200 p-3 shadow-lg rounded-sm text-slate-900 font-mono text-xs">
                <div className="font-bold text-slate-500 mb-2 uppercase tracking-wide border-b border-slate-100 pb-1">Block #{label}</div>
                <div className="space-y-1">
                    <p><span className="text-slate-500">Confidence Score:</span> <span className="text-slate-900 font-bold">{payload[0]?.value.toFixed(4)}</span></p>
                    {payload[0]?.payload?.on_chain && (
                        <p className="text-slate-700 font-bold flex items-center gap-1 mt-1">
                            <CheckCircle size={10} /> Anchored to Polygon
                        </p>
                    )}
                </div>
            </div>
        );
    }
    return null;
};

const BlockchainView = ({ stats, refineryStats, proofLedger }) => {
    const stamps = proofLedger?.blockchain_stamps || [];
    const chain = proofLedger?.proof_chain || [];
    const chainLength = proofLedger?.chain_length || 0;
    const isConnected = stats?.blockchain_connected || false;

    const chartData = useMemo(() => {
        if (!chain || chain.length === 0) return [];
        return [...chain].reverse().map(block => ({
            id: block.record_id,
            score: block.score ? Math.round(Number(block.score) * 100) : null,
            on_chain: block.on_chain
        })).filter(b => b.score !== null);
    }, [chain]);

    return (
        <div className="p-8 max-w-7xl mx-auto space-y-8 animate-fade-in">
            <header className="flex items-end justify-between border-b-2 border-slate-900 pb-6 mb-8">
                <div>
                    <div className="flex items-center gap-3 mb-2">
                        <Cpu className="text-slate-700" size={28} />
                        <h1 className="text-3xl font-black tracking-tight text-slate-900 uppercase">On-Chain Registry</h1>
                    </div>
                    <p className="text-sm font-semibold text-slate-500 tracking-wide uppercase">Blockchain Anchoring & Merkle Proof Chain</p>
                    <p className="text-xs text-slate-400 mt-2 max-w-2xl leading-relaxed normal-case">
                        Tamper-evident audit trail where every verification verdict is cryptographically chained. Proof hashes are permanently recorded on Polygon — anyone can independently verify on-chain. The Merkle chain ensures any record alteration breaks all subsequent hashes.
                    </p>
                </div>
                <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-slate-600 animate-pulse' : 'bg-slate-300'}`} />
                    <span className={`text-[10px] font-bold uppercase tracking-widest font-mono ${isConnected ? 'text-slate-700' : 'text-slate-400'}`}>
                        {isConnected ? 'Connected' : 'Offline'}
                    </span>
                </div>
            </header>

            {/* Contract Info */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <ContractCard
                    name="SwarmProofRegistry"
                    address="0x110affBAC98FCC6b86Da499550B1fC0aCA22e946"
                    purpose="Data verification proof anchoring"
                    network="Polygon Amoy"
                    proofCount={chainLength}
                />
                <ContractCard
                    name="SwarmAgentRegistry"
                    address="0xc9177baBF86FF16794AABd1a2169f898986a0D7D"
                    purpose="M2M agent identity & reputation"
                    network="Polygon Amoy"
                    proofCount={stats?.active_agents || 0}
                    countLabel="Agents"
                />
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-4 gap-4">
                <StatBox label="Total Proofs" value={stats?.total_proofs_generated || 0} icon={Shield} />
                <StatBox label="Anchored On-Chain" value={stats?.proofs_anchored_on_chain || 0} icon={LinkIcon} color="indigo" />
                <StatBox label="Blockchain Stamps" value={refineryStats?.blockchain_stamps || 0} icon={Database} color="indigo" />
                <StatBox label="Local Chain" value={chainLength} icon={Activity} />
            </div>

            {/* Confidence Score Chart (merged from ProofLedgerView) */}
            <div className="bg-white border border-slate-200 rounded-sm shadow-sm p-6">
                <div className="flex items-center justify-between mb-6 border-b border-slate-100 pb-4">
                    <div className="flex items-center gap-2">
                        <Activity size={18} className="text-slate-500" />
                        <h2 className="text-xs font-bold text-slate-700 uppercase tracking-widest">Merkle Integrity Sequence (Confidence Scoring)</h2>
                    </div>
                </div>

                <div className="h-48 w-full">
                    {chartData.length > 0 ? (
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={chartData} margin={{ top: 10, right: 20, bottom: 5, left: -20 }}>
                                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                                <XAxis
                                    dataKey="id"
                                    tick={{ fontSize: 10, fill: '#64748b', fontFamily: 'JetBrains Mono' }}
                                    stroke="#cbd5e1"
                                    minTickGap={20}
                                />
                                <YAxis
                                    domain={[0, 100]}
                                    tick={{ fontSize: 10, fill: '#64748b', fontFamily: 'JetBrains Mono' }}
                                    stroke="#cbd5e1"
                                />
                                <RechartsTooltip content={<CustomTooltip />} cursor={{ strokeDasharray: '3 3', stroke: '#cbd5e1' }} />
                                <Line
                                    type="stepAfter"
                                    dataKey="score"
                                    stroke="#334155"
                                    strokeWidth={2}
                                    dot={(props) => {
                                        const { cx, cy, payload, index } = props;
                                        if (!cx || !cy) return null;
                                        return (
                                            <circle
                                                key={`dot-${index}`}
                                                cx={cx} cy={cy} r={payload.on_chain ? 4 : 2}
                                                fill={payload.on_chain ? '#334155' : '#94A3B8'}
                                                stroke="none"
                                            />
                                        );
                                    }}
                                    activeDot={{ r: 6, fill: '#0F172A', stroke: '#fff', strokeWidth: 2 }}
                                />
                            </LineChart>
                        </ResponsiveContainer>
                    ) : (
                        <div className="w-full h-full flex flex-col items-center justify-center text-slate-400">
                            <Hash size={32} className="mb-4 opacity-30" />
                            <p className="text-xs font-bold uppercase tracking-widest">Awaiting Sequential Block Generation</p>
                        </div>
                    )}
                </div>
                <div className="flex gap-4 mt-4 px-2 text-[10px] font-bold uppercase font-mono tracking-wider items-center justify-end">
                    <div className="flex items-center gap-1.5 text-slate-500"><span className="w-1.5 h-1.5 rounded-full bg-slate-400"></span> Local Block</div>
                    <div className="flex items-center gap-1.5 text-slate-700"><span className="w-2.5 h-2.5 rounded-full bg-slate-700"></span> Network Anchor</div>
                </div>
            </div>

            {/* Merkle Proof Chain Table (merged from ProofLedgerView) */}
            <div className="bg-white border border-slate-200 rounded-sm shadow-sm">
                <div className="px-6 py-4 border-b border-slate-200 flex items-center gap-2 bg-slate-50">
                    <Hash size={16} className="text-slate-600" />
                    <h2 className="text-[10px] font-bold text-slate-700 uppercase tracking-widest">Merkle Proof Chain</h2>
                    <span className="text-[10px] font-mono text-slate-400 ml-auto">{chain.length} records</span>
                </div>
                <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr className="bg-white border-b border-slate-200">
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest w-16">ID</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Block Hash</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Previous Hash</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Consensus</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest text-center">Score</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest text-center">Layer</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Time</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                            {chain.length > 0 ? (
                                chain.map((r, idx) => {
                                    const verdictColor = {
                                        GOLD: 'text-slate-900 bg-slate-200 border-slate-400',
                                        VERIFIED: 'text-slate-700 bg-slate-100 border-slate-300',
                                        QUARANTINE: 'text-slate-500 bg-slate-100 border-slate-300',
                                        REJECTED: 'text-slate-400 bg-slate-50 border-slate-200',
                                    }[r.verdict] || 'text-slate-600 bg-slate-50 border-slate-200';
                                    return (
                                        <tr key={r.record_id || idx} className="hover:bg-slate-50 transition-colors bg-white">
                                            <td className="py-3 px-5 text-xs font-mono font-bold text-slate-500">#{r.record_id}</td>
                                            <td className="py-3 px-5">
                                                <span className="text-[10px] font-mono text-slate-700 bg-slate-100 border border-slate-200 px-1.5 py-0.5 rounded select-all" title={r.block_hash}>
                                                    {r.block_hash?.substring(0, 20)}...
                                                </span>
                                            </td>
                                            <td className="py-3 px-5">
                                                <span className="text-[10px] font-mono text-slate-400 select-all" title={r.previous_hash}>
                                                    {r.previous_hash?.substring(0, 16)}...
                                                </span>
                                            </td>
                                            <td className="py-3 px-5">
                                                <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase tracking-wider border ${verdictColor}`}>
                                                    {r.verdict}
                                                </span>
                                            </td>
                                            <td className="py-3 px-5 text-center text-xs font-mono font-bold text-slate-900">
                                                {r.score != null ? Number(r.score).toFixed(4) : '-'}
                                            </td>
                                            <td className="py-3 px-5 text-center">
                                                {r.on_chain ? (
                                                    <span className="inline-flex items-center gap-1 text-[9px] font-bold uppercase tracking-widest text-slate-700 bg-slate-100 border border-slate-300 px-2 py-0.5 rounded">
                                                        Polygon
                                                    </span>
                                                ) : (
                                                    <span className="text-[10px] text-slate-400 font-mono">LOCAL</span>
                                                )}
                                            </td>
                                            <td className="py-3 px-5 text-[10px] font-mono text-slate-500">
                                                {r.timestamp || '-'}
                                            </td>
                                        </tr>
                                    );
                                })
                            ) : (
                                <tr>
                                    <td colSpan="7" className="py-12 text-center bg-white">
                                        <Database size={32} className="mx-auto mb-3 text-slate-300" />
                                        <p className="text-sm font-bold text-slate-400 uppercase tracking-widest">No Proof Records Generated</p>
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Recent On-Chain Stamps */}
            <div className="bg-white border border-slate-200 rounded-sm shadow-sm">
                <div className="px-6 py-4 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <LinkIcon size={16} className="text-slate-700" />
                        <h2 className="text-[10px] font-bold text-slate-700 uppercase tracking-widest">Recent On-Chain Commitments</h2>
                    </div>
                    <span className="text-[10px] font-mono font-bold text-slate-400">{stamps.length} stamps</span>
                </div>

                {stamps.length > 0 ? (
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="bg-white border-b border-slate-200">
                                    <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Proof Hash</th>
                                    <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Tx Hash</th>
                                    <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Verdict</th>
                                    <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Block</th>
                                    <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Time</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {stamps.map((s) => (
                                    <tr key={s.id} className="hover:bg-slate-50 transition-colors bg-white">
                                        <td className="py-3 px-5">
                                            <span className="text-[10px] font-mono text-slate-700 bg-slate-100 border border-slate-200 px-1.5 py-0.5 rounded select-all">
                                                {s.proof_hash?.substring(0, 20)}...
                                            </span>
                                        </td>
                                        <td className="py-3 px-5">
                                            {s.tx_hash ? (
                                                <a href={`https://amoy.polygonscan.com/tx/${s.tx_hash}`} target="_blank" rel="noreferrer"
                                                    className="text-[10px] font-mono text-slate-600 hover:text-slate-900">
                                                    {s.tx_hash.substring(0, 16)}...
                                                </a>
                                            ) : (
                                                <span className="text-[10px] font-mono text-slate-400">Pending</span>
                                            )}
                                        </td>
                                        <td className="py-3 px-5">
                                            <span className={`text-[10px] font-bold uppercase tracking-widest ${
                                                s.verdict === 'GOLD' ? 'text-slate-900' :
                                                s.verdict === 'VERIFIED' ? 'text-slate-700' : 'text-slate-500'
                                            }`}>{s.verdict}</span>
                                        </td>
                                        <td className="py-3 px-5 text-[10px] font-mono text-slate-500">
                                            {s.block_number || '-'}
                                        </td>
                                        <td className="py-3 px-5 text-[10px] font-mono text-slate-400">
                                            {s.created_at ? new Date(s.created_at).toLocaleString() : '-'}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                ) : (
                    <div className="px-6 py-12 text-center bg-white">
                        <Cpu size={32} className="mx-auto mb-3 text-slate-300" />
                        <p className="text-sm font-bold text-slate-400 uppercase tracking-widest">No On-Chain Stamps Yet</p>
                        <p className="text-xs text-slate-400 mt-1">Stamps are created when VERIFIED or GOLD verdicts are anchored</p>
                    </div>
                )}
            </div>
        </div>
    );
};

const ContractCard = ({ name, address, purpose, network, proofCount, countLabel = "Proofs" }) => (
    <div className="bg-white border border-slate-200 rounded-sm p-5">
        <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wide">{name}</h3>
            <span className="text-[9px] font-bold text-slate-700 uppercase tracking-widest bg-slate-100 border border-slate-300 px-2 py-0.5 rounded">{network}</span>
        </div>
        <div className="mb-3">
            <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Contract Address</div>
            <a href={`https://amoy.polygonscan.com/address/${address}`} target="_blank" rel="noreferrer"
                className="text-[10px] font-mono text-slate-600 hover:text-slate-900 break-all">
                {address}
            </a>
        </div>
        <div className="text-[10px] text-slate-500 mb-3">{purpose}</div>
        <div className="flex items-center justify-between pt-3 border-t border-slate-100">
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">{countLabel}</span>
            <span className="text-lg font-black font-mono text-slate-900">{proofCount}</span>
        </div>
    </div>
);

const StatBox = ({ label, value, icon: Icon, color = 'slate' }) => {
    const colorMap = {
        indigo: 'border-slate-300 bg-slate-50',
        slate: 'border-slate-200 bg-white',
    };
    const iconMap = {
        indigo: 'text-slate-700',
        slate: 'text-slate-600',
    };
    return (
        <div className={`rounded-sm border p-4 ${colorMap[color]}`}>
            <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-bold uppercase tracking-widest text-slate-400">{label}</span>
                <Icon size={14} className={iconMap[color]} />
            </div>
            <div className="text-xl font-black font-mono text-slate-900">{value}</div>
        </div>
    );
};

export default BlockchainView;

import React, { useState, useEffect, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, Server, Activity, FileCheck, Shield, Clock, CheckCircle, ExternalLink, AlertTriangle, Loader2, ChevronDown, ChevronRight, Info } from 'lucide-react';
import { swarmService, DEMO_MODE } from '../../services/api';
import BehaviorButtons from '../BehaviorButtons';
import SimulationPanel from '../SimulationPanel';

const phaseColors = {
    discovery: { bg: 'bg-slate-50', border: 'border-slate-200', text: 'text-slate-500' },
    production: { bg: 'bg-slate-50', border: 'border-slate-300', text: 'text-slate-700' },
    compliance: { bg: 'bg-slate-100', border: 'border-slate-300', text: 'text-slate-700' },
    logistics: { bg: 'bg-slate-50', border: 'border-slate-300', text: 'text-slate-600' },
    buyer_verification: { bg: 'bg-slate-100', border: 'border-slate-300', text: 'text-slate-700' },
    registry_verification: { bg: 'bg-slate-100', border: 'border-slate-400', text: 'text-slate-800' },
    registry_base_verification: { bg: 'bg-slate-100', border: 'border-slate-400', text: 'text-slate-800' },
};

const verdictColors = {
    REJECTED: 'text-slate-400 bg-slate-50 border-slate-200',
    QUARANTINE: 'text-slate-500 bg-slate-100 border-slate-300',
    VERIFIED: 'text-slate-700 bg-slate-100 border-slate-300',
    GOLD: 'text-slate-900 bg-slate-200 border-slate-400',
};

const trustVerdictStyles = {
    TRUSTED: { bg: 'bg-slate-100', border: 'border-slate-400', text: 'text-slate-800', dot: 'bg-slate-700' },
    SUSPICIOUS: { bg: 'bg-slate-100', border: 'border-slate-300', text: 'text-slate-600', dot: 'bg-slate-500' },
    MALICIOUS: { bg: 'bg-slate-50', border: 'border-slate-300', text: 'text-slate-500', dot: 'bg-slate-400' },
    UNVERIFIED: { bg: 'bg-slate-50', border: 'border-slate-200', text: 'text-slate-400', dot: 'bg-slate-300' },
};

const trustLevelStyles = {
    GOLD: { bg: 'bg-slate-200', border: 'border-slate-500', text: 'text-slate-900' },
    ESTABLISHED: { bg: 'bg-slate-100', border: 'border-slate-400', text: 'text-slate-800' },
    VERIFIED: { bg: 'bg-slate-100', border: 'border-slate-300', text: 'text-slate-700' },
    BASIC: { bg: 'bg-slate-50', border: 'border-slate-300', text: 'text-slate-600' },
    NEW: { bg: 'bg-slate-50', border: 'border-slate-200', text: 'text-slate-500' },
    NONE: { bg: 'bg-slate-50', border: 'border-slate-200', text: 'text-slate-400' },
};

const riskCategoryStyles = {
    NONE: { bg: 'bg-slate-50', text: 'text-slate-500', border: 'border-slate-200' },
    LOW: { bg: 'bg-slate-50', text: 'text-slate-600', border: 'border-slate-200' },
    MEDIUM: { bg: 'bg-slate-100', text: 'text-slate-600', border: 'border-slate-300' },
    HIGH: { bg: 'bg-slate-100', text: 'text-slate-700', border: 'border-slate-400' },
    CRITICAL: { bg: 'bg-slate-200', text: 'text-slate-800', border: 'border-slate-500' },
};

const checkLabels = {
    identity: { name: 'Identity', tier: 1, desc: 'Live agent card probe + DB cross-check' },
    cryptographic: { name: 'Crypto', tier: 1, desc: 'Key validation + signature verification' },
    capabilities: { name: 'Capability', tier: 2, desc: 'Declared vs demonstrated capabilities' },
    reputation: { name: 'Reputation', tier: 2, desc: 'Submission verdicts + handoff history' },
    payload_quality: { name: 'Payload', tier: 2, desc: 'Submission quality + template detection' },
    behavioral: { name: 'Behavior', tier: 3, desc: 'Protocol bus patterns + timing analysis' },
    network: { name: 'Network', tier: 3, desc: 'Live probe + TLS + URL uniqueness' },
    cross_reference: { name: 'Cross-Ref', tier: 3, desc: 'Trusted agent connections' },
    anti_sybil: { name: 'Anti-Sybil', tier: 3, desc: 'Key/URL collision + burst detection' },
    temporal: { name: 'Temporal', tier: 3, desc: 'Account age + score trajectory' },
};

const tierLabels = { 1: 'Cryptographic', 2: 'Historical', 3: 'Behavioral' };
const tierColors = {
    1: 'text-slate-800',
    2: 'text-slate-600',
    3: 'text-slate-500',
};

const CheckCard = ({ name, check }) => {
    const [expanded, setExpanded] = useState(false);
    const passed = check?.passed ?? false;
    const checkScore = check?.score ?? 0;
    const detail = check?.detail || '';
    const evidence = check?.evidence || [];
    const veto = check?.veto || false;
    const meta = checkLabels[name] || { name, tier: 0, desc: '' };

    return (
        <div className={`border rounded-sm ${passed ? 'border-slate-300 bg-slate-50/50' : veto ? 'border-slate-400 bg-slate-100' : 'border-slate-300 bg-slate-50/50'}`}>
            <button
                onClick={() => evidence.length > 0 && setExpanded(!expanded)}
                className="w-full p-3 text-left"
            >
                <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-1.5">
                        <span className={`text-[8px] font-bold uppercase tracking-widest ${tierColors[meta.tier] || 'text-slate-400'}`}>
                            T{meta.tier}
                        </span>
                        <span className="text-[9px] font-bold uppercase tracking-widest text-slate-500">
                            {meta.name}
                        </span>
                    </div>
                    <div className="flex items-center gap-1">
                        {veto && <span className="text-[8px] font-black text-slate-700 bg-slate-200 px-1 rounded">VETO</span>}
                        {passed ? (
                            <CheckCircle size={11} className="text-slate-600" />
                        ) : (
                            <AlertTriangle size={11} className={veto ? 'text-slate-700' : 'text-slate-500'} />
                        )}
                        <span className={`text-sm font-black font-mono ${passed ? 'text-slate-700' : veto ? 'text-slate-700' : 'text-slate-500'}`}>
                            {checkScore.toFixed(2)}
                        </span>
                    </div>
                </div>
                {detail && (
                    <div className="text-[9px] text-slate-500 truncate">{detail}</div>
                )}
                {evidence.length > 0 && (
                    <div className="flex items-center gap-0.5 mt-1 text-[8px] text-slate-400">
                        {expanded ? <ChevronDown size={9} /> : <ChevronRight size={9} />}
                        {evidence.length} evidence items
                    </div>
                )}
            </button>
            {expanded && evidence.length > 0 && (
                <div className="border-t border-slate-200/60 px-3 py-2 space-y-1 bg-white/50">
                    {evidence.map((e, i) => (
                        <div key={i} className="text-[9px] font-mono text-slate-500 flex items-start gap-1">
                            <span className="text-slate-300 mt-0.5 shrink-0">-</span>
                            <span className="break-all">{e}</span>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

const TrustPassport = ({ passport, agentId, onVerify }) => {
    const [verifying, setVerifying] = useState(false);

    if (!passport) return null;

    const status = passport.status || 'UNVERIFIED';
    const style = trustVerdictStyles[status] || trustVerdictStyles.UNVERIFIED;
    const score = passport.trust_score || 0;
    const checks = passport.checks_passed || {};
    const riskFlags = passport.risk_flags || [];
    const proofHash = passport.proof_hash || '';
    const txHash = passport.tx_hash || '';
    const expiresAt = passport.expires_at || '';
    const trustLevel = passport.trust_level || '';
    const riskCategory = passport.risk_category || '';
    const recommendations = passport.recommendations || [];

    // Days remaining
    let expiryText = '';
    if (expiresAt) {
        const days = Math.ceil((new Date(expiresAt) - new Date()) / (1000 * 60 * 60 * 24));
        expiryText = days > 0 ? `${days} days remaining` : 'EXPIRED';
    }

    const handleVerify = async () => {
        setVerifying(true);
        try {
            await onVerify();
        } finally {
            setVerifying(false);
        }
    };

    const tlStyle = trustLevelStyles[trustLevel] || trustLevelStyles.NONE;
    const rcStyle = riskCategoryStyles[riskCategory] || riskCategoryStyles.NONE;

    // Group checks by tier
    const checkEntries = Object.entries(checks);
    const tier1 = checkEntries.filter(([name]) => (checkLabels[name]?.tier || 0) === 1);
    const tier2 = checkEntries.filter(([name]) => (checkLabels[name]?.tier || 0) === 2);
    const tier3 = checkEntries.filter(([name]) => (checkLabels[name]?.tier || 0) === 3);
    const uncategorized = checkEntries.filter(([name]) => !(checkLabels[name]?.tier));

    return (
        <div className="bg-white border border-slate-200 rounded-sm p-6">
            {/* Header */}
            <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                    <Shield size={16} className="text-slate-500" />
                    <h2 className="text-xs font-bold text-slate-700 uppercase tracking-widest">Trust Passport</h2>
                    <span className="text-[9px] font-mono text-slate-400">10-check pipeline</span>
                </div>
                <div className="flex items-center gap-2">
                    {trustLevel && (
                        <span className={`text-[9px] font-bold uppercase tracking-widest px-2 py-0.5 rounded border ${tlStyle.bg} ${tlStyle.border} ${tlStyle.text}`}>
                            {trustLevel}
                        </span>
                    )}
                    <span className={`text-[10px] font-bold uppercase tracking-widest px-2.5 py-1 rounded border flex items-center gap-1.5 ${style.bg} ${style.border} ${style.text}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
                        {status}
                    </span>
                </div>
            </div>

            {/* Trust score bar + risk category */}
            {status !== 'UNVERIFIED' && (
                <div className="mb-5">
                    <div className="flex items-center justify-between mb-1.5">
                        <div className="flex items-center gap-3">
                            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Trust Score</span>
                            {riskCategory && (
                                <span className={`text-[9px] font-bold uppercase tracking-widest px-1.5 py-0.5 rounded border ${rcStyle.bg} ${rcStyle.border} ${rcStyle.text}`}>
                                    Risk: {riskCategory}
                                </span>
                            )}
                        </div>
                        <span className="text-sm font-black font-mono text-slate-900">{score.toFixed(4)}</span>
                    </div>
                    <div className="w-full bg-slate-100 rounded-full h-2.5">
                        <div
                            className={`h-2.5 rounded-full transition-all duration-500 ${score >= 0.65 ? 'bg-slate-700' : score >= 0.40 ? 'bg-slate-500' : 'bg-slate-300'}`}
                            style={{ width: `${Math.min(score * 100, 100)}%` }}
                        />
                    </div>
                    {/* Score range labels */}
                    <div className="flex justify-between mt-1 text-[8px] font-mono text-slate-300">
                        <span>MALICIOUS</span>
                        <span>SUSPICIOUS</span>
                        <span>TRUSTED</span>
                    </div>
                </div>
            )}

            {/* 10-check grid grouped by tier */}
            {checkEntries.length > 0 && (
                <div className="space-y-4 mb-5">
                    {[
                        { checks: tier1, tier: 1, label: 'Tier 1 — Cryptographic Proofs', weight: '30%' },
                        { checks: tier2, tier: 2, label: 'Tier 2 — Historical Evidence', weight: '35%' },
                        { checks: tier3, tier: 3, label: 'Tier 3 — Behavioral & Environmental', weight: '35%' },
                    ].filter(g => g.checks.length > 0).map(group => (
                        <div key={group.tier}>
                            <div className="flex items-center gap-2 mb-2">
                                <span className={`text-[9px] font-bold uppercase tracking-widest ${tierColors[group.tier]}`}>
                                    {group.label}
                                </span>
                                <span className="text-[8px] font-mono text-slate-300">{group.weight}</span>
                            </div>
                            <div className={`grid gap-2 ${group.checks.length <= 2 ? 'grid-cols-2' : 'grid-cols-3'}`}>
                                {group.checks.map(([name, check]) => (
                                    <CheckCard key={name} name={name} check={check} />
                                ))}
                            </div>
                        </div>
                    ))}
                    {uncategorized.length > 0 && (
                        <div className="grid grid-cols-3 gap-2">
                            {uncategorized.map(([name, check]) => (
                                <CheckCard key={name} name={name} check={check} />
                            ))}
                        </div>
                    )}
                </div>
            )}

            {/* Risk flags */}
            {riskFlags.length > 0 && (
                <div className="mb-4">
                    <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-2">Risk Flags ({riskFlags.length})</div>
                    <div className="space-y-1 max-h-32 overflow-y-auto">
                        {riskFlags.map((flag, i) => (
                            <div key={i} className="text-xs font-mono text-slate-600 flex items-start gap-1.5">
                                <AlertTriangle size={10} className="mt-0.5 shrink-0" />
                                <span className="break-all">{flag}</span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Recommendations */}
            {recommendations.length > 0 && (
                <div className="mb-4">
                    <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-2">Recommendations</div>
                    <div className="space-y-1.5">
                        {recommendations.map((rec, i) => (
                            <div key={i} className="text-xs text-slate-600 flex items-start gap-1.5">
                                <Info size={10} className="mt-0.5 shrink-0 text-slate-400" />
                                <span>{rec}</span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Proof + expiry */}
            {(proofHash || expiryText) && (
                <div className="border-t border-slate-100 pt-4 space-y-2">
                    {proofHash && (
                        <div className="flex items-center gap-2 text-[10px]">
                            <span className="font-bold text-slate-400 uppercase tracking-widest">Proof:</span>
                            <span className="font-mono text-slate-600">{proofHash.substring(0, 24)}...</span>
                            {txHash && (
                                <a
                                    href={`https://amoy.polygonscan.com/tx/${txHash}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-slate-600 hover:text-slate-800 flex items-center gap-0.5"
                                >
                                    <ExternalLink size={9} /> Polygonscan
                                </a>
                            )}
                        </div>
                    )}
                    {expiryText && (
                        <div className="text-[10px]">
                            <span className="font-bold text-slate-400 uppercase tracking-widest">Expires:</span>
                            <span className={`ml-2 font-mono ${expiryText === 'EXPIRED' ? 'text-slate-600 font-bold' : 'text-slate-600'}`}>
                                {expiryText}
                            </span>
                        </div>
                    )}
                </div>
            )}

            {/* Verify button */}
            {status === 'UNVERIFIED' && (
                <div className="mt-5 border-t border-slate-100 pt-4">
                    <button
                        onClick={DEMO_MODE ? undefined : handleVerify}
                        disabled={verifying || DEMO_MODE}
                        className={`w-full py-2.5 text-[11px] font-bold uppercase tracking-widest rounded-sm flex items-center justify-center gap-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${DEMO_MODE ? 'bg-slate-200 text-slate-400' : 'bg-slate-900 text-white hover:bg-slate-800'}`}
                    >
                        {DEMO_MODE ? (
                            <><Shield size={14} /> Demo Mode — Verify Disabled</>
                        ) : verifying ? (
                            <><Loader2 size={14} className="animate-spin" /> Running 10-Check Pipeline...</>
                        ) : (
                            <><Shield size={14} /> Verify This Agent</>
                        )}
                    </button>
                </div>
            )}

            {/* Re-verify button for already verified agents */}
            {status !== 'UNVERIFIED' && (
                <div className="mt-5 border-t border-slate-100 pt-4">
                    <button
                        onClick={DEMO_MODE ? undefined : handleVerify}
                        disabled={verifying || DEMO_MODE}
                        className={`w-full py-2 text-[10px] font-bold uppercase tracking-widest rounded-sm flex items-center justify-center gap-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${DEMO_MODE ? 'bg-slate-100 text-slate-400' : 'bg-slate-100 text-slate-700 hover:bg-slate-200'}`}
                    >
                        {DEMO_MODE ? (
                            <><Shield size={12} /> Demo Mode — Verify Disabled</>
                        ) : verifying ? (
                            <><Loader2 size={12} className="animate-spin" /> Re-verifying...</>
                        ) : (
                            <><Shield size={12} /> Re-verify Agent</>
                        )}
                    </button>
                </div>
            )}
        </div>
    );
};

const AgentDetailView = () => {
    const { agentId } = useParams();
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
    const [simulationResult, setSimulationResult] = useState(null);

    const fetchDetail = useCallback(async () => {
        try {
            const resp = await swarmService.getAgentDetail(agentId);
            setData(resp.data);
            setError(null);
        } catch (err) {
            setError(err.message || 'Failed to load agent detail');
        }
    }, [agentId]);

    useEffect(() => {
        let isMounted = true;
        const fetch = async () => {
            if (!isMounted) return;
            await fetchDetail();
        };
        fetch();
        const interval = setInterval(fetch, 10000);
        return () => { isMounted = false; clearInterval(interval); };
    }, [fetchDetail]);

    const handleVerify = async () => {
        try {
            await swarmService.verifyAgentFromDashboard(agentId);
            await fetchDetail(); // Refresh to show updated passport
        } catch (err) {
            console.error('Verification failed:', err);
        }
    };

    if (error && !data) {
        return (
            <div className="p-8 max-w-5xl mx-auto animate-fade-in">
                <Link to="/dashboard/agents" className="inline-flex items-center gap-2 text-sm font-bold text-slate-500 hover:text-slate-700 mb-6">
                    <ArrowLeft size={16} /> Back to Agent Network
                </Link>
                <div className="bg-slate-50 border border-slate-200 rounded-sm p-8 text-center">
                    <Server size={32} className="mx-auto mb-3 text-slate-400" />
                    <p className="text-sm font-bold text-slate-600">Agent Not Found</p>
                    <p className="text-xs text-slate-400 mt-1">{error}</p>
                </div>
            </div>
        );
    }

    if (!data) {
        return (
            <div className="p-8 max-w-5xl mx-auto animate-fade-in">
                <div className="text-center py-20">
                    <Activity size={24} className="mx-auto mb-3 text-slate-400 animate-pulse" />
                    <p className="text-sm font-bold text-slate-400 uppercase tracking-widest">Loading Agent Detail...</p>
                </div>
            </div>
        );
    }

    const { agent, trust_passport, activity = [], submissions = [], submission_stats = {} } = data;
    const trustScore = agent.reputation_score ?? 1.0;
    const skills = agent.skills || [];
    const totalEvents = activity.length;
    const totalSubmissions = submission_stats.total || 0;
    const verdicts = submission_stats.verdicts || {};
    const verdictSummary = Object.entries(verdicts).map(([v, c]) => `${c} ${v}`).join(', ') || 'None';

    return (
        <div className="p-8 max-w-5xl mx-auto space-y-6 animate-fade-in">
            {/* Back link */}
            <Link to="/dashboard/agents" className="inline-flex items-center gap-2 text-sm font-bold text-slate-500 hover:text-slate-700 transition-colors">
                <ArrowLeft size={16} /> Back to Agent Network
            </Link>

            {/* Agent header */}
            <div className="bg-white border border-slate-200 rounded-sm p-6">
                <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center gap-4">
                        <div className="w-14 h-14 rounded bg-slate-100 border border-slate-300 flex items-center justify-center text-slate-700">
                            <Server size={28} />
                        </div>
                        <div>
                            <div className="flex items-center gap-3">
                                <h1 className="text-2xl font-black tracking-tight text-slate-900">{agent.name || agent.agent_id}</h1>
                                {agent.version && <span className="text-xs font-mono text-slate-400">v{agent.version}</span>}
                                <span className={`text-[9px] font-bold uppercase tracking-widest px-2 py-0.5 rounded border ${
                                    agent.status === 'online' ? 'bg-slate-100 text-slate-700 border-slate-300' : 'bg-slate-50 text-slate-500 border-slate-200'
                                }`}>
                                    {agent.status || 'unknown'}
                                </span>
                            </div>
                            {agent.description && (
                                <p className="text-sm text-slate-500 mt-1 max-w-xl">{agent.description}</p>
                            )}
                            {agent.url && (
                                <div className="flex items-center gap-1 mt-1 text-[10px] font-mono text-slate-400">
                                    <ExternalLink size={10} />
                                    {agent.url}
                                </div>
                            )}
                        </div>
                    </div>
                    <BehaviorButtons agentId={agentId} onSimulationResult={setSimulationResult} />
                </div>

                {/* Stat cards */}
                <div className="grid grid-cols-4 gap-4 mt-6">
                    <div className="bg-slate-50 border border-slate-200 rounded-sm p-4 text-center">
                        <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Events</div>
                        <div className="text-2xl font-black font-mono text-slate-900">{totalEvents}</div>
                    </div>
                    <div className="bg-slate-50 border border-slate-200 rounded-sm p-4 text-center">
                        <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Submissions</div>
                        <div className="text-2xl font-black font-mono text-slate-900">{totalSubmissions}</div>
                    </div>
                    <div className="bg-slate-50 border border-slate-200 rounded-sm p-4 text-center">
                        <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Verdicts</div>
                        <div className="text-sm font-bold font-mono text-slate-700 mt-1">{verdictSummary}</div>
                    </div>
                    <div className="bg-slate-50 border border-slate-200 rounded-sm p-4 text-center">
                        <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Trust</div>
                        <div className={`text-2xl font-black font-mono ${trustScore >= 0.7 ? 'text-slate-800' : trustScore >= 0.4 ? 'text-slate-600' : 'text-slate-400'}`}>
                            {(trustScore * 100).toFixed(0)}%
                        </div>
                    </div>
                </div>
            </div>

            {/* Trust Passport */}
            <TrustPassport passport={trust_passport} agentId={agentId} onVerify={handleVerify} />

            {/* Simulation Result */}
            {simulationResult && (
                <SimulationPanel result={simulationResult} onDismiss={() => setSimulationResult(null)} />
            )}

            {/* Skills */}
            {skills.length > 0 && (
                <div className="bg-white border border-slate-200 rounded-sm p-6">
                    <h2 className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-4">Skills</h2>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        {skills.map((skill, idx) => (
                            <div key={idx} className="border border-slate-100 rounded-sm p-3">
                                <div className="text-sm font-bold text-slate-800">{skill.name || skill}</div>
                                {skill.tags && skill.tags.length > 0 && (
                                    <div className="flex flex-wrap gap-1.5 mt-2">
                                        {skill.tags.map((tag, ti) => (
                                            <span key={ti} className="px-2 py-0.5 bg-slate-100 text-slate-600 text-[9px] font-mono rounded border border-slate-200">
                                                {tag}
                                            </span>
                                        ))}
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Activity Log */}
            <div className="bg-white border border-slate-200 rounded-sm shadow-sm overflow-hidden">
                <div className="px-5 py-4 border-b border-slate-100 flex items-center gap-2">
                    <Activity size={16} className="text-slate-500" />
                    <h2 className="text-xs font-bold text-slate-700 uppercase tracking-widest">Activity Log</h2>
                    <span className="text-[10px] font-mono text-slate-400 ml-auto">{activity.length} events</span>
                </div>
                <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr className="bg-slate-50 border-b border-slate-200">
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest w-28">Time</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Phase</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Direction</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Action</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest text-center">Status</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                            {activity.length > 0 ? activity.map((evt) => {
                                const pc = phaseColors[evt.phase] || phaseColors.discovery;
                                const direction = evt.from_agent === (agent.name || agentId)
                                    ? `-> ${evt.to_agent || 'Last Bastion'}`
                                    : `<- ${evt.from_agent || 'Last Bastion'}`;
                                return (
                                    <tr key={evt.id} className="hover:bg-slate-50 transition-colors">
                                        <td className="py-3 px-5 text-[10px] font-mono text-slate-400">
                                            {evt.timestamp ? new Date(evt.timestamp).toLocaleString() : '-'}
                                        </td>
                                        <td className="py-3 px-5">
                                            <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${pc.bg} ${pc.border} ${pc.text}`}>
                                                {evt.phase}
                                            </span>
                                        </td>
                                        <td className="py-3 px-5 text-xs font-mono text-slate-500">{direction}</td>
                                        <td className="py-3 px-5 text-xs text-slate-600 max-w-xs truncate">{evt.action}</td>
                                        <td className="py-3 px-5 text-center">
                                            <div className="inline-flex items-center gap-1">
                                                {evt.status === 'active' ? (
                                                    <Clock size={11} className="text-slate-500 animate-pulse" />
                                                ) : (
                                                    <CheckCircle size={11} className="text-slate-600" />
                                                )}
                                                <span className={`text-[10px] font-bold uppercase tracking-widest font-mono ${
                                                    evt.status === 'active' ? 'text-slate-500' : 'text-slate-700'
                                                }`}>
                                                    {evt.status}
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                );
                            }) : (
                                <tr>
                                    <td colSpan="5" className="py-8 text-center">
                                        <p className="text-sm font-bold text-slate-400 uppercase tracking-widest">No Activity</p>
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Submissions */}
            <div className="bg-white border border-slate-200 rounded-sm shadow-sm overflow-hidden">
                <div className="px-5 py-4 border-b border-slate-100 flex items-center gap-2">
                    <FileCheck size={16} className="text-slate-500" />
                    <h2 className="text-xs font-bold text-slate-700 uppercase tracking-widest">Submissions</h2>
                    <span className="text-[10px] font-mono text-slate-400 ml-auto">{submissions.length} records</span>
                </div>
                <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr className="bg-slate-50 border-b border-slate-200">
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">ID</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Hash</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Verdict</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Score</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Time</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                            {submissions.length > 0 ? submissions.map((sub) => {
                                const vc = verdictColors[sub.verdict] || 'text-slate-500 bg-slate-50 border-slate-200';
                                return (
                                    <tr key={sub.id} className="hover:bg-slate-50 transition-colors">
                                        <td className="py-3 px-5 text-[10px] font-mono text-slate-500">{sub.id?.substring(0, 12)}...</td>
                                        <td className="py-3 px-5 text-[10px] font-mono text-slate-400">{sub.data_hash?.substring(0, 12)}...</td>
                                        <td className="py-3 px-5">
                                            {sub.verdict ? (
                                                <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${vc}`}>
                                                    {sub.verdict}
                                                </span>
                                            ) : (
                                                <span className="text-[10px] text-slate-400">Pending</span>
                                            )}
                                        </td>
                                        <td className="py-3 px-5 text-xs font-mono text-slate-600">
                                            {sub.score != null ? sub.score.toFixed(4) : '-'}
                                        </td>
                                        <td className="py-3 px-5 text-[10px] font-mono text-slate-400">
                                            {sub.created_at ? new Date(sub.created_at).toLocaleString() : '-'}
                                        </td>
                                    </tr>
                                );
                            }) : (
                                <tr>
                                    <td colSpan="5" className="py-8 text-center">
                                        <p className="text-sm font-bold text-slate-400 uppercase tracking-widest">No Submissions</p>
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};

export default AgentDetailView;

import React, { useState, useCallback } from 'react';
import { Inbox, CheckCircle, XCircle, Clock, ShieldAlert, Database, Info, Lock } from 'lucide-react';
import { swarmService, DEMO_MODE } from '../../services/api';

const VerdictBadge = ({ verdict, score }) => {
    const config = {
        GOLD: { color: 'bg-slate-200 text-slate-900 border-slate-400', icon: CheckCircle },
        VERIFIED: { color: 'bg-slate-100 text-slate-700 border-slate-300', icon: CheckCircle },
        QUARANTINE: { color: 'bg-slate-100 text-slate-500 border-slate-300', icon: ShieldAlert },
        REJECTED: { color: 'bg-slate-50 text-slate-400 border-slate-200', icon: XCircle },
    };
    const cfg = config[verdict] || { color: 'bg-slate-100 text-slate-500 border-slate-200', icon: Clock };
    const Icon = cfg.icon;
    return (
        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase tracking-wider border ${cfg.color}`}>
            <Icon size={11} />
            {verdict || 'PENDING'}
        </span>
    );
};

const ScoreLegend = () => (
    <div className="bg-white border border-slate-200 rounded-sm p-4">
        <div className="flex items-center gap-2 mb-3">
            <Info size={14} className="text-slate-400" />
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Score Thresholds</span>
        </div>
        <div className="flex gap-2">
            {[
                { label: 'REJECTED', range: '< 0.40', color: 'bg-slate-50 text-slate-400 border-slate-200' },
                { label: 'QUARANTINE', range: '0.40 - 0.70', color: 'bg-slate-100 text-slate-500 border-slate-300' },
                { label: 'VERIFIED', range: '0.70 - 0.90', color: 'bg-slate-100 text-slate-700 border-slate-300' },
                { label: 'GOLD', range: '>= 0.90', color: 'bg-slate-200 text-slate-900 border-slate-400' },
            ].map(t => (
                <div key={t.label} className={`flex-1 px-2 py-1.5 rounded border text-center ${t.color}`}>
                    <div className="text-[9px] font-bold uppercase tracking-wider">{t.label}</div>
                    <div className="text-[10px] font-mono mt-0.5">{t.range}</div>
                </div>
            ))}
        </div>
    </div>
);

const SubmissionsView = ({ submissions, refineryStats, calibration }) => {
    const quarantineQueue = calibration?.quarantine_queue || [];
    const [resolving, setResolving] = useState(null);

    const handleResolve = async (id, resolution) => {
        setResolving(id);
        try {
            await swarmService.resolveQuarantine(id, resolution);
            // Data will refresh on next poll cycle (5s)
        } catch {
            // handled
        } finally {
            setResolving(null);
        }
    };

    return (
        <div className="p-8 max-w-7xl mx-auto space-y-8 animate-fade-in">
            <header className="flex items-end justify-between border-b-2 border-slate-900 pb-6 mb-8">
                <div>
                    <div className="flex items-center gap-3 mb-2">
                        <Inbox className="text-slate-700" size={28} />
                        <h1 className="text-3xl font-black tracking-tight text-slate-900 uppercase">Submissions</h1>
                    </div>
                    <p className="text-sm font-semibold text-slate-500 tracking-wide uppercase">Raw Data Submission Pipeline</p>
                    <p className="text-xs text-slate-400 mt-2 max-w-2xl leading-relaxed normal-case">
                        Ingestion pipeline for all data entering the platform. External agents submit raw payloads — PDFs, images, JSON, CSV — which are format-detected, deduplicated, and queued for verification. Each submission is tracked from receipt through to final verdict.
                    </p>
                </div>
                <div className="flex gap-6 text-right">
                    <div>
                        <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Total</div>
                        <div className="text-2xl font-black font-mono text-slate-900">{refineryStats?.total_submissions || 0}</div>
                    </div>
                    <div>
                        <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Duplicates</div>
                        <div className="text-2xl font-black font-mono text-slate-500">{refineryStats?.duplicates || 0}</div>
                    </div>
                </div>
            </header>

            {/* Score Legend */}
            <ScoreLegend />

            {/* Quarantine Review Queue */}
            {quarantineQueue.length > 0 && (
                <div className="bg-white border border-slate-300 rounded-sm shadow-sm">
                    <div className="px-6 py-4 border-b border-slate-300 bg-slate-100 flex items-center justify-between">
                        <div className="flex items-center gap-2">
                            <ShieldAlert size={16} className="text-slate-600" />
                            <h2 className="text-[10px] font-bold text-slate-700 uppercase tracking-widest">Quarantine Review Queue</h2>
                        </div>
                        <span className="text-[10px] font-mono font-bold text-slate-600">{quarantineQueue.length} pending</span>
                    </div>
                    <div className="divide-y divide-slate-100">
                        {quarantineQueue.map((item) => (
                            <div key={item.id} className="px-6 py-4 flex items-center justify-between hover:bg-slate-50 transition-colors">
                                <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-3 mb-1">
                                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-100 text-slate-600 text-[10px] font-bold font-mono uppercase border border-slate-300">
                                            <Clock size={10} />
                                            PENDING
                                        </span>
                                        <span className="text-[10px] font-mono text-slate-400">
                                            Score: {item.score?.toFixed(4) || '?'}
                                        </span>
                                    </div>
                                    <div className="text-xs font-mono text-slate-600 truncate" title={item.data_hash}>
                                        <Database size={10} className="inline mr-1 text-slate-400" />
                                        {item.data_hash?.substring(0, 24)}...
                                    </div>
                                    <div className="text-[10px] text-slate-400 mt-1 truncate">
                                        {item.reason || 'Score in quarantine range (0.40-0.70)'}
                                    </div>
                                </div>
                                <div className="flex gap-2 ml-4 shrink-0">
                                    {DEMO_MODE ? (
                                        <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-slate-100 text-slate-400 text-[10px] font-bold uppercase tracking-wider cursor-not-allowed">
                                            <Lock size={10} />
                                            Demo Mode — Read Only
                                        </span>
                                    ) : (
                                        <>
                                            <button
                                                onClick={() => handleResolve(item.id, 'APPROVED')}
                                                disabled={resolving === item.id}
                                                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-slate-800 text-white text-[10px] font-bold uppercase tracking-wider hover:bg-slate-900 transition-colors disabled:opacity-50"
                                            >
                                                <CheckCircle size={12} />
                                                Approve
                                            </button>
                                            <button
                                                onClick={() => handleResolve(item.id, 'REJECTED')}
                                                disabled={resolving === item.id}
                                                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-slate-500 text-white text-[10px] font-bold uppercase tracking-wider hover:bg-slate-600 transition-colors disabled:opacity-50"
                                            >
                                                <XCircle size={12} />
                                                Reject
                                            </button>
                                        </>
                                    )}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Submissions Table */}
            <div className="bg-white border border-slate-200 rounded-sm shadow-sm overflow-hidden">
                <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr className="bg-slate-50 border-b border-slate-200">
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Submission ID</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Data Hash</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Source Agent</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest text-center">Format</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest text-center">Size</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest text-center">Score</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Verdict</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Time</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                            {submissions && submissions.length > 0 ? (
                                submissions.map((s) => (
                                    <tr key={s.id} className="hover:bg-slate-50 transition-colors">
                                        <td className="py-3 px-5">
                                            <span className="text-xs font-mono text-slate-700 bg-slate-100 px-1.5 py-0.5 rounded">
                                                {s.id?.substring(0, 16)}
                                            </span>
                                        </td>
                                        <td className="py-3 px-5">
                                            <span className="text-[10px] font-mono text-slate-500 select-all" title={s.data_hash}>
                                                {s.data_hash?.substring(0, 16)}...
                                            </span>
                                        </td>
                                        <td className="py-3 px-5">
                                            <span className="text-xs font-bold text-slate-700">{s.source_agent_id || 'Unknown'}</span>
                                        </td>
                                        <td className="py-3 px-5 text-center">
                                            <span className="text-[10px] font-mono font-bold text-slate-500 uppercase bg-slate-100 px-1.5 py-0.5 rounded">
                                                {s.format || '-'}
                                            </span>
                                        </td>
                                        <td className="py-3 px-5 text-center">
                                            <span className="text-[10px] font-mono text-slate-500">
                                                {s.raw_size_bytes ? `${(s.raw_size_bytes / 1024).toFixed(1)}KB` : '-'}
                                            </span>
                                        </td>
                                        <td className="py-3 px-5 text-center">
                                            <span className="text-xs font-mono font-bold text-slate-900">
                                                {s.score != null ? s.score.toFixed(4) : '-'}
                                            </span>
                                        </td>
                                        <td className="py-3 px-5">
                                            <VerdictBadge verdict={s.verdict} score={s.score} />
                                            {s.is_duplicate && (
                                                <span className="ml-2 text-[9px] font-bold text-slate-500 uppercase tracking-widest">DUP</span>
                                            )}
                                        </td>
                                        <td className="py-3 px-5 text-[10px] font-mono text-slate-400">
                                            {s.created_at ? new Date(s.created_at).toLocaleString() : '-'}
                                        </td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan="8" className="py-12 text-center">
                                        <Database size={32} className="mx-auto mb-3 text-slate-300" />
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

export default SubmissionsView;

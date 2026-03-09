import React from 'react';
import { ShieldCheck, CheckCircle, XCircle, ShieldAlert, BarChart3, Layers } from 'lucide-react';

const VerificationView = ({ refineryStats, calibration }) => {
    const stats = refineryStats || {};
    const verdicts = stats.verdicts || {};
    const totalVerdicts = Object.values(verdicts).reduce((a, b) => a + b, 0);
    const health = calibration?.pipeline_health || {};

    // Simulated pillar data from stats
    const pillars = [
        { name: 'Schema Gatekeeper', layer: 'Gate 1', desc: 'Structural + injection detection', weight: 'Veto right', color: 'slate' },
        { name: 'Consistency Analyzer', layer: 'Gate 2', desc: 'Arithmetic + cross-field logic', weight: 'Gate', color: 'slate' },
        { name: 'Forensic Integrity', layer: 'Pillar 1', desc: 'ELA, noise, copy-move, metadata', weight: '30-40%', color: 'slate' },
        { name: 'Logic Triangulation', layer: 'Pillar 2', desc: 'Cross-reference, temporal, domain', weight: '45-60%', color: 'slate' },
        { name: 'Attestation Verifier', layer: 'Pillar 3', desc: 'GPS, depth, device, anti-replay', weight: '25%', color: 'slate' },
        { name: 'Adversarial Challenge', layer: 'Final', desc: "Devil's advocate scoring", weight: 'Penalty', color: 'slate' },
    ];

    return (
        <div className="p-8 max-w-7xl mx-auto space-y-8 animate-fade-in">
            <header className="flex items-end justify-between border-b-2 border-slate-900 pb-6 mb-8">
                <div>
                    <div className="flex items-center gap-3 mb-2">
                        <ShieldCheck className="text-slate-700" size={28} />
                        <h1 className="text-3xl font-black tracking-tight text-slate-900 uppercase">Verification Pipeline</h1>
                    </div>
                    <p className="text-sm font-semibold text-slate-500 tracking-wide uppercase">5-Layer Verification Detail View</p>
                    <p className="text-xs text-slate-400 mt-2 max-w-2xl leading-relaxed normal-case">
                        Every payload passes through five independent verification layers: schema validation with injection detection, cross-field consistency checks, forensic integrity analysis (ELA, metadata, copy-move detection), logic triangulation against known data sources, and adversarial challenge by a devil's advocate AI. The combined score determines the verdict: Rejected, Quarantine, Verified, or Gold.
                    </p>
                </div>
                <div className="flex gap-6 text-right">
                    <div>
                        <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Total Verdicts</div>
                        <div className="text-2xl font-black font-mono text-slate-900">{totalVerdicts}</div>
                    </div>
                </div>
            </header>

            {/* Verdict Stats */}
            <div className="grid grid-cols-4 gap-4">
                <StatCard label="Gold" value={verdicts.gold || 0} color="dark" icon={<CheckCircle size={16} />} />
                <StatCard label="Verified" value={verdicts.verified || 0} color="medium" icon={<CheckCircle size={16} />} />
                <StatCard label="Quarantine" value={verdicts.quarantine || 0} color="light" icon={<ShieldAlert size={16} />} />
                <StatCard label="Rejected" value={verdicts.rejected || 0} color="faint" icon={<XCircle size={16} />} />
            </div>

            {/* Verdict Bar */}
            {totalVerdicts > 0 && (
                <div className="bg-white border border-slate-200 rounded-sm p-6">
                    <div className="flex items-center gap-2 mb-4">
                        <BarChart3 size={16} className="text-slate-600" />
                        <h2 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Verdict Distribution</h2>
                    </div>
                    <div className="flex h-6 rounded overflow-hidden border border-slate-200">
                        {['gold', 'verified', 'quarantine', 'rejected'].map(v => {
                            const count = verdicts[v] || 0;
                            if (count === 0) return null;
                            const colors = { gold: 'bg-slate-900', verified: 'bg-slate-600', quarantine: 'bg-slate-400', rejected: 'bg-slate-200' };
                            return <div key={v} className={colors[v]} style={{ width: `${(count / totalVerdicts) * 100}%` }} title={`${v.toUpperCase()}: ${count}`} />;
                        })}
                    </div>
                </div>
            )}

            {/* Pipeline Layers */}
            <div className="bg-white border border-slate-200 rounded-sm p-6">
                <div className="flex items-center gap-2 mb-6">
                    <Layers size={16} className="text-slate-600" />
                    <h2 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Pipeline Architecture</h2>
                </div>
                <div className="space-y-3">
                    {pillars.map((p, idx) => (
                        <div key={idx} className="flex items-center gap-4 p-4 bg-slate-50 border border-slate-200 rounded-sm">
                            <div className="w-16 text-center">
                                <span className="text-[9px] font-bold text-slate-400 uppercase tracking-widest">{p.layer}</span>
                            </div>
                            <div className="h-8 w-px bg-slate-300" />
                            <div className="flex-1">
                                <div className="text-xs font-bold text-slate-900 uppercase tracking-wide">{p.name}</div>
                                <div className="text-[10px] text-slate-500 mt-0.5">{p.desc}</div>
                            </div>
                            <div className="text-right">
                                <span className="text-[10px] font-mono font-bold text-slate-500 uppercase bg-white px-2 py-1 rounded border border-slate-200">
                                    {p.weight}
                                </span>
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Scoring Thresholds */}
            <div className="bg-white border border-slate-200 rounded-sm p-6">
                <h2 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-4">Scoring Thresholds</h2>
                <div className="grid grid-cols-4 gap-3">
                    <ThresholdCard range="< 0.40" verdict="REJECTED" action="Flag agent" color="faint" />
                    <ThresholdCard range="0.40 - 0.70" verdict="QUARANTINE" action="Human review" color="light" />
                    <ThresholdCard range="0.70 - 0.90" verdict="VERIFIED" action="Blockchain stamp" color="medium" />
                    <ThresholdCard range=">= 0.90" verdict="GOLD" action="Forensic >= 0.80" color="dark" />
                </div>
            </div>
        </div>
    );
};

const StatCard = ({ label, value, color, icon }) => {
    const colorMap = {
        dark: 'bg-slate-200 text-slate-900 border-slate-400',
        medium: 'bg-slate-100 text-slate-700 border-slate-300',
        light: 'bg-slate-100 text-slate-600 border-slate-300',
        faint: 'bg-slate-50 text-slate-400 border-slate-200',
    };
    return (
        <div className={`rounded-sm border p-4 ${colorMap[color] || 'bg-slate-50 text-slate-700 border-slate-200'}`}>
            <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-bold uppercase tracking-widest opacity-70">{label}</span>
                {icon}
            </div>
            <div className="text-xl font-black font-mono">{value}</div>
        </div>
    );
};

const ThresholdCard = ({ range, verdict, action, color }) => {
    const colorMap = {
        faint: 'border-slate-200 bg-slate-50',
        light: 'border-slate-300 bg-slate-100',
        medium: 'border-slate-300 bg-slate-100',
        dark: 'border-slate-400 bg-slate-200',
    };
    return (
        <div className={`rounded-sm border p-3 text-center ${colorMap[color]}`}>
            <div className="text-xs font-mono font-bold text-slate-900 mb-1">{range}</div>
            <div className="text-[10px] font-bold uppercase tracking-widest text-slate-600">{verdict}</div>
            <div className="text-[9px] text-slate-500 mt-1">{action}</div>
        </div>
    );
};

export default VerificationView;

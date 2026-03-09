import React from 'react';
import { X, AlertTriangle, CheckCircle, ShieldAlert, Clock, ChevronRight, Info } from 'lucide-react';

const verdictColors = {
    REJECTED: { bg: 'bg-slate-50', border: 'border-slate-200', text: 'text-slate-400', bar: 'bg-slate-300' },
    QUARANTINE: { bg: 'bg-slate-100', border: 'border-slate-300', text: 'text-slate-500', bar: 'bg-slate-400' },
    VERIFIED: { bg: 'bg-slate-100', border: 'border-slate-300', text: 'text-slate-700', bar: 'bg-slate-600' },
    GOLD: { bg: 'bg-slate-200', border: 'border-slate-400', text: 'text-slate-900', bar: 'bg-slate-800' },
};

const severityStyles = {
    critical: 'bg-slate-200 text-slate-800 border-slate-400',
    high: 'bg-slate-200 text-slate-700 border-slate-300',
    medium: 'bg-slate-100 text-slate-600 border-slate-300',
    low: 'bg-slate-50 text-slate-500 border-slate-200',
};

const traceResultStyles = {
    PASS: { icon: CheckCircle, color: 'text-slate-700', bg: 'bg-slate-100', label: 'PASS' },
    FAIL: { icon: AlertTriangle, color: 'text-slate-500', bg: 'bg-slate-50', label: 'FAIL' },
    VETO: { icon: ShieldAlert, color: 'text-slate-800', bg: 'bg-slate-200', label: 'VETO' },
    WARN: { icon: AlertTriangle, color: 'text-slate-500', bg: 'bg-slate-100', label: 'WARN' },
    SKIPPED: { icon: Clock, color: 'text-slate-400', bg: 'bg-slate-50', label: 'SKIP' },
};

const behaviorTypeLabels = {
    hallucinating: { label: 'Hallucinating Agent', color: 'text-slate-700 bg-slate-100 border-slate-300' },
    badly_programmed: { label: 'Badly Programmed', color: 'text-slate-600 bg-slate-100 border-slate-300' },
    malicious: { label: 'Malicious Agent', color: 'text-slate-800 bg-slate-200 border-slate-400' },
    poisoned_payload: { label: 'Poisoned Payload', color: 'text-slate-700 bg-slate-100 border-slate-300' },
};

const SimulationPanel = ({ result, onDismiss }) => {
    if (!result) return null;

    const vc = verdictColors[result.verdict] || verdictColors.REJECTED;
    const bt = behaviorTypeLabels[result.behavior_type] || { label: result.behavior_type, color: 'text-slate-600 bg-slate-50 border-slate-200' };
    const scorePercent = Math.min(Math.round((result.score || 0) * 100), 100);

    return (
        <div className="bg-white border border-slate-200 rounded-sm shadow-sm animate-fade-in">
            {/* Header */}
            <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
                <div className="flex items-center gap-3">
                    <ShieldAlert size={16} className="text-slate-500" />
                    <h3 className="text-xs font-bold text-slate-700 uppercase tracking-widest">Simulation Result</h3>
                    <span className={`text-[9px] font-bold uppercase tracking-widest px-2 py-0.5 rounded border ${bt.color}`}>
                        {bt.label}
                    </span>
                </div>
                <button onClick={onDismiss} className="p-1 hover:bg-slate-100 rounded transition-colors">
                    <X size={14} className="text-slate-400" />
                </button>
            </div>

            <div className="p-5 space-y-5">
                {/* Verdict + Score */}
                <div className="flex items-center gap-4">
                    <span className={`text-sm font-black uppercase tracking-widest px-3 py-1.5 rounded border ${vc.bg} ${vc.border} ${vc.text}`}>
                        {result.verdict}
                    </span>
                    <div className="flex-1">
                        <div className="flex items-center justify-between mb-1">
                            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Score</span>
                            <span className="text-sm font-black font-mono text-slate-900">{scorePercent}%</span>
                        </div>
                        <div className="w-full bg-slate-100 rounded-full h-2">
                            <div
                                className={`h-2 rounded-full transition-all duration-700 ${vc.bar}`}
                                style={{ width: `${scorePercent}%` }}
                            />
                        </div>
                    </div>
                </div>

                {/* Summary + Error Code */}
                <div className={`p-3 rounded border ${vc.bg} ${vc.border}`}>
                    <div className="flex items-start gap-2">
                        <Info size={14} className={`mt-0.5 shrink-0 ${vc.text}`} />
                        <div>
                            <p className={`text-xs font-bold ${vc.text}`}>{result.summary}</p>
                            {result.error_code && result.error_code !== 'PASS' && (
                                <span className="text-[9px] font-mono text-slate-500 mt-1 inline-block">
                                    Code: {result.error_code}
                                </span>
                            )}
                        </div>
                    </div>
                </div>

                {/* Field Issues */}
                {result.field_issues && result.field_issues.length > 0 && (
                    <div>
                        <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-2">
                            Field Issues ({result.field_issues.length})
                        </h4>
                        <div className="border border-slate-200 rounded-sm overflow-hidden">
                            <table className="w-full text-left">
                                <thead>
                                    <tr className="bg-slate-50 border-b border-slate-200">
                                        <th className="py-2 px-3 text-[9px] font-bold text-slate-500 uppercase tracking-widest">Field</th>
                                        <th className="py-2 px-3 text-[9px] font-bold text-slate-500 uppercase tracking-widest">Issue</th>
                                        <th className="py-2 px-3 text-[9px] font-bold text-slate-500 uppercase tracking-widest">Severity</th>
                                        <th className="py-2 px-3 text-[9px] font-bold text-slate-500 uppercase tracking-widest">Detail</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-100">
                                    {result.field_issues.map((fi, i) => {
                                        const ss = severityStyles[fi.severity] || severityStyles.medium;
                                        return (
                                            <tr key={i} className="hover:bg-slate-50">
                                                <td className="py-2 px-3 text-[10px] font-mono font-bold text-slate-700">{fi.field}</td>
                                                <td className="py-2 px-3 text-[10px] font-mono text-slate-600">{fi.issue}</td>
                                                <td className="py-2 px-3">
                                                    <span className={`text-[8px] font-bold uppercase tracking-widest px-1.5 py-0.5 rounded border ${ss}`}>
                                                        {fi.severity}
                                                    </span>
                                                </td>
                                                <td className="py-2 px-3 text-[10px] text-slate-500 max-w-xs truncate">{fi.detail}</td>
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        </div>
                    </div>
                )}

                {/* Pipeline Trace */}
                {result.pipeline_trace && result.pipeline_trace.length > 0 && (
                    <div>
                        <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-2">Pipeline Trace</h4>
                        <div className="space-y-1">
                            {result.pipeline_trace.map((step, i) => {
                                const rs = traceResultStyles[step.result] || traceResultStyles.SKIPPED;
                                const Icon = rs.icon;
                                return (
                                    <div key={i} className="flex items-center gap-2">
                                        {/* Vertical connector */}
                                        <div className="flex flex-col items-center w-5">
                                            <div className={`w-5 h-5 rounded-full flex items-center justify-center ${rs.bg}`}>
                                                <Icon size={11} className={rs.color} />
                                            </div>
                                            {i < result.pipeline_trace.length - 1 && (
                                                <div className="w-px h-3 bg-slate-200" />
                                            )}
                                        </div>
                                        {/* Layer info */}
                                        <div className="flex-1 flex items-center justify-between py-1">
                                            <span className="text-[10px] font-bold text-slate-600">{step.layer}</span>
                                            <div className="flex items-center gap-2">
                                                {step.score != null && (
                                                    <span className="text-[10px] font-mono text-slate-400">
                                                        {step.score.toFixed(4)}
                                                    </span>
                                                )}
                                                <span className={`text-[8px] font-black uppercase tracking-widest px-1.5 py-0.5 rounded ${rs.bg} ${rs.color}`}>
                                                    {rs.label}
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    </div>
                )}

                {/* Recommendation */}
                {result.recommendation && (
                    <div className="bg-slate-100 border border-slate-300 rounded p-3">
                        <div className="flex items-start gap-2">
                            <ChevronRight size={12} className="text-slate-600 mt-0.5 shrink-0" />
                            <p className="text-xs text-slate-700">{result.recommendation}</p>
                        </div>
                    </div>
                )}

                {/* Proof hash */}
                {result.proof_hash && (
                    <div className="text-[9px] font-mono text-slate-400 border-t border-slate-100 pt-3">
                        Proof: {result.proof_hash.substring(0, 32)}...
                    </div>
                )}
            </div>
        </div>
    );
};

export default SimulationPanel;

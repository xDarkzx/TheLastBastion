import React from 'react';
import { Search, Zap, CheckCircle, ArrowUpRight, Activity, Loader2, Bot, Globe, Shield } from 'lucide-react';
import UnifiedSwarmGrid from '../common/UnifiedSwarmGrid';

const IntelligenceHub = ({ loading, results, workers, tasks, logs, onTriggerDiscovery }) => {
    return (
        <section className="flex-1 flex flex-col relative bg-workspace overflow-hidden h-full">
            {/* Professional Breadcrumb Line */}
            <div className="h-14 flex items-center justify-between px-10 bg-surface border-b border-border shadow-sm z-10">
                <div className="flex items-center gap-4">
                    <span className="text-[10px] font-black text-text-secondary/40 tracking-[0.2em] uppercase">Intelligence Hub</span>
                    <div className="h-3 w-[1px] bg-border" />
                    <div className="flex items-center gap-2.5">
                        <div className={`w-2 h-2 rounded-full ${loading ? 'bg-accent animate-pulse' : 'bg-slate-600'}`} />
                        <span className="text-[10px] font-black text-text-primary uppercase tracking-widest">
                            {loading ? 'Interrogating Network...' : 'Data Synthesis Ready'}
                        </span>
                    </div>
                </div>
                <div className="flex gap-3">
                    <div className="text-[9px] font-black text-text-secondary/60 px-4 py-1.5 rounded-full bg-workspace border border-border uppercase tracking-widest italic">Node: Primary</div>
                </div>
            </div>

            <div className="flex-1 overflow-y-auto p-12 thin-scrollbar bg-workspace">
                {loading ? (
                    <div className="max-w-6xl mx-auto flex flex-col gap-16 animate-[fade-in_400ms_ease-out]">
                        <div className="text-center space-y-6">
                            <div className="inline-flex items-center gap-3 px-5 py-2 bg-accent/5 border border-accent/10 rounded-full text-accent text-[10px] font-black uppercase tracking-[0.3em] shadow-sm">
                                <Activity size={14} className="animate-pulse" /> Live System Telemetry
                            </div>
                            <h3 className="text-5xl font-black text-text-primary tracking-tighter uppercase leading-none">Robotic Audit Active</h3>
                            <p className="text-text-secondary text-lg max-w-2xl mx-auto font-medium leading-relaxed font-mono opacity-70">
                                Swarm agents are currently executing regional data extraction. Mapping tariff structures and pricing variances...
                            </p>
                        </div>

                        {/* High-Fidelity Grid */}
                        <div className="bg-surface border border-border rounded-[40px] overflow-hidden shadow-2xl">
                            <UnifiedSwarmGrid workers={workers} tasks={tasks} logs={logs} />
                        </div>

                        {/* Terminal Style Log */}
                        <div className="bg-accent text-white rounded-3xl p-10 shadow-2xl relative overflow-hidden">
                            <div className="absolute top-0 right-0 p-10 opacity-5">
                                <Shield size={160} />
                            </div>
                            <div className="relative z-10">
                                <div className="flex items-center gap-3 mb-6">
                                    <div className="w-2 h-2 bg-slate-400 rounded-full animate-pulse" />
                                    <span className="text-[10px] font-black uppercase tracking-[0.3em] opacity-60">Industrial Packet Stream</span>
                                </div>
                                <div className="font-mono text-[11px] space-y-2 opacity-80">
                                    {Array.isArray(logs) && logs.slice(0, 3).map((log, i) => (
                                        <p key={i} className="flex gap-6 border-l-2 border-white/10 pl-4 py-1">
                                            <span className="opacity-40 shrink-0">[{new Date(log.timestamp).toLocaleTimeString()}]</span>
                                            <span className="text-slate-300 font-bold uppercase truncate w-24">
                                                {log.worker_id?.slice(0, 8) || 'KERNEL'}
                                            </span>
                                            <span className="truncate">{log.message}</span>
                                        </p>
                                    ))}
                                </div>
                            </div>
                        </div>
                    </div>
                ) : Array.isArray(results) && results.length > 0 ? (
                    <div className="w-full max-w-7xl mx-auto animate-[fade-in_400ms_ease-out]">
                        <div className="flex justify-between items-end mb-12">
                            <div>
                                <h1 className="text-6xl font-black text-text-primary tracking-tighter uppercase leading-none mb-4">Strategic Briefing</h1>
                                <p className="text-text-secondary text-xl font-medium italic opacity-60">Synthesis complete. {results.length} regional providers mapped.</p>
                            </div>
                            <div className="flex flex-col items-end gap-3">
                                <span className="text-[10px] font-black text-slate-700 bg-slate-100 px-6 py-2.5 rounded-2xl border border-slate-200 uppercase tracking-[2px] flex items-center gap-3 shadow-sm">
                                    <CheckCircle size={14} strokeWidth={3} /> Robotic Verification Alpha
                                </span>
                            </div>
                        </div>

                        <div className="bg-surface border border-border rounded-[2.5rem] overflow-hidden shadow-2xl">
                            <table className="w-full border-collapse text-left">
                                <thead>
                                    <tr className="bg-workspace/50 border-b border-border text-text-secondary uppercase tracking-[0.2em] text-[9px] font-black">
                                        <th className="px-10 py-8">Swarm Node</th>
                                        <th className="px-10 py-8">Annual Estimate</th>
                                        <th className="px-10 py-8">Tariff Decomposition</th>
                                        <th className="px-10 py-8 text-right">Intel Access</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-border/50">
                                    {results.map((item, idx) => (
                                        <tr key={idx} className="hover:bg-workspace/80 transition-all group">
                                            <td className="px-10 py-10">
                                                <div className="flex items-center gap-6">
                                                    <div className="w-20 h-20 rounded-3xl bg-surface border-2 border-border flex items-center justify-center text-3xl font-black text-accent shadow-sm group-hover:scale-105 transition-transform">
                                                        {item.provider[0]}
                                                    </div>
                                                    <div>
                                                        <span className="font-black text-2xl text-text-primary tracking-tighter block mb-1">{item.provider}</span>
                                                        <div className="flex items-center gap-2">
                                                            <div className="w-2 h-2 rounded-full bg-slate-600" />
                                                            <span className="text-[10px] text-text-secondary font-black uppercase tracking-widest opacity-40">Provider Mapped</span>
                                                        </div>
                                                    </div>
                                                </div>
                                            </td>
                                            <td className="px-10 py-10">
                                                <div className={`inline-flex flex-col p-6 rounded-3xl border ${idx === 0 ? 'bg-accent text-white border-white/10 shadow-2xl shadow-accent/20' : 'bg-surface border-border'}`}>
                                                    <span className="text-[9px] font-black uppercase tracking-[0.2em] opacity-60 mb-1 leading-none">Estimated Total</span>
                                                    <span className="text-3xl font-black tracking-tighter leading-none italic">${item.total_estimated_annual?.toLocaleString() || 0}</span>
                                                </div>
                                            </td>
                                            <td className="px-10 py-10">
                                                <div className="flex gap-10 font-mono text-[13px]">
                                                    <div className="flex flex-col"><span className="text-[9px] font-black text-text-secondary/40 uppercase tracking-widest mb-1 italic">Fixed</span> <span className="font-bold font-black text-text-primary text-lg tracking-tighter leading-none">${item.breakdown?.fixed || 0}</span></div>
                                                    <div className="flex flex-col"><span className="text-[9px] font-black text-text-secondary/40 uppercase tracking-widest mb-1 italic">Variable</span> <span className="font-bold font-black text-text-primary text-lg tracking-tighter leading-none">${item.breakdown?.peak || 0}</span></div>
                                                </div>
                                            </td>
                                            <td className="px-10 py-10 text-right">
                                                <button className="px-8 py-4 bg-accent hover:bg-zinc-800 text-white text-[10px] font-black rounded-2xl transition-all uppercase tracking-[0.2em] shadow-xl shadow-accent/20 group-hover:scale-105">
                                                    Exploration Mode
                                                </button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                ) : (
                    <div className="flex flex-col items-center justify-center h-full text-center max-w-3xl mx-auto py-32">
                        <div className="w-32 h-32 bg-surface border-2 border-dashed border-border rounded-[40px] flex items-center justify-center mb-12 shadow-sm relative group cursor-pointer" onClick={onTriggerDiscovery}>
                            <Zap size={60} strokeWidth={1.5} className="text-text-secondary/30 group-hover:text-accent group-hover:scale-120 transition-all" />
                        </div>
                        <h3 className="text-6xl font-black text-text-primary tracking-tighter uppercase leading-tight mb-6">Briefing Pipeline Offline</h3>
                        <p className="text-text-secondary font-medium text-xl leading-relaxed italic opacity-50 mb-12 max-w-xl mx-auto">
                            "Currently awaiting strategic directives. Deploy a robotic swarm to interrogating regional markets."
                        </p>
                        <button
                            onClick={onTriggerDiscovery}
                            className="px-12 py-6 bg-accent text-white rounded-2xl font-black uppercase tracking-[0.3em] shadow-[0_20px_40px_rgba(15,23,42,0.1)] hover:bg-zinc-800 hover:-translate-y-1 transition-all flex items-center gap-5 group"
                        >
                            <Bot size={24} className="group-hover:rotate-12 transition-transform" /> Initialize Swarm
                        </button>
                    </div>
                )}
            </div>
        </section>
    );
};

export default IntelligenceHub;

import React from 'react';
import {
    Zap,
    Cpu,
    Activity,
    Database,
    Clock,
    AlertCircle,
    Link2,
    CheckCircle2,
    ChevronRight,
    Search,
    Settings2,
    RefreshCcw,
    Loader2
} from 'lucide-react';

const UnifiedSwarmGrid = ({ tasks, workers, logs }) => {
    // Define the Swarm Pipeline Logic
    const pipeline = [
        { id: 'gather', label: 'Resource Gathering Bot', icon: Search, taskType: 'SCRAPE', program: 'discovery_agent.v4.bin' },
        { id: 'clean', label: 'Data Registry Cleaner', icon: Database, taskType: 'CLEAN', program: 'sanitizer_prime.so' },
        { id: 'compare', label: 'Price Analytics Engine', icon: Zap, taskType: 'COMPARE', program: 'comparator_delta.py' },
        { id: 'dispatch', label: 'Intelligence Dispatch', icon: Activity, taskType: 'SELL', program: 'intel_relay.node' }
    ];

    const getStageRealtimeData = (stage, idx) => {
        // 1. Find if any worker is currently assigned to this stage's task type
        const activeWorker = Array.isArray(workers) ? workers.find(w => w.current_task && w.current_task.includes(stage.taskType)) : null;

        // 2. Find the latest diagnostic log for this stage
        const relevantLog = Array.isArray(logs) ? logs.find(log =>
            log.message?.toUpperCase().includes(stage.taskType) ||
            (activeWorker && log.worker_id === activeWorker.id)
        ) : null;

        // 3. Determine Status
        let status = 'pending';
        let progress = 0;
        let diagnosticMsg = relevantLog ? relevantLog.message : 'Monitoring market activity...';

        if (activeWorker) {
            status = activeWorker.status === 'error' ? 'error' : 'busy';
            progress = activeWorker.load || 45; // Default to 45 if active
        } else {
            // Logic for "Awaiting" - if a previous stage is active or has tasks
            const prevStage = pipeline[idx - 1];
            if (prevStage) {
                const prevTasks = tasks?.[prevStage.taskType] || 0;
                const prevActive = Array.isArray(workers) ? workers.find(w => w.current_task && w.current_task.includes(prevStage.taskType)) : null;
                if (prevTasks > 0 || prevActive) {
                    status = 'awaiting';
                    diagnosticMsg = `Awaiting output from ${prevStage.label}...`;
                }
            }
        }

        // Explicit check for "Stuck" logs
        if (relevantLog && (relevantLog.level === 'error' || relevantLog.message?.includes('failed') || relevantLog.message?.includes('timeout'))) {
            status = 'error';
            diagnosticMsg = relevantLog.message;
        }

        return { status, progress, diagnosticMsg, workerId: activeWorker?.id, activeWorker };
    };

    const renderStatus = (status, action, progress) => {
        switch (status) {
            case 'busy':
                return (
                    <div className="flex flex-col gap-1 w-full animate-[fade-in_300ms_ease-out]">
                        <div className="flex justify-between items-center mb-1">
                            <span className="text-[10px] font-black text-slate-700 uppercase animate-pulse">Live Action</span>
                            <span className="text-[10px] font-mono text-text-primary px-1.5 py-0.5 bg-slate-100 rounded border border-slate-200">{progress}%</span>
                        </div>
                        <div className="h-1.5 w-full bg-slate-100 rounded-xl overflow-hidden border border-slate-200">
                            <div className="h-full bg-slate-600 transition-all duration-1000" style={{ width: `${progress}%` }} />
                        </div>
                        <p className="text-[11px] font-bold text-text-primary mt-1 line-clamp-1 flex items-center gap-1">
                            <Loader2 size={10} className="animate-spin" /> {action}
                        </p>
                    </div>
                );
            case 'awaiting':
                return (
                    <div className="flex items-center gap-2 opacity-60 italic py-2">
                        <Link2 size={12} className="text-text-secondary" />
                        <span className="text-[11px] font-bold text-text-secondary">{action}</span>
                    </div>
                );
            case 'error':
                return (
                    <div className="flex flex-col gap-1 py-1">
                        <div className="flex items-center gap-1.5 text-slate-500">
                            <AlertCircle size={14} className="animate-bounce" />
                            <span className="text-[10px] font-black uppercase tracking-widest">Diagnostic Alert: Bot Stuck</span>
                        </div>
                        <p className="text-[11px] font-bold text-slate-400 bg-slate-50 px-2 py-1.5 rounded border border-slate-200 mt-1 shadow-sm leading-tight">
                            {action}
                        </p>
                    </div>
                );
            case 'pending':
                return (
                    <div className="flex flex-col gap-1 opacity-40 py-2">
                        <span className="text-[10px] font-black text-text-secondary uppercase">Pending Deployment</span>
                        <div className="h-1 w-24 bg-hover rounded-xl overflow-hidden">
                            <div className="h-full bg-border w-1/3" />
                        </div>
                    </div>
                );
            default:
                return (
                    <div className="flex flex-col gap-1 py-2">
                        <span className="text-[10px] font-black text-text-secondary uppercase">Standby</span>
                        <p className="text-[11px] font-medium text-text-secondary">Ready for initialization...</p>
                    </div>
                );
        }
    };

    return (
        <div className="bg-white border border-border rounded-xl shadow-2xl shadow-slate-100/20 overflow-hidden">
            <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left">
                    <thead>
                        <tr className="bg-surface/80 backdrop-blur-md border-b border-border">
                            <th className="px-8 py-5 text-[10px] font-black text-text-secondary uppercase tracking-[2px]">Swarm Node</th>
                            <th className="px-8 py-5 text-[10px] font-black text-text-secondary uppercase tracking-[2px]">Observability & Progress</th>
                            <th className="px-8 py-5 text-[10px] font-black text-text-secondary uppercase tracking-[2px]">Node Analytics</th>
                            <th className="px-8 py-5 text-[10px] font-black text-text-secondary uppercase tracking-[2px]">Operational Status</th>
                            <th className="px-8 py-5 text-[10px] font-black text-text-secondary uppercase tracking-[2px] text-right">Action</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-border/50">
                        {pipeline.map((stage, idx) => {
                            const { status, progress, diagnosticMsg, workerId } = getStageRealtimeData(stage, idx);

                            return (
                                <tr key={stage.id} className={`group transition-all hover:bg-hover/10 ${status === 'busy' ? 'bg-slate-100/20' : ''}`}>
                                    <td className="px-8 py-7">
                                        <div className="flex items-center gap-5">
                                            <div className={`w-14 h-14 rounded-xl flex items-center justify-center border-2 transition-all ${status === 'busy' ? 'bg-slate-700 border-slate-600 shadow-xl shadow-slate-200 text-white' :
                                                status === 'error' ? 'bg-slate-500 border-slate-400 shadow-xl shadow-slate-200 text-white' :
                                                    status === 'awaiting' ? 'bg-white border-border border-dashed text-text-secondary opacity-50' :
                                                        'bg-surface border-border text-text-secondary'
                                                }`}>
                                                <stage.icon size={24} strokeWidth={status === 'busy' ? 2.5 : 1.5} className={status === 'busy' ? 'animate-pulse' : ''} />
                                            </div>
                                            <div>
                                                <p className={`font-bold text-lg tracking-tight ${status === 'awaiting' ? 'text-text-secondary opacity-60' : 'text-text-primary'}`}>
                                                    {stage.label}
                                                </p>
                                                <div className="flex items-center gap-2 mt-1">
                                                    <span className="text-[10px] font-black text-text-secondary uppercase tracking-widest">
                                                        {workerId ? `NODE ID: ${workerId.slice(0, 8)}` : `STAGE ${idx + 1}-SA`}
                                                    </span>
                                                    {status === 'busy' && <span className="w-1.5 h-1.5 bg-slate-600 rounded-xl animate-ping" />}
                                                </div>
                                            </div>
                                        </div>
                                    </td>

                                    <td className="px-8 py-7 max-w-md">
                                        {renderStatus(status, diagnosticMsg, progress)}
                                    </td>

                                    <td className="px-8 py-7">
                                        <div className="flex flex-col gap-2">
                                            <div className="flex items-center gap-2 text-text-secondary">
                                                <Clock size={12} className="opacity-40" />
                                                <span className="text-[10px] font-bold tabular-nums">
                                                    Uptime: {status === 'busy' && activeWorker?.task_started_at ? (
                                                        (() => {
                                                            const start = new Date(activeWorker.task_started_at);
                                                            const diff = Math.floor((new Date() - start) / 1000);
                                                            const mins = Math.floor(diff / 60).toString().padStart(2, '0');
                                                            const secs = (diff % 60).toString().padStart(2, '0');
                                                            return `${mins}:${secs}s`;
                                                        })()
                                                    ) : '00:00s'}
                                                </span>
                                            </div>
                                            <div className="flex items-center gap-2 text-text-secondary">
                                                <Cpu size={12} className="opacity-40" />
                                                <span className="text-[10px] font-bold truncate max-w-[120px]">
                                                    {status === 'busy' ? stage.program : 'Runtime Idle'}
                                                </span>
                                            </div>
                                        </div>
                                    </td>

                                    <td className="px-8 py-7">
                                        <div className="flex items-center gap-3">
                                            <div className={`px-4 py-2 rounded-xl border text-[10px] font-black uppercase tracking-[2px] flex items-center gap-2 transition-all ${status === 'busy' ? 'bg-slate-700 text-white border-slate-600 shadow-lg shadow-slate-100' :
                                                status === 'error' ? 'bg-slate-500 text-white border-slate-400 shadow-lg shadow-slate-100' :
                                                    status === 'awaiting' ? 'bg-white text-text-secondary border-dashed border-border opacity-50' :
                                                        'bg-surface text-text-secondary border-border shadow-inner'
                                                }`}>
                                                {status === 'busy' ? 'Active' :
                                                    status === 'error' ? 'Stuck / Failed' :
                                                        status === 'awaiting' ? 'Awaiting Data' : 'Standby'}
                                            </div>
                                        </div>
                                    </td>

                                    <td className="px-8 py-7 text-right">
                                        <button className="p-3 bg-surface hover:bg-white border border-border rounded-xl transition-all shadow-sm hover:shadow-md hover:text-accent group/btn">
                                            <ChevronRight size={18} className="group-hover:translate-x-1 transition-transform" />
                                        </button>
                                    </td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            </div>

            {/* Diagnostics Footer */}
            <div className="px-8 py-5 bg-text-primary flex items-center justify-between">
                <div className="flex items-center gap-8">
                    <div className="flex items-center gap-3">
                        <Activity size={16} className="text-slate-300" />
                        <span className="text-white text-[10px] font-black uppercase tracking-[3px]">Swarm Health: Optimized</span>
                    </div>
                    <div className="flex items-center gap-3">
                        <RefreshCcw size={16} className="text-slate-300 animate-spin-slow" />
                        <span className="text-white text-[10px] font-black uppercase tracking-[3px]">Conveyor Speed: 5.2k Tasks/Hr</span>
                    </div>
                </div>
                <div className="flex items-center gap-3">
                    <span className="text-white/40 text-[9px] font-bold uppercase tracking-widest">Global Telemetry Link Encrypted</span>
                    <div className="w-2 h-2 bg-slate-400 rounded-xl shadow-[0_0_8px_rgba(100,116,139,0.8)]" />
                </div>
            </div>
        </div>
    );
};

export default UnifiedSwarmGrid;

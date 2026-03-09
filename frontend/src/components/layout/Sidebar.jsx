import React from 'react';
import { Cpu, Terminal, Zap } from 'lucide-react';
import WorkerCard from '../common/WorkerCard';
import TelemetryFeed from '../common/TelemetryFeed';

const Sidebar = ({ workers, logs }) => {
    return (
        <div className="flex h-full w-full gap-8">
            {/* Bot Fleet List */}
            <div className="flex-1 flex flex-col min-w-0">
                <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                        <Cpu size={16} className="text-accent" />
                        <span className="text-[10px] font-bold text-text-secondary tracking-[2px] uppercase">Active Fleet Registry</span>
                    </div>
                    <div className="flex items-center gap-1.5 bg-slate-100 px-2.5 py-1 rounded-full border border-slate-200">
                        <div className="w-1.5 h-1.5 bg-slate-600 rounded-full animate-pulse" />
                        <span className="text-[9px] font-bold text-slate-700 uppercase">LIVE</span>
                    </div>
                </div>
                <div className="flex-1 overflow-y-auto space-y-4 thin-scrollbar pr-2">
                    {Array.isArray(workers) && workers.length > 0 ? workers.map(w => (
                        <WorkerCard key={w.id} worker={w} />
                    )) : (
                        <div className="h-40 flex flex-col items-center justify-center text-center bg-surface border border-dashed border-border rounded-2xl opacity-40 grayscale translate-y-0 active:scale-100 transition-all select-none">
                            <Cpu size={32} strokeWidth={1.5} className="mb-3 text-text-secondary" />
                            <p className="text-[10px] font-bold uppercase tracking-widest text-text-secondary">No active bots detected</p>
                        </div>
                    )}
                </div>
            </div>

            {/* Telemetry Tunnel */}
            <div className="w-[450px] flex flex-col min-w-0">
                <div className="flex items-center justify-between mb-4 px-1">
                    <div className="flex items-center gap-2">
                        <Terminal size={16} className="text-text-secondary" />
                        <span className="text-[10px] font-bold text-text-secondary tracking-[2px] uppercase">Robotic Telemetry Stream</span>
                    </div>
                    <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-text-secondary/50 font-mono text-[9px] font-bold uppercase tracking-[2px]">
                        Pipeline: Encrypted
                    </div>
                </div>
                <div className="flex-1">
                    <TelemetryFeed logs={logs} />
                </div>
            </div>
        </div>
    );
};

export default Sidebar;

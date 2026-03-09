import React, { useEffect, useRef } from 'react';

const TelemetryFeed = ({ logs }) => {
    const scrollRef = useRef(null);

    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [logs]);

    const getLevelStyle = (level) => {
        switch (level.toLowerCase()) {
            case 'success': return 'border-slate-600 text-slate-600 bg-slate-100/50';
            case 'error': return 'border-slate-400 text-slate-500 bg-slate-50/50';
            case 'warning': return 'border-slate-500 text-slate-600 bg-slate-100/50';
            default: return 'border-accent text-accent bg-accent/5';
        }
    };

    return (
        <div className="flex flex-col h-full bg-surface/50 font-mono text-[11px] overflow-hidden rounded-xl border border-border">
            <div ref={scrollRef} className="flex-1 overflow-y-auto p-4 space-y-2 thin-scrollbar">
                {Array.isArray(logs) ? logs.map((log, idx) => (
                    <div key={idx} className={`pl-3 py-1.5 border-l-2 ${getLevelStyle(log.level)} transition-all duration-200 hover:bg-white/50 rounded-r-lg`}>
                        <div className="flex items-center gap-3 mb-0.5">
                            <span className="text-text-secondary/40 text-[9px]">[{new Date(log.timestamp).toLocaleTimeString()}]</span>
                            <span className="font-bold uppercase tracking-widest text-[9px] opacity-70">{log.tag}</span>
                        </div>
                        <span className="leading-relaxed block pr-2 text-text-primary/80 font-medium">{log.message}</span>
                    </div>
                )) : (
                    <div className="h-full flex flex-col items-center justify-center text-[10px] text-text-secondary uppercase tracking-[3px] font-bold opacity-30">
                        Awaiting Telemetry Feed
                    </div>
                )}
            </div>
        </div>
    );
};

export default TelemetryFeed;

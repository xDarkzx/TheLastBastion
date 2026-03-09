import React from 'react';
import { Cpu, Zap, Activity, AlertTriangle } from 'lucide-react';

const WorkerCard = ({ worker }) => {
    const getStatusStyles = (status) => {
        switch (status.toLowerCase()) {
            case 'active':
            case 'idle': return 'text-slate-600 bg-slate-100 border-slate-200';
            case 'busy': return 'text-accent bg-accent/5 border-accent/20';
            case 'error': return 'text-slate-500 bg-slate-50 border-slate-200';
            default: return 'text-text-secondary bg-hover border-border';
        }
    };

    return (
        <div className={`p-4 rounded-xl border border-border bg-white hover:border-accent transition-all group ${worker.status === 'busy' ? 'shadow-sm' : 'opacity-80 grayscale hover:grayscale-0'}`}>
            <div className="flex justify-between items-start mb-4">
                <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg ${getStatusStyles(worker.status)}`}>
                        <Cpu size={16} />
                    </div>
                    <div>
                        <p className="text-sm font-bold text-text-primary group-hover:text-accent transition-colors capitalize">
                            {worker.id.slice(0, 8)}
                        </p>
                        <p className="text-[10px] font-mono text-text-secondary uppercase tracking-tight font-bold">{worker.type || 'Comparison Bot'}</p>
                    </div>
                </div>
                <span className={`text-[9px] px-2 py-0.5 rounded-full font-bold uppercase border tracking-widest ${getStatusStyles(worker.status)}`}>
                    {worker.status}
                </span>
            </div>

            <div className="space-y-3">
                <div className="flex items-center gap-2">
                    <Activity size={12} className="text-text-secondary" />
                    <span className="text-[11px] font-medium text-text-primary truncate">
                        {worker.task || 'Active Monitor'}
                    </span>
                </div>

                {worker.load && (
                    <div>
                        <div className="flex justify-between text-[9px] font-bold text-text-secondary mb-1 uppercase tracking-tighter">
                            <span>Intelligence Load</span>
                            <span>{worker.load}%</span>
                        </div>
                        <div className="h-1 bg-hover rounded-full overflow-hidden">
                            <div
                                className="h-full bg-accent transition-all duration-700 ease-out"
                                style={{ width: `${worker.load}%` }}
                            />
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default WorkerCard;

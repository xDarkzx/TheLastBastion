import React from 'react';
import { Search, Database, Activity, TrendingUp } from 'lucide-react';

const FactoryBelt = ({ tasks }) => {
    const nodes = [
        { label: 'Market Discovery Bots', val: tasks.SCRAPE, icon: Search, color: 'text-slate-600 bg-slate-100 border-slate-200' },
        { label: 'Data Cleaners', val: tasks.CLEAN, icon: Database, color: 'text-slate-600 bg-slate-100 border-slate-200' },
        { label: 'Comparison Engine', val: tasks.COMPARE, icon: Activity, color: 'text-slate-500 bg-slate-50 border-slate-200' },
        { label: 'Seller Dispatch', val: tasks.SELL, icon: TrendingUp, color: 'text-slate-600 bg-slate-100 border-slate-200' }
    ];

    return (
        <div className="grid grid-cols-4 gap-4 p-4 w-full">
            {nodes.map((node, idx) => (
                <div
                    key={idx}
                    className={`p-6 rounded-2xl border transition-all duration-300 ${node.val > 0 ? 'bg-white border-accent shadow-sm ring-1 ring-accent/5' : 'bg-surface border-border grayscale opacity-50'}`}
                >
                    <div className="flex justify-between items-start mb-6">
                        <div className={`p-3 rounded-xl border ${node.val > 0 ? node.color : 'bg-hover border-border'}`}>
                            <node.icon size={20} strokeWidth={node.val > 0 ? 2.5 : 2} />
                        </div>
                        <span className="text-[9px] font-bold text-text-secondary uppercase tracking-[2px]">Node 0{idx + 1}</span>
                    </div>

                    <div>
                        <p className="text-[10px] font-bold text-text-secondary uppercase tracking-widest mb-1">{node.label}</p>
                        <div className="flex items-baseline gap-2">
                            <span className={`text-4xl font-bold tracking-tight ${node.val > 0 ? 'text-text-primary' : 'text-text-secondary'}`}>{node.val}</span>
                            <span className="text-[10px] font-medium text-text-secondary uppercase tracking-widest">Active Tasks</span>
                        </div>
                    </div>

                    <div className="mt-6 h-1 bg-hover rounded-full overflow-hidden">
                        <div
                            className="h-full bg-accent transition-all duration-1000 ease-out"
                            style={{ width: `${Math.min(node.val * 20, 100)}%` }}
                        />
                    </div>
                </div>
            ))}
        </div>
    );
};

export default FactoryBelt;

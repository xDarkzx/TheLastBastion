import React from 'react';
import { RefreshCcw } from 'lucide-react';

const Header = ({ activeWorkers, pendingTasks }) => {
    return (
        <header className="h-16 flex items-center justify-between px-8 bg-black border-b border-carbon-border z-50">
            <div className="flex items-center gap-6">
                <div className="flex items-center gap-3">
                    <div className="w-4 h-4 bg-carbon-accent rounded-[2px]" />
                    <span className="font-bold text-sm tracking-[3px] text-white">LAST BASTION COMMAND</span>
                </div>
                <div className="h-6 w-[1px] bg-carbon-border" />
                <div className="flex items-center gap-3 px-3 py-1.5 bg-carbon-card rounded border border-carbon-border">
                    <div className="w-2 h-2 bg-slate-500 rounded-full animate-pulse" />
                    <span className="text-[10px] font-mono text-carbon-muted uppercase">Backbone: <span className="text-carbon-accent">Distributed-v8</span></span>
                </div>
            </div>

            <div className="flex items-center gap-12">
                <div className="flex gap-10">
                    <div className="flex flex-col">
                        <span className="text-[10px] text-carbon-muted uppercase tracking-widest font-bold">Bot Fleet</span>
                        <span className="text-xl font-semibold text-white leading-none mt-1">{activeWorkers}</span>
                    </div>
                    <div className="flex flex-col">
                        <span className="text-[10px] text-carbon-muted uppercase tracking-widest font-bold">Tasks on Belt</span>
                        <span className="text-xl font-semibold text-white leading-none mt-1">{pendingTasks}</span>
                    </div>
                    <div className="flex flex-col">
                        <span className="text-[10px] text-carbon-muted uppercase tracking-widest font-bold">Production Yield</span>
                        <span className="text-xl font-semibold text-slate-300 leading-none mt-1">99.9%</span>
                    </div>
                </div>

                <button className="flex items-center gap-2 bg-carbon-card border border-carbon-border px-4 py-2 rounded-full text-xs font-bold hover:bg-carbon-hover transition-all">
                    <RefreshCcw size={14} className="text-carbon-accent" />
                    GLOBAL SYNC
                </button>
            </div>
        </header>
    );
};

export default Header;

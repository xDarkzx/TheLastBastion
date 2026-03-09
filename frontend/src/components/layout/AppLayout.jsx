import React from 'react';
import SidebarNav from './SidebarNav';

const AppLayout = ({ children, stats }) => {
    return (
        <div className="flex min-h-screen bg-white text-slate-900">
            <SidebarNav stats={stats} />

            <main className="flex-1 ml-64 flex flex-col h-screen overflow-hidden">
                <header className="h-14 flex items-center justify-between px-8 bg-white border-b border-slate-100 shrink-0 z-40">
                    <div className="flex items-center gap-4">
                        <div className="flex items-center gap-3 text-slate-400 font-bold text-[10px]">
                            <span className="uppercase tracking-[0.2em] text-slate-900">Universal Factory</span>
                            <div className="h-4 w-[1px] bg-slate-200" />
                            <span className="uppercase tracking-[0.2em] font-mono text-slate-500">v5.0.0-PRO</span>
                        </div>
                    </div>

                    <div className="flex items-center gap-6">
                        <div className="flex items-center gap-4">
                            <div className="w-8 h-8 bg-slate-50 flex items-center justify-center text-[10px] font-bold text-slate-900 border border-slate-200 rounded-sm">
                                OP
                            </div>
                            <span className="text-[11px] font-bold text-slate-900 uppercase tracking-wider">Operator_01</span>
                        </div>
                    </div>
                </header>

                <div className="flex-1 bg-slate-50 relative overflow-hidden flex flex-col">
                    {children}
                </div>
            </main>
        </div>
    );
};

export default AppLayout;

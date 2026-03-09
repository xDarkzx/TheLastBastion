import React, { useState } from 'react';
import {
    X, Shield, Zap, Info, Cpu, Globe,
    ArrowRight, Lock, Key, Server, Search, Check
} from 'lucide-react';

const SwarmBriefing = ({ isOpen, onClose, onDeploy }) => {
    const swarms = [
        { id: 'power', region: 'Global', category: 'Energy', label: 'Hunter for Power v4.0', desc: 'The Last Bastion Optimized Regional Energy Scraper', icon: Zap, color: 'text-slate-700', bg: 'bg-white' },
        { id: 'insurance', region: 'Global', category: 'Insurance', label: 'Insurance Intelligence Alpha', desc: 'Stealth Coverage Mapping and Pricing Intelligence', icon: Shield, color: 'text-slate-700', bg: 'bg-white' },
    ];

    const [botComposition, setBotComposition] = useState({
        discovery: 1,
        scraper: 2,
        cleaner: 1,
        comparing: 0,
        seller: 0
    });
    const [selectedSwarmProfile, setSelectedSwarmProfile] = useState(null);
    const [swarmName, setSwarmName] = useState('');

    const updateBotCount = (type, delta) => {
        setBotComposition(prev => ({
            ...prev,
            [type]: Math.max(0, Math.min(10, prev[type] + delta))
        }));
    };

    const totalBots = Object.values(botComposition).reduce((a, b) => a + b, 0);

    const handleDeploy = () => {
        const finalName = swarmName || (selectedSwarmProfile ? `${selectedSwarmProfile.label}-${Math.floor(Math.random() * 1000)}` : 'Unnamed Swarm');
        onDeploy(
            selectedSwarmProfile?.region || 'GLOBAL',
            selectedSwarmProfile?.category || 'General',
            totalBots,
            finalName,
            botComposition
        );
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 z-[2000] bg-slate-900/60 backdrop-blur-md flex items-center justify-center p-8 animate-in fade-in duration-300">
            <div className="bg-white w-full max-w-6xl h-[90vh] shadow-[0_0_150px_rgba(0,0,0,0.3)] flex flex-col border border-slate-300 animate-in slide-in-from-bottom-4">
                {/* Deployment Header */}
                <div className="px-10 py-6 bg-white border-b border-slate-200 flex items-center justify-between shrink-0">
                    <div className="flex items-center gap-6">
                        <div className="w-10 h-10 bg-slate-900 flex items-center justify-center text-white">
                            <Zap size={20} fill="currentColor" />
                        </div>
                        <div>
                            <h2 className="text-[11px] font-black text-slate-400 uppercase tracking-[0.3em] leading-none mb-2">Orchestration Module</h2>
                            <h3 className="text-2xl font-bold text-slate-900 tracking-tight">Initialize Swarm Cluster</h3>
                        </div>
                    </div>
                    <button onClick={onClose} className="p-3 hover:bg-slate-100 text-slate-400 hover:text-slate-900 transition-all border border-transparent hover:border-slate-200">
                        <X size={20} />
                    </button>
                </div>

                <div className="flex-1 flex overflow-hidden">
                    {/* Main Configuration */}
                    <div className="flex-1 overflow-y-auto p-12 space-y-16 thin-scrollbar bg-white">
                        {/* Section 1: Identification */}
                        <section className="space-y-8">
                            <div className="flex items-center gap-3 border-b border-slate-900 pb-3">
                                <h3 className="text-[10px] font-black text-slate-900 uppercase tracking-[0.3em]">01. IDENTIFICATION</h3>
                            </div>
                            <div className="space-y-3 max-w-xl">
                                <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Swarm Descriptor</label>
                                <input
                                    type="text"
                                    placeholder="E.G. ENERGY_SURVEILLANCE_01"
                                    className="w-full px-5 py-3 border border-slate-200 text-sm font-bold text-slate-900 placeholder:text-slate-300 focus:border-slate-900 outline-none bg-slate-50/30"
                                    value={swarmName}
                                    onChange={(e) => setSwarmName(e.target.value)}
                                />
                                <p className="text-[9px] font-bold text-slate-400 italic uppercase">Broadcast ID used for regional telemetry packets.</p>
                            </div>
                        </section>

                        {/* Section 2: Swarm Profiles */}
                        <section className="space-y-8">
                            <div className="flex items-center gap-3 border-b border-slate-900 pb-3">
                                <h3 className="text-[10px] font-black text-slate-900 uppercase tracking-[0.3em]">02. SWARM_TARGET</h3>
                            </div>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                {swarms.map((m) => (
                                    <div
                                        key={m.id}
                                        onClick={() => setSelectedSwarmProfile(m)}
                                        className={`p-6 border transition-all cursor-pointer flex items-center gap-6 ${selectedSwarmProfile?.id === m.id ? 'border-slate-900 bg-slate-50' : 'border-slate-200 bg-white hover:border-slate-400'}`}
                                    >
                                        <div className={`w-12 h-12 border border-slate-100 flex items-center justify-center bg-white ${m.color} shadow-sm`}>
                                            <m.icon size={24} strokeWidth={2.5} />
                                        </div>
                                        <div className="flex-1">
                                            <h4 className="text-[11px] font-black text-slate-900 uppercase tracking-widest mb-1">{m.label}</h4>
                                            <p className="text-[10px] font-bold text-slate-400 uppercase leading-relaxed">{m.desc}</p>
                                        </div>
                                        <div className={`w-5 h-5 border-2 flex items-center justify-center ${selectedSwarmProfile?.id === m.id ? 'border-slate-900 bg-slate-900' : 'border-slate-200'}`}>
                                            {selectedSwarmProfile?.id === m.id && <Check size={12} className="text-white" />}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </section>

                        {/* Section 3: Bot Composition */}
                        <section className="space-y-8">
                            <div className="flex items-center gap-3 border-b border-slate-900 pb-3">
                                <h3 className="text-[10px] font-black text-slate-900 uppercase tracking-[0.3em]">03. BOT_COMPOSITION</h3>
                            </div>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-x-12 gap-y-6">
                                {[
                                    { id: 'discovery', label: 'Discovery Bots', desc: 'Maps regional infrastructure & providers' },
                                    { id: 'scraper', label: 'Scraper Bots', desc: 'High-fidelity data extraction nodes' },
                                    { id: 'cleaner', label: 'Cleaner Bots', desc: 'Normalizes raw intelligence streams' },
                                    { id: 'comparing', label: 'Comparison Bots', desc: 'Differential analysis of pricing data' },
                                    { id: 'seller', label: 'Seller Bots', desc: 'Automated marketplace interactions' }
                                ].map((bot) => (
                                    <div key={bot.id} className="flex items-center justify-between p-4 border border-slate-200 bg-slate-50/30">
                                        <div className="flex-1">
                                            <h4 className="text-[10px] font-black text-slate-900 uppercase tracking-widest">{bot.label}</h4>
                                            <p className="text-[9px] font-bold text-slate-400 uppercase">{bot.desc}</p>
                                        </div>
                                        <div className="flex items-center gap-3">
                                            <span className="w-8 text-center text-xs font-black font-mono text-slate-900">{botComposition[bot.id]}</span>
                                            <div className="flex gap-1">
                                                <button onClick={() => updateBotCount(bot.id, -1)} className="w-7 h-7 border border-slate-300 bg-white font-black hover:bg-slate-100 flex items-center justify-center">-</button>
                                                <button onClick={() => updateBotCount(bot.id, 1)} className="w-7 h-7 border border-slate-300 bg-white font-black hover:bg-slate-100 flex items-center justify-center">+</button>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </section>
                    </div>

                    {/* Summary Sidebar */}
                    <div className="w-96 bg-slate-900 border-l border-slate-800 p-12 space-y-12 shrink-0 text-white shadow-[-20px_0_50px_rgba(0,0,0,0.2)]">
                        <div className="space-y-2">
                            <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-[0.3em]">Swarm Deployment Summary</h3>
                            <div className="w-12 h-1 bg-slate-400" />
                        </div>

                        <div className="space-y-8">
                            <div className="space-y-2">
                                <label className="text-[9px] font-black text-slate-500 uppercase tracking-widest">Total Active Nodes</label>
                                <p className="text-4xl font-black text-white font-mono tracking-tighter">{totalBots}</p>
                            </div>
                            <div className="space-y-2">
                                <label className="text-[9px] font-black text-slate-500 uppercase tracking-widest">Target Objective</label>
                                <p className="text-sm font-bold text-white uppercase tracking-widest leading-relaxed">{selectedSwarmProfile?.label || 'Awaiting Selection'}</p>
                            </div>
                            <div className="space-y-3 pt-8 border-t border-slate-800">
                                <div className="flex justify-between items-center text-[10px] font-bold uppercase tracking-widest">
                                    <span className="text-slate-500">Resource Segment</span>
                                    <span className="text-white">Isolated</span>
                                </div>
                                <div className="flex justify-between items-center text-[10px] font-bold uppercase tracking-widest">
                                    <span className="text-slate-500">Uplink Protocol</span>
                                    <span className="text-white">Industrial v4</span>
                                </div>
                            </div>
                        </div>

                        <div className="pt-10 space-y-4 mt-auto">
                            <button
                                onClick={handleDeploy}
                                disabled={!selectedSwarmProfile}
                                className={`w-full py-5 bg-white text-slate-900 font-black text-[11px] uppercase tracking-[0.2em] shadow-lg shadow-white/5 transition-all active:scale-95 flex items-center justify-center gap-3 ${!selectedSwarmProfile ? 'opacity-20 grayscale cursor-not-allowed' : 'hover:bg-slate-100'}`}
                            >
                                <Zap size={16} fill="currentColor" />
                                <span>Launch Swarm</span>
                            </button>
                            <button
                                onClick={onClose}
                                className="w-full py-3 text-[10px] font-bold text-slate-500 hover:text-white transition-colors uppercase tracking-[0.2em]"
                            >
                                TERMINATE_REQUEST
                            </button>
                        </div>

                        <div className="bg-slate-800/50 p-6 border border-slate-700/50 space-y-3">
                            <div className="flex items-center gap-3 text-slate-300">
                                <Globe size={16} />
                                <span className="text-[10px] font-black uppercase tracking-widest">Link Status</span>
                            </div>
                            <p className="text-[10px] text-slate-400 leading-relaxed font-bold uppercase tracking-wider">Node segment ready for regional deployment in {selectedSwarmProfile?.region || 'GLOBAL'}. Uplink stable.</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default SwarmBriefing;

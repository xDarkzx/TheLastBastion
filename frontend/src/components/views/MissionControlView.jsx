import React from 'react';
import { Clock, CheckCircle, Activity, Truck, ShieldCheck, Package, UserCheck, Shield, ArrowDown, AlertTriangle, Info, Zap } from 'lucide-react';

const phaseColors = {
    discovery: { bg: 'bg-slate-50', border: 'border-slate-200', text: 'text-slate-500' },
    production: { bg: 'bg-slate-50', border: 'border-slate-300', text: 'text-slate-700' },
    compliance: { bg: 'bg-slate-100', border: 'border-slate-300', text: 'text-slate-700' },
    logistics: { bg: 'bg-slate-50', border: 'border-slate-300', text: 'text-slate-600' },
    buyer_verification: { bg: 'bg-slate-100', border: 'border-slate-300', text: 'text-slate-700' },
    bastion_verification: { bg: 'bg-slate-100', border: 'border-slate-400', text: 'text-slate-800' },
    bastion_gate: { bg: 'bg-slate-100', border: 'border-slate-400', text: 'text-slate-700' },
    handoff: { bg: 'bg-slate-50', border: 'border-slate-200', text: 'text-slate-600' },
    registration: { bg: 'bg-slate-50', border: 'border-slate-200', text: 'text-slate-600' },
    heartbeat: { bg: 'bg-slate-50', border: 'border-slate-200', text: 'text-slate-500' },
};

const statusIcons = {
    active: <Clock size={12} className="text-slate-500 animate-pulse" />,
    complete: <CheckCircle size={12} className="text-slate-700" />,
};

// --- Vertical Workflow Node ---
const WorkflowNode = ({ name, desc, icon: Icon, status, data, isBastion, events }) => {
    const isActive = status === 'ACTIVE';
    const isComplete = status === 'COMPLETE';

    const borderClass = isBastion
        ? (isComplete ? 'border-slate-500 border-2 bg-slate-100' : isActive ? 'border-slate-400 border-2 bg-slate-50 ring-2 ring-slate-300' : 'border-slate-300 border-2 bg-white')
        : (isComplete ? 'border-slate-400 bg-slate-50' : isActive ? 'border-slate-300 bg-slate-50 ring-2 ring-slate-200' : 'border-slate-200 bg-white');

    const iconClass = isBastion
        ? 'text-slate-700'
        : (isComplete ? 'text-slate-700' : isActive ? 'text-slate-500' : 'text-slate-400');

    return (
        <div className={`border rounded-sm p-5 transition-all w-full max-w-lg ${borderClass}`}>
            <div className="flex items-center gap-3 mb-1">
                <div className={`w-9 h-9 rounded flex items-center justify-center ${
                    isBastion ? 'bg-slate-200 border border-slate-400' :
                    isComplete ? 'bg-slate-200 border border-slate-400' :
                    isActive ? 'bg-slate-100 border border-slate-300' :
                    'bg-slate-100 border border-slate-200'
                }`}>
                    <Icon size={18} className={iconClass} />
                </div>
                <div className="flex-1">
                    <div className="text-sm font-bold text-slate-800">{name}</div>
                    <div className="flex items-center gap-1.5">
                        {isComplete && <CheckCircle size={10} className="text-slate-600" />}
                        {isActive && <Clock size={10} className="text-slate-500 animate-pulse" />}
                        <span className={`text-[9px] font-bold uppercase tracking-widest font-mono ${
                            isComplete ? 'text-slate-700' : isActive ? 'text-slate-500' : 'text-slate-400'
                        }`}>
                            {isComplete ? 'COMPLETE' : isActive ? 'ACTIVE' : 'WAITING'}
                        </span>
                    </div>
                </div>
            </div>
            {desc && (
                <p className="text-[10px] text-slate-400 leading-relaxed mt-1 mb-2">{desc}</p>
            )}
            {/* Show latest action text from events */}
            {events.length > 0 && (
                <div className="mt-2 pt-2 border-t border-slate-100 space-y-1">
                    {events.slice(0, 3).map((evt, i) => (
                        <div key={i} className="text-[10px] font-mono text-slate-500 truncate flex items-center gap-1.5">
                            {evt.status === 'active'
                                ? <Clock size={9} className="text-slate-500 shrink-0" />
                                : <CheckCircle size={9} className="text-slate-600 shrink-0" />
                            }
                            <span className="truncate">{evt.action}</span>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

// --- Connector with data label ---
const Connector = ({ label, isBastion }) => (
    <div className="flex flex-col items-center py-1">
        <div className={`w-px h-4 ${isBastion ? 'bg-slate-400' : 'bg-slate-300'}`} />
        <ArrowDown size={14} className={isBastion ? 'text-slate-500 -my-0.5' : 'text-slate-400 -my-0.5'} />
        {label && (
            <div className={`text-[9px] font-mono mt-1 max-w-xs text-center leading-tight ${isBastion ? 'text-slate-500' : 'text-slate-400'}`}>
                {label}
            </div>
        )}
        <div className={`w-px h-2 mt-1 ${isBastion ? 'bg-slate-400' : 'bg-slate-300'}`} />
    </div>
);

const MissionControlView = ({ activity = [], agents = [] }) => {
    // Index all events by phase — collect ALL events per phase (newest first)
    const eventsByPhase = {};
    for (const evt of activity) {
        const key = evt.phase;
        if (!eventsByPhase[key]) eventsByPhase[key] = [];
        eventsByPhase[key].push(evt);
    }

    // Derive status from latest event
    const getStageStatus = (...phaseNames) => {
        for (const phaseName of phaseNames) {
            const events = eventsByPhase[phaseName];
            if (events && events.length > 0) {
                // If any event is "complete", stage is complete
                const hasComplete = events.some(e => e.status === 'complete');
                if (hasComplete) return 'COMPLETE';
                return 'ACTIVE';
            }
        }
        return 'WAITING';
    };

    const getPhaseEvents = (...phaseNames) => {
        const all = [];
        for (const p of phaseNames) {
            if (eventsByPhase[p]) all.push(...eventsByPhase[p]);
        }
        return all.sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0));
    };

    // Count events by status
    const totalEvents = activity.length;
    const activeEvents = activity.filter(e => e.status === 'active').length;
    const completeEvents = activity.filter(e => e.status === 'complete').length;
    const supplyChainPhases = ['production', 'compliance', 'logistics', 'buyer_verification', 'bastion_verification', 'bastion_gate', 'handoff'];
    const supplyChainEvents = activity.filter(e => supplyChainPhases.includes(e.phase)).length;

    // The bastion_gate connector labels (these sit between agent stages)
    const getBastionGateLabel = (fromAgent) => {
        const gateEvents = (eventsByPhase['bastion_gate'] || [])
            .filter(e => e.action?.toLowerCase().includes(fromAgent.toLowerCase()) || e.from_agent?.toLowerCase().includes('bastion'));
        if (gateEvents.length > 0) {
            return gateEvents[0].action?.substring(0, 60);
        }
        return 'Bastion verifies before forwarding';
    };

    const stages = [
        {
            name: 'ProducerBot',
            desc: 'Generates structured batch data — product records, quantities, grades, farm origins. This is the raw data that enters the supply chain.',
            phases: ['production'],
            icon: Package,
        },
        {
            name: 'ComplianceBot',
            desc: 'Validates the batch against export regulations — checks certifications, safety standards, and issues a compliance certificate.',
            phases: ['compliance'],
            icon: ShieldCheck,
        },
        {
            name: 'LogisticsBot',
            desc: 'Assigns shipping containers, books vessels, and monitors cold chain temperature throughout transit.',
            phases: ['logistics'],
            icon: Truck,
        },
        {
            name: 'BuyerBot',
            desc: 'Cross-verifies the entire provenance chain — production records, compliance certs, and shipping manifests must all match.',
            phases: ['buyer_verification'],
            icon: UserCheck,
        },
        {
            name: 'The Last Bastion',
            desc: 'Final neutral arbiter. Runs the full chain through the 5-layer verification pipeline — schema, consistency, forensics, triangulation, adversarial challenge.',
            phases: ['bastion_verification', 'bastion_gate'],
            icon: Shield,
            isBastion: true,
        },
    ];

    return (
        <div className="p-8 max-w-7xl mx-auto space-y-6 animate-fade-in">
            <header className="border-b-2 border-slate-900 pb-6">
                <div className="flex items-end justify-between">
                    <div>
                        <div className="flex items-center gap-3 mb-2">
                            <Truck className="text-slate-700" size={28} />
                            <h1 className="text-3xl font-black tracking-tight text-slate-900 uppercase">Supply Chain Flow</h1>
                        </div>
                        <p className="text-xs text-slate-500 mt-1 max-w-3xl leading-relaxed normal-case">
                            This page shows a live multi-agent supply chain running autonomously. Four independent agents — Producer,
                            Compliance, Logistics, and Buyer — exchange structured data with each other. Every handoff between agents
                            passes through <span className="font-bold text-slate-700">The Last Bastion as a neutral middleware</span>:
                            each payload is verified before being forwarded to the next agent. If any agent sends bad data,
                            the chain halts at that point.
                        </p>
                    </div>
                    <div className="flex gap-5 text-right shrink-0">
                        <div>
                            <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Events</div>
                            <div className="text-2xl font-black font-mono text-slate-900">{totalEvents}</div>
                        </div>
                        <div>
                            <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Supply Chain</div>
                            <div className="text-2xl font-black font-mono text-slate-700">{supplyChainEvents}</div>
                        </div>
                    </div>
                </div>
            </header>

            {/* Explainer — how the chain works */}
            <div className="bg-slate-50 border border-slate-200 rounded-sm p-5">
                <div className="flex items-center gap-2 mb-3">
                    <Info size={14} className="text-slate-400" />
                    <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest">How This Works</h3>
                </div>
                <div className="grid grid-cols-3 gap-6">
                    <div>
                        <div className="text-[10px] font-bold text-slate-700 uppercase tracking-wider mb-1">Continuous Loop</div>
                        <p className="text-[10px] text-slate-400 leading-relaxed">
                            The supply chain runs automatically every 10–25 seconds. Each cycle, agents generate real data,
                            exchange it via A2A messages, and submit payloads for verification. Stages show WAITING until
                            the next cycle reaches that phase.
                        </p>
                    </div>
                    <div>
                        <div className="text-[10px] font-bold text-slate-700 uppercase tracking-wider mb-1">Bastion as Middleware</div>
                        <p className="text-[10px] text-slate-400 leading-relaxed">
                            Between every agent handoff, The Last Bastion verifies the payload. If the data is REJECTED (bad schema,
                            injection, inconsistencies), the chain halts — the next agent never receives the data.
                        </p>
                    </div>
                    <div>
                        <div className="text-[10px] font-bold text-slate-700 uppercase tracking-wider mb-1">Real Agent Communication</div>
                        <p className="text-[10px] text-slate-400 leading-relaxed">
                            These are real A2A protocol messages between independent processes. Each agent has its own
                            endpoint, keypair, and Agent Card. They don't share memory — data moves via verified handoffs only.
                        </p>
                    </div>
                </div>
            </div>

            {/* Status summary */}
            {totalEvents === 0 && (
                <div className="bg-slate-100 border border-slate-300 rounded-sm p-4 flex items-center gap-3">
                    <AlertTriangle size={16} className="text-slate-500 shrink-0" />
                    <div>
                        <div className="text-[10px] font-bold text-slate-700 uppercase tracking-wider">No activity yet</div>
                        <p className="text-[10px] text-slate-500 mt-0.5">
                            The supply chain loop runs every 10–25 seconds. If the backend just started, wait a moment for the first cycle to complete.
                            Events will appear here as agents begin exchanging data.
                        </p>
                    </div>
                </div>
            )}

            {/* Workflow Map */}
            <div className="bg-white border border-slate-200 rounded-sm p-6">
                <div className="flex items-center justify-between mb-6">
                    <h2 className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Supply Chain Workflow Map</h2>
                    {totalEvents > 0 && (
                        <div className="flex items-center gap-4 text-[9px] font-bold uppercase tracking-widest">
                            <span className="flex items-center gap-1 text-slate-700"><CheckCircle size={10} /> {completeEvents} complete</span>
                            <span className="flex items-center gap-1 text-slate-500"><Clock size={10} /> {activeEvents} active</span>
                        </div>
                    )}
                </div>
                <div className="flex flex-col items-center">
                    {stages.map((stage, i) => (
                        <React.Fragment key={stage.phases[0]}>
                            <WorkflowNode
                                name={stage.name}
                                desc={stage.desc}
                                icon={stage.icon}
                                status={getStageStatus(...stage.phases)}
                                events={getPhaseEvents(...stage.phases)}
                                isBastion={stage.isBastion}
                            />
                            {i < stages.length - 1 && (
                                <Connector
                                    label={getBastionGateLabel(stage.name)}
                                    isBastion
                                />
                            )}
                        </React.Fragment>
                    ))}

                    {/* Handoff stage — if any handoff events exist */}
                    {(eventsByPhase['handoff'] || []).length > 0 && (
                        <>
                            <Connector label="Agent-to-agent provenance handoff" />
                            <WorkflowNode
                                name="Provenance Handoff"
                                desc="Final transfer of verified data between producer and buyer — recorded as a tamper-evident handoff receipt."
                                icon={Zap}
                                status={getStageStatus('handoff')}
                                events={getPhaseEvents('handoff')}
                            />
                        </>
                    )}
                </div>
            </div>

            {/* Activity Feed Table */}
            <div className="bg-white border border-slate-200 rounded-sm shadow-sm overflow-hidden">
                <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <Activity size={16} className="text-slate-500" />
                        <h2 className="text-xs font-bold text-slate-700 uppercase tracking-widest">Live Activity Feed</h2>
                    </div>
                    <p className="text-[9px] text-slate-400">Events appear as agents exchange data — newest first</p>
                </div>
                <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr className="bg-slate-50 border-b border-slate-200">
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest w-40">Timestamp</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Phase</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">From</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">To</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Action</th>
                                <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest text-center">Status</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                            {activity.length > 0 ? activity.map((evt) => {
                                const pc = phaseColors[evt.phase] || phaseColors.discovery;
                                return (
                                    <tr key={evt.id} className="hover:bg-slate-50 transition-colors">
                                        <td className="py-3 px-5 text-[10px] font-mono text-slate-400">
                                            {evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : '-'}
                                        </td>
                                        <td className="py-3 px-5">
                                            <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${pc.bg} ${pc.border} ${pc.text}`}>
                                                {evt.phase?.replace('_', ' ')}
                                            </span>
                                        </td>
                                        <td className="py-3 px-5 text-xs font-bold text-slate-700">{evt.from_agent || '-'}</td>
                                        <td className="py-3 px-5 text-xs font-mono text-slate-500">{evt.to_agent || '-'}</td>
                                        <td className="py-3 px-5 text-xs text-slate-600 max-w-xs truncate">{evt.action}</td>
                                        <td className="py-3 px-5 text-center">
                                            <div className="inline-flex items-center gap-1">
                                                {statusIcons[evt.status] || statusIcons.complete}
                                                <span className={`text-[10px] font-bold uppercase tracking-widest font-mono ${
                                                    evt.status === 'active' ? 'text-slate-600' : 'text-slate-700'
                                                }`}>
                                                    {evt.status}
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                );
                            }) : (
                                <tr>
                                    <td colSpan="6" className="py-12 text-center">
                                        <Activity size={32} className="mx-auto mb-3 text-slate-300" />
                                        <p className="text-sm font-bold text-slate-400 uppercase tracking-widest">Waiting for first supply chain cycle</p>
                                        <p className="text-[10px] text-slate-400 mt-1">The agent loop runs every 10–25 seconds. Events will appear automatically.</p>
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};

export default MissionControlView;

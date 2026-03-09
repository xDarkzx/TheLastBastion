import React, { useState, useEffect, useRef } from 'react';
import { Loader2, ChevronDown, Zap, Lock } from 'lucide-react';
import { swarmService, DEMO_MODE } from '../services/api';

const behaviorStyles = {
    hallucinating: { bg: 'bg-slate-50', hover: 'hover:bg-slate-100', text: 'text-slate-700', border: 'border-slate-300', dot: 'bg-slate-600' },
    badly_programmed: { bg: 'bg-slate-50', hover: 'hover:bg-slate-100', text: 'text-slate-600', border: 'border-slate-300', dot: 'bg-slate-500' },
    malicious: { bg: 'bg-slate-50', hover: 'hover:bg-slate-100', text: 'text-slate-800', border: 'border-slate-400', dot: 'bg-slate-700' },
    poisoned_payload: { bg: 'bg-slate-50', hover: 'hover:bg-slate-100', text: 'text-slate-700', border: 'border-slate-300', dot: 'bg-slate-600' },
};

const BehaviorButtons = ({ agentId, onSimulationResult }) => {
    const [open, setOpen] = useState(false);
    const [loading, setLoading] = useState(null); // behavior_type being loaded
    const [types, setTypes] = useState([]);
    const dropdownRef = useRef(null);

    useEffect(() => {
        swarmService.getSimulationTypes()
            .then(res => setTypes(res.data?.types || res.data || []))
            .catch(() => {
                // Fallback if endpoint not available yet
                setTypes([
                    { id: 'hallucinating', label: 'Hallucinating Agent', description: 'Fabricated values', color: 'purple' },
                    { id: 'badly_programmed', label: 'Badly Programmed', description: 'Garbled data types', color: 'amber' },
                    { id: 'malicious', label: 'Malicious Agent', description: 'Injection payloads', color: 'rose' },
                    { id: 'poisoned_payload', label: 'Poisoned Payload', description: 'Subtly wrong data', color: 'orange' },
                ]);
            });
    }, []);

    // Close dropdown on outside click
    useEffect(() => {
        const handler = (e) => {
            if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
                setOpen(false);
            }
        };
        document.addEventListener('mousedown', handler);
        return () => document.removeEventListener('mousedown', handler);
    }, []);

    const handleSimulate = async (behaviorType) => {
        setLoading(behaviorType);
        setOpen(false);
        try {
            const res = await swarmService.simulateBehavior(agentId, behaviorType);
            onSimulationResult(res.data);
        } catch (err) {
            onSimulationResult({
                simulation: true,
                behavior_type: behaviorType,
                verdict: 'ERROR',
                score: 0,
                error_code: 'REQUEST_FAILED',
                summary: err.response?.data?.detail || err.message || 'Simulation request failed',
                field_issues: [],
                pipeline_trace: [],
                recommendation: 'Check that the backend is running and try again.',
            });
        } finally {
            setLoading(null);
        }
    };

    if (DEMO_MODE) {
        return (
            <div className="inline-flex items-center gap-2 px-3 py-2 bg-slate-100 text-slate-400 text-[10px] font-bold uppercase tracking-widest rounded-sm cursor-not-allowed">
                <Lock size={10} />
                Simulations Disabled in Demo
            </div>
        );
    }

    return (
        <div className="relative" ref={dropdownRef}>
            <button
                onClick={() => setOpen(!open)}
                disabled={loading !== null}
                className="inline-flex items-center gap-2 px-3 py-2 bg-slate-900 text-white text-[10px] font-bold uppercase tracking-widest rounded-sm hover:bg-slate-800 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
                {loading ? (
                    <>
                        <Loader2 size={12} className="animate-spin" />
                        Running Simulation...
                    </>
                ) : (
                    <>
                        <Zap size={12} />
                        Simulate Behavior
                        <ChevronDown size={10} />
                    </>
                )}
            </button>

            {open && !loading && (
                <div className="absolute right-0 mt-1 w-72 bg-white border border-slate-200 rounded-sm shadow-lg z-50">
                    <div className="px-3 py-2 border-b border-slate-100">
                        <span className="text-[9px] font-bold text-slate-400 uppercase tracking-widest">
                            Choose Misbehavior Type
                        </span>
                    </div>
                    <div className="py-1">
                        {types.map((type) => {
                            const style = behaviorStyles[type.id] || behaviorStyles.hallucinating;
                            return (
                                <button
                                    key={type.id}
                                    onClick={() => handleSimulate(type.id)}
                                    className={`w-full text-left px-3 py-2.5 ${style.hover} transition-colors`}
                                >
                                    <div className="flex items-center gap-2 mb-0.5">
                                        <span className={`w-2 h-2 rounded-full ${style.dot}`} />
                                        <span className={`text-[11px] font-bold ${style.text}`}>{type.label}</span>
                                    </div>
                                    <p className="text-[9px] text-slate-500 ml-4">{type.description}</p>
                                    {type.expected_verdict && (
                                        <p className="text-[8px] font-mono text-slate-400 ml-4 mt-0.5">
                                            Expected: {type.expected_verdict}
                                        </p>
                                    )}
                                </button>
                            );
                        })}
                    </div>
                </div>
            )}
        </div>
    );
};

export default BehaviorButtons;

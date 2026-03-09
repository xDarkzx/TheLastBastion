import React, { useState, useEffect, useCallback } from 'react';
import {
    Shield, Upload, CheckCircle, XCircle, AlertTriangle,
    FileKey, Eye, ArrowRight, RefreshCw, Clock
} from 'lucide-react';

const API_BASE = 'http://localhost:8000/sandbox';

const CHECK_LABELS = {
    identity: 'Identity',
    cryptographic: 'Cryptographic',
    capabilities: 'Capabilities',
    reputation: 'Reputation',
    payload_quality: 'Payload Quality',
    behavioral: 'Behavioral',
    network: 'Network',
    cross_reference: 'Cross-Reference',
    anti_sybil: 'Anti-Sybil',
    temporal: 'Temporal',
};

const CHECK_ORDER = [
    'identity', 'cryptographic', 'capabilities', 'reputation',
    'payload_quality', 'behavioral', 'network', 'cross_reference',
    'anti_sybil', 'temporal',
];

const StatusBadge = ({ status }) => {
    const styles = {
        TRUSTED: 'bg-emerald-50 text-emerald-700 border-emerald-200',
        APPROVED: 'bg-emerald-50 text-emerald-700 border-emerald-200',
        SUSPICIOUS: 'bg-amber-50 text-amber-700 border-amber-200',
        PENDING_REVIEW: 'bg-blue-50 text-blue-700 border-blue-200',
        MALICIOUS: 'bg-red-50 text-red-700 border-red-200',
        REJECTED: 'bg-red-50 text-red-700 border-red-200',
    };
    return (
        <span className={`px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border rounded-sm ${styles[status] || 'bg-slate-50 text-slate-600 border-slate-200'}`}>
            {status}
        </span>
    );
};

const CheckRow = ({ index, name, check, animate }) => {
    const score = check?.score ?? 0;
    const passed = check?.passed ?? false;
    const detail = check?.detail ?? '';
    const veto = check?.veto ?? false;

    let statusIcon, statusColor;
    if (veto) {
        statusIcon = <XCircle size={14} />;
        statusColor = 'text-red-600';
    } else if (passed) {
        statusIcon = <CheckCircle size={14} />;
        statusColor = score >= 0.7 ? 'text-emerald-600' : 'text-amber-500';
    } else {
        statusIcon = score >= 0.4 ? <AlertTriangle size={14} /> : <XCircle size={14} />;
        statusColor = score >= 0.4 ? 'text-amber-500' : 'text-red-600';
    }

    return (
        <div
            className={`flex items-center gap-3 px-4 py-2.5 border-b border-slate-100 last:border-0 transition-all duration-300 ${animate ? 'animate-fade-in' : ''}`}
            style={animate ? { animationDelay: `${index * 120}ms` } : {}}
        >
            <span className="text-[10px] font-mono text-slate-400 w-6">#{index + 1}</span>
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-700 w-28">
                {CHECK_LABELS[name] || name}
            </span>
            <div className="flex-1 h-1.5 bg-slate-100 rounded-full overflow-hidden">
                <div
                    className={`h-full rounded-full transition-all duration-500 ${score >= 0.7 ? 'bg-emerald-500' : score >= 0.4 ? 'bg-amber-400' : 'bg-red-500'
                        }`}
                    style={{ width: `${score * 100}%`, transitionDelay: animate ? `${index * 120 + 200}ms` : '0ms' }}
                />
            </div>
            <span className={`text-xs font-mono font-bold w-10 text-right ${statusColor}`}>
                {score.toFixed(2)}
            </span>
            <span className={`${statusColor} w-5`}>{statusIcon}</span>
            <span className="text-[10px] text-slate-500 truncate max-w-[200px]" title={detail}>
                {veto ? 'VETO — Hard reject' : detail}
            </span>
        </div>
    );
};

const PassportVerificationView = () => {
    const [file, setFile] = useState(null);
    const [uploading, setUploading] = useState(false);
    const [verificationResult, setVerificationResult] = useState(null);
    const [allPassports, setAllPassports] = useState([]);
    const [error, setError] = useState('');
    const [animateChecks, setAnimateChecks] = useState(false);

    const fetchPassports = useCallback(async () => {
        try {
            const resp = await fetch(`${API_BASE}/passport/all`);
            if (resp.ok) setAllPassports(await resp.json());
        } catch { /* backend not running */ }
    }, []);

    useEffect(() => {
        fetchPassports();
        const interval = setInterval(fetchPassports, 5000);
        return () => clearInterval(interval);
    }, [fetchPassports]);

    const handleFileChange = (e) => {
        const selected = e.target.files[0];
        if (selected) {
            setFile(selected);
            setError('');
            setVerificationResult(null);
        }
    };

    const handleUpload = async () => {
        if (!file) return;
        setUploading(true);
        setError('');
        setVerificationResult(null);

        try {
            const buffer = await file.arrayBuffer();
            const b64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));

            const resp = await fetch(`${API_BASE}/passport/upload`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ passport_b64: b64 }),
            });

            if (!resp.ok) {
                const errData = await resp.json().catch(() => ({}));
                setError(errData.detail || `Upload failed: ${resp.status}`);
                return;
            }

            const result = await resp.json();
            setVerificationResult(result);
            setAnimateChecks(true);
            setTimeout(() => setAnimateChecks(false), 2000);
            fetchPassports();
        } catch (e) {
            setError(`Upload error: ${e.message}`);
        } finally {
            setUploading(false);
        }
    };

    const handleDecision = async (id, action) => {
        try {
            const resp = await fetch(`${API_BASE}/passport/${id}/${action}`, { method: 'POST' });
            if (resp.ok) {
                setVerificationResult(prev => prev ? { ...prev, status: action === 'approve' ? 'approved' : 'rejected' } : null);
                fetchPassports();
            }
        } catch (e) {
            setError(`Action failed: ${e.message}`);
        }
    };

    const verdictStyles = {
        TRUSTED: {
            label: 'TRUSTED',
            desc: 'All checks passed. This agent appears legitimate.',
            container: 'border-emerald-200 bg-emerald-50',
            text: 'text-emerald-700',
        },
        SUSPICIOUS: {
            label: 'SUSPICIOUS',
            desc: 'Some checks raised concerns. Review carefully.',
            container: 'border-amber-200 bg-amber-50',
            text: 'text-amber-700',
        },
        MALICIOUS: {
            label: 'MALICIOUS',
            desc: 'Critical checks failed. This agent may be compromised or forged.',
            container: 'border-red-200 bg-red-50',
            text: 'text-red-700',
        },
    };
    const verdictInfo = verificationResult
        ? verdictStyles[verificationResult.verdict] || {
            label: verificationResult.verdict, desc: '',
            container: 'border-slate-200 bg-slate-50', text: 'text-slate-700',
        }
        : null;

    return (
        <div className="p-8 max-w-5xl mx-auto space-y-6 animate-fade-in">
            {/* Header */}
            <div className="flex items-center gap-4 mb-2">
                <div className="w-12 h-12 bg-slate-100 rounded-sm flex items-center justify-center border border-slate-200">
                    <Shield size={24} className="text-slate-700" />
                </div>
                <div>
                    <h1 className="text-xl font-extrabold text-slate-900 uppercase tracking-wide">Passport Verification</h1>
                    <p className="text-xs text-slate-500 font-medium">Upload an agent passport, watch every check run, then approve or reject.</p>
                </div>
            </div>

            {/* Upload Section */}
            <div className="bg-white border border-slate-200 rounded-sm p-6">
                <div className="flex items-center gap-3 mb-4">
                    <Upload size={16} className="text-slate-600" />
                    <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800">Upload Passport File</h2>
                </div>

                <div className="flex items-center gap-3">
                    <label className="flex items-center gap-2 px-4 py-2 bg-slate-100 border border-slate-300 rounded-sm cursor-pointer hover:bg-slate-200 transition-colors">
                        <FileKey size={14} className="text-slate-600" />
                        <span className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                            {file ? file.name : 'Choose File'}
                        </span>
                        <input type="file" className="hidden" onChange={handleFileChange} accept=".passport,.bin" />
                    </label>
                    <button
                        onClick={handleUpload}
                        disabled={!file || uploading}
                        className={`flex items-center gap-2 px-5 py-2 rounded-sm text-xs font-bold uppercase tracking-wider transition-colors ${file && !uploading
                            ? 'bg-slate-900 text-white hover:bg-slate-800'
                            : 'bg-slate-200 text-slate-400 cursor-not-allowed'
                            }`}
                    >
                        {uploading ? <RefreshCw size={14} className="animate-spin" /> : <ArrowRight size={14} />}
                        {uploading ? 'Verifying...' : 'Upload & Verify'}
                    </button>
                </div>

                {error && (
                    <div className="mt-3 px-4 py-2 bg-red-50 border border-red-200 rounded-sm">
                        <span className="text-xs font-medium text-red-700">{error}</span>
                    </div>
                )}

                <p className="text-[10px] text-slate-400 mt-3">
                    Generate passport files using the SDK: <code className="bg-slate-100 px-1 py-0.5 rounded text-[10px]">python run_border_demo.py</code>
                </p>
            </div>

            {/* Verification Results */}
            {verificationResult && (
                <div className="bg-white border border-slate-200 rounded-sm overflow-hidden">
                    <div className="px-6 py-4 border-b border-slate-200 bg-slate-50">
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-3">
                                <Eye size={16} className="text-slate-600" />
                                <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800">Verification Results</h2>
                            </div>
                            <div className="flex items-center gap-3">
                                <span className="text-[10px] text-slate-400 font-mono">
                                    {verificationResult.agent_id} / {verificationResult.passport_id}
                                </span>
                                <StatusBadge status={verificationResult.verdict} />
                            </div>
                        </div>
                    </div>

                    {/* 10-Check Table */}
                    <div>
                        {CHECK_ORDER.map((name, i) => (
                            <CheckRow
                                key={name}
                                index={i}
                                name={name}
                                check={verificationResult.checks?.[name]}
                                animate={animateChecks}
                            />
                        ))}
                    </div>

                    {/* Overall Verdict */}
                    {verdictInfo && (
                        <div className={`px-6 py-4 border-t-2 ${verdictInfo.container}`}>
                            <div className="flex items-center justify-between">
                                <div>
                                    <span className={`text-lg font-extrabold ${verdictInfo.text} uppercase tracking-wide`}>
                                        {verdictInfo.label}
                                    </span>
                                    <span className="text-sm font-mono text-slate-600 ml-3">
                                        Score: {verificationResult.trust_score?.toFixed(2)}
                                    </span>
                                    {verdictInfo.desc && (
                                        <p className="text-xs text-slate-600 mt-1">{verdictInfo.desc}</p>
                                    )}
                                </div>
                            </div>

                            {verificationResult.risk_flags?.length > 0 && (
                                <div className="mt-2 flex flex-wrap gap-1">
                                    {verificationResult.risk_flags.map((flag, i) => (
                                        <span key={i} className="px-2 py-0.5 text-[9px] font-bold bg-red-100 text-red-700 border border-red-200 rounded-sm uppercase tracking-wider">
                                            {flag}
                                        </span>
                                    ))}
                                </div>
                            )}
                        </div>
                    )}

                    {/* Human-in-Loop Decision */}
                    {verificationResult.status === 'pending_review' && (
                        <div className="px-6 py-5 border-t border-slate-200 bg-white">
                            <p className="text-xs text-slate-600 mb-4">
                                In production, a security admin reviews these results and makes the final call.
                                In sandbox mode, <strong>you are the admin</strong>.
                            </p>
                            <div className="flex items-center gap-3">
                                <button
                                    onClick={() => handleDecision(verificationResult.id, 'approve')}
                                    className="flex items-center gap-2 px-6 py-2.5 bg-emerald-600 text-white rounded-sm text-xs font-bold uppercase tracking-wider hover:bg-emerald-700 transition-colors"
                                >
                                    <CheckCircle size={14} />
                                    Approve
                                </button>
                                <button
                                    onClick={() => handleDecision(verificationResult.id, 'reject')}
                                    className="flex items-center gap-2 px-6 py-2.5 bg-red-600 text-white rounded-sm text-xs font-bold uppercase tracking-wider hover:bg-red-700 transition-colors"
                                >
                                    <XCircle size={14} />
                                    Reject
                                </button>
                            </div>

                            {verificationResult.verdict === 'MALICIOUS' && (
                                <p className="text-[10px] text-amber-600 mt-3 italic">
                                    Even though you CAN approve this in sandbox mode, in production this would be auto-rejected.
                                    The critical checks have veto power.
                                </p>
                            )}
                        </div>
                    )}

                    {verificationResult.status === 'approved' && (
                        <div className="px-6 py-4 border-t border-emerald-200 bg-emerald-50">
                            <div className="flex items-center gap-2">
                                <CheckCircle size={14} className="text-emerald-600" />
                                <span className="text-xs font-bold text-emerald-700 uppercase tracking-wider">
                                    Passport Approved
                                </span>
                            </div>
                            <p className="text-xs text-slate-600 mt-1">
                                This agent can now connect to the Border Police on port 9200 using the binary protocol.
                            </p>
                        </div>
                    )}

                    {verificationResult.status === 'rejected' && (
                        <div className="px-6 py-4 border-t border-red-200 bg-red-50">
                            <div className="flex items-center gap-2">
                                <XCircle size={14} className="text-red-600" />
                                <span className="text-xs font-bold text-red-700 uppercase tracking-wider">
                                    Passport Rejected
                                </span>
                            </div>
                            <p className="text-xs text-slate-600 mt-1">
                                This agent will be denied access if it tries to connect via the binary protocol.
                            </p>
                        </div>
                    )}
                </div>
            )}

            {/* What Happens Next */}
            {verificationResult?.status === 'approved' && (
                <div className="bg-white border border-slate-200 rounded-sm p-6">
                    <h3 className="text-sm font-bold uppercase tracking-wider text-slate-800 mb-3">What Happens Next</h3>
                    <div className="space-y-2 text-xs text-slate-600">
                        <p>After approval, the agent can connect to the Border Police on <code className="bg-slate-100 px-1 py-0.5 rounded text-[10px]">port 9200</code> using the binary protocol.</p>
                        <p>Start the Border Police:</p>
                        <pre className="bg-slate-50 border border-slate-200 rounded-sm p-3 text-[10px] font-mono text-slate-700 overflow-x-auto">
                            python -c "from core.border_agent import BorderAgent; import asyncio; asyncio.run(BorderAgent().start())"
                        </pre>
                        <p>Then connect with the approved passport using <code className="bg-slate-100 px-1 py-0.5 rounded text-[10px]">python run_border_demo.py</code> and select option [C].</p>
                    </div>
                </div>
            )}

            {/* All Passports History */}
            {allPassports.length > 0 && (
                <div className="bg-white border border-slate-200 rounded-sm overflow-hidden">
                    <div className="px-6 py-4 border-b border-slate-200 bg-slate-50">
                        <div className="flex items-center gap-3">
                            <Clock size={16} className="text-slate-600" />
                            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800">
                                Passport History
                            </h2>
                            <span className="text-[10px] text-slate-400 font-mono">{allPassports.length} records</span>
                        </div>
                    </div>
                    <div className="divide-y divide-slate-100">
                        {allPassports.slice(0, 20).map((p) => (
                            <div key={p.id} className="flex items-center justify-between px-6 py-3 hover:bg-slate-50 transition-colors">
                                <div className="flex items-center gap-3">
                                    <span className="text-[10px] font-mono text-slate-400">#{p.id}</span>
                                    <span className="text-xs font-bold text-slate-800">{p.agent_name || p.agent_id}</span>
                                    <span className="text-[10px] text-slate-400 font-mono">{p.public_key}</span>
                                </div>
                                <div className="flex items-center gap-3">
                                    <span className="text-[10px] font-mono text-slate-500">
                                        {p.trust_score?.toFixed(2)}
                                    </span>
                                    <StatusBadge status={p.verdict} />
                                    <span className="text-[10px] text-slate-400">
                                        {p.submitted_at ? new Date(p.submitted_at).toLocaleString() : ''}
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
};

export default PassportVerificationView;

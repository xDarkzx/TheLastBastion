import React, { useState, useMemo } from 'react';
import { Shield, Lock, Key, Fingerprint, ArrowRight, ArrowDown, ChevronDown, ChevronRight, Zap, Radio, AlertTriangle, Check, Clock, FileText, Image, BarChart3 } from 'lucide-react';

const frameTypeColors = {
    HELLO: { bg: 'bg-slate-50', border: 'border-slate-300', text: 'text-slate-700' },
    HELLO_ACK: { bg: 'bg-slate-50', border: 'border-slate-300', text: 'text-slate-600' },
    DATA: { bg: 'bg-slate-100', border: 'border-slate-300', text: 'text-slate-700' },
    DATA_ACK: { bg: 'bg-slate-100', border: 'border-slate-300', text: 'text-slate-600' },
    PING: { bg: 'bg-slate-50', border: 'border-slate-200', text: 'text-slate-500' },
    PONG: { bg: 'bg-slate-50', border: 'border-slate-200', text: 'text-slate-500' },
    ERROR: { bg: 'bg-slate-100', border: 'border-slate-400', text: 'text-slate-800' },
    CLOSE: { bg: 'bg-slate-100', border: 'border-slate-300', text: 'text-slate-600' },
    STREAM_START: { bg: 'bg-slate-50', border: 'border-slate-300', text: 'text-slate-700' },
    STREAM_CHUNK: { bg: 'bg-slate-50', border: 'border-slate-300', text: 'text-slate-600' },
    STREAM_END: { bg: 'bg-slate-50', border: 'border-slate-200', text: 'text-slate-500' },
    BEHAVIOR_SIMULATION: { bg: 'bg-slate-100', border: 'border-slate-300', text: 'text-slate-700' },
    SIM_COMPLETE: { bg: 'bg-slate-100', border: 'border-slate-300', text: 'text-slate-600' },
};

// Human-readable labels for frame types (raw enum names are confusing)
const frameTypeLabels = {
    HELLO: 'Hello',
    HELLO_ACK: 'Hello Ack',
    DATA: 'Data',
    DATA_ACK: 'Data Ack',
    PING: 'Ping',
    PONG: 'Pong',
    ERROR: 'Error',
    CLOSE: 'Close',
    STREAM_START: 'Stream Start',
    STREAM_CHUNK: 'Stream Chunk',
    STREAM_END: 'Stream End',
    BEHAVIOR_SIMULATION: 'Simulation',
    SIM_COMPLETE: 'Sim Complete',
};

const frameTypeHex = {
    HELLO: '0x01', HELLO_ACK: '0x02', DATA: '0x03', DATA_ACK: '0x04',
    STREAM_START: '0x05', STREAM_CHUNK: '0x06', STREAM_END: '0x07',
    PING: '0x08', PONG: '0x09', ERROR: '0x0A', CLOSE: '0x0B',
    BEHAVIOR_SIMULATION: '0x40', SIM_COMPLETE: '0x41',
};

const payloadTypeBadge = {
    'application/msgpack': { label: 'MSGPACK', color: 'bg-slate-200 text-slate-700' },
    'application/pdf': { label: 'PDF', color: 'bg-slate-200 text-slate-700' },
    'image/jpeg': { label: 'JPEG', color: 'bg-slate-100 text-slate-600' },
    'image/png': { label: 'PNG', color: 'bg-slate-100 text-slate-600' },
    'text/csv': { label: 'CSV', color: 'bg-slate-100 text-slate-600' },
    'video/mp4': { label: 'MP4', color: 'bg-slate-200 text-slate-700' },
    'application/json': { label: 'JSON', color: 'bg-slate-100 text-slate-600' },
    'signed-envelope': { label: 'ENVELOPE', color: 'bg-slate-200 text-slate-700' },
};

const agentConfig = [
    { name: 'producer', label: 'ProducerBot', port: 9101, role: 'DATA_PROVIDER' },
    { name: 'compliance', label: 'ComplianceBot', port: 9102, role: 'VERIFIER' },
    { name: 'logistics', label: 'LogisticsBot', port: 9103, role: 'DATA_PROVIDER' },
    { name: 'buyer', label: 'BuyerBot', port: 9104, role: 'DATA_CONSUMER' },
];

const agentLabelMap = { producer: 'ProducerBot', compliance: 'ComplianceBot', logistics: 'LogisticsBot', buyer: 'BuyerBot' };

const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1048576).toFixed(1)} MB`;
};

const formatTime = (ts) => {
    if (!ts) return '';
    try {
        const d = new Date(ts + 'Z');
        return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
        return ts.slice(11, 19);
    }
};

// Payload type badge component
const PayloadBadge = ({ type }) => {
    const badge = payloadTypeBadge[type];
    if (!badge) return null;
    return (
        <span className={`text-[8px] font-bold px-1.5 py-0.5 rounded ${badge.color}`}>
            {badge.label}
        </span>
    );
};

// Wire format diagram for expanded frame detail
const WireFormatDiagram = ({ frame }) => {
    const typeHex = frameTypeHex[frame.frame_type] || '0x??';
    const passportShort = frame.passport_hash ? frame.passport_hash.slice(0, 8) + '...' : '--------';
    const seqHex = frame.sequence ? frame.sequence.toString().padStart(4, '0') : '0000';
    const lenHex = frame.payload_size || 0;
    const sigStatus = frame.signature_verified ? 'VALID Ed25519' : 'UNVERIFIED';

    return (
        <div className="bg-white border border-slate-200 rounded-sm p-3 font-mono text-[10px]">
            <div className="text-[8px] font-bold text-slate-400 uppercase tracking-widest mb-2">Wire Format — This Frame</div>
            <div className="flex items-center gap-0.5 flex-wrap">
                <span className="bg-slate-100 text-slate-700 border border-slate-300 px-1.5 py-1 rounded-l">
                    Ver:<span className="text-slate-900 font-bold">0x01</span>
                </span>
                <span className="bg-slate-100 text-slate-700 border border-slate-300 px-1.5 py-1">
                    Type:<span className="text-slate-900 font-bold">{typeHex}</span>
                </span>
                <span className="bg-slate-100 text-slate-700 border border-slate-300 px-1.5 py-1">
                    Passport:<span className="text-slate-900 font-bold">{passportShort}</span>
                </span>
                <span className="bg-slate-100 text-slate-700 border border-slate-300 px-1.5 py-1">
                    Seq:<span className="text-slate-900 font-bold">{seqHex}</span>
                </span>
                <span className="bg-slate-100 text-slate-700 border border-slate-300 px-1.5 py-1">
                    Len:<span className="text-slate-900 font-bold">{lenHex}</span>
                </span>
                <span className="bg-slate-50 text-slate-600 border border-slate-200 px-2 py-1 flex-1 text-center">
                    {frame.encrypted ? 'Payload (encrypted)' : 'Payload (cleartext)'}
                </span>
                <span className={`${frame.signature_verified ? 'bg-slate-200 text-slate-800 border-slate-400' : 'bg-slate-50 text-slate-400 border-slate-200'} border px-1.5 py-1 rounded-r`}>
                    Sig:<span className="font-bold">{sigStatus}</span>
                </span>
            </div>
        </div>
    );
};

// Rich expanded detail per frame type
const ExpandedFrameDetail = ({ frame, frames }) => {
    const ft = frame.frame_type;

    return (
        <td colSpan={10} className="px-4 py-3 bg-white">
            {/* Wire format for all frame types */}
            <WireFormatDiagram frame={frame} />

            <div className="mt-3">
                {/* HELLO / HELLO_ACK */}
                {(ft === 'HELLO' || ft === 'HELLO_ACK') && (
                    <div className="space-y-3">
                        {frame.handshake_params && Object.keys(frame.handshake_params).length > 0 && (
                            <div>
                                <div className="text-[9px] font-bold text-slate-400 uppercase mb-2">Signed Passport Envelope</div>
                                <div className="grid grid-cols-3 gap-3 text-[10px]">
                                    {frame.handshake_params.agent_id && (
                                        <div>
                                            <span className="font-bold text-slate-400">agent_id</span>
                                            <div className="font-mono text-slate-700">{frame.handshake_params.agent_id}</div>
                                        </div>
                                    )}
                                    {frame.handshake_params.issuer && (
                                        <div>
                                            <span className="font-bold text-slate-400">issuer</span>
                                            <div className="font-mono text-slate-700">{frame.handshake_params.issuer}</div>
                                        </div>
                                    )}
                                    {frame.handshake_params.capabilities && (
                                        <div>
                                            <span className="font-bold text-slate-400">capabilities</span>
                                            <div className="font-mono text-slate-700">[{frame.handshake_params.capabilities.join(', ')}]</div>
                                        </div>
                                    )}
                                    {frame.handshake_params.issued_at && (
                                        <div>
                                            <span className="font-bold text-slate-400">issued_at</span>
                                            <div className="font-mono text-slate-700">{frame.handshake_params.issued_at}</div>
                                        </div>
                                    )}
                                    {frame.handshake_params.expires_at && (
                                        <div>
                                            <span className="font-bold text-slate-400">expires_at</span>
                                            <div className="font-mono text-slate-700">{frame.handshake_params.expires_at}</div>
                                        </div>
                                    )}
                                    {frame.handshake_params.nonce && (
                                        <div>
                                            <span className="font-bold text-slate-400">nonce</span>
                                            <div className="font-mono text-slate-700">{frame.handshake_params.nonce}</div>
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}
                        {frame.key_exchange_pub && (
                            <div className="text-[10px]">
                                <span className="font-bold text-slate-400">X25519 Public Key: </span>
                                <span className="font-mono text-slate-600">{frame.key_exchange_pub}</span>
                            </div>
                        )}
                        <div className="bg-slate-50 border border-slate-200 rounded p-2 text-[10px] text-slate-600">
                            Encryption: None — key exchange in progress (this is expected during handshake)
                        </div>
                    </div>
                )}

                {/* DATA frames */}
                {ft === 'DATA' && (
                    <div className="space-y-3">
                        {frame.payload_description && (
                            <div className="text-[10px]">
                                <span className="font-bold text-slate-400 uppercase text-[9px]">Payload Description</span>
                                <div className="text-slate-700 mt-0.5">{frame.payload_description}</div>
                            </div>
                        )}
                        <div className="grid grid-cols-4 gap-3 text-[10px]">
                            {frame.payload_type && (
                                <div>
                                    <span className="font-bold text-slate-400">Payload Type</span>
                                    <div className="mt-0.5"><PayloadBadge type={frame.payload_type} /></div>
                                </div>
                            )}
                            <div>
                                <span className="font-bold text-slate-400">Cipher</span>
                                <div className="font-mono text-slate-700 mt-0.5">{frame.cipher || '—'}</div>
                            </div>
                            <div>
                                <span className="font-bold text-slate-400">Encoding</span>
                                <div className="font-mono text-slate-700 mt-0.5">{frame.payload_encoding || '—'}</div>
                            </div>
                            <div>
                                <span className="font-bold text-slate-400">Integrity</span>
                                <div className={`font-bold mt-0.5 ${frame.integrity_check === 'PASS' ? 'text-slate-700' : frame.integrity_check === 'FAIL' ? 'text-slate-400' : 'text-slate-400'}`}>
                                    {frame.integrity_check || '—'}
                                </div>
                            </div>
                        </div>
                        {frame.nonce && (
                            <div className="text-[10px]">
                                <span className="font-bold text-slate-400">Nonce: </span>
                                <span className="font-mono text-slate-500">{frame.nonce}</span>
                            </div>
                        )}
                        <div className="grid grid-cols-3 gap-3 text-[10px]">
                            <div>
                                <span className="font-bold text-slate-400">Session</span>
                                <div className="font-mono text-slate-600 mt-0.5">{frame.session_id || '—'}</div>
                            </div>
                            <div>
                                <span className="font-bold text-slate-400">Total Frame Size</span>
                                <div className="font-mono text-slate-600 mt-0.5">{formatBytes(frame.total_frame_size || 0)}</div>
                            </div>
                            <div>
                                <span className="font-bold text-slate-400">Latency</span>
                                <div className="font-mono text-slate-600 mt-0.5">{frame.latency_ms ? `${frame.latency_ms.toFixed(1)}ms` : '—'}</div>
                            </div>
                        </div>
                    </div>
                )}

                {/* DATA_ACK */}
                {ft === 'DATA_ACK' && (
                    <div className="space-y-2">
                        <div className="bg-slate-50 border border-slate-200 rounded p-3">
                            <div className="flex items-center gap-2 text-[11px] font-bold text-slate-700">
                                <Check size={14} />
                                Acknowledged: DATA seq={frame.sequence} from {agentLabelMap[frame.receiver_agent] || frame.receiver_agent}
                            </div>
                            {frame.payload_description && (
                                <div className="text-[10px] text-slate-600 mt-1">{frame.payload_description}</div>
                            )}
                            <div className="text-[10px] text-slate-600 mt-1">
                                Poly1305 MAC verification: <span className="font-bold">PASS</span>
                            </div>
                        </div>
                        <div className="grid grid-cols-2 gap-3 text-[10px]">
                            <div>
                                <span className="font-bold text-slate-400">Session</span>
                                <div className="font-mono text-slate-600 mt-0.5">{frame.session_id || '—'}</div>
                            </div>
                            <div>
                                <span className="font-bold text-slate-400">Cipher</span>
                                <div className="font-mono text-slate-600 mt-0.5">{frame.cipher || '—'}</div>
                            </div>
                        </div>
                    </div>
                )}

                {/* ERROR */}
                {ft === 'ERROR' && (
                    <div className="bg-slate-100 border border-slate-300 rounded p-3 space-y-2">
                        <div className="flex items-center gap-2 text-[11px] font-bold text-slate-800">
                            <AlertTriangle size={14} />
                            Protocol Error
                        </div>
                        {frame.error_code > 0 && (
                            <div className="text-[10px] text-slate-600">
                                <span className="font-bold">Error Code:</span> 0x{frame.error_code.toString(16).toUpperCase().padStart(2, '0')}
                            </div>
                        )}
                        {frame.error_message && (
                            <div className="text-[10px] text-slate-700 font-mono">{frame.error_message}</div>
                        )}
                    </div>
                )}

                {/* STREAM_START */}
                {ft === 'STREAM_START' && (
                    <div className="space-y-2">
                        <div className="bg-slate-50 border border-slate-200 rounded p-3">
                            <div className="flex items-center gap-2 text-[11px] font-bold text-slate-700">
                                <BarChart3 size={14} />
                                Stream Initiated
                            </div>
                            {frame.payload_description && (
                                <div className="text-[10px] text-slate-600 mt-1">{frame.payload_description}</div>
                            )}
                        </div>
                        {frame.payload_type && (
                            <div className="text-[10px]">
                                <span className="font-bold text-slate-400">Type: </span>
                                <PayloadBadge type={frame.payload_type} />
                            </div>
                        )}
                    </div>
                )}

                {/* STREAM_CHUNK */}
                {ft === 'STREAM_CHUNK' && (
                    <div className="space-y-2">
                        {frame.payload_description && (
                            <div className="text-[10px] text-slate-700">{frame.payload_description}</div>
                        )}
                        <div className="grid grid-cols-3 gap-3 text-[10px]">
                            <div>
                                <span className="font-bold text-slate-400">Chunk Size</span>
                                <div className="font-mono text-slate-600 mt-0.5">{formatBytes(frame.payload_size || 0)}</div>
                            </div>
                            <div>
                                <span className="font-bold text-slate-400">Cipher</span>
                                <div className="font-mono text-slate-600 mt-0.5">{frame.cipher || '—'}</div>
                            </div>
                            <div>
                                <span className="font-bold text-slate-400">Session</span>
                                <div className="font-mono text-slate-600 mt-0.5">{frame.session_id || '—'}</div>
                            </div>
                        </div>
                    </div>
                )}

                {/* STREAM_END */}
                {ft === 'STREAM_END' && (
                    <div className="bg-slate-50 border border-slate-200 rounded p-3 space-y-1">
                        <div className="flex items-center gap-2 text-[11px] font-bold text-slate-700">
                            <Check size={14} />
                            Stream Complete
                        </div>
                        {frame.payload_description && (
                            <div className="text-[10px] text-slate-600">{frame.payload_description}</div>
                        )}
                        {frame.integrity_check && (
                            <div className={`text-[10px] font-bold ${frame.integrity_check === 'PASS' ? 'text-slate-700' : 'text-slate-400'}`}>
                                Integrity: {frame.integrity_check}
                            </div>
                        )}
                    </div>
                )}

                {/* PING/PONG/CLOSE — simple info */}
                {(ft === 'PING' || ft === 'PONG' || ft === 'CLOSE') && (
                    <div className="grid grid-cols-3 gap-3 text-[10px]">
                        <div>
                            <span className="font-bold text-slate-400">Session</span>
                            <div className="font-mono text-slate-600 mt-0.5">{frame.session_id || '—'}</div>
                        </div>
                        <div>
                            <span className="font-bold text-slate-400">Passport</span>
                            <div className="font-mono text-slate-600 mt-0.5">{frame.passport_hash || '—'}</div>
                        </div>
                        <div>
                            <span className="font-bold text-slate-400">Latency</span>
                            <div className="font-mono text-slate-600 mt-0.5">{frame.latency_ms ? `${frame.latency_ms.toFixed(1)}ms` : '—'}</div>
                        </div>
                    </div>
                )}
            </div>
        </td>
    );
};

const BastionProtocolView = ({ bastionData, protocolLog }) => {
    const [expandedId, setExpandedId] = useState(null);
    const [filterFrameType, setFilterFrameType] = useState('');
    const [filterAgent, setFilterAgent] = useState('');
    const [filterEventType, setFilterEventType] = useState('');
    const [filterAuthStatus, setFilterAuthStatus] = useState('');

    const frames = bastionData?.frames || [];
    const stats = bastionData?.stats || {};
    const connections = bastionData?.connections || [];
    const agentStatus = bastionData?.agent_status || {};

    // Client-side filtering
    const filtered = frames.filter(f => {
        if (filterFrameType && f.frame_type !== filterFrameType) return false;
        if (filterAgent && !f.sender_agent?.includes(filterAgent) && !f.receiver_agent?.includes(filterAgent)) return false;
        if (filterEventType && f.event_type !== filterEventType) return false;
        return true;
    });

    const allFrameTypes = [...new Set(frames.map(f => f.frame_type).filter(Boolean))].sort();
    const allEventTypes = [...new Set(frames.map(f => f.event_type).filter(Boolean))].sort();

    const hasActivity = frames.length > 0;

    // Find the most recent complete session for the pipeline explanation
    const pipelineSession = useMemo(() => {
        // Find a session with HELLO, HELLO_ACK, DATA, and DATA_ACK
        const sessions = {};
        frames.forEach(f => {
            if (f.session_id) {
                if (!sessions[f.session_id]) sessions[f.session_id] = [];
                sessions[f.session_id].push(f);
            }
        });

        for (const [sid, sFrames] of Object.entries(sessions)) {
            const types = new Set(sFrames.map(f => f.frame_type));
            if (types.has('HELLO') && types.has('HELLO_ACK') && (types.has('DATA') || types.has('STREAM_START'))) {
                const hello = sFrames.find(f => f.frame_type === 'HELLO');
                const helloAck = sFrames.find(f => f.frame_type === 'HELLO_ACK');
                const data = sFrames.find(f => f.frame_type === 'DATA');
                const dataAck = sFrames.find(f => f.frame_type === 'DATA_ACK');
                return { sid, hello, helloAck, data, dataAck, frames: sFrames };
            }
        }
        return null;
    }, [frames]);

    return (
        <div className="p-8 max-w-6xl mx-auto space-y-6 animate-fade-in">
            {/* Section 1: Header + Stats */}
            <div>
                <div className="flex items-center gap-3 mb-2">
                    <div className="w-10 h-10 bg-slate-100 border border-slate-200 rounded-sm flex items-center justify-center">
                        <Shield size={20} className="text-slate-700" />
                    </div>
                    <div>
                        <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight uppercase">Bastion Protocol</h1>
                        <p className="text-xs text-slate-500 font-medium">Native Agent-to-Agent Communication Layer</p>
                    </div>
                </div>
                <p className="text-sm text-slate-600 max-w-3xl mt-3 leading-relaxed">
                    Agents should not communicate over infrastructure designed for browsers. The Bastion Protocol
                    replaces HTTP request/response with a binary frame format built on PyNaCl and MessagePack —
                    agents authenticate via Ed25519-signed passport envelopes (MessagePack + raw signature), derive per-session encryption keys through
                    X25519 Diffie-Hellman, and exchange data encrypted with NaCl SecretBox (XSalsa20-Poly1305).
                    Identity, signing, and encryption are enforced by the frame encoder itself — they are not
                    optional headers or middleware. Every interaction on this page is a real TCP session between
                    agents running on ports 9101–9104.
                </p>

                {/* Stats Cards */}
                <div className="grid grid-cols-4 gap-4 mt-6">
                    {[
                        { label: 'Active Connections', value: stats.active_connections || 0, color: 'text-slate-700' },
                        { label: 'Frames Exchanged', value: stats.total_frames || 0, color: 'text-slate-700' },
                        { label: 'Bytes Transferred', value: formatBytes(stats.total_bytes || 0), color: 'text-slate-700' },
                        { label: 'Handshakes Completed', value: stats.handshakes_completed || 0, color: 'text-slate-700' },
                    ].map(s => (
                        <div key={s.label} className="bg-white border border-slate-200 rounded-sm p-4">
                            <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">{s.label}</div>
                            <div className={`text-2xl font-extrabold ${s.color} font-mono`}>{s.value}</div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Section 2: Live Connection Diagram */}
            <div className="bg-white border border-slate-200 rounded-sm p-6">
                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-4">Active Agent Sessions</div>
                <div className="flex items-center justify-between gap-2">
                    {agentConfig.map((agent, i) => {
                        const isActive = agentStatus[agent.name] === 'online'
                            || connections.some(c => c.agents?.includes(agent.name));
                        const passportHash = frames.find(f =>
                            f.sender_agent === agent.name && f.passport_hash
                        )?.passport_hash || '';

                        return (
                            <React.Fragment key={agent.name}>
                                <div className={`flex-1 border rounded-sm p-4 text-center transition-all ${
                                    isActive
                                        ? 'border-slate-400 bg-slate-50/50'
                                        : 'border-slate-200 bg-slate-50/50'
                                }`}>
                                    <div className="flex items-center justify-center gap-1.5 mb-2">
                                        <div className={`w-2 h-2 rounded-full ${isActive ? 'bg-slate-600 animate-pulse' : 'bg-slate-300'}`} />
                                        <span className="text-xs font-bold text-slate-700">{agent.label}</span>
                                    </div>
                                    <div className="text-[10px] font-mono text-slate-400">TCP:{agent.port}</div>
                                    <div className="text-[9px] font-bold text-slate-400 uppercase mt-1">{agent.role}</div>
                                    {passportHash && (
                                        <div className="text-[9px] font-mono text-slate-400 mt-1 flex items-center justify-center gap-1">
                                            <Fingerprint size={9} />
                                            {passportHash.slice(0, 8)}...
                                        </div>
                                    )}
                                    {isActive && (
                                        <div className="flex items-center justify-center gap-1 mt-2">
                                            <Lock size={9} className="text-slate-700" />
                                            <span className="text-[9px] font-bold text-slate-700">ENCRYPTED</span>
                                        </div>
                                    )}
                                </div>
                                {i < agentConfig.length - 1 && (
                                    <div className="flex flex-col items-center">
                                        <div className={`w-8 h-px ${isActive ? 'bg-slate-400' : 'bg-slate-200'}`} />
                                        {isActive && <Zap size={10} className="text-slate-500 mt-0.5" />}
                                    </div>
                                )}
                            </React.Fragment>
                        );
                    })}
                </div>
            </div>

            {/* Section 3: Frame Log (Packet Capture Style) */}
            <div className="bg-white border border-slate-200 rounded-sm">
                <div className="p-4 border-b border-slate-100 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <Radio size={14} className="text-slate-500" />
                        <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Frame Log</span>
                        <span className="text-[10px] font-mono text-slate-400">({filtered.length} frames)</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <select
                            value={filterFrameType}
                            onChange={e => setFilterFrameType(e.target.value)}
                            className="text-[10px] border border-slate-200 rounded px-2 py-1 bg-white text-slate-600"
                        >
                            <option value="">All Types</option>
                            {allFrameTypes.map(t => <option key={t} value={t}>{frameTypeLabels[t] || t}</option>)}
                        </select>
                        <select
                            value={filterEventType}
                            onChange={e => setFilterEventType(e.target.value)}
                            className="text-[10px] border border-slate-200 rounded px-2 py-1 bg-white text-slate-600"
                        >
                            <option value="">All Events</option>
                            {allEventTypes.map(t => <option key={t} value={t}>{t}</option>)}
                        </select>
                        <input
                            value={filterAgent}
                            onChange={e => setFilterAgent(e.target.value)}
                            placeholder="Filter agent..."
                            className="text-[10px] border border-slate-200 rounded px-2 py-1 bg-white text-slate-600 w-28"
                        />
                    </div>
                </div>

                {!hasActivity ? (
                    <div className="p-12 text-center">
                        <Shield size={32} className="text-slate-300 mx-auto mb-3" />
                        <p className="text-sm font-medium text-slate-400">No active agent sessions</p>
                        <p className="text-xs text-slate-400 mt-1">Frame-level events will appear here when agents establish sessions and exchange data</p>
                    </div>
                ) : (
                    <div className="max-h-[500px] overflow-y-auto thin-scrollbar">
                        <table className="w-full text-[11px]">
                            <thead className="bg-slate-50 sticky top-0">
                                <tr>
                                    <th className="text-left px-3 py-2 text-[9px] font-bold text-slate-400 uppercase">Time</th>
                                    <th className="text-center px-2 py-2 text-[9px] font-bold text-slate-400 uppercase">Dir</th>
                                    <th className="text-left px-3 py-2 text-[9px] font-bold text-slate-400 uppercase">Frame Type</th>
                                    <th className="text-left px-3 py-2 text-[9px] font-bold text-slate-400 uppercase">Sender</th>
                                    <th className="text-left px-3 py-2 text-[9px] font-bold text-slate-400 uppercase">Receiver</th>
                                    <th className="text-right px-3 py-2 text-[9px] font-bold text-slate-400 uppercase">Seq</th>
                                    <th className="text-right px-3 py-2 text-[9px] font-bold text-slate-400 uppercase">Size</th>
                                    <th className="text-center px-2 py-2 text-[9px] font-bold text-slate-400 uppercase">Type</th>
                                    <th className="text-center px-2 py-2 text-[9px] font-bold text-slate-400 uppercase">Security</th>
                                    <th className="w-6"></th>
                                </tr>
                            </thead>
                            <tbody>
                                {filtered.slice(0, 100).map(frame => {
                                    const colors = frameTypeColors[frame.frame_type] || { bg: 'bg-slate-50', border: 'border-slate-200', text: 'text-slate-600' };
                                    const isExpanded = expandedId === frame.log_id;

                                    // ACK indicator: check if DATA frame has matching DATA_ACK
                                    const isDataSent = frame.frame_type === 'DATA' && frame.direction === 'SENT';
                                    const hasAck = isDataSent && frames.some(f =>
                                        f.session_id === frame.session_id &&
                                        f.frame_type === 'DATA_ACK' &&
                                        f.sequence === frame.sequence
                                    );

                                    return (
                                        <React.Fragment key={frame.log_id}>
                                            <tr
                                                className="border-b border-slate-50 hover:bg-slate-50/50 cursor-pointer transition-colors"
                                                onClick={() => setExpandedId(isExpanded ? null : frame.log_id)}
                                            >
                                                <td className="px-3 py-2 font-mono text-slate-500">{formatTime(frame.timestamp)}</td>
                                                <td className="px-2 py-2 text-center">
                                                    {frame.direction === 'SENT' ? (
                                                        <ArrowRight size={12} className="text-slate-500 inline" />
                                                    ) : (
                                                        <ArrowDown size={12} className="text-slate-500 inline" />
                                                    )}
                                                </td>
                                                <td className="px-3 py-2">
                                                    <div className="flex items-center gap-1.5">
                                                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${colors.bg} ${colors.border} ${colors.text}`}>
                                                            {frameTypeLabels[frame.frame_type] || frame.frame_type}
                                                        </span>
                                                        {isDataSent && (
                                                            hasAck
                                                                ? <span className="text-[8px] font-bold text-slate-700 bg-slate-100 px-1 rounded">ACK</span>
                                                                : <span className="text-[8px] font-bold text-slate-400 bg-slate-50 px-1 rounded">PENDING</span>
                                                        )}
                                                        {frame.accepted && frame.frame_type === 'DATA_ACK' && (
                                                            <Check size={10} className="text-slate-600" />
                                                        )}
                                                    </div>
                                                </td>
                                                <td className="px-3 py-2 font-medium text-slate-700">{agentLabelMap[frame.sender_agent] || frame.sender_agent || '—'}</td>
                                                <td className="px-3 py-2 font-medium text-slate-700">{agentLabelMap[frame.receiver_agent] || frame.receiver_agent || '—'}</td>
                                                <td className="px-3 py-2 text-right font-mono text-slate-400">{frame.sequence || '—'}</td>
                                                <td className="px-3 py-2 text-right font-mono text-slate-500">{formatBytes(frame.payload_size || 0)}</td>
                                                <td className="px-2 py-2 text-center">
                                                    {frame.payload_type && <PayloadBadge type={frame.payload_type} />}
                                                </td>
                                                <td className="px-2 py-2 text-center">
                                                    <div className="flex items-center justify-center gap-1">
                                                        {frame.encrypted && <Lock size={10} className="text-slate-600" />}
                                                        {frame.signature_verified && <Key size={10} className="text-slate-600" />}
                                                        {frame.passport_hash && <Fingerprint size={10} className="text-slate-500" />}
                                                    </div>
                                                </td>
                                                <td className="pr-2">
                                                    {isExpanded
                                                        ? <ChevronDown size={12} className="text-slate-400" />
                                                        : <ChevronRight size={12} className="text-slate-300" />
                                                    }
                                                </td>
                                            </tr>
                                            {isExpanded && (
                                                <tr className="border-b border-slate-100">
                                                    <ExpandedFrameDetail frame={frame} frames={frames} />
                                                </tr>
                                            )}
                                        </React.Fragment>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* Section 4: Data-Driven Pipeline Explanation */}
            <div className="bg-white border border-slate-200 rounded-sm p-6">
                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-4">Session Pipeline</div>

                {pipelineSession ? (() => {
                    const { hello, helloAck, data, dataAck, sid } = pipelineSession;
                    const senderLabel = agentLabelMap[hello?.sender_agent] || hello?.sender_agent || 'Agent A';
                    const receiverLabel = agentLabelMap[hello?.receiver_agent] || hello?.receiver_agent || 'Agent B';

                    const steps = [
                        {
                            num: 1,
                            label: 'Agent Identity',
                            detail: `${senderLabel} boots with Ed25519 keypair, passport hash: ${hello?.passport_hash || '—'}`,
                            color: 'border-slate-400 bg-slate-100',
                            dotColor: 'bg-slate-600',
                        },
                        {
                            num: 2,
                            label: 'HELLO',
                            detail: `Sends signed passport envelope + ephemeral X25519 public key${hello?.key_exchange_pub ? ` (${hello.key_exchange_pub.slice(0, 14)}...)` : ''} to ${receiverLabel}`,
                            color: 'border-slate-300 bg-slate-50',
                            dotColor: 'bg-slate-500',
                        },
                        {
                            num: 3,
                            label: 'Key Exchange',
                            detail: `X25519 Diffie-Hellman derives shared secret — ${receiverLabel} responds with HELLO_ACK`,
                            color: 'border-slate-300 bg-slate-50',
                            dotColor: 'bg-slate-500',
                        },
                        {
                            num: 4,
                            label: 'Session Established',
                            detail: `XSalsa20-Poly1305 cipher active, session ${sid}${helloAck?.latency_ms ? `, latency ${helloAck.latency_ms.toFixed(1)}ms` : ''}`,
                            color: 'border-slate-400 bg-slate-100',
                            dotColor: 'bg-slate-700',
                        },
                    ];

                    if (data) {
                        steps.push({
                            num: 5,
                            label: 'Encrypted Payload',
                            detail: data.payload_description || `Data sent (${formatBytes(data.payload_size || 0)} ${data.payload_encoding || 'msgpack'}, encrypted)`,
                            color: 'border-slate-300 bg-slate-50',
                            dotColor: 'bg-slate-600',
                        });
                    }

                    if (dataAck) {
                        steps.push({
                            num: 6,
                            label: 'Acknowledged',
                            detail: `${receiverLabel} verifies MAC, sends DATA_ACK — payload accepted`,
                            color: 'border-slate-400 bg-slate-100',
                            dotColor: 'bg-slate-700',
                        });
                    }

                    return (
                        <div className="max-w-2xl mx-auto">
                            <div className="text-[10px] text-slate-500 mb-4">
                                Latest session: <span className="font-mono font-bold">{sid}</span> — {senderLabel} → {receiverLabel}
                            </div>
                            <div className="relative">
                                {/* Vertical timeline line */}
                                <div className="absolute left-4 top-4 bottom-4 w-px bg-slate-200" />

                                <div className="space-y-3">
                                    {steps.map((step) => (
                                        <div key={step.num} className="flex items-start gap-4">
                                            <div className={`w-8 h-8 rounded-full ${step.dotColor} flex items-center justify-center text-white text-[11px] font-bold z-10 flex-shrink-0`}>
                                                {step.num}
                                            </div>
                                            <div className={`flex-1 border rounded-sm p-3 ${step.color}`}>
                                                <div className="text-[10px] font-bold text-slate-700 uppercase">{step.label}</div>
                                                <div className="text-[10px] text-slate-600 mt-0.5">{step.detail}</div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    );
                })() : (
                    /* Fallback: static handshake diagram (original) */
                    <div className="max-w-lg mx-auto">
                        <div className="space-y-3">
                            <div className="flex items-center gap-4">
                                <div className="w-28 text-right">
                                    <span className="text-[10px] font-bold text-slate-700">Initiator</span>
                                </div>
                                <div className="flex-1 flex items-center">
                                    <div className="flex-1 h-px bg-slate-400 relative">
                                        <ArrowRight size={12} className="text-slate-500 absolute -right-1 -top-1.5" />
                                    </div>
                                </div>
                                <div className="w-28">
                                    <span className="text-[10px] font-bold text-slate-500">Responder</span>
                                </div>
                            </div>
                            <div className="text-center">
                                <span className="text-[9px] font-bold text-slate-700 bg-slate-100 border border-slate-300 px-2 py-0.5 rounded">
                                    HELLO: Signed Envelope + X25519 Pub + Nonce
                                </span>
                            </div>

                            <div className="flex items-center gap-4 mt-4">
                                <div className="w-28 text-right">
                                    <span className="text-[10px] font-bold text-slate-500">Initiator</span>
                                </div>
                                <div className="flex-1 flex items-center rotate-180">
                                    <div className="flex-1 h-px bg-slate-400 relative">
                                        <ArrowRight size={12} className="text-slate-500 absolute -right-1 -top-1.5" />
                                    </div>
                                </div>
                                <div className="w-28">
                                    <span className="text-[10px] font-bold text-slate-700">Responder</span>
                                </div>
                            </div>
                            <div className="text-center">
                                <span className="text-[9px] font-bold text-slate-700 bg-slate-100 border border-slate-300 px-2 py-0.5 rounded">
                                    HELLO_ACK: Signed Envelope + X25519 Pub + Nonce Echo
                                </span>
                            </div>

                            <div className="text-center mt-4">
                                <div className="inline-flex items-center gap-2 bg-slate-800 border border-slate-900 px-3 py-1.5 rounded">
                                    <Lock size={11} className="text-white" />
                                    <span className="text-[9px] font-bold text-white">SESSION ESTABLISHED — XSalsa20-Poly1305</span>
                                </div>
                            </div>

                            <div className="flex items-center gap-4 mt-4">
                                <div className="w-28 text-right">
                                    <span className="text-[10px] font-bold text-slate-700">Agent A</span>
                                </div>
                                <div className="flex-1 flex items-center">
                                    <div className="flex-1 h-px bg-slate-400 relative" style={{ backgroundImage: 'repeating-linear-gradient(90deg, transparent, transparent 4px, #94a3b8 4px, #94a3b8 8px)' }}>
                                        <ArrowRight size={12} className="text-slate-500 absolute -right-1 -top-1.5" />
                                    </div>
                                </div>
                                <div className="w-28">
                                    <span className="text-[10px] font-bold text-slate-700">Agent B</span>
                                </div>
                            </div>
                            <div className="text-center">
                                <span className="text-[9px] font-bold text-slate-700 bg-slate-100 border border-slate-300 px-2 py-0.5 rounded">
                                    DATA: Encrypted Payload (MessagePack + Signature)
                                </span>
                            </div>
                        </div>

                        <div className="flex items-center justify-center gap-4 mt-6 pt-4 border-t border-slate-100">
                            <div className="flex items-center gap-1">
                                <div className="w-6 h-px bg-slate-400" />
                                <span className="text-[9px] text-slate-400">Handshake (unencrypted)</span>
                            </div>
                            <div className="flex items-center gap-1">
                                <div className="w-6 h-px bg-slate-700" />
                                <span className="text-[9px] text-slate-400">Session established</span>
                            </div>
                            <div className="flex items-center gap-1">
                                <div className="w-6 h-px" style={{ backgroundImage: 'repeating-linear-gradient(90deg, transparent, transparent 2px, #94a3b8 2px, #94a3b8 4px)' }} />
                                <span className="text-[9px] text-slate-400">Encrypted data flow</span>
                            </div>
                        </div>
                    </div>
                )}
            </div>

            {/* Section 5: Protocol Messages (merged from ProtocolMonitorView) */}
            {(() => {
                const messages = protocolLog?.messages || [];
                const filteredMessages = messages.filter(m => {
                    if (filterAuthStatus && m.auth_result !== filterAuthStatus) return false;
                    return true;
                });
                const authStatuses = [...new Set(messages.map(m => m.auth_result).filter(Boolean))].sort();

                return (
                    <div className="bg-white border border-slate-200 rounded-sm">
                        <div className="p-4 border-b border-slate-100 flex items-center justify-between">
                            <div className="flex items-center gap-2">
                                <Radio size={14} className="text-slate-500" />
                                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">API-Layer Protocol Messages</span>
                                <span className="text-[10px] font-mono text-slate-400">({filteredMessages.length} messages)</span>
                            </div>
                            <select
                                value={filterAuthStatus}
                                onChange={e => setFilterAuthStatus(e.target.value)}
                                className="text-[10px] border border-slate-200 rounded px-2 py-1 bg-white text-slate-600"
                            >
                                <option value="">All Auth Status</option>
                                {authStatuses.map(s => <option key={s} value={s}>{s}</option>)}
                            </select>
                        </div>

                        {filteredMessages.length === 0 ? (
                            <div className="p-8 text-center">
                                <Radio size={24} className="text-slate-300 mx-auto mb-2" />
                                <p className="text-sm text-slate-400">No protocol messages yet</p>
                            </div>
                        ) : (
                            <div className="max-h-[300px] overflow-y-auto thin-scrollbar">
                                <table className="w-full text-[11px]">
                                    <thead className="bg-slate-50 sticky top-0">
                                        <tr>
                                            <th className="text-left px-3 py-2 text-[9px] font-bold text-slate-400 uppercase">Time</th>
                                            <th className="text-left px-3 py-2 text-[9px] font-bold text-slate-400 uppercase">Type</th>
                                            <th className="text-left px-3 py-2 text-[9px] font-bold text-slate-400 uppercase">Sender</th>
                                            <th className="text-left px-3 py-2 text-[9px] font-bold text-slate-400 uppercase">Endpoint</th>
                                            <th className="text-center px-3 py-2 text-[9px] font-bold text-slate-400 uppercase">Auth</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {filteredMessages.slice(0, 50).map((msg, idx) => {
                                            const authColor = {
                                                'AUTHENTICATED': 'text-slate-700 bg-slate-100 border-slate-300',
                                                'REJECTED': 'text-slate-400 bg-slate-50 border-slate-200',
                                                'SKIPPED': 'text-slate-500 bg-slate-50 border-slate-200',
                                                'CHALLENGE_ISSUED': 'text-slate-600 bg-slate-50 border-slate-200',
                                            }[msg.auth_result] || 'text-slate-500 bg-slate-50 border-slate-200';

                                            return (
                                                <tr key={idx} className="border-b border-slate-50 hover:bg-slate-50/50">
                                                    <td className="px-3 py-2 font-mono text-slate-500">
                                                        {msg.timestamp ? formatTime(msg.timestamp) : '-'}
                                                    </td>
                                                    <td className="px-3 py-2">
                                                        <span className="text-[9px] font-bold text-slate-600">{msg.message_type || '-'}</span>
                                                    </td>
                                                    <td className="px-3 py-2 font-medium text-slate-700">
                                                        {msg.sender_id || msg.agent_id || 'unknown'}
                                                    </td>
                                                    <td className="px-3 py-2 font-mono text-slate-400 text-[10px]">
                                                        {msg.endpoint || '-'}
                                                    </td>
                                                    <td className="px-3 py-2 text-center">
                                                        <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${authColor}`}>
                                                            {msg.auth_result || '-'}
                                                        </span>
                                                    </td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                );
            })()}

            {/* Section 6: Educational Explainer — "Why Binary?" */}
            <div className="bg-white border border-slate-200 rounded-sm p-6">
                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-2">Why Agents Need Their Own Protocol</div>
                <p className="text-sm text-slate-600 mb-4">
                    When agents communicate over REST APIs, security is opt-in. The developer must add authentication
                    middleware, configure TLS, implement replay protection, and hope every service in the chain does the same.
                    In multi-agent systems — where agents make decisions and act on each other's data without human review —
                    a single misconfigured endpoint becomes an attack surface for impersonation, data poisoning, or replay attacks.
                </p>
                <p className="text-sm text-slate-600 mb-6">
                    The Bastion Protocol makes security structural, not optional. The frame encoder requires an Ed25519
                    signing key and a passport hash to construct any frame — there is no code path to send an unsigned
                    or unattributed message. Session keys are derived via ephemeral X25519 key exchange and discarded
                    after use (forward secrecy). Every frame carries a microsecond timestamp and monotonic sequence
                    number, enforced within a 60-second freshness window — replaying or delaying frames is not a
                    configuration risk, it is a protocol-level impossibility.
                </p>

                {/* Three comparison cards */}
                <div className="grid grid-cols-3 gap-4 mb-6">
                    <div className="border border-slate-200 rounded-sm p-4">
                        <div className="flex items-center gap-2 mb-3">
                            <Fingerprint size={16} className="text-slate-700" />
                            <span className="text-xs font-bold text-slate-900">Every Frame Has an Owner</span>
                        </div>
                        <div className="space-y-2">
                            <div className="bg-slate-50 border border-slate-200 rounded p-2">
                                <div className="text-[9px] font-bold text-slate-400 uppercase mb-0.5">Traditional API</div>
                                <div className="text-[10px] text-slate-600">Optional Authorization header carrying a bearer token. An agent can send requests with no provable link to a verified identity.</div>
                            </div>
                            <div className="bg-slate-100 border border-slate-200 rounded p-2">
                                <div className="text-[9px] font-bold text-slate-600 uppercase mb-0.5">Bastion Protocol</div>
                                <div className="text-[10px] text-slate-600">
                                    Every frame carries a full 32-byte SHA-256 passport hash and a 64-byte Ed25519 signature
                                    computed over the entire frame contents, including a microsecond timestamp. The protocol
                                    physically cannot construct a frame without a signing key bound to a verified passport —
                                    anonymous or forged messages do not exist at the wire level.
                                </div>
                            </div>
                        </div>
                    </div>

                    <div className="border border-slate-200 rounded-sm p-4">
                        <div className="flex items-center gap-2 mb-3">
                            <Lock size={16} className="text-slate-700" />
                            <span className="text-xs font-bold text-slate-900">Session-Level Authenticated Encryption</span>
                        </div>
                        <div className="space-y-2">
                            <div className="bg-slate-50 border border-slate-200 rounded p-2">
                                <div className="text-[9px] font-bold text-slate-400 uppercase mb-0.5">Traditional API</div>
                                <div className="text-[10px] text-slate-600">TLS operates at the transport layer and is routinely skipped between internal services. The application has no guarantee that encryption occurred.</div>
                            </div>
                            <div className="bg-slate-100 border border-slate-200 rounded p-2">
                                <div className="text-[9px] font-bold text-slate-600 uppercase mb-0.5">Bastion Protocol</div>
                                <div className="text-[10px] text-slate-600">
                                    During handshake, agents exchange ephemeral X25519 keys and derive a shared session secret.
                                    Every data frame is encrypted and authenticated with NaCl SecretBox (XSalsa20-Poly1305).
                                    Ephemeral keys are discarded after derivation — even if a long-term key is compromised,
                                    past sessions cannot be decrypted (forward secrecy). This is application-layer encryption
                                    enforced by the frame encoder, not a deployment configuration.
                                </div>
                            </div>
                        </div>
                    </div>

                    <div className="border border-slate-200 rounded-sm p-4">
                        <div className="flex items-center gap-2 mb-3">
                            <Zap size={16} className="text-slate-700" />
                            <span className="text-xs font-bold text-slate-900">Binary-Native Serialization</span>
                        </div>
                        <div className="space-y-2">
                            <div className="bg-slate-50 border border-slate-200 rounded p-2">
                                <div className="text-[9px] font-bold text-slate-400 uppercase mb-0.5">Traditional API</div>
                                <div className="text-[10px] text-slate-600">JSON text encoding requires serialization/parsing overhead, cannot natively represent binary data (base64 adds ~33%), and carries ~800 bytes of HTTP headers per request.</div>
                            </div>
                            <div className="bg-slate-100 border border-slate-200 rounded p-2">
                                <div className="text-[9px] font-bold text-slate-600 uppercase mb-0.5">Bastion Protocol</div>
                                <div className="text-[10px] text-slate-600">
                                    Payloads are serialized with MessagePack — a typed binary format that handles raw bytes, integers,
                                    floats, and nested structures without text conversion. The v2 frame header is 116 bytes
                                    (version + type + flags + passport hash + sequence + timestamp + length + signature). A complete
                                    authenticated, encrypted agent interaction fits in under 250 bytes where HTTP/JSON would require over 1KB.
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Overhead comparison table */}
                <div className="border border-slate-200 rounded-sm overflow-hidden">
                    <table className="w-full text-[11px]">
                        <thead className="bg-slate-50">
                            <tr>
                                <th className="text-left px-4 py-2.5 text-[9px] font-bold text-slate-400 uppercase tracking-widest w-1/3"></th>
                                <th className="text-left px-4 py-2.5 text-[9px] font-bold text-slate-400 uppercase tracking-widest w-1/3">Traditional REST API</th>
                                <th className="text-left px-4 py-2.5 text-[9px] font-bold text-slate-600 uppercase tracking-widest w-1/3">Agent-Native Protocol</th>
                            </tr>
                        </thead>
                        <tbody>
                            {[
                                ['Identity', 'Optional Bearer token in Authorization header', 'Full SHA-256 passport hash (32B) in every frame header'],
                                ['Signing', 'No per-request signatures', 'Ed25519 signature (64B) over full frame contents'],
                                ['Key exchange', 'None (server holds static TLS cert)', 'Ephemeral X25519 Diffie-Hellman per session (forward secrecy)'],
                                ['Encryption', 'TLS at transport layer (routinely skipped internally)', 'NaCl SecretBox (XSalsa20-Poly1305) per data frame'],
                                ['Serialization', 'JSON text (~800B headers + base64 for binary)', 'MessagePack binary (116B fixed overhead, native binary support)'],
                                ['Anti-replay', 'No built-in protection', 'Monotonic sequence + per-frame μs timestamp + 60s freshness window'],
                                ['Accountability', 'Requests can be unsigned and anonymous', 'Frame encoder requires signing key — unsigned frames cannot exist'],
                            ].map(([label, http, bastion], i) => (
                                <tr key={label} className={i % 2 === 0 ? 'bg-white' : 'bg-slate-50/50'}>
                                    <td className="px-4 py-2 font-bold text-slate-700">{label}</td>
                                    <td className="px-4 py-2 text-slate-500">{http}</td>
                                    <td className="px-4 py-2 text-slate-700 font-medium">{bastion}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>

                {/* Frame format breakdown */}
                <div className="mt-6 bg-white border border-slate-200 rounded-sm p-4">
                    <div className="text-[9px] font-bold text-slate-400 uppercase tracking-widest mb-3">Wire Format v2 (116-byte fixed overhead)</div>
                    <div className="flex items-center gap-0.5 font-mono text-[10px]">
                        <div className="bg-slate-100 text-slate-700 border border-slate-300 px-2 py-1.5 rounded-l text-center">
                            <div className="font-bold">Ver</div>
                            <div className="text-[8px] text-slate-500">1B</div>
                        </div>
                        <div className="bg-slate-100 text-slate-700 border border-slate-300 px-2 py-1.5 text-center">
                            <div className="font-bold">Type</div>
                            <div className="text-[8px] text-slate-500">1B</div>
                        </div>
                        <div className="bg-slate-100 text-slate-700 border border-slate-300 px-2 py-1.5 text-center">
                            <div className="font-bold">Flags</div>
                            <div className="text-[8px] text-slate-500">2B</div>
                        </div>
                        <div className="bg-slate-100 text-slate-700 border border-slate-300 px-3 py-1.5 text-center">
                            <div className="font-bold">Passport Hash</div>
                            <div className="text-[8px] text-slate-500">32B</div>
                        </div>
                        <div className="bg-slate-100 text-slate-700 border border-slate-300 px-2 py-1.5 text-center">
                            <div className="font-bold">Seq</div>
                            <div className="text-[8px] text-slate-500">4B</div>
                        </div>
                        <div className="bg-slate-100 text-slate-700 border border-slate-300 px-2 py-1.5 text-center">
                            <div className="font-bold">Time</div>
                            <div className="text-[8px] text-slate-500">8B</div>
                        </div>
                        <div className="bg-slate-100 text-slate-700 border border-slate-300 px-2 py-1.5 text-center">
                            <div className="font-bold">Len</div>
                            <div className="text-[8px] text-slate-500">4B</div>
                        </div>
                        <div className="bg-slate-50 text-slate-700 border border-slate-200 flex-1 px-3 py-1.5 text-center">
                            <div className="font-bold">Payload</div>
                            <div className="text-[8px] text-slate-500">N bytes (encrypted)</div>
                        </div>
                        <div className="bg-slate-100 text-slate-700 border border-slate-300 px-3 py-1.5 rounded-r text-center">
                            <div className="font-bold">Signature</div>
                            <div className="text-[8px] text-slate-500">64B (Ed25519)</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default BastionProtocolView;

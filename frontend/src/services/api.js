import axios from "axios";

// Auto-detect: if running standalone (npm run dev outside Docker), hit localhost:8000 directly.
// If running inside Docker with vite proxy, use relative paths (same origin).
const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";

// Demo mode: disables destructive actions (approve/reject/verify/simulate)
export const DEMO_MODE = import.meta.env.VITE_DEMO_MODE === "true";

// M2M API — targets /m2m router
const m2mApi = axios.create({
    baseURL: `${API_BASE}/m2m`,
    timeout: 15000,
    headers: {
        'Content-Type': 'application/json',
        'X-System-ID': 'LAST-BASTION-V2-M2M'
    }
});

// Refinery API — targets /refinery router
const refineryApi = axios.create({
    baseURL: `${API_BASE}/refinery`,
    timeout: 15000,
    headers: {
        'Content-Type': 'application/json',
        'X-System-ID': 'LAST-BASTION-V2-M2M'
    }
});

// Core API — targets root endpoints (/health, /stats, etc.)
const coreApi = axios.create({
    baseURL: API_BASE,
    timeout: 15000,
    headers: {
        'Content-Type': 'application/json',
        'X-System-ID': 'LAST-BASTION-V2-M2M'
    }
});

// Shared response interceptor
const addInterceptors = (instance) => {
    instance.interceptors.response.use(
        (response) => {
            const contentType = response.headers['content-type'];
            if (contentType && !contentType.includes('application/json')) {
                return Promise.reject(new Error("API returned malformed structural data."));
            }
            return response;
        },
        (error) => {
            if (error.code === 'ECONNABORTED') {
                return Promise.reject(new Error("Command Link Timeout: The backend is under heavy load."));
            }
            if (!error.response) {
                return Promise.reject(new Error("Network desync. Syncing..."));
            }
            return Promise.reject(error);
        }
    );
};

addInterceptors(m2mApi);
addInterceptors(refineryApi);
addInterceptors(coreApi);

export const swarmService = {
    // Core system
    getHealth: () => coreApi.get('/health'),

    // M2M Command Center
    getDashboardStats: () => m2mApi.get('/dashboard/stats'),
    getDashboardAgents: () => m2mApi.get('/dashboard/agents'),
    getDashboardActivity: (limit = 50) => m2mApi.get(`/dashboard/activity?limit=${limit}`),
    getAgentDetail: (agentId) => m2mApi.get(`/dashboard/agents/${agentId}`),

    // Refinery
    getCalibrationData: () => refineryApi.get('/calibration'),
    getQuarantineQueue: (limit = 50) => refineryApi.get(`/quarantine?limit=${limit}`),
    resolveQuarantine: (id, resolution, resolvedBy = 'dashboard-operator') =>
        refineryApi.post(`/quarantine/${id}/resolve?resolution=${resolution}&resolved_by=${resolvedBy}`),
    getRefineryStats: () => refineryApi.get('/stats'),
    getRefinerySubmissions: (limit = 50) => refineryApi.get(`/submissions?limit=${limit}`),
    getRefineryLedger: (limit = 50) => refineryApi.get(`/ledger?limit=${limit}`),

    // Blockchain Anchoring (human-in-the-loop)
    getPendingAnchors: (limit = 50) => m2mApi.get(`/dashboard/pending-anchors?limit=${limit}`),
    approveAnchor: (stampId, approvedBy = 'dashboard-operator') =>
        coreApi.post(`/anchoring/approve/${stampId}?approved_by=${approvedBy}`),

    // Protocol Monitor
    getProtocolLog: (limit = 50, messageType, senderId, authResult) => {
        const params = new URLSearchParams({ limit });
        if (messageType) params.set('message_type', messageType);
        if (senderId) params.set('sender_id', senderId);
        if (authResult) params.set('auth_result', authResult);
        return m2mApi.get(`/dashboard/protocol-log?${params}`);
    },

    // Bastion Protocol
    getBastionLog: (limit = 200) => m2mApi.get(`/dashboard/bastion-log?limit=${limit}`),
    getBastionConnections: () => m2mApi.get('/dashboard/bastion-connections'),
    getBastionComparison: () => m2mApi.get('/dashboard/bastion-comparison'),

    // Verification Reports (PDF)
    getVerificationReportUrl: (submissionId) =>
        `${API_BASE}/refinery/report/${submissionId}`,
    getVerificationReportByHashUrl: (proofHash) =>
        `${API_BASE}/refinery/report/by-hash/${proofHash}`,

    // Bulk Submission
    submitBulk: (items, sourceAgentId = 'dashboard-operator') =>
        refineryApi.post('/bulk', { items, source_agent_id: sourceAgentId }),

    // Agent Verification (from dashboard)
    verifyAgentFromDashboard: (agentId) =>
        m2mApi.post(`/dashboard/agents/${agentId}/verify`),

    // Sandbox
    getSandboxStats: () => coreApi.get('/sandbox/dashboard/stats'),
    getSandboxLeaderboard: (limit = 25) => coreApi.get(`/sandbox/leaderboard?limit=${limit}`),
    getSandboxSessions: (status, limit = 20) => {
        const params = new URLSearchParams({ limit });
        if (status) params.set('status', status);
        return coreApi.get(`/sandbox/dashboard/sessions?${params}`);
    },
    getSandboxSessionDetail: (sessionId) => coreApi.get(`/sandbox/dashboard/sessions/${sessionId}/detail`),
    getSandboxAttackHistory: (limit = 50, attackType) => {
        const params = new URLSearchParams({ limit });
        if (attackType) params.set('attack_type', attackType);
        return coreApi.get(`/sandbox/dashboard/attack-history?${params}`);
    },
    getSandboxAgentProfile: (agentId) => coreApi.get(`/sandbox/dashboard/agents/${agentId}/profile`),
    createQuickSession: (agentId) => coreApi.post('/sandbox/dashboard/quick-session', { agent_id: agentId }),
    runSandboxAttacks: (sessionId, attackTypes = []) =>
        coreApi.post(`/sandbox/dashboard/sessions/${sessionId}/run-attacks`, { attack_types: attackTypes }),

    // Behavior Simulation
    simulateBehavior: (agentId, behaviorType) =>
        m2mApi.post('/simulate-behavior', { agent_id: agentId, behavior_type: behaviorType }),
    getSimulationTypes: () => m2mApi.get('/dashboard/simulation-types'),

    // Research Loop / Think Tank
    getResearchStatus: () => coreApi.get('/sandbox/research/status'),
    getResearchDiscoveries: (limit = 50) => coreApi.get(`/sandbox/research/discoveries?limit=${limit}`),
    getResearchRounds: (limit = 20) => coreApi.get(`/sandbox/research/rounds?limit=${limit}`),
    getResearchRoundDetail: (roundNumber) => coreApi.get(`/sandbox/research/rounds/${roundNumber}`),
    getResearchCategories: () => coreApi.get('/sandbox/research/categories'),

    // CART — Security Posture
    getVulnerabilities: (params = {}) => coreApi.get('/sandbox/research/vulnerabilities', { params }),
    getCountermeasures: (params = {}) => coreApi.get('/sandbox/research/countermeasures', { params }),
    getSecurityPosture: () => coreApi.get('/sandbox/research/posture'),
};

// Demo Agent API — targets /demo-agent router
const demoApi = axios.create({
    baseURL: `${API_BASE}/demo-agent`,
    timeout: 120000,
    headers: { 'Content-Type': 'application/json' }
});
addInterceptors(demoApi);

export const demoService = {
    chat: (message) => demoApi.post('/chat', { message }),
    negotiate: (category, user_context = '') => demoApi.post('/negotiate', { category, user_context }),
    getStatus: () => demoApi.get('/status'),
    reset: () => demoApi.post('/reset'),
};

export default m2mApi;

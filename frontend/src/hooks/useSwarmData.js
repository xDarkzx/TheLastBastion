import { useState, useEffect, useCallback, useRef, useReducer } from 'react';
import { swarmService } from '../services/api';

/**
 * View-aware data hook. Only fetches endpoints relevant to the active view.
 *
 * Performance optimizations:
 * - Single state update per poll cycle (useReducer batching)
 * - AbortController cancels in-flight requests on view change/unmount
 * - View-specific fetch — no wasted API calls
 * - Stale response detection — ignores responses from previous poll cycles
 */

const initialState = {
    stats: {
        active_agents: 0,
        total_tasks: 0,
        total_extractions: 0,
        total_proofs_generated: 0,
        proofs_anchored_on_chain: 0,
        blockchain_connected: false,
    },
    agents: [],
    health: null,
    refineryStats: null,
    submissions: [],
    proofLedger: null,
    activity: [],
    protocolLog: null,
    bastionData: null,
    calibration: null,
    error: null,
};

function dataReducer(state, action) {
    switch (action.type) {
        case 'BATCH_UPDATE':
            return { ...state, ...action.payload, error: null };
        case 'SET_ERROR':
            return { ...state, error: action.payload };
        default:
            return state;
    }
}

export const useSwarmData = (activeView, pollingInterval = 5000) => {
    const [state, dispatch] = useReducer(dataReducer, initialState);
    const abortRef = useRef(null);
    const fetchIdRef = useRef(0);

    const fetchData = useCallback(async () => {
        // Cancel previous in-flight requests
        if (abortRef.current) {
            abortRef.current.abort();
        }
        const controller = new AbortController();
        abortRef.current = controller;
        const currentFetchId = ++fetchIdRef.current;

        const fetches = [];
        const signal = controller.signal;

        // Always fetch stats (used by sidebar + many views)
        fetches.push(
            swarmService.getDashboardStats({ signal })
                .then(r => ({ key: 'stats', data: r.data }))
                .catch(() => null)
        );

        // View-specific fetches — each view gets ONLY what it needs
        switch (activeView) {
            case 'overview':
                fetches.push(
                    swarmService.getHealth({ signal }).then(r => ({ key: 'health', data: r.data })).catch(() => null),
                    swarmService.getRefineryStats({ signal }).then(r => ({ key: 'refineryStats', data: r.data })).catch(() => null),
                    swarmService.getDashboardActivity(10, { signal }).then(r => ({ key: 'activity', data: r.data })).catch(() => null),
                );
                break;
            case 'supply-chain':
                fetches.push(
                    swarmService.getDashboardActivity(50, { signal }).then(r => ({ key: 'activity', data: r.data })).catch(() => null),
                    swarmService.getDashboardAgents({ signal }).then(r => ({ key: 'agents', data: r.data })).catch(() => null),
                );
                break;
            case 'agents':
                fetches.push(
                    swarmService.getDashboardAgents({ signal }).then(r => ({ key: 'agents', data: r.data })).catch(() => null),
                );
                break;
            case 'submissions':
                fetches.push(
                    swarmService.getRefinerySubmissions(50, { signal }).then(r => ({ key: 'submissions', data: r.data })).catch(() => null),
                    swarmService.getRefineryStats({ signal }).then(r => ({ key: 'refineryStats', data: r.data })).catch(() => null),
                    swarmService.getCalibrationData({ signal }).then(r => ({ key: 'calibration', data: r.data })).catch(() => null),
                );
                break;
            case 'verification':
                fetches.push(
                    swarmService.getRefineryStats({ signal }).then(r => ({ key: 'refineryStats', data: r.data })).catch(() => null),
                    swarmService.getCalibrationData({ signal }).then(r => ({ key: 'calibration', data: r.data })).catch(() => null),
                );
                break;
            case 'blockchain':
                fetches.push(
                    swarmService.getRefineryStats({ signal }).then(r => ({ key: 'refineryStats', data: r.data })).catch(() => null),
                    swarmService.getRefineryLedger(50, { signal }).then(r => ({ key: 'proofLedger', data: r.data })).catch(() => null),
                );
                break;
            case 'bastion-protocol':
                fetches.push(
                    swarmService.getBastionLog(50, { signal }).then(r => ({ key: 'bastionData', data: r.data })).catch(() => null),
                    swarmService.getBastionComparison({ signal }).then(r => ({ key: 'bastionComparison', data: r.data })).catch(() => null),
                    swarmService.getProtocolLog(50, { signal }).then(r => ({ key: 'protocolLog', data: r.data })).catch(() => null),
                );
                break;
            default:
                break;
        }

        try {
            const results = await Promise.allSettled(fetches);

            // Stale response check — if a newer fetch started, discard this one
            if (currentFetchId !== fetchIdRef.current) return;
            if (signal.aborted) return;

            // Build a single batch update object
            const updates = {};
            results.forEach(r => {
                if (r.status === 'fulfilled' && r.value) {
                    const { key, data } = r.value;
                    switch (key) {
                        case 'stats': updates.stats = data; break;
                        case 'health': updates.health = data; break;
                        case 'refineryStats': updates.refineryStats = data; break;
                        case 'agents': updates.agents = Array.isArray(data) ? data : []; break;
                        case 'submissions': updates.submissions = data?.submissions || []; break;
                        case 'proofLedger': updates.proofLedger = data; break;
                        case 'activity': updates.activity = Array.isArray(data) ? data : []; break;
                        case 'protocolLog': updates.protocolLog = data; break;
                        case 'calibration': updates.calibration = data; break;
                        case 'bastionData': updates.bastionData = data; break;
                        case 'bastionComparison':
                            // Merge comparison into bastion data
                            updates.bastionData = { ...(updates.bastionData || {}), comparison: data };
                            break;
                    }
                }
            });

            // Single dispatch — one re-render
            if (Object.keys(updates).length > 0) {
                dispatch({ type: 'BATCH_UPDATE', payload: updates });
            }

            // Check if stats fetch failed (critical)
            const statsFetch = results[0];
            if (statsFetch.status === 'rejected') {
                dispatch({ type: 'SET_ERROR', payload: statsFetch.reason?.message || "Command Link Offline" });
            }
        } catch (err) {
            if (!signal.aborted) {
                dispatch({ type: 'SET_ERROR', payload: err.message || "Command Link Offline. Retrying..." });
            }
        }
    }, [activeView]);

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, pollingInterval);
        return () => {
            clearInterval(interval);
            if (abortRef.current) {
                abortRef.current.abort();
            }
        };
    }, [fetchData, pollingInterval]);

    return state;
};

import React from 'react';
import { Routes, Route, useLocation } from 'react-router-dom';
import { useSwarmData } from './hooks/useSwarmData';
import AppLayout from './components/layout/AppLayout';
import LandingPage from './components/landing/LandingPage';
import ErrorBoundary from './components/ErrorBoundary';

// Views
import AgentDirectoryView from './components/views/AgentDirectoryView';
import SystemOverviewView from './components/views/SystemOverviewView';
import MissionControlView from './components/views/MissionControlView';
import SubmissionsView from './components/views/SubmissionsView';
import VerificationView from './components/views/VerificationView';
import BlockchainView from './components/views/BlockchainView';
import AgentDetailView from './components/views/AgentDetailView';
import BastionProtocolView from './components/views/BastionProtocolView';
import PassportVerificationView from './components/views/PassportVerificationView';
import DemoAgentView from './components/views/DemoAgentView';

const Dashboard = () => {
  const location = useLocation();
  const getActiveViewSlug = (path) => {
    const sub = path.replace('/dashboard', '') || '/';
    if (sub === '/' || sub === '') return 'overview';
    if (sub.startsWith('/agents/')) return 'agent-detail';
    if (sub === '/bastion') return 'bastion-protocol';
    return sub.replace('/', '') || 'overview';
  };

  const activeView = getActiveViewSlug(location.pathname);
  const data = useSwarmData(activeView, 5000);

  const renderContent = () => {
    if (data.error) {
      return (
        <div className="flex-1 flex flex-col items-center justify-center p-20 text-center animate-fade-in h-full bg-slate-50">
          <div className="w-16 h-16 bg-slate-100 rounded-sm flex items-center justify-center text-slate-500 mb-6 border border-slate-200">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <h3 className="font-extrabold text-xl text-slate-900 mb-2 uppercase tracking-wide">Critical System Desync</h3>
          <p className="text-sm font-medium text-slate-500 max-w-md">{data.error}</p>
          <p className="text-xs text-slate-400 mt-4 font-mono">Ensure The Last Bastion API is running on port 8000.</p>
        </div>
      );
    }

    return (
      <ErrorBoundary>
        <Routes>
          <Route path="/" element={<ErrorBoundary><SystemOverviewView stats={data.stats} health={data.health} refineryStats={data.refineryStats} activity={data.activity} /></ErrorBoundary>} />
          <Route path="/supply-chain" element={<ErrorBoundary><MissionControlView activity={data.activity} agents={data.agents} /></ErrorBoundary>} />
          <Route path="/agents" element={<ErrorBoundary><AgentDirectoryView agents={data.agents} stats={data.stats} /></ErrorBoundary>} />
          <Route path="/agents/:agentId" element={<ErrorBoundary><AgentDetailView /></ErrorBoundary>} />
          <Route path="/submissions" element={<ErrorBoundary><SubmissionsView submissions={data.submissions} refineryStats={data.refineryStats} calibration={data.calibration} /></ErrorBoundary>} />
          <Route path="/verification" element={<ErrorBoundary><VerificationView refineryStats={data.refineryStats} calibration={data.calibration} /></ErrorBoundary>} />
          <Route path="/bastion" element={<ErrorBoundary><BastionProtocolView bastionData={data.bastionData} protocolLog={data.protocolLog} /></ErrorBoundary>} />
          <Route path="/passport" element={<ErrorBoundary><PassportVerificationView /></ErrorBoundary>} />
          <Route path="/blockchain" element={<ErrorBoundary><BlockchainView stats={data.stats} refineryStats={data.refineryStats} proofLedger={data.proofLedger} /></ErrorBoundary>} />
        </Routes>
      </ErrorBoundary>
    );
  };

  return (
    <AppLayout stats={data.stats}>
      <div className="flex-1 overflow-y-auto thin-scrollbar h-[calc(100vh-56px)]">
        {renderContent()}
      </div>
    </AppLayout>
  );
};

const App = () => {
  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/demo" element={<DemoAgentView />} />
      <Route path="/dashboard/*" element={<Dashboard />} />
    </Routes>
  );
};

export default App;

import React from 'react';
import { Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from 'react-query';
import Layout from './components/Layout/Layout';
import Dashboard from './pages/Dashboard';
import Investigations from './pages/Investigations';
import Reports from './pages/Reports';
import Monitoring from './pages/Monitoring';
import Integrations from './pages/Integrations';
import Tasks from './pages/Tasks';
import Audit from './pages/Audit';
import InvestigationDetail from './pages/InvestigationDetail';
import ReportDetail from './pages/ReportDetail';
import { ThreatSentinelProvider } from './context/ThreatSentinelContext';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 5 * 60 * 1000,
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThreatSentinelProvider>
        <div className="min-h-screen bg-dark-900">
          <Layout>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/investigations" element={<Investigations />} />
              <Route path="/investigations/:id" element={<InvestigationDetail />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/reports/:id" element={<ReportDetail />} />
              <Route path="/monitoring" element={<Monitoring />} />
              <Route path="/integrations" element={<Integrations />} />
              <Route path="/tasks" element={<Tasks />} />
              <Route path="/audit" element={<Audit />} />
            </Routes>
          </Layout>
        </div>
      </ThreatSentinelProvider>
    </QueryClientProvider>
  );
}

export default App; 
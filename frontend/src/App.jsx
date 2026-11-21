import React from 'react';
import { Routes, Route } from 'react-router-dom';
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
import NotFound from './pages/NotFound';
import { ThreatSentinelProvider } from './context/ThreatSentinelContext';

function App() {
  return (
    <ThreatSentinelProvider>
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
          <Route path="*" element={<NotFound />} />
        </Routes>
      </Layout>
    </ThreatSentinelProvider>
  );
}

export default App;

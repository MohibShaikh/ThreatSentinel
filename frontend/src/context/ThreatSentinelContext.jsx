import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from 'react-query';
import axios from 'axios';
import toast from 'react-hot-toast';
import { errorMessage } from '../components/ui';

// API base. The token is never baked in with a default: it comes from the
// analyst's session (sessionStorage) or, only if explicitly provided at build
// time, from VITE_API_TOKEN.
export const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';
export const API_ROOT = API_BASE.replace(/\/api\/v1\/?$/, '');
const BUILD_TOKEN = import.meta.env.VITE_API_TOKEN || '';
const TOKEN_KEY = 'ts_api_token';

export function getToken() {
  try {
    return sessionStorage.getItem(TOKEN_KEY) || BUILD_TOKEN;
  } catch {
    return BUILD_TOKEN;
  }
}

function storeToken(token) {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    // storage unavailable (private mode); token lives only for this request cycle
  }
}

const api = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// 401 listeners: the provider subscribes so any page's request can open the auth modal
const unauthorizedListeners = new Set();
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error?.response?.status === 401) unauthorizedListeners.forEach((fn) => fn());
    return Promise.reject(error);
  }
);

const ThreatSentinelContext = createContext(null);

export function ThreatSentinelProvider({ children }) {
  const queryClient = useQueryClient();
  const [authRequired, setAuthRequired] = useState(false);
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [hasToken, setHasToken] = useState(() => Boolean(getToken()));

  useEffect(() => {
    const onUnauthorized = () => {
      setAuthRequired(true);
      setAuthModalOpen(true);
    };
    unauthorizedListeners.add(onUnauthorized);
    return () => unauthorizedListeners.delete(onUnauthorized);
  }, []);

  const signIn = useCallback((token) => {
    storeToken(token.trim());
    setHasToken(Boolean(getToken()));
    setAuthRequired(false);
    setAuthModalOpen(false);
    queryClient.invalidateQueries();
  }, [queryClient]);

  const signOut = useCallback(() => {
    storeToken('');
    setHasToken(Boolean(getToken()));
    queryClient.clear();
    setAuthModalOpen(true);
  }, [queryClient]);

  // Liveness lives at the API root, unauthenticated
  const { data: healthData, isError: healthError } = useQuery(
    'systemHealth',
    () => api.get(`${API_ROOT}/health`).then((r) => r.data),
    { refetchInterval: 30000 }
  );
  const systemStatus = healthError ? 'error' : healthData?.status || 'unknown';

  const { data: statsData } = useQuery(
    'agentStats',
    () => api.get('/stats').then((r) => r.data),
    { refetchInterval: 30000, retry: false }
  );

  const fail = (what) => (error) => toast.error(`${what}: ${errorMessage(error)}`);

  const createInvestigation = useMutation(
    ({ event_data, emergency_mode = false }) =>
      api.post('/investigations/', { event_data, emergency_mode }).then((r) => r.data),
    {
      onSuccess: () => {
        toast.success('Investigation queued');
        queryClient.invalidateQueries('investigations');
        queryClient.invalidateQueries('agentStats');
      },
      onError: fail('Failed to create investigation'),
    }
  );

  const executeAction = useMutation(
    ({ action_type, target, context = {}, preferred_integrations = null }) =>
      api.post('/integrations/actions/execute', { action_type, target, context, preferred_integrations })
        .then((r) => r.data),
    {
      onSuccess: (data) => {
        if (data?.execution_result?.success) toast.success('Action executed');
        else toast.error('Action ran but no integration succeeded');
        queryClient.invalidateQueries('integrations');
      },
      onError: fail('Failed to execute action'),
    }
  );

  const generateReport = useMutation(
    ({ investigation_id, format = 'json', include_raw_data = false }) =>
      api.post('/reports/generate', { investigation_id, format, include_raw_data }).then((r) => r.data),
    {
      onSuccess: () => {
        toast.success('Report generated');
        queryClient.invalidateQueries('reports');
      },
      onError: fail('Failed to generate report'),
    }
  );

  const submitFeedback = useMutation(
    ({ id, feedback }) => api.post(`/investigations/${id}/feedback`, feedback).then((r) => r.data),
    {
      onSuccess: (_data, { id }) => {
        toast.success('Analyst decision recorded');
        queryClient.invalidateQueries(['investigation', id]);
        queryClient.invalidateQueries('investigations');
        queryClient.invalidateQueries('pendingReviews');
        queryClient.invalidateQueries('agentStats');
      },
      onError: fail('Failed to submit feedback'),
    }
  );

  const createTask = useMutation(
    ({ task_type = 'investigation', payload, priority = 'medium', max_retries = 3, timeout_seconds = 300 }) =>
      api.post('/tasks/', { task_type, payload, priority, max_retries, timeout_seconds }).then((r) => r.data),
    {
      onSuccess: () => {
        toast.success('Task enqueued');
        queryClient.invalidateQueries('tasks');
        queryClient.invalidateQueries('agentStats');
      },
      onError: fail('Failed to create task'),
    }
  );

  const value = {
    api,
    systemStatus,
    healthData,
    statsData,
    activeInvestigations: statsData?.active_investigations ?? 0,
    pendingTasks: statsData?.pending_tasks ?? 0,
    pendingReviews: statsData?.pending_reviews ?? 0,
    llmProvider: statsData?.llm_provider ?? null,
    intelSources: statsData?.intel_sources ?? [],
    authRequired,
    authModalOpen,
    hasToken,
    openAuthModal: () => setAuthModalOpen(true),
    closeAuthModal: () => setAuthModalOpen(false),
    signIn,
    signOut,
    createInvestigation,
    executeAction,
    generateReport,
    submitFeedback,
    createTask,
  };

  return <ThreatSentinelContext.Provider value={value}>{children}</ThreatSentinelContext.Provider>;
}

export function useThreatSentinel() {
  const context = useContext(ThreatSentinelContext);
  if (!context) throw new Error('useThreatSentinel must be used within a ThreatSentinelProvider');
  return context;
}

export { api };

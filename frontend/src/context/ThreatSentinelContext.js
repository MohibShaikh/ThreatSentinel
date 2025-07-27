import React, { createContext, useContext, useReducer, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import axios from 'axios';
import toast from 'react-hot-toast';

// API base configuration
const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

// Create axios instance with default config
const api = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Context
const ThreatSentinelContext = createContext();

// Initial state
const initialState = {
  user: null,
  theme: 'dark',
  notifications: [],
  systemStatus: 'unknown',
  activeInvestigations: 0,
  pendingTasks: 0,
  alerts: [],
};

// Reducer
function threatSentinelReducer(state, action) {
  switch (action.type) {
    case 'SET_USER':
      return { ...state, user: action.payload };
    case 'SET_THEME':
      return { ...state, theme: action.payload };
    case 'ADD_NOTIFICATION':
      return { 
        ...state, 
        notifications: [...state.notifications, action.payload].slice(-50) 
      };
    case 'CLEAR_NOTIFICATIONS':
      return { ...state, notifications: [] };
    case 'SET_SYSTEM_STATUS':
      return { ...state, systemStatus: action.payload };
    case 'UPDATE_COUNTERS':
      return { 
        ...state, 
        activeInvestigations: action.payload.activeInvestigations || state.activeInvestigations,
        pendingTasks: action.payload.pendingTasks || state.pendingTasks,
      };
    case 'ADD_ALERT':
      return { 
        ...state, 
        alerts: [...state.alerts, action.payload].slice(-100) 
      };
    case 'CLEAR_ALERTS':
      return { ...state, alerts: [] };
    default:
      return state;
  }
}

// Provider component
export function ThreatSentinelProvider({ children }) {
  const [state, dispatch] = useReducer(threatSentinelReducer, initialState);
  const queryClient = useQueryClient();

  // System health check
  const { data: healthData } = useQuery(
    'systemHealth',
    async () => {
      const response = await api.get('/health');
      return response.data;
    },
    {
      refetchInterval: 30000, // Check every 30 seconds
      onSuccess: (data) => {
        dispatch({ type: 'SET_SYSTEM_STATUS', payload: data.status });
      },
      onError: () => {
        dispatch({ type: 'SET_SYSTEM_STATUS', payload: 'error' });
      },
    }
  );

  // Agent stats
  const { data: statsData } = useQuery(
    'agentStats',
    async () => {
      const response = await api.get('/stats');
      return response.data;
    },
    {
      refetchInterval: 60000, // Check every minute
      onSuccess: (data) => {
        dispatch({ 
          type: 'UPDATE_COUNTERS', 
          payload: {
            activeInvestigations: data.active_investigations,
            pendingTasks: data.pending_tasks,
          }
        });
      },
    }
  );

  // API hooks
  const createInvestigation = useMutation(
    async (investigationData) => {
      const response = await api.post('/investigations/', investigationData);
      return response.data;
    },
    {
      onSuccess: (data) => {
        toast.success('Investigation created successfully');
        queryClient.invalidateQueries('investigations');
        queryClient.invalidateQueries('agentStats');
      },
      onError: (error) => {
        toast.error(`Failed to create investigation: ${error.response?.data?.detail || error.message}`);
      },
    }
  );

  const getInvestigation = useMutation(
    async (id) => {
      const response = await api.get(`/investigations/${id}`);
      return response.data;
    },
    {
      onError: (error) => {
        toast.error(`Failed to fetch investigation: ${error.response?.data?.detail || error.message}`);
      },
    }
  );

  const executeAction = useMutation(
    async ({ integrationName, action, parameters }) => {
      const response = await api.post('/integrations/actions/execute', {
        integration_name: integrationName,
        action,
        parameters,
      });
      return response.data;
    },
    {
      onSuccess: (data) => {
        toast.success('Action executed successfully');
        queryClient.invalidateQueries('integrations');
      },
      onError: (error) => {
        toast.error(`Failed to execute action: ${error.response?.data?.detail || error.message}`);
      },
    }
  );

  const generateReport = useMutation(
    async (reportData) => {
      const response = await api.post('/reports/generate', reportData);
      return response.data;
    },
    {
      onSuccess: (data) => {
        toast.success('Report generated successfully');
        queryClient.invalidateQueries('reports');
      },
      onError: (error) => {
        toast.error(`Failed to generate report: ${error.response?.data?.detail || error.message}`);
      },
    }
  );

  const createTask = useMutation(
    async (taskData) => {
      const response = await api.post('/tasks/', taskData);
      return response.data;
    },
    {
      onSuccess: (data) => {
        toast.success('Task created successfully');
        queryClient.invalidateQueries('tasks');
        queryClient.invalidateQueries('agentStats');
      },
      onError: (error) => {
        toast.error(`Failed to create task: ${error.response?.data?.detail || error.message}`);
      },
    }
  );

  // Context value
  const value = {
    ...state,
    dispatch,
    api,
    createInvestigation,
    getInvestigation,
    executeAction,
    generateReport,
    createTask,
    healthData,
    statsData,
  };

  return (
    <ThreatSentinelContext.Provider value={value}>
      {children}
    </ThreatSentinelContext.Provider>
  );
}

// Custom hook to use the context
export function useThreatSentinel() {
  const context = useContext(ThreatSentinelContext);
  if (!context) {
    throw new Error('useThreatSentinel must be used within a ThreatSentinelProvider');
  }
  return context;
}

// Export API instance for direct use
export { api }; 
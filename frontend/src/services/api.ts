import axios, { AxiosInstance, AxiosError } from 'axios';
import { useAuthStore } from '../stores/authStore';

// Create axios instance with base configuration
export const api: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor - add auth token
api.interceptors.request.use(
  (config) => {
    const token = useAuthStore.getState().token;
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor - handle errors
api.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (error.response?.status === 401) {
      // Token expired or invalid - logout
      useAuthStore.getState().logout();
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Auth API
export const authApi = {
  login: async (username: string, password: string) => {
    const formData = new URLSearchParams();
    formData.append('username', username);
    formData.append('password', password);
    
    const response = await api.post('/api/v1/auth/token', formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.data;
  },
  
  getMe: async () => {
    const response = await api.get('/api/v1/users/me');
    return response.data;
  },
  
  logout: async () => {
    try {
      await api.post('/api/v1/auth/logout');
    } catch (error) {
      // Ignore logout errors
    }
  },
};

// Scans API
export const scansApi = {
  create: async (data: {
    target: string;
    scan_type: string;
    tools?: string[];
    options?: Record<string, any>;
  }) => {
    const response = await api.post('/api/v1/scans', data);
    return response.data;
  },
  
  list: async (params?: {
    page?: number;
    per_page?: number;
    status?: string;
  }) => {
    const response = await api.get('/api/v1/scans', { params });
    return response.data;
  },
  
  get: async (scanId: string) => {
    const response = await api.get(`/api/v1/scans/${scanId}`);
    return response.data;
  },
  
  getProgress: async (scanId: string) => {
    const response = await api.get(`/api/v1/scans/${scanId}/progress`);
    return response.data;
  },
  
  getFindings: async (scanId: string, params?: {
    severity?: string;
    page?: number;
    per_page?: number;
  }) => {
    const response = await api.get(`/api/v1/scans/${scanId}/findings`, { params });
    return response.data;
  },
  
  cancel: async (scanId: string) => {
    const response = await api.post(`/api/v1/scans/${scanId}/cancel`);
    return response.data;
  },
  
  delete: async (scanId: string) => {
    const response = await api.delete(`/api/v1/scans/${scanId}`);
    return response.data;
  },
};

// Dashboard API
export const dashboardApi = {
  getStats: async () => {
    const response = await api.get('/api/v1/dashboard/stats');
    return response.data;
  },
};

// Reports API
export const reportsApi = {
  list: async () => {
    const response = await api.get('/api/v1/reports');
    return response.data;
  },
  
  generate: async (scanId: string, format: 'pdf' | 'html' | 'json' = 'pdf') => {
    const response = await api.post(`/api/v1/reports/generate/${scanId}`, null, {
      params: { format },
    });
    return response.data;
  },
  
  download: async (reportId: string) => {
    const response = await api.get(`/api/v1/reports/${reportId}/download`, {
      responseType: 'blob',
    });
    return response.data;
  },
};

// Admin API
export const adminApi = {
  getUsers: async () => {
    const response = await api.get('/api/v1/admin/users');
    return response.data;
  },
  
  createUser: async (data: {
    username: string;
    email: string;
    password: string;
    role: string;
  }) => {
    const response = await api.post('/api/v1/admin/users', data);
    return response.data;
  },
  
  updateUser: async (userId: string, data: Partial<{
    email: string;
    role: string;
    is_active: boolean;
  }>) => {
    const response = await api.patch(`/api/v1/admin/users/${userId}`, data);
    return response.data;
  },
  
  deleteUser: async (userId: string) => {
    const response = await api.delete(`/api/v1/admin/users/${userId}`);
    return response.data;
  },
  
  getSystemSettings: async () => {
    const response = await api.get('/api/v1/admin/settings');
    return response.data;
  },
  
  updateSystemSettings: async (data: Record<string, any>) => {
    const response = await api.put('/api/v1/admin/settings', data);
    return response.data;
  },
  
  getAuditLogs: async (params?: {
    page?: number;
    per_page?: number;
  }) => {
    const response = await api.get('/api/v1/admin/audit-logs', { params });
    return response.data;
  },
};

export default api;

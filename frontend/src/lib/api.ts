import axios from 'axios';
import Cookies from 'js-cookie';

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

export const api = axios.create({
  baseURL: BASE_URL,
  headers: { 'Content-Type': 'application/json' },
});

// Attach JWT token to every request
api.interceptors.request.use((config) => {
  const token = Cookies.get('sstb_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Redirect to login on 401
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401 && typeof window !== 'undefined') {
      Cookies.remove('sstb_token');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

// Auth
export const login = (username: string, password: string) =>
  api.post('/auth/login', { username, password });

export const register = (email: string, username: string, password: string) =>
  api.post('/auth/register', { email, username, password });

export const getMe = () => api.get('/auth/me');

// Dashboard
export const getDashboardStats = () => api.get('/dashboard/stats');
export const getAttackTimeline = (days = 7) => api.get(`/dashboard/attack-timeline?days=${days}`);
export const getTopAttackers = (limit = 10) => api.get(`/dashboard/top-attackers?limit=${limit}`);
export const getMikroTikStatus = () => api.get('/dashboard/mikrotik-status');
export const getCVEAlerts = (limit = 10) => api.get(`/dashboard/cve-alerts?limit=${limit}`);

// Blocklist
export const getBlocklist = (skip = 0, limit = 100) =>
  api.get(`/blocklist/?skip=${skip}&limit=${limit}`);

export const blockIP = (address: string, reason?: string, comment?: string) =>
  api.post('/blocklist/', { address, reason, comment, source: 'manual' });

export const unblockIP = (ip: string) => api.delete(`/blocklist/${ip}`);

export const syncFromMikroTik = () => api.post('/blocklist/sync');

// Threats
export const getAttackLogs = (skip = 0, limit = 50) =>
  api.get(`/threats/logs?skip=${skip}&limit=${limit}`);

export const scanIP = (ip: string) => api.get(`/threats/scan/${ip}`);

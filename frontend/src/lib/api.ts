import axios from 'axios';
import Cookies from 'js-cookie';

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';
const WS_URL = BASE_URL.replace(/^http/, 'ws');

export const api = axios.create({
  baseURL: BASE_URL,
  headers: { 'Content-Type': 'application/json' },
});

// Attach JWT token to every request
api.interceptors.request.use((config) => {
  const token = Cookies.get('sstb_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
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

// ── Auth ──────────────────────────────────────────────────────────────────────
export const login = (username: string, password: string) =>
  api.post('/auth/login', { username, password });
export const register = (email: string, username: string, password: string) =>
  api.post('/auth/register', { email, username, password });
export const getMe = () => api.get('/auth/me');

// ── Dashboard ─────────────────────────────────────────────────────────────────
export const getDashboardStats = () => api.get('/dashboard/stats');
export const getAttackTimeline = (days = 7) => api.get(`/dashboard/attack-timeline?days=${days}`);
export const getTopAttackers = (limit = 10) => api.get(`/dashboard/top-attackers?limit=${limit}`);
export const getMikroTikStatus = () => api.get('/dashboard/mikrotik-status');
export const getCVEAlerts = (limit = 20, kevOnly = false) =>
  api.get(`/dashboard/cve-alerts?limit=${limit}&kev_only=${kevOnly}`);
export const getGeoStats = (limit = 20) => api.get(`/dashboard/geo-stats?limit=${limit}`);
export const getProtocolStats = () => api.get('/dashboard/protocol-stats');
export const getHourlyHeatmap = (days = 30) => api.get(`/dashboard/hourly-heatmap?days=${days}`);
export const getThreatScoreDistribution = () => api.get('/dashboard/threat-score-distribution');
export const getSummaryCounts = () => api.get('/dashboard/summary-counts');

// ── Blocklist ─────────────────────────────────────────────────────────────────
export const getBlocklist = (skip = 0, limit = 100) =>
  api.get(`/blocklist/?skip=${skip}&limit=${limit}`);
export const blockIP = (address: string, reason?: string, comment?: string, expiresHours?: number) =>
  api.post('/blocklist/', { address, reason, comment, source: 'manual', expires_hours: expiresHours });
export const unblockIP = (ip: string) => api.delete(`/blocklist/${ip}`);
export const syncFromMikroTik = () => api.post('/blocklist/sync');

// ── Threats / Scan ────────────────────────────────────────────────────────────
export const getAttackLogs = (skip = 0, limit = 50, filters?: {
  status?: string; attack_type?: string; country_code?: string; min_score?: number;
}) => {
  const params = new URLSearchParams({ skip: String(skip), limit: String(limit) });
  if (filters?.status) params.append('status', filters.status);
  if (filters?.attack_type) params.append('attack_type', filters.attack_type);
  if (filters?.country_code) params.append('country_code', filters.country_code);
  if (filters?.min_score != null) params.append('min_score', String(filters.min_score));
  return api.get(`/threats/logs?${params}`);
};
export const scanIP = (ip: string, useCache = true) =>
  api.get(`/threats/scan/${ip}?use_cache=${useCache}`);
export const getCachedScan = (ip: string) => api.get(`/threats/cache/${ip}`);
export const getThreatSummary = () => api.get('/threats/stats/summary');

// ── Whitelist ─────────────────────────────────────────────────────────────────
export const getWhitelist = (skip = 0, limit = 100) =>
  api.get(`/whitelist/?skip=${skip}&limit=${limit}`);
export const addToWhitelist = (address: string, reason?: string, comment?: string) =>
  api.post('/whitelist/', { address, reason, comment });
export const removeFromWhitelist = (ip: string) => api.delete(`/whitelist/${ip}`);
export const syncWhitelist = () => api.post('/whitelist/sync');

// ── MikroTik Monitor ──────────────────────────────────────────────────────────
const _dq = (deviceId?: number) => (deviceId != null ? `device_id=${deviceId}` : '');
const _qs = (...parts: string[]) => { const q = parts.filter(Boolean).join('&'); return q ? `?${q}` : ''; };

export const getMikroTikInterfaces = (deviceId?: number) =>
  api.get(`/mikrotik/interfaces${_qs(_dq(deviceId))}`);
export const getMikroTikFirewallRules = (chain?: string, deviceId?: number) =>
  api.get(`/mikrotik/firewall/rules${_qs(chain ? `chain=${chain}` : '', _dq(deviceId))}`);
export const toggleFirewallRule = (ruleId: string, disabled: boolean) =>
  api.patch(`/mikrotik/firewall/rules/${ruleId}/toggle?disabled=${disabled}`);
export const getMikroTikNatRules = (deviceId?: number) =>
  api.get(`/mikrotik/firewall/nat${_qs(_dq(deviceId))}`);
export const getMikroTikAddressLists = (deviceId?: number) =>
  api.get(`/mikrotik/firewall/address-lists${_qs(_dq(deviceId))}`);
export const getMikroTikDhcpLeases = (deviceId?: number) =>
  api.get(`/mikrotik/dhcp/leases${_qs(_dq(deviceId))}`);
export const getMikroTikConnections = (limit = 100, deviceId?: number) =>
  api.get(`/mikrotik/connections${_qs(`limit=${limit}`, _dq(deviceId))}`);
export const getMikroTikLogs = (count = 100, topics?: string, deviceId?: number) =>
  api.get(`/mikrotik/logs${_qs(`count=${count}`, topics ? `topics=${topics}` : '', _dq(deviceId))}`);
export const getMikroTikRoutes = (deviceId?: number) =>
  api.get(`/mikrotik/routes${_qs(_dq(deviceId))}`);
export const getMikroTikAddresses = (deviceId?: number) =>
  api.get(`/mikrotik/addresses${_qs(_dq(deviceId))}`);
export const getMikroTikIdentity = () => api.get('/mikrotik/identity');

// ── WebSocket Live Feed ────────────────────────────────────────────────────────
export const createLiveFeed = (onMessage: (data: any) => void, onError?: (e: Event) => void) => {
  const token = Cookies.get('sstb_token');
  const ws = new WebSocket(`${WS_URL}/ws/feed${token ? `?token=${token}` : ''}`);

  ws.onmessage = (e) => {
    try { onMessage(JSON.parse(e.data)); } catch {}
  };
  ws.onerror = onError || (() => {});

  // Keep-alive ping every 20s
  const pingInterval = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) ws.send('ping');
  }, 20000);

  return {
    ws,
    close: () => {
      clearInterval(pingInterval);
      ws.close();
    },
  };
};

// ── Settings / MikroTik Device Management ─────────────────────────────────────
export const listMikroTikDevices = () => api.get('/settings/mikrotik');
export const addMikroTikDevice = (data: {
  name: string; host: string; port?: number; use_ssl?: boolean;
  api_user: string; api_password: string; location?: string;
  description?: string; is_default?: boolean;
}) => api.post('/settings/mikrotik', data);
export const getMikroTikDevice = (id: number) => api.get(`/settings/mikrotik/${id}`);
export const updateMikroTikDevice = (id: number, data: any) => api.put(`/settings/mikrotik/${id}`, data);
export const deleteMikroTikDevice = (id: number) => api.delete(`/settings/mikrotik/${id}`);
export const testMikroTikDevice = (id: number) => api.post(`/settings/mikrotik/${id}/test`);
export const setDefaultMikroTikDevice = (id: number) => api.post(`/settings/mikrotik/${id}/set-default`);
export const refreshAllDevices = () => api.post('/settings/mikrotik/refresh-all');
export const getMikroTikTopology = () => api.get('/settings/mikrotik/topology/view');
export const setupFirewallRules = (id: number) => api.post(`/settings/mikrotik/${id}/setup-firewall`);
export const setupFirewallRulesDefault = () => api.post('/settings/mikrotik/setup-firewall/default');

// ── Helpers ───────────────────────────────────────────────────────────────────
export const formatBytes = (bytes: number): string => {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
};

export const countryFlagEmoji = (code: string): string => {
  if (!code || code.length !== 2) return '🌐';
  const offset = 127397;
  return String.fromCodePoint(...code.toUpperCase().split('').map((c) => c.charCodeAt(0) + offset));
};

'use client';
import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import Cookies from 'js-cookie';
import {
  getDashboardStats,
  getAttackTimeline,
  getTopAttackers,
  getBlocklist,
  getAttackLogs,
  getCVEAlerts,
  getMikroTikStatus,
  blockIP,
  unblockIP,
  scanIP,
  syncFromMikroTik,
} from '@/lib/api';
import {
  Shield, AlertTriangle, Ban, Activity, Wifi, WifiOff,
  RefreshCw, LogOut, Search, Plus, Trash2, ChevronRight,
  Router, Bug, Database, Zap, Eye, Globe
} from 'lucide-react';
import {
  Chart as ChartJS,
  CategoryScale, LinearScale, BarElement, LineElement,
  PointElement, Title, Tooltip, Legend, Filler
} from 'chart.js';
import { Bar, Line } from 'react-chartjs-2';
import clsx from 'clsx';

ChartJS.register(
  CategoryScale, LinearScale, BarElement, LineElement,
  PointElement, Title, Tooltip, Legend, Filler
);

// Types
interface Stats {
  total_blocked: number;
  blocked_today: number;
  threats_detected: number;
  threats_today: number;
  active_cve_alerts: number;
  critical_cve_count: number;
  mikrotik_connected: boolean;
  auto_block_enabled: boolean;
}

interface BlockedIP {
  id: number;
  address: string;
  threat_score: number;
  reason: string;
  source: string;
  comment: string;
  country: string;
  blocked_at: string;
  synced_to_mikrotik: boolean;
}

interface AttackLog {
  id: number;
  source_ip: string;
  target_port: number;
  protocol: string;
  attack_type: string;
  threat_score: number;
  status: string;
  detected_at: string;
}

interface CVEAlert {
  id: number;
  cve_id: string;
  description: string;
  severity: string;
  cvss_score: number;
  is_kev: boolean;
  affected_product: string;
}

type Tab = 'overview' | 'blocklist' | 'threats' | 'cve';

export default function DashboardPage() {
  const router = useRouter();
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [stats, setStats] = useState<Stats | null>(null);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [topAttackers, setTopAttackers] = useState<any[]>([]);
  const [blocklist, setBlocklist] = useState<BlockedIP[]>([]);
  const [attackLogs, setAttackLogs] = useState<AttackLog[]>([]);
  const [cveAlerts, setCveAlerts] = useState<CVEAlert[]>([]);
  const [mikrotikStatus, setMikrotikStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Block IP modal
  const [showBlockModal, setShowBlockModal] = useState(false);
  const [blockForm, setBlockForm] = useState({ address: '', reason: '', comment: '' });
  const [blockLoading, setBlockLoading] = useState(false);

  // Scan modal
  const [scanIP_input, setScanIPInput] = useState('');
  const [scanResult, setScanResult] = useState<any>(null);
  const [scanLoading, setScanLoading] = useState(false);

  // IP search filter
  const [ipFilter, setIpFilter] = useState('');

  const fetchAll = useCallback(async () => {
    try {
      const [statsRes, timelineRes, attackersRes, blocklistRes, logsRes, cveRes, statusRes] =
        await Promise.allSettled([
          getDashboardStats(),
          getAttackTimeline(7),
          getTopAttackers(10),
          getBlocklist(0, 100),
          getAttackLogs(0, 50),
          getCVEAlerts(10),
          getMikroTikStatus(),
        ]);

      if (statsRes.status === 'fulfilled') setStats(statsRes.value.data);
      if (timelineRes.status === 'fulfilled') setTimeline(timelineRes.value.data);
      if (attackersRes.status === 'fulfilled') setTopAttackers(attackersRes.value.data);
      if (blocklistRes.status === 'fulfilled') setBlocklist(blocklistRes.value.data);
      if (logsRes.status === 'fulfilled') setAttackLogs(logsRes.value.data);
      if (cveRes.status === 'fulfilled') setCveAlerts(cveRes.value.data);
      if (statusRes.status === 'fulfilled') setMikrotikStatus(statusRes.value.data);
    } catch (e) {
      // handled per-request above
    }
  }, []);

  useEffect(() => {
    const token = Cookies.get('sstb_token');
    if (!token) {
      router.push('/login');
      return;
    }

    fetchAll().finally(() => setLoading(false));

    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchAll, 30000);
    return () => clearInterval(interval);
  }, [fetchAll, router]);

  const handleRefresh = async () => {
    setRefreshing(true);
    await fetchAll();
    setRefreshing(false);
  };

  const handleLogout = () => {
    Cookies.remove('sstb_token');
    router.push('/login');
  };

  const handleBlockIP = async () => {
    if (!blockForm.address) return;
    setBlockLoading(true);
    try {
      await blockIP(blockForm.address, blockForm.reason, blockForm.comment);
      setShowBlockModal(false);
      setBlockForm({ address: '', reason: '', comment: '' });
      await fetchAll();
    } catch (e: any) {
      alert(e.response?.data?.detail || 'Gagal memblokir IP');
    } finally {
      setBlockLoading(false);
    }
  };

  const handleUnblock = async (ip: string) => {
    if (!confirm(`Unblock IP ${ip}?`)) return;
    try {
      await unblockIP(ip);
      await fetchAll();
    } catch (e) {
      alert('Gagal unblock IP');
    }
  };

  const handleScan = async () => {
    if (!scanIP_input) return;
    setScanLoading(true);
    setScanResult(null);
    try {
      const res = await scanIP(scanIP_input);
      setScanResult(res.data);
    } catch (e) {
      alert('Gagal scan IP');
    } finally {
      setScanLoading(false);
    }
  };

  const handleSync = async () => {
    try {
      const res = await syncFromMikroTik();
      alert(res.data.message);
      await fetchAll();
    } catch (e) {
      alert('Gagal sinkronisasi dari MikroTik');
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-cyber-dark flex items-center justify-center">
        <div className="text-center">
          <div className="w-12 h-12 border-2 border-cyber-cyan/30 border-t-cyber-cyan rounded-full animate-spin mx-auto mb-4" />
          <p className="text-cyber-cyan text-sm">Initializing SSTB...</p>
        </div>
      </div>
    );
  }

  // Chart data
  const chartLabels = timeline.map((d) => d.date.slice(5));
  const attackChartData = {
    labels: chartLabels,
    datasets: [
      {
        label: 'Attacks',
        data: timeline.map((d) => d.attacks),
        backgroundColor: 'rgba(255, 68, 68, 0.3)',
        borderColor: '#ff4444',
        borderWidth: 1,
      },
      {
        label: 'Blocked',
        data: timeline.map((d) => d.blocked),
        backgroundColor: 'rgba(0, 212, 255, 0.3)',
        borderColor: '#00d4ff',
        borderWidth: 1,
      },
    ],
  };

  const chartOptions: any = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { labels: { color: '#9ca3af', font: { family: 'monospace', size: 11 } } },
    },
    scales: {
      x: { ticks: { color: '#6b7280' }, grid: { color: '#1a2744' } },
      y: { ticks: { color: '#6b7280' }, grid: { color: '#1a2744' } },
    },
  };

  const filteredBlocklist = blocklist.filter((b) =>
    b.address.includes(ipFilter) ||
    b.source?.toLowerCase().includes(ipFilter.toLowerCase())
  );

  const severityColor = (s: string) => {
    if (s === 'CRITICAL') return 'text-red-400 bg-red-500/10 border-red-500/30';
    if (s === 'HIGH') return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
    if (s === 'MEDIUM') return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
    return 'text-green-400 bg-green-500/10 border-green-500/30';
  };

  const statusColor = (s: string) => {
    if (s === 'blocked') return 'text-red-400';
    if (s === 'analyzing') return 'text-yellow-400';
    if (s === 'pending') return 'text-gray-400';
    return 'text-green-400';
  };

  return (
    <div className="min-h-screen bg-cyber-dark flex">
      {/* Sidebar */}
      <aside className="w-64 bg-cyber-card border-r border-cyber-border flex flex-col flex-shrink-0">
        {/* Logo */}
        <div className="p-5 border-b border-cyber-border">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-cyber-cyan/10 border border-cyber-cyan/30 flex items-center justify-center glow-cyan">
              <Shield className="w-5 h-5 text-cyber-cyan" />
            </div>
            <div>
              <h1 className="text-sm font-bold text-white">SSTB</h1>
              <p className="text-xs text-gray-500">Threat Blocker</p>
            </div>
          </div>
        </div>

        {/* MikroTik Status */}
        <div className="p-4 border-b border-cyber-border">
          <div className="flex items-center gap-2 text-xs">
            {stats?.mikrotik_connected ? (
              <>
                <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                <span className="text-green-400">Router Online</span>
              </>
            ) : (
              <>
                <div className="w-2 h-2 rounded-full bg-red-400" />
                <span className="text-red-400">Router Offline</span>
              </>
            )}
          </div>
          <p className="text-xs text-gray-600 mt-1">192.168.100.3</p>
        </div>

        {/* Nav */}
        <nav className="flex-1 p-3 space-y-1">
          {[
            { id: 'overview', label: 'Overview', icon: Activity },
            { id: 'blocklist', label: 'IP Blocklist', icon: Ban },
            { id: 'threats', label: 'Attack Logs', icon: AlertTriangle },
            { id: 'cve', label: 'CVE Alerts', icon: Bug },
          ].map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id as Tab)}
              className={clsx(
                'w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all',
                activeTab === id
                  ? 'bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/20'
                  : 'text-gray-400 hover:bg-white/5 hover:text-white'
              )}
            >
              <Icon className="w-4 h-4" />
              {label}
              {id === 'blocklist' && blocklist.length > 0 && (
                <span className="ml-auto text-xs bg-cyber-cyan/20 text-cyber-cyan px-1.5 py-0.5 rounded">
                  {blocklist.length}
                </span>
              )}
            </button>
          ))}
        </nav>

        {/* Bottom actions */}
        <div className="p-3 border-t border-cyber-border space-y-2">
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs text-gray-400 hover:bg-white/5 hover:text-white transition-all"
          >
            <RefreshCw className={clsx('w-3.5 h-3.5', refreshing && 'animate-spin')} />
            Refresh Data
          </button>
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs text-red-400 hover:bg-red-500/10 transition-all"
          >
            <LogOut className="w-3.5 h-3.5" />
            Logout
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        {/* Topbar */}
        <div className="sticky top-0 z-10 bg-cyber-card/80 backdrop-blur-sm border-b border-cyber-border px-6 py-3 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-white capitalize">{activeTab}</h2>
            <p className="text-xs text-gray-500">
              Last updated: {new Date().toLocaleTimeString('id-ID')}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {stats?.auto_block_enabled && (
              <span className="flex items-center gap-1 text-xs bg-green-500/10 text-green-400 border border-green-500/20 px-2 py-1 rounded">
                <Zap className="w-3 h-3" />
                Auto-Block ON
              </span>
            )}
          </div>
        </div>

        <div className="p-6">
          {/* ===== OVERVIEW TAB ===== */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Stats grid */}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <StatCard
                  title="Total Blocked IPs"
                  value={stats?.total_blocked ?? 0}
                  sub={`+${stats?.blocked_today ?? 0} hari ini`}
                  icon={<Ban className="w-5 h-5" />}
                  color="cyan"
                />
                <StatCard
                  title="Threats Detected"
                  value={stats?.threats_detected ?? 0}
                  sub={`${stats?.threats_today ?? 0} hari ini`}
                  icon={<AlertTriangle className="w-5 h-5" />}
                  color="red"
                />
                <StatCard
                  title="CVE Alerts"
                  value={stats?.active_cve_alerts ?? 0}
                  sub={`${stats?.critical_cve_count ?? 0} CRITICAL`}
                  icon={<Bug className="w-5 h-5" />}
                  color="orange"
                />
                <StatCard
                  title="Router Status"
                  value={stats?.mikrotik_connected ? 'ONLINE' : 'OFFLINE'}
                  sub="MikroTik 192.168.100.3"
                  icon={<Router className="w-5 h-5" />}
                  color={stats?.mikrotik_connected ? 'green' : 'red'}
                  isText
                />
              </div>

              {/* Attack timeline chart */}
              <div className="bg-cyber-card border border-cyber-border rounded-xl p-5">
                <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                  <Activity className="w-4 h-4 text-cyber-cyan" />
                  Attack Timeline (7 Hari)
                </h3>
                <div className="h-48">
                  {timeline.length > 0 ? (
                    <Bar data={attackChartData} options={chartOptions} />
                  ) : (
                    <div className="h-full flex items-center justify-center text-gray-600 text-sm">
                      Belum ada data serangan
                    </div>
                  )}
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Top attackers */}
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-5">
                  <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                    <Globe className="w-4 h-4 text-red-400" />
                    Top Attackers
                  </h3>
                  {topAttackers.length === 0 ? (
                    <p className="text-gray-600 text-xs">Belum ada data</p>
                  ) : (
                    <div className="space-y-2">
                      {topAttackers.slice(0, 8).map((a, i) => (
                        <div key={a.ip} className="flex items-center gap-3">
                          <span className="text-xs text-gray-600 w-5">{i + 1}</span>
                          <code className="text-xs text-cyber-cyan flex-1">{a.ip}</code>
                          <span className="text-xs text-gray-400">{a.count}x</span>
                          <div
                            className="h-1.5 rounded-full bg-red-500/30"
                            style={{ width: `${Math.min((a.count / (topAttackers[0]?.count || 1)) * 80, 80)}px` }}
                          >
                            <div
                              className="h-full rounded-full bg-red-500"
                              style={{ width: '100%' }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* MikroTik info */}
                <div className="bg-cyber-card border border-cyber-border rounded-xl p-5">
                  <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                    <Router className="w-4 h-4 text-cyber-cyan" />
                    MikroTik Router Info
                  </h3>
                  {mikrotikStatus?.connected ? (
                    <div className="space-y-2">
                      {Object.entries(mikrotikStatus.data || {}).map(([k, v]) => (
                        <div key={k} className="flex justify-between text-xs">
                          <span className="text-gray-500 capitalize">{k.replace(/-/g, ' ')}</span>
                          <span className="text-gray-300">{String(v)}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center py-6 text-center">
                      <WifiOff className="w-8 h-8 text-red-400 mb-2" />
                      <p className="text-red-400 text-sm">Router tidak terhubung</p>
                      <p className="text-gray-600 text-xs mt-1">{mikrotikStatus?.error}</p>
                    </div>
                  )}
                </div>
              </div>

              {/* Recent logs preview */}
              <div className="bg-cyber-card border border-cyber-border rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-yellow-400" />
                    Log Serangan Terbaru
                  </h3>
                  <button
                    onClick={() => setActiveTab('threats')}
                    className="text-xs text-cyber-cyan hover:underline flex items-center gap-1"
                  >
                    Lihat semua <ChevronRight className="w-3 h-3" />
                  </button>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="text-gray-500 border-b border-cyber-border">
                        <th className="text-left pb-2">IP Sumber</th>
                        <th className="text-left pb-2">Tipe</th>
                        <th className="text-left pb-2">Port</th>
                        <th className="text-left pb-2">Score</th>
                        <th className="text-left pb-2">Status</th>
                        <th className="text-left pb-2">Waktu</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-cyber-border/50">
                      {attackLogs.slice(0, 8).map((log) => (
                        <tr key={log.id} className="hover:bg-white/5">
                          <td className="py-2"><code className="text-cyber-cyan">{log.source_ip}</code></td>
                          <td className="py-2 text-gray-400">{log.attack_type || '-'}</td>
                          <td className="py-2 text-gray-400">{log.target_port || '-'}</td>
                          <td className="py-2">
                            <ThreatScoreBadge score={log.threat_score} />
                          </td>
                          <td className={clsx('py-2 capitalize', statusColor(log.status))}>
                            {log.status}
                          </td>
                          <td className="py-2 text-gray-600">
                            {new Date(log.detected_at).toLocaleTimeString('id-ID')}
                          </td>
                        </tr>
                      ))}
                      {attackLogs.length === 0 && (
                        <tr>
                          <td colSpan={6} className="py-8 text-center text-gray-600">
                            Belum ada log serangan
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ===== BLOCKLIST TAB ===== */}
          {activeTab === 'blocklist' && (
            <div className="space-y-4">
              {/* Actions bar */}
              <div className="flex flex-wrap items-center gap-3">
                <div className="relative flex-1 min-w-48">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                  <input
                    type="text"
                    value={ipFilter}
                    onChange={(e) => setIpFilter(e.target.value)}
                    placeholder="Filter IP atau source..."
                    className="cyber-input w-full rounded-lg pl-9 pr-4 py-2 text-sm"
                  />
                </div>
                <button
                  onClick={() => setShowBlockModal(true)}
                  className="cyber-btn flex items-center gap-2 px-4 py-2 rounded-lg text-sm"
                >
                  <Plus className="w-4 h-4" /> Block IP
                </button>
                <button
                  onClick={handleSync}
                  className="cyber-btn flex items-center gap-2 px-4 py-2 rounded-lg text-sm"
                >
                  <RefreshCw className="w-4 h-4" /> Sync MikroTik
                </button>
              </div>

              {/* IP Scan */}
              <div className="bg-cyber-card border border-cyber-border rounded-xl p-5">
                <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                  <Eye className="w-4 h-4 text-cyber-cyan" />
                  Threat Intelligence Scan
                </h3>
                <div className="flex gap-3">
                  <input
                    type="text"
                    value={scanIP_input}
                    onChange={(e) => setScanIPInput(e.target.value)}
                    placeholder="Masukkan IP untuk scan..."
                    className="cyber-input flex-1 rounded-lg px-4 py-2 text-sm"
                    onKeyDown={(e) => e.key === 'Enter' && handleScan()}
                  />
                  <button
                    onClick={handleScan}
                    disabled={scanLoading}
                    className="cyber-btn px-5 py-2 rounded-lg text-sm flex items-center gap-2 disabled:opacity-50"
                  >
                    {scanLoading ? (
                      <span className="w-4 h-4 border-2 border-cyber-cyan/30 border-t-cyber-cyan rounded-full animate-spin" />
                    ) : (
                      <Search className="w-4 h-4" />
                    )}
                    Scan
                  </button>
                </div>

                {scanResult && (
                  <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-3">
                    <div className={clsx(
                      'rounded-lg p-3 border text-center',
                      scanResult.is_malicious
                        ? 'bg-red-500/10 border-red-500/30'
                        : 'bg-green-500/10 border-green-500/30'
                    )}>
                      <p className="text-xs text-gray-400">Status</p>
                      <p className={clsx('text-sm font-bold', scanResult.is_malicious ? 'text-red-400' : 'text-green-400')}>
                        {scanResult.is_malicious ? 'MALICIOUS' : 'CLEAN'}
                      </p>
                    </div>
                    <div className="bg-cyber-darker rounded-lg p-3 border border-cyber-border text-center">
                      <p className="text-xs text-gray-400">Total Score</p>
                      <p className="text-sm font-bold text-white">{scanResult.threat_score.toFixed(1)}/10</p>
                    </div>
                    <div className="bg-cyber-darker rounded-lg p-3 border border-cyber-border text-center">
                      <p className="text-xs text-gray-400">VirusTotal</p>
                      <p className="text-sm font-bold text-yellow-400">{scanResult.virustotal_score.toFixed(1)}</p>
                    </div>
                    <div className="bg-cyber-darker rounded-lg p-3 border border-cyber-border text-center">
                      <p className="text-xs text-gray-400">AlienVault</p>
                      <p className="text-sm font-bold text-orange-400">{scanResult.alienvault_score.toFixed(1)}</p>
                    </div>
                    {scanResult.is_malicious && (
                      <button
                        onClick={() => {
                          setBlockForm({ address: scanResult.ip, reason: `Score: ${scanResult.threat_score}`, comment: `Sources: ${scanResult.sources.join(', ')}` });
                          setShowBlockModal(true);
                        }}
                        className="col-span-2 md:col-span-4 cyber-btn-danger py-2 rounded-lg text-sm flex items-center justify-center gap-2"
                      >
                        <Ban className="w-4 h-4" /> Block IP {scanResult.ip}
                      </button>
                    )}
                  </div>
                )}
              </div>

              {/* Blocklist table */}
              <div className="bg-cyber-card border border-cyber-border rounded-xl overflow-hidden">
                <div className="p-4 border-b border-cyber-border flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                    <Ban className="w-4 h-4 text-red-400" />
                    IP Blocklist ({filteredBlocklist.length})
                  </h3>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="bg-cyber-darker text-gray-500 border-b border-cyber-border">
                        <th className="text-left p-3">IP Address</th>
                        <th className="text-left p-3">Score</th>
                        <th className="text-left p-3">Source</th>
                        <th className="text-left p-3">Reason</th>
                        <th className="text-left p-3">MikroTik</th>
                        <th className="text-left p-3">Blocked At</th>
                        <th className="text-left p-3">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-cyber-border/30">
                      {filteredBlocklist.map((ip) => (
                        <tr key={ip.id} className="hover:bg-white/5">
                          <td className="p-3">
                            <code className="text-cyber-cyan">{ip.address}</code>
                          </td>
                          <td className="p-3">
                            <ThreatScoreBadge score={ip.threat_score} />
                          </td>
                          <td className="p-3">
                            <span className="bg-cyber-border px-2 py-0.5 rounded text-gray-300">
                              {ip.source || 'manual'}
                            </span>
                          </td>
                          <td className="p-3 text-gray-400 max-w-40 truncate">
                            {ip.reason || '-'}
                          </td>
                          <td className="p-3">
                            {ip.synced_to_mikrotik ? (
                              <span className="text-green-400">✓ Synced</span>
                            ) : (
                              <span className="text-yellow-400">⚠ Pending</span>
                            )}
                          </td>
                          <td className="p-3 text-gray-500">
                            {new Date(ip.blocked_at).toLocaleDateString('id-ID')}
                          </td>
                          <td className="p-3">
                            <button
                              onClick={() => handleUnblock(ip.address)}
                              className="cyber-btn-danger px-2 py-1 rounded text-xs flex items-center gap-1"
                            >
                              <Trash2 className="w-3 h-3" /> Unblock
                            </button>
                          </td>
                        </tr>
                      ))}
                      {filteredBlocklist.length === 0 && (
                        <tr>
                          <td colSpan={7} className="p-8 text-center text-gray-600">
                            {ipFilter ? 'Tidak ditemukan IP yang cocok' : 'Belum ada IP yang diblokir'}
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ===== THREATS TAB ===== */}
          {activeTab === 'threats' && (
            <div className="space-y-4">
              <div className="bg-cyber-card border border-cyber-border rounded-xl overflow-hidden">
                <div className="p-4 border-b border-cyber-border">
                  <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-yellow-400" />
                    Log Serangan ({attackLogs.length})
                  </h3>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="bg-cyber-darker text-gray-500 border-b border-cyber-border">
                        <th className="text-left p-3">IP Sumber</th>
                        <th className="text-left p-3">Tipe Serangan</th>
                        <th className="text-left p-3">Port</th>
                        <th className="text-left p-3">Protokol</th>
                        <th className="text-left p-3">Threat Score</th>
                        <th className="text-left p-3">Status</th>
                        <th className="text-left p-3">Waktu Deteksi</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-cyber-border/30">
                      {attackLogs.map((log) => (
                        <tr key={log.id} className="hover:bg-white/5">
                          <td className="p-3"><code className="text-cyber-cyan">{log.source_ip}</code></td>
                          <td className="p-3 text-gray-300">{log.attack_type || '-'}</td>
                          <td className="p-3 text-gray-400">{log.target_port || '-'}</td>
                          <td className="p-3 text-gray-400 uppercase">{log.protocol || '-'}</td>
                          <td className="p-3"><ThreatScoreBadge score={log.threat_score} /></td>
                          <td className={clsx('p-3 capitalize font-medium', statusColor(log.status))}>
                            {log.status}
                          </td>
                          <td className="p-3 text-gray-500">
                            {new Date(log.detected_at).toLocaleString('id-ID')}
                          </td>
                        </tr>
                      ))}
                      {attackLogs.length === 0 && (
                        <tr>
                          <td colSpan={7} className="p-8 text-center text-gray-600">
                            Belum ada log serangan
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ===== CVE TAB ===== */}
          {activeTab === 'cve' && (
            <div className="space-y-4">
              <div className="bg-cyber-card border border-cyber-border rounded-xl overflow-hidden">
                <div className="p-4 border-b border-cyber-border">
                  <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                    <Bug className="w-4 h-4 text-orange-400" />
                    CVE Alerts - MikroTik RouterOS
                  </h3>
                  <p className="text-xs text-gray-500 mt-1">
                    Data dari NVD (National Vulnerability Database) & CISA KEV
                  </p>
                </div>

                {cveAlerts.length === 0 ? (
                  <div className="p-12 text-center">
                    <Database className="w-12 h-12 text-gray-700 mx-auto mb-3" />
                    <p className="text-gray-500 text-sm">Belum ada data CVE</p>
                    <p className="text-gray-600 text-xs mt-1">
                      Worker akan melakukan sinkronisasi dari NVD setiap hari pukul 03:00 UTC
                    </p>
                  </div>
                ) : (
                  <div className="divide-y divide-cyber-border/30">
                    {cveAlerts.map((cve) => (
                      <div key={cve.id} className="p-4 hover:bg-white/5">
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <code className="text-cyber-cyan text-xs font-bold">{cve.cve_id}</code>
                              <span className={clsx(
                                'text-xs px-2 py-0.5 rounded border',
                                severityColor(cve.severity)
                              )}>
                                {cve.severity}
                              </span>
                              {cve.is_kev && (
                                <span className="text-xs px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">
                                  KEV
                                </span>
                              )}
                            </div>
                            <p className="text-xs text-gray-400 line-clamp-2">{cve.description}</p>
                            {cve.affected_product && (
                              <p className="text-xs text-gray-600 mt-1">
                                Affected: {cve.affected_product}
                              </p>
                            )}
                          </div>
                          <div className="text-right flex-shrink-0">
                            <p className="text-lg font-bold text-white">{cve.cvss_score.toFixed(1)}</p>
                            <p className="text-xs text-gray-500">CVSS</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Block IP Modal */}
      {showBlockModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-cyber-card border border-cyber-border rounded-xl w-full max-w-md p-6">
            <h3 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
              <Ban className="w-4 h-4 text-red-400" />
              Block IP Address
            </h3>
            <div className="space-y-3">
              <div>
                <label className="block text-xs text-gray-400 mb-1">IP Address *</label>
                <input
                  type="text"
                  value={blockForm.address}
                  onChange={(e) => setBlockForm({ ...blockForm, address: e.target.value })}
                  className="cyber-input w-full rounded-lg px-3 py-2 text-sm"
                  placeholder="e.g. 1.2.3.4"
                />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Alasan</label>
                <input
                  type="text"
                  value={blockForm.reason}
                  onChange={(e) => setBlockForm({ ...blockForm, reason: e.target.value })}
                  className="cyber-input w-full rounded-lg px-3 py-2 text-sm"
                  placeholder="e.g. SSH Brute Force"
                />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Komentar</label>
                <input
                  type="text"
                  value={blockForm.comment}
                  onChange={(e) => setBlockForm({ ...blockForm, comment: e.target.value })}
                  className="cyber-input w-full rounded-lg px-3 py-2 text-sm"
                  placeholder="Catatan tambahan..."
                />
              </div>
            </div>
            <div className="flex gap-3 mt-5">
              <button
                onClick={() => { setShowBlockModal(false); setBlockForm({ address: '', reason: '', comment: '' }); }}
                className="flex-1 border border-cyber-border rounded-lg py-2 text-sm text-gray-400 hover:bg-white/5"
              >
                Batal
              </button>
              <button
                onClick={handleBlockIP}
                disabled={blockLoading || !blockForm.address}
                className="flex-1 cyber-btn-danger rounded-lg py-2 text-sm font-semibold disabled:opacity-50"
              >
                {blockLoading ? 'Blocking...' : 'Block IP'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Sub-components
function StatCard({
  title, value, sub, icon, color, isText = false,
}: {
  title: string;
  value: number | string;
  sub: string;
  icon: React.ReactNode;
  color: 'cyan' | 'red' | 'green' | 'orange';
  isText?: boolean;
}) {
  const colorMap = {
    cyan: 'text-cyber-cyan border-cyber-cyan/20 bg-cyber-cyan/5',
    red: 'text-red-400 border-red-500/20 bg-red-500/5',
    green: 'text-green-400 border-green-500/20 bg-green-500/5',
    orange: 'text-orange-400 border-orange-500/20 bg-orange-500/5',
  };

  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs text-gray-400">{title}</p>
        <div className={clsx('w-8 h-8 rounded-lg flex items-center justify-center border', colorMap[color])}>
          {icon}
        </div>
      </div>
      <p className={clsx('font-bold mb-1', isText ? 'text-lg' : 'text-2xl', colorMap[color].split(' ')[0])}>
        {isText ? value : Number(value).toLocaleString()}
      </p>
      <p className="text-xs text-gray-500">{sub}</p>
    </div>
  );
}

function ThreatScoreBadge({ score }: { score: number }) {
  const color =
    score >= 7 ? 'text-red-400 bg-red-500/10'
    : score >= 4 ? 'text-yellow-400 bg-yellow-500/10'
    : 'text-green-400 bg-green-500/10';

  return (
    <span className={clsx('px-2 py-0.5 rounded text-xs font-mono', color)}>
      {score.toFixed(1)}
    </span>
  );
}

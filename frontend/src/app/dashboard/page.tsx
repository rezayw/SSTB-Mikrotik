'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { useRouter } from 'next/navigation';
import Cookies from 'js-cookie';
import { Bar, Doughnut, Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale, LinearScale, BarElement, LineElement, PointElement,
  ArcElement, Title, Tooltip, Legend, Filler,
} from 'chart.js';
import * as api from '@/lib/api';

ChartJS.register(
  CategoryScale, LinearScale, BarElement, LineElement, PointElement,
  ArcElement, Title, Tooltip, Legend, Filler,
);

// ── Types ─────────────────────────────────────────────────────────────────────
type Tab = 'overview' | 'blocklist' | 'logs' | 'cve' | 'mikrotik' | 'geo' | 'whitelist' | 'settings';
type MikroTikTab = 'interfaces' | 'firewall' | 'dhcp' | 'logs' | 'connections' | 'nat';

// ── Sub-components ────────────────────────────────────────────────────────────
const StatCard = ({ title, value, subtitle, icon, color }: any) => {
  const colors: Record<string, string> = {
    cyan: 'border-cyan-500/30 bg-cyan-500/5 text-cyan-400',
    red: 'border-red-500/30 bg-red-500/5 text-red-400',
    green: 'border-green-500/30 bg-green-500/5 text-green-400',
    orange: 'border-orange-500/30 bg-orange-500/5 text-orange-400',
    purple: 'border-purple-500/30 bg-purple-500/5 text-purple-400',
    yellow: 'border-yellow-500/30 bg-yellow-500/5 text-yellow-400',
  };
  return (
    <div className={`border rounded-xl p-4 ${colors[color] || colors.cyan}`}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-slate-400 uppercase tracking-wider">{title}</span>
        <span className="text-lg">{icon}</span>
      </div>
      <div className="text-2xl font-bold text-white mb-1">{value}</div>
      {subtitle && <div className="text-xs text-slate-400">{subtitle}</div>}
    </div>
  );
};

const ThreatScoreBadge = ({ score }: { score: number }) => {
  const color = score >= 7 ? 'bg-red-500/20 text-red-400 border-red-500/30'
    : score >= 4 ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
    : 'bg-green-500/20 text-green-400 border-green-500/30';
  return (
    <span className={`px-2 py-0.5 rounded border text-xs font-mono font-bold ${color}`}>
      {score?.toFixed(1) ?? '—'}
    </span>
  );
};

const CategoryBadge = ({ cat }: { cat: string }) => {
  const map: Record<string, string> = {
    'brute-force': 'bg-red-500/20 text-red-300 border-red-500/40',
    'port-scanner': 'bg-orange-500/20 text-orange-300 border-orange-500/40',
    'botnet': 'bg-purple-500/20 text-purple-300 border-purple-500/40',
    'malware-c2': 'bg-red-600/20 text-red-300 border-red-600/40',
    'phishing': 'bg-pink-500/20 text-pink-300 border-pink-500/40',
    'ddos': 'bg-orange-600/20 text-orange-300 border-orange-600/40',
    'spam': 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',
    'tor-exit-node': 'bg-indigo-500/20 text-indigo-300 border-indigo-500/40',
    'proxy/vpn': 'bg-blue-500/20 text-blue-300 border-blue-500/40',
    'hosting-abuse': 'bg-slate-500/20 text-slate-300 border-slate-500/40',
    'ransomware': 'bg-red-700/20 text-red-200 border-red-700/40',
    'web-attack': 'bg-yellow-600/20 text-yellow-300 border-yellow-600/40',
  };
  return (
    <span className={`px-1.5 py-0.5 rounded border text-[10px] font-medium ${map[cat] || 'bg-slate-500/20 text-slate-400 border-slate-500/40'}`}>
      {cat}
    </span>
  );
};

// ── IP Scan Detail Modal ───────────────────────────────────────────────────────
const IPScanDetail = ({ result, onBlock, onClose }: {
  result: any; onBlock: () => void; onClose: () => void;
}) => {
  const [scanTab, setScanTab] = useState<'overview' | 'vt' | 'av' | 'tf' | 'geo'>('overview');
  const tabs = [
    { id: 'overview', label: '📊 Overview' },
    { id: 'vt', label: '🔬 VirusTotal' },
    { id: 'av', label: '👽 AlienVault' },
    { id: 'tf', label: '🦊 ThreatFox' },
    { id: 'geo', label: '🌍 Geolocation' },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-3xl max-h-[90vh] overflow-hidden flex flex-col">
        <div className="flex items-center justify-between p-4 border-b border-slate-700">
          <div className="flex items-center gap-3 flex-wrap">
            <span className={`text-xl font-bold font-mono ${result.is_malicious ? 'text-red-400' : 'text-green-400'}`}>{result.ip}</span>
            <span className={`px-2 py-1 rounded-full text-xs font-bold border ${result.is_malicious ? 'bg-red-500/20 text-red-300 border-red-500/40' : 'bg-green-500/20 text-green-300 border-green-500/40'}`}>
              {result.is_malicious ? '⚠ MALICIOUS' : '✓ CLEAN'}
            </span>
            {result.cached && <span className="text-xs text-slate-500 border border-slate-700 rounded px-2 py-0.5">cached</span>}
            {result.threat_categories?.map((c: string) => <CategoryBadge key={c} cat={c} />)}
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white text-xl">✕</button>
        </div>

        <div className="flex gap-1 p-3 border-b border-slate-700 overflow-x-auto">
          {tabs.map((t) => (
            <button key={t.id} onClick={() => setScanTab(t.id as any)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-colors ${
                scanTab === t.id ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}>{t.label}</button>
          ))}
        </div>

        <div className="overflow-y-auto flex-1 p-4">
          {scanTab === 'overview' && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[
                  { label: 'Total Score', value: result.threat_score?.toFixed(1), color: result.threat_score >= 7 ? 'red' : result.threat_score >= 4 ? 'orange' : 'green' },
                  { label: 'VirusTotal', value: result.virustotal_score?.toFixed(1), color: 'cyan' },
                  { label: 'AlienVault', value: result.alienvault_score?.toFixed(1), color: 'purple' },
                  { label: 'ThreatFox', value: result.threatfox_score?.toFixed(1), color: 'orange' },
                ].map((s) => <StatCard key={s.label} title={s.label} value={s.value} subtitle="/10" color={s.color} icon="🎯" />)}
              </div>
              {result.sources?.length > 0 && (
                <div>
                  <div className="text-xs text-slate-400 mb-2 uppercase tracking-wider">Detected By</div>
                  <div className="flex flex-wrap gap-2">
                    {result.sources.map((s: string) => (
                      <span key={s} className="px-2 py-1 rounded bg-red-500/10 border border-red-500/30 text-red-300 text-xs">{s}</span>
                    ))}
                  </div>
                </div>
              )}
              <div className="grid grid-cols-2 gap-2 text-sm">
                {[
                  { label: 'Country', value: result.country ? `${api.countryFlagEmoji(result.country_code)} ${result.country}` : '—' },
                  { label: 'City', value: result.city || '—' },
                  { label: 'ISP', value: result.isp || '—' },
                  { label: 'ASN', value: result.asn || '—' },
                  { label: 'Tor Exit Node', value: result.is_tor ? '⚠ Yes' : 'No' },
                  { label: 'Proxy / Hosting', value: result.is_proxy ? '⚠ Yes' : 'No' },
                ].map(({ label, value }) => (
                  <div key={label} className="flex justify-between border border-slate-700/50 rounded-lg p-2 bg-slate-800/30">
                    <span className="text-slate-400 text-xs">{label}</span>
                    <span className="text-slate-200 text-xs font-medium">{value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {scanTab === 'vt' && result.virustotal && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <StatCard title="Score" value={result.virustotal.score?.toFixed(1)} subtitle="/10" color="cyan" icon="🔬" />
                <StatCard title="Malicious Engines" value={result.virustotal.malicious_engines} subtitle={`of ${result.virustotal.total_engines}`} color="red" icon="🚫" />
                <StatCard title="Suspicious" value={result.virustotal.suspicious_engines} color="orange" icon="⚠" />
                <StatCard title="Reputation" value={result.virustotal.reputation} color={result.virustotal.reputation < 0 ? 'red' : 'green'} icon="📊" />
              </div>
              {result.virustotal.flagged_engines?.length > 0 && (
                <div>
                  <div className="text-xs text-slate-400 mb-2">Flagged By Engines</div>
                  <div className="flex flex-wrap gap-1.5">
                    {result.virustotal.flagged_engines.map((e: string) => (
                      <span key={e} className="px-2 py-0.5 rounded bg-red-500/10 border border-red-500/30 text-red-300 text-xs font-mono">{e}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {scanTab === 'av' && result.alienvault && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <StatCard title="Score" value={result.alienvault.score?.toFixed(1)} subtitle="/10" color="purple" icon="👽" />
                <StatCard title="Pulse Count" value={result.alienvault.pulse_count} color="red" icon="📡" />
              </div>
              {result.alienvault.tags?.length > 0 && (
                <div>
                  <div className="text-xs text-slate-400 mb-2">Tags</div>
                  <div className="flex flex-wrap gap-1.5">
                    {result.alienvault.tags.map((t: string) => (
                      <span key={t} className="px-2 py-0.5 rounded bg-purple-500/10 border border-purple-500/30 text-purple-300 text-xs">{t}</span>
                    ))}
                  </div>
                </div>
              )}
              {result.alienvault.malware_families?.length > 0 && (
                <div>
                  <div className="text-xs text-slate-400 mb-2">Malware Families</div>
                  <div className="flex flex-wrap gap-1.5">
                    {result.alienvault.malware_families.map((f: string) => (
                      <span key={f} className="px-2 py-0.5 rounded bg-red-500/10 border border-red-500/30 text-red-300 text-xs">{f}</span>
                    ))}
                  </div>
                </div>
              )}
              {result.alienvault.adversaries?.length > 0 && (
                <div>
                  <div className="text-xs text-slate-400 mb-2">Adversaries</div>
                  <div className="flex flex-wrap gap-1.5">
                    {result.alienvault.adversaries.map((a: string) => (
                      <span key={a} className="px-2 py-0.5 rounded bg-orange-500/10 border border-orange-500/30 text-orange-300 text-xs font-bold">{a}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {scanTab === 'tf' && result.threatfox && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <StatCard title="Score" value={result.threatfox.score?.toFixed(1)} subtitle="/10" color="orange" icon="🦊" />
                <StatCard title="IoC Hits" value={result.threatfox.ioc_count} color="red" icon="🎯" />
                <StatCard title="Avg Confidence" value={`${result.threatfox.avg_confidence}%`} color="yellow" icon="📊" />
              </div>
              {result.threatfox.malware_names?.length > 0 && (
                <div>
                  <div className="text-xs text-slate-400 mb-2">Malware Names</div>
                  <div className="flex flex-wrap gap-1.5">
                    {result.threatfox.malware_names.map((n: string) => (
                      <span key={n} className="px-2 py-0.5 rounded bg-red-500/10 border border-red-500/30 text-red-300 text-xs font-mono">{n}</span>
                    ))}
                  </div>
                </div>
              )}
              {result.threatfox.threat_types?.length > 0 && (
                <div>
                  <div className="text-xs text-slate-400 mb-2">Threat Types</div>
                  <div className="flex flex-wrap gap-1.5">
                    {result.threatfox.threat_types.map((t: string) => (
                      <span key={t} className="px-2 py-0.5 rounded bg-orange-500/10 border border-orange-500/30 text-orange-300 text-xs">{t}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}


          {scanTab === 'geo' && result.geo && (
            <div className="space-y-4">
              <div className="text-5xl text-center py-2">{api.countryFlagEmoji(result.geo.country_code)}</div>
              <div className="grid grid-cols-2 gap-2">
                {[
                  { label: 'Country', value: result.geo.country },
                  { label: 'Region', value: result.geo.region },
                  { label: 'City', value: result.geo.city },
                  { label: 'ISP', value: result.geo.isp },
                  { label: 'Organization', value: result.geo.org },
                  { label: 'ASN', value: result.geo.asn },
                  { label: 'Timezone', value: result.geo.timezone },
                  { label: 'Coordinates', value: `${result.geo.lat?.toFixed(3)}, ${result.geo.lon?.toFixed(3)}` },
                  { label: 'Proxy / VPN', value: result.geo.is_proxy ? '⚠ Yes' : 'No' },
                  { label: 'Hosting Provider', value: result.geo.is_hosting ? '⚠ Yes' : 'No' },
                ].map(({ label, value }) => (
                  <div key={label} className="flex justify-between border border-slate-700/50 rounded-lg p-2 bg-slate-800/30">
                    <span className="text-slate-400 text-xs">{label}</span>
                    <span className="text-slate-200 text-xs font-medium">{value || '—'}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="flex gap-3 p-4 border-t border-slate-700">
          {result.is_malicious && (
            <button onClick={onBlock} className="flex-1 bg-red-500 hover:bg-red-600 text-white font-bold py-2.5 rounded-xl text-sm transition-colors">
              🚫 Block {result.ip}
            </button>
          )}
          <button onClick={onClose} className="flex-1 bg-slate-700 hover:bg-slate-600 text-white py-2.5 rounded-xl text-sm transition-colors">
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

// ── Profile & 2FA Modal ────────────────────────────────────────────────────────
const ProfileModal = ({ user, onClose, onUserUpdate }: {
  user: any; onClose: () => void; onUserUpdate: (u: any) => void;
}) => {
  const [totpPhase, setTotpPhase] = useState<'idle' | 'setup' | 'disable'>('idle');
  const [setupData, setSetupData] = useState<{ secret: string; provisioning_uri: string } | null>(null);
  const [code, setCode] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [QRCodeSVG, setQRCodeSVG] = useState<any>(null);

  // Lazy-load qrcode.react only in browser
  useEffect(() => {
    import('qrcode.react').then((m) => setQRCodeSVG(() => m.QRCodeSVG));
  }, []);

  const startSetup = async () => {
    setErr(''); setBusy(true);
    try {
      const res = await (await import('@/lib/api')).totpSetup();
      setSetupData(res.data);
      setTotpPhase('setup');
    } catch (e: any) {
      setErr(e.response?.data?.detail || 'Gagal memulai setup TOTP');
    } finally { setBusy(false); }
  };

  const confirmEnable = async () => {
    if (code.length !== 6) return;
    setErr(''); setBusy(true);
    try {
      await (await import('@/lib/api')).totpEnable(code);
      onUserUpdate({ ...user, totp_enabled: true });
      setTotpPhase('idle'); setCode(''); setSetupData(null);
    } catch (e: any) {
      setErr(e.response?.data?.detail || 'Kode tidak valid');
    } finally { setBusy(false); }
  };

  const confirmDisable = async () => {
    if (code.length !== 6) return;
    setErr(''); setBusy(true);
    try {
      await (await import('@/lib/api')).totpDisable(code);
      onUserUpdate({ ...user, totp_enabled: false });
      setTotpPhase('idle'); setCode('');
    } catch (e: any) {
      setErr(e.response?.data?.detail || 'Kode tidak valid');
    } finally { setBusy(false); }
  };

  const cancelPhase = () => { setTotpPhase('idle'); setCode(''); setErr(''); setSetupData(null); };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-md mx-4 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-slate-800">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            👤 Profile
          </h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition-colors text-xl leading-none">×</button>
        </div>

        <div className="p-5 space-y-4">
          {/* User info */}
          <div className="bg-slate-800/50 rounded-xl p-4 space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-slate-400">Username</span>
              <span className="text-white font-mono">{user?.username}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-slate-400">Email</span>
              <span className="text-slate-300">{user?.email}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-slate-400">Role</span>
              <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${user?.is_admin ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'bg-slate-700 text-slate-400'}`}>
                {user?.is_admin ? 'Administrator' : 'User'}
              </span>
            </div>
          </div>

          {/* 2FA section */}
          <div className="bg-slate-800/50 rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <div>
                <div className="text-sm font-medium text-white flex items-center gap-2">
                  🔐 Two-Factor Authentication
                </div>
                <div className="text-xs text-slate-500 mt-0.5">Google Authenticator compatible</div>
              </div>
              <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${user?.totp_enabled ? 'bg-green-500/20 text-green-400 border border-green-500/30' : 'bg-slate-700 text-slate-400'}`}>
                {user?.totp_enabled ? 'ACTIVE' : 'OFF'}
              </span>
            </div>

            {err && (
              <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg p-2 mb-3">
                {err}
              </div>
            )}

            {totpPhase === 'idle' && (
              <>
                {!user?.totp_enabled ? (
                  <button
                    onClick={startSetup}
                    disabled={busy}
                    className="w-full py-2 rounded-lg text-sm font-medium bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-400 border border-cyan-500/30 transition-colors disabled:opacity-50"
                  >
                    {busy ? 'Loading...' : 'Enable 2FA'}
                  </button>
                ) : (
                  <button
                    onClick={() => setTotpPhase('disable')}
                    className="w-full py-2 rounded-lg text-sm font-medium bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 transition-colors"
                  >
                    Disable 2FA
                  </button>
                )}
              </>
            )}

            {totpPhase === 'setup' && setupData && (
              <div className="space-y-3">
                <p className="text-xs text-slate-400">Scan QR code ini dengan Google Authenticator:</p>
                <div className="flex justify-center bg-white p-3 rounded-xl">
                  {QRCodeSVG
                    ? <QRCodeSVG value={setupData.provisioning_uri} size={160} />
                    : <div className="w-40 h-40 flex items-center justify-center text-slate-400 text-xs">Loading QR...</div>
                  }
                </div>
                <div className="text-center">
                  <p className="text-[10px] text-slate-500 mb-1">Atau masukkan kode manual:</p>
                  <code className="text-xs font-mono text-cyan-400 bg-slate-900 px-2 py-1 rounded select-all">{setupData.secret}</code>
                </div>
                <p className="text-xs text-slate-400">Masukkan kode 6 digit untuk konfirmasi:</p>
                <input
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-center text-xl font-mono tracking-[0.4em] text-white focus:border-cyan-500/50 outline-none"
                  placeholder="000000"
                  autoFocus
                />
                <div className="flex gap-2">
                  <button onClick={cancelPhase} className="flex-1 py-2 rounded-lg text-xs text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 transition-colors">
                    Batal
                  </button>
                  <button
                    onClick={confirmEnable}
                    disabled={busy || code.length !== 6}
                    className="flex-1 py-2 rounded-lg text-xs font-medium bg-green-500/20 hover:bg-green-500/30 text-green-400 border border-green-500/30 transition-colors disabled:opacity-40"
                  >
                    {busy ? 'Verifying...' : 'Aktifkan 2FA'}
                  </button>
                </div>
              </div>
            )}

            {totpPhase === 'disable' && (
              <div className="space-y-3">
                <p className="text-xs text-slate-400">Masukkan kode dari Google Authenticator untuk menonaktifkan 2FA:</p>
                <input
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-center text-xl font-mono tracking-[0.4em] text-white focus:border-red-500/50 outline-none"
                  placeholder="000000"
                  autoFocus
                />
                <div className="flex gap-2">
                  <button onClick={cancelPhase} className="flex-1 py-2 rounded-lg text-xs text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 transition-colors">
                    Batal
                  </button>
                  <button
                    onClick={confirmDisable}
                    disabled={busy || code.length !== 6}
                    className="flex-1 py-2 rounded-lg text-xs font-medium bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/20 transition-colors disabled:opacity-40"
                  >
                    {busy ? 'Verifying...' : 'Nonaktifkan 2FA'}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

// ── Topology SVG Component ─────────────────────────────────────────────────────
const TopologyDiagram = ({ nodes, onRefresh, refreshing }: {
  nodes: any[]; onRefresh: () => void; refreshing: boolean;
}) => {
  const [hovered, setHovered] = useState<number | null>(null);
  const W = 700, H = 420, cx = 350, cy = 210, R = 155;

  const positions = nodes.map((_, i) => {
    const angle = (2 * Math.PI / Math.max(nodes.length, 1)) * i - Math.PI / 2;
    return { x: cx + R * Math.cos(angle), y: cy + R * Math.sin(angle) };
  });

  const statusColor = (s: string) =>
    s === 'online' ? '#22c55e' : s === 'offline' ? '#ef4444' : '#94a3b8';
  const statusBg = (s: string) =>
    s === 'online' ? '#14532d' : s === 'offline' ? '#7f1d1d' : '#1e293b';

  return (
    <div className="relative">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-slate-300">Network Topology</h3>
        <button
          onClick={onRefresh}
          disabled={refreshing}
          className="px-3 py-1.5 text-xs bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/30 disabled:opacity-50 transition-colors"
        >
          {refreshing ? '⟳ Refreshing...' : '⟳ Refresh All'}
        </button>
      </div>

      {nodes.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-64 text-slate-500 border border-dashed border-slate-700 rounded-xl">
          <span className="text-4xl mb-3">🔌</span>
          <p className="text-sm">No MikroTik devices configured yet.</p>
          <p className="text-xs mt-1">Add a device in the Settings tab below.</p>
        </div>
      ) : (
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full rounded-xl bg-slate-900/60 border border-slate-700/50" style={{ maxHeight: 420 }}>
          {/* Grid dots */}
          <defs>
            <pattern id="grid" width="30" height="30" patternUnits="userSpaceOnUse">
              <circle cx="15" cy="15" r="0.8" fill="#1e293b" />
            </pattern>
            <filter id="glow">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
          </defs>
          <rect width={W} height={H} fill="url(#grid)" />

          {/* Connection lines */}
          {positions.map((pos, i) => {
            const node = nodes[i];
            const isOnline = node.status === 'online';
            const isHov = hovered === node.id;
            return (
              <g key={`line-${node.id}`}>
                <line
                  x1={cx} y1={cy} x2={pos.x} y2={pos.y}
                  stroke={isOnline ? '#22c55e' : '#ef4444'}
                  strokeWidth={isHov ? 2 : 1}
                  strokeOpacity={isHov ? 0.9 : 0.4}
                  strokeDasharray={isOnline ? 'none' : '6 4'}
                />
                {isOnline && (
                  <circle r="3" fill="#22c55e" opacity="0.9">
                    <animateMotion dur={`${2 + i * 0.4}s`} repeatCount="indefinite">
                      <mpath href={`#path-${node.id}`} />
                    </animateMotion>
                  </circle>
                )}
                <path id={`path-${node.id}`} d={`M${cx},${cy} L${pos.x},${pos.y}`} fill="none" />
              </g>
            );
          })}

          {/* SSTB central node */}
          <g filter="url(#glow)">
            <polygon
              points={[0,1,2,3,4,5].map(i => {
                const a = (Math.PI / 3) * i - Math.PI / 6;
                return `${cx + 38 * Math.cos(a)},${cy + 38 * Math.sin(a)}`;
              }).join(' ')}
              fill="#0f172a"
              stroke="#06b6d4"
              strokeWidth="2"
            />
          </g>
          <text x={cx} y={cy - 6} textAnchor="middle" fill="#06b6d4" fontSize="18">🛡</text>
          <text x={cx} y={cy + 12} textAnchor="middle" fill="#67e8f9" fontSize="9" fontWeight="bold">SSTB</text>
          <text x={cx} y={cy + 23} textAnchor="middle" fill="#475569" fontSize="7">v2.0.0</text>

          {/* Device nodes */}
          {positions.map((pos, i) => {
            const node = nodes[i];
            const col = statusColor(node.status);
            const bg = statusBg(node.status);
            const isHov = hovered === node.id;
            const nw = 110, nh = 66;

            return (
              <g key={`node-${node.id}`}
                onMouseEnter={() => setHovered(node.id)}
                onMouseLeave={() => setHovered(null)}
                style={{ cursor: 'pointer' }}
              >
                {/* Glow ring on hover */}
                {isHov && (
                  <rect
                    x={pos.x - nw / 2 - 3} y={pos.y - nh / 2 - 3}
                    width={nw + 6} height={nh + 6} rx="11"
                    fill="none" stroke={col} strokeWidth="2" opacity="0.6"
                  />
                )}
                <rect
                  x={pos.x - nw / 2} y={pos.y - nh / 2}
                  width={nw} height={nh} rx="9"
                  fill={bg} stroke={col} strokeWidth={isHov ? 1.5 : 1} opacity={isHov ? 1 : 0.85}
                />
                {/* Default star */}
                {node.is_default && (
                  <text x={pos.x + nw / 2 - 8} y={pos.y - nh / 2 + 12} fill="#fbbf24" fontSize="10">★</text>
                )}
                {/* Status dot */}
                <circle cx={pos.x - nw / 2 + 10} cy={pos.y - nh / 2 + 10} r="4" fill={col}>
                  {node.status === 'online' && (
                    <animate attributeName="opacity" values="1;0.4;1" dur="2s" repeatCount="indefinite" />
                  )}
                </circle>
                {/* Icon */}
                <text x={pos.x - nw / 2 + 22} y={pos.y - nh / 2 + 14} fill={col} fontSize="13" textAnchor="middle">🔀</text>
                {/* Name */}
                <text x={pos.x} y={pos.y - nh / 2 + 20} textAnchor="middle" fill="#e2e8f0" fontSize="9" fontWeight="bold">
                  {node.name.length > 14 ? node.name.slice(0, 14) + '…' : node.name}
                </text>
                {/* Host */}
                <text x={pos.x} y={pos.y - nh / 2 + 32} textAnchor="middle" fill="#64748b" fontSize="7.5" fontFamily="monospace">
                  {node.host}:{node.port}
                </text>
                {/* Model */}
                <text x={pos.x} y={pos.y - nh / 2 + 44} textAnchor="middle" fill="#94a3b8" fontSize="7.5">
                  {node.router_model || node.router_identity || 'Unknown'}
                </text>
                {/* Version / CPU */}
                <text x={pos.x} y={pos.y - nh / 2 + 56} textAnchor="middle" fill="#475569" fontSize="7">
                  {node.router_version ? `v${node.router_version}` : ''}
                  {node.cpu_load != null ? `  CPU ${node.cpu_load}%` : ''}
                </text>
              </g>
            );
          })}
        </svg>
      )}

      {/* Hover detail card */}
      {hovered !== null && (() => {
        const node = nodes.find(n => n.id === hovered);
        if (!node) return null;
        const fmtBytes = (b: number) => b > 1e9 ? `${(b / 1e9).toFixed(1)}G` : b > 1e6 ? `${(b / 1e6).toFixed(1)}M` : `${(b / 1e3).toFixed(0)}K`;
        return (
          <div className="mt-3 p-4 bg-slate-800/90 border border-slate-600 rounded-xl text-xs grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div><span className="text-slate-500 block">Identity</span><span className="text-white font-mono">{node.router_identity || '—'}</span></div>
            <div><span className="text-slate-500 block">Model</span><span className="text-white">{node.router_model || '—'}</span></div>
            <div><span className="text-slate-500 block">RouterOS</span><span className="text-white">{node.router_version || '—'}</span></div>
            <div><span className="text-slate-500 block">Uptime</span><span className="text-green-400">{node.uptime || '—'}</span></div>
            <div><span className="text-slate-500 block">CPU Load</span><span className={node.cpu_load > 80 ? 'text-red-400' : 'text-white'}>{node.cpu_load != null ? `${node.cpu_load}%` : '—'}</span></div>
            <div><span className="text-slate-500 block">Free Memory</span><span className="text-white">{node.free_memory ? fmtBytes(node.free_memory) : '—'}</span></div>
            <div><span className="text-slate-500 block">Interfaces</span><span className="text-white">{node.interface_count ?? '—'}</span></div>
            <div><span className="text-slate-500 block">Location</span><span className="text-white">{node.location || '—'}</span></div>
          </div>
        );
      })()}
    </div>
  );
};


// ── Device Form Modal ──────────────────────────────────────────────────────────
const DeviceFormModal = ({ device, onSave, onClose }: {
  device?: any; onSave: (data: any) => Promise<void>; onClose: () => void;
}) => {
  const [form, setForm] = useState({
    name: device?.name || '',
    host: device?.host || '',
    port: device?.port ?? 443,
    use_ssl: device?.use_ssl ?? true,
    api_user: device?.api_user || '',
    api_password: '',
    location: device?.location || '',
    description: device?.description || '',
    is_default: device?.is_default ?? false,
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const isEdit = !!device;

  const handle = async () => {
    if (!form.name || !form.host || !form.api_user) {
      setError('Name, Host, and API User are required.');
      return;
    }
    if (!isEdit && !form.api_password) {
      setError('API Password is required.');
      return;
    }
    setSaving(true);
    setError('');
    try {
      const payload = { ...form };
      if (isEdit && !payload.api_password) delete (payload as any).api_password;
      await onSave(payload);
      onClose();
    } catch (e: any) {
      setError(e?.response?.data?.detail || 'Failed to save device.');
    } finally {
      setSaving(false);
    }
  };

  const inp = 'w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500';
  const lbl = 'block text-xs text-slate-400 mb-1';

  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4">
      <div className="bg-slate-800 border border-slate-600 rounded-2xl w-full max-w-lg shadow-2xl">
        <div className="flex items-center justify-between p-5 border-b border-slate-700">
          <h2 className="text-white font-semibold">{isEdit ? '✏️ Edit Device' : '➕ Add MikroTik Device'}</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white text-xl">✕</button>
        </div>
        <div className="p-5 space-y-3 max-h-[70vh] overflow-y-auto">
          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2">
              <label className={lbl}>Device Name *</label>
              <input className={inp} placeholder="e.g. Router Utama" value={form.name}
                onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
            </div>
            <div>
              <label className={lbl}>Host / IP *</label>
              <input className={inp} placeholder="192.168.88.1" value={form.host}
                onChange={e => setForm(f => ({ ...f, host: e.target.value }))} />
            </div>
            <div>
              <label className={lbl}>Port</label>
              <input className={inp} type="number" value={form.port}
                onChange={e => setForm(f => ({ ...f, port: parseInt(e.target.value) || 443 }))} />
            </div>
            <div>
              <label className={lbl}>API User *</label>
              <input className={inp} placeholder="admin" value={form.api_user}
                onChange={e => setForm(f => ({ ...f, api_user: e.target.value }))} />
            </div>
            <div>
              <label className={lbl}>API Password {isEdit && <span className="text-slate-500">(leave blank to keep)</span>}</label>
              <input className={inp} type="password" placeholder={isEdit ? '••••••••' : 'password'} value={form.api_password}
                onChange={e => setForm(f => ({ ...f, api_password: e.target.value }))} />
            </div>
            <div className="col-span-2">
              <label className={lbl}>Location</label>
              <input className={inp} placeholder="e.g. Gedung A, Lantai 2" value={form.location}
                onChange={e => setForm(f => ({ ...f, location: e.target.value }))} />
            </div>
            <div className="col-span-2">
              <label className={lbl}>Description</label>
              <input className={inp} placeholder="Optional notes about this router" value={form.description}
                onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
            </div>
          </div>
          <div className="flex gap-4 pt-1">
            <label className="flex items-center gap-2 text-sm text-slate-300 cursor-pointer">
              <input type="checkbox" checked={form.use_ssl}
                onChange={e => setForm(f => ({ ...f, use_ssl: e.target.checked }))}
                className="rounded" />
              Use SSL (HTTPS)
            </label>
            <label className="flex items-center gap-2 text-sm text-slate-300 cursor-pointer">
              <input type="checkbox" checked={form.is_default}
                onChange={e => setForm(f => ({ ...f, is_default: e.target.checked }))}
                className="rounded" />
              Set as Default
            </label>
          </div>
          {error && <p className="text-red-400 text-xs bg-red-500/10 border border-red-500/20 rounded p-2">{error}</p>}
        </div>
        <div className="flex gap-3 p-5 border-t border-slate-700">
          <button onClick={onClose} className="flex-1 py-2 text-sm text-slate-400 border border-slate-600 rounded-lg hover:bg-slate-700 transition-colors">Cancel</button>
          <button onClick={handle} disabled={saving}
            className="flex-1 py-2 text-sm bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg disabled:opacity-50 transition-colors font-medium">
            {saving ? 'Saving…' : isEdit ? 'Save Changes' : 'Add & Test Connection'}
          </button>
        </div>
      </div>
    </div>
  );
};


// ── Settings Tab Component ─────────────────────────────────────────────────────
const SettingsTab = () => {
  const [devices, setDevices] = useState<any[]>([]);
  const [topology, setTopology] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [testing, setTesting] = useState<number | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [editDevice, setEditDevice] = useState<any>(null);
  const [err, setErr] = useState('');

  const loadAll = async () => {
    try {
      const [devRes, topoRes] = await Promise.all([
        api.listMikroTikDevices(),
        api.getMikroTikTopology(),
      ]);
      setDevices(devRes.data);
      setTopology(topoRes.data);
    } catch (e) {
      setErr('Failed to load devices.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadAll(); }, []);

  const handleRefreshAll = async () => {
    setRefreshing(true);
    try {
      await api.refreshAllDevices();
      await loadAll();
    } finally {
      setRefreshing(false);
    }
  };

  const handleTest = async (id: number) => {
    setTesting(id);
    try {
      await api.testMikroTikDevice(id);
      await loadAll();
    } finally {
      setTesting(null);
    }
  };

  const handleSetDefault = async (id: number) => {
    await api.setDefaultMikroTikDevice(id);
    await loadAll();
  };

  const handleDelete = async (id: number, name: string) => {
    if (!confirm(`Delete device "${name}"? This cannot be undone.`)) return;
    try {
      await api.deleteMikroTikDevice(id);
      await loadAll();
    } catch (e: any) {
      alert(e?.response?.data?.detail || 'Failed to delete device.');
    }
  };

  const handleSave = async (data: any) => {
    if (editDevice) {
      await api.updateMikroTikDevice(editDevice.id, data);
    } else {
      await api.addMikroTikDevice(data);
    }
    setEditDevice(null);
    await loadAll();
  };

  const [settingUpFw, setSettingUpFw] = useState<number | null>(null);
  const [fwResult, setFwResult] = useState<{ id: number; msg: string } | null>(null);
  const handleSetupFirewall = async (id: number) => {
    setSettingUpFw(id);
    setFwResult(null);
    try {
      const res = await api.setupFirewallRules(id);
      const d = res.data;
      const created = d.created?.length ? `Created: ${d.created.join(', ')}` : '';
      const exist = d.already_exist?.length ? `Exist: ${d.already_exist.join(', ')}` : '';
      const failed = d.failed?.length ? `Failed: ${d.failed.join(', ')}` : '';
      setFwResult({ id, msg: [created, exist, failed].filter(Boolean).join(' | ') || 'Done' });
    } catch (e: any) {
      setFwResult({ id, msg: e?.response?.data?.detail || 'Error' });
    } finally {
      setSettingUpFw(null);
    }
  };

  const statusDot = (s: string) =>
    s === 'online' ? 'bg-green-500' : s === 'offline' ? 'bg-red-500' : 'bg-slate-500';
  const statusLabel = (s: string) =>
    s === 'online' ? 'text-green-400' : s === 'offline' ? 'text-red-400' : 'text-slate-400';

  if (loading) return <div className="flex items-center justify-center h-48 text-slate-400 text-sm">Loading devices…</div>;

  return (
    <div className="space-y-6">
      {/* Topology */}
      <div className="bg-slate-800/40 border border-slate-700 rounded-2xl p-5">
        <TopologyDiagram
          nodes={topology?.nodes || []}
          onRefresh={handleRefreshAll}
          refreshing={refreshing}
        />
      </div>

      {/* Device list */}
      <div className="bg-slate-800/40 border border-slate-700 rounded-2xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-white font-semibold">MikroTik Devices</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              {topology?.online_count || 0} online · {topology?.offline_count || 0} offline · {topology?.total_devices || 0} total
            </p>
          </div>
          <button
            onClick={() => { setEditDevice(null); setShowForm(true); }}
            className="px-4 py-2 text-sm bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors font-medium"
          >
            + Add Device
          </button>
        </div>

        {err && <p className="text-red-400 text-xs mb-3">{err}</p>}

        {devices.length === 0 ? (
          <div className="text-center py-12 text-slate-500">
            <span className="text-4xl block mb-3">🔌</span>
            <p className="text-sm">No MikroTik devices configured.</p>
            <p className="text-xs mt-1">Click "Add Device" to connect your first router.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {devices.map(dev => (
              <div key={dev.id} className="bg-slate-900/60 border border-slate-700 rounded-xl p-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-start gap-3 min-w-0">
                    <div className="mt-1 relative flex-shrink-0">
                      <span className={`w-3 h-3 rounded-full block ${statusDot(dev.last_status)}`} />
                      {dev.last_status === 'online' && (
                        <span className={`absolute inset-0 rounded-full ${statusDot(dev.last_status)} animate-ping opacity-40`} />
                      )}
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-white font-semibold text-sm">{dev.name}</span>
                        {dev.is_default && <span className="text-[10px] bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 px-1.5 py-0.5 rounded">★ Default</span>}
                        <span className={`text-[10px] font-medium ${statusLabel(dev.last_status)}`}>{dev.last_status.toUpperCase()}</span>
                      </div>
                      <p className="text-xs text-slate-400 font-mono mt-0.5">{dev.use_ssl ? 'https' : 'http'}://{dev.host}:{dev.port}</p>
                      <div className="flex flex-wrap gap-x-4 gap-y-0.5 mt-1.5">
                        {dev.router_identity && <span className="text-xs text-slate-500">🔀 {dev.router_identity}</span>}
                        {dev.router_model && <span className="text-xs text-slate-500">📟 {dev.router_model}</span>}
                        {dev.router_version && <span className="text-xs text-slate-500">🏷 v{dev.router_version}</span>}
                        {dev.uptime && <span className="text-xs text-green-600">⏱ {dev.uptime}</span>}
                        {dev.cpu_load != null && <span className={`text-xs ${dev.cpu_load > 80 ? 'text-red-400' : 'text-slate-500'}`}>🖥 CPU {dev.cpu_load}%</span>}
                        {dev.location && <span className="text-xs text-slate-500">📍 {dev.location}</span>}
                      </div>
                      {dev.last_checked && (
                        <p className="text-[10px] text-slate-600 mt-1">
                          Last checked: {new Date(dev.last_checked).toLocaleString()}
                        </p>
                      )}
                    </div>
                  </div>
                  <div className="flex flex-col gap-1.5 flex-shrink-0">
                    <button
                      onClick={() => handleTest(dev.id)}
                      disabled={testing === dev.id}
                      className="px-3 py-1 text-xs bg-blue-500/20 text-blue-300 border border-blue-500/30 rounded-lg hover:bg-blue-500/30 disabled:opacity-50 transition-colors"
                    >
                      {testing === dev.id ? '⟳ Testing…' : '🔌 Test'}
                    </button>
                    {!dev.is_default && (
                      <button
                        onClick={() => handleSetDefault(dev.id)}
                        className="px-3 py-1 text-xs bg-yellow-500/20 text-yellow-300 border border-yellow-500/30 rounded-lg hover:bg-yellow-500/30 transition-colors"
                      >
                        ★ Default
                      </button>
                    )}
                    <button
                      onClick={() => { setEditDevice(dev); setShowForm(true); }}
                      className="px-3 py-1 text-xs bg-slate-700 text-slate-300 border border-slate-600 rounded-lg hover:bg-slate-600 transition-colors"
                    >
                      ✏️ Edit
                    </button>
                    <button
                      onClick={() => handleSetupFirewall(dev.id)}
                      disabled={settingUpFw === dev.id}
                      title="Buat firewall DROP rules untuk SSTB-Blacklist di device ini"
                      className="px-3 py-1 text-xs bg-orange-500/20 text-orange-300 border border-orange-500/30 rounded-lg hover:bg-orange-500/30 disabled:opacity-50 transition-colors"
                    >
                      {settingUpFw === dev.id ? '⟳ Setting…' : '🛡 Setup FW'}
                    </button>
                    {fwResult?.id === dev.id && (
                      <p className="text-[10px] text-slate-400 max-w-[140px] break-words">{fwResult?.msg}</p>
                    )}
                    <button
                      onClick={() => handleDelete(dev.id, dev.name)}
                      disabled={dev.is_default}
                      className="px-3 py-1 text-xs bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg hover:bg-red-500/30 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                    >
                      🗑 Delete
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Form modal */}
      {showForm && (
        <DeviceFormModal
          device={editDevice}
          onSave={handleSave}
          onClose={() => { setShowForm(false); setEditDevice(null); }}
        />
      )}
    </div>
  );
};


// ── Main Dashboard ─────────────────────────────────────────────────────────────
export default function DashboardPage() {
  const router = useRouter();
  const [tab, setTab] = useState<Tab>('overview');
  const [mtTab, setMtTab] = useState<MikroTikTab>('interfaces');
  const [mtDevices, setMtDevices] = useState<any[]>([]);
  const [selectedDeviceId, setSelectedDeviceId] = useState<number | undefined>(undefined);

  // Data
  const [stats, setStats] = useState<any>(null);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [topAttackers, setTopAttackers] = useState<any[]>([]);
  const [blocklist, setBlocklist] = useState<any[]>([]);
  const [attackLogs, setAttackLogs] = useState<any[]>([]);
  const [cveAlerts, setCveAlerts] = useState<any[]>([]);
  const [mikrotikStatus, setMikrotikStatus] = useState<any>(null);
  const [geoStats, setGeoStats] = useState<any[]>([]);
  const [protocolStats, setProtocolStats] = useState<any>(null);
  const [hourlyHeatmap, setHourlyHeatmap] = useState<any[]>([]);
  const [whitelist, setWhitelist] = useState<any[]>([]);
  const [summaryCounts, setSummaryCounts] = useState<any>(null);

  // MikroTik Monitor
  const [mtInterfaces, setMtInterfaces] = useState<any[]>([]);
  const [mtFirewallRules, setMtFirewallRules] = useState<any[]>([]);
  const [mtDhcpLeases, setMtDhcpLeases] = useState<any[]>([]);
  const [mtLogs, setMtLogs] = useState<any[]>([]);
  const [mtConnections, setMtConnections] = useState<any[]>([]);
  const [mtNatRules, setMtNatRules] = useState<any[]>([]);
  const [mtLoading, setMtLoading] = useState(false);
  const [mtChain, setMtChain] = useState('');

  // UI
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState('');
  const [scanIPVal, setScanIPVal] = useState('');
  const [scanResult, setScanResult] = useState<any>(null);
  const [scanLoading, setScanLoading] = useState(false);
  const [blockModal, setBlockModal] = useState(false);
  const [blockAddress, setBlockAddress] = useState('');
  const [blockReason, setBlockReason] = useState('');
  const [blockLoading, setBlockLoading] = useState(false);
  const [whitelistModal, setWhitelistModal] = useState(false);
  const [wlAddress, setWlAddress] = useState('');
  const [wlReason, setWlReason] = useState('');
  const [wlLoading, setWlLoading] = useState(false);
  const [searchFilter, setSearchFilter] = useState('');
  const [logFilter, setLogFilter] = useState('');
  const [syncLoading, setSyncLoading] = useState(false);
  const [liveFeed, setLiveFeed] = useState<any[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const [currentUser, setCurrentUser] = useState<any>(null);

  const feedRef = useRef<ReturnType<typeof api.createLiveFeed> | null>(null);

  const fetchCoreData = useCallback(async () => {
    const results = await Promise.allSettled([
      api.getDashboardStats(),
      api.getAttackTimeline(14),
      api.getTopAttackers(10),
      api.getBlocklist(0, 100),
      api.getAttackLogs(0, 100),
      api.getCVEAlerts(20),
      api.getMikroTikStatus(),
      api.getGeoStats(20),
      api.getProtocolStats(),
      api.getHourlyHeatmap(30),
      api.getWhitelist(0, 100),
      api.getSummaryCounts(),
    ]);
    if (results[0].status === 'fulfilled') setStats(results[0].value.data);
    if (results[1].status === 'fulfilled') setTimeline(results[1].value.data);
    if (results[2].status === 'fulfilled') setTopAttackers(results[2].value.data);
    if (results[3].status === 'fulfilled') setBlocklist(results[3].value.data);
    if (results[4].status === 'fulfilled') setAttackLogs(results[4].value.data);
    if (results[5].status === 'fulfilled') setCveAlerts(results[5].value.data);
    if (results[6].status === 'fulfilled') setMikrotikStatus(results[6].value.data);
    if (results[7].status === 'fulfilled') setGeoStats(results[7].value.data);
    if (results[8].status === 'fulfilled') setProtocolStats(results[8].value.data);
    if (results[9].status === 'fulfilled') setHourlyHeatmap(results[9].value.data);
    if (results[10].status === 'fulfilled') setWhitelist(results[10].value.data);
    if (results[11].status === 'fulfilled') setSummaryCounts(results[11].value.data);
    setLastUpdated(new Date().toLocaleTimeString());
    setLoading(false);
  }, []);

  const fetchMikroTikData = useCallback(async (devId?: number) => {
    const did = devId !== undefined ? devId : selectedDeviceId;
    setMtLoading(true);
    const results = await Promise.allSettled([
      api.getMikroTikInterfaces(did),
      api.getMikroTikFirewallRules(mtChain || undefined, did),
      api.getMikroTikDhcpLeases(did),
      api.getMikroTikLogs(150, undefined, did),
      api.getMikroTikConnections(100, did),
      api.getMikroTikNatRules(did),
    ]);
    if (results[0].status === 'fulfilled') setMtInterfaces(results[0].value.data);
    if (results[1].status === 'fulfilled') setMtFirewallRules(results[1].value.data);
    if (results[2].status === 'fulfilled') setMtDhcpLeases(results[2].value.data);
    if (results[3].status === 'fulfilled') setMtLogs(results[3].value.data);
    if (results[4].status === 'fulfilled') setMtConnections(results[4].value.data);
    if (results[5].status === 'fulfilled') setMtNatRules(results[5].value.data);
    setMtLoading(false);
  }, [mtChain, selectedDeviceId]);

  const loadMtDevices = useCallback(async () => {
    try {
      const res = await api.listMikroTikDevices();
      setMtDevices(res.data);
    } catch {}
  }, []);

  useEffect(() => {
    const token = Cookies.get('sstb_token');
    if (!token) { router.push('/login'); return; }
    fetchCoreData();
    api.getMe().then((r) => setCurrentUser(r.data)).catch(() => {});
    const interval = setInterval(fetchCoreData, 30000);
    try {
      feedRef.current = api.createLiveFeed(
        (data) => {
          setWsConnected(true);
          if (data.type !== 'pong' && data.type !== 'connected') {
            setLiveFeed((prev) => [data, ...prev].slice(0, 50));
          }
        },
        () => setWsConnected(false),
      );
    } catch {}
    return () => { clearInterval(interval); feedRef.current?.close(); };
  }, [fetchCoreData, router]);

  useEffect(() => {
    if (tab === 'mikrotik') { loadMtDevices(); fetchMikroTikData(); }
  }, [tab, fetchMikroTikData, loadMtDevices]);

  useEffect(() => {
    if (tab === 'mikrotik') fetchMikroTikData();
  }, [mtChain]); // eslint-disable-line

  const handleScan = async () => {
    if (!scanIPVal.trim()) return;
    setScanLoading(true);
    setScanResult(null);
    try {
      const res = await api.scanIP(scanIPVal.trim(), false);
      setScanResult(res.data);
    } catch {}
    setScanLoading(false);
  };

  const handleBlock = async () => {
    if (!blockAddress.trim()) return;
    setBlockLoading(true);
    try {
      await api.blockIP(blockAddress, blockReason);
      setBlockModal(false); setBlockAddress(''); setBlockReason('');
      fetchCoreData();
    } catch {}
    setBlockLoading(false);
  };

  const handleUnblock = async (ip: string) => {
    if (!confirm(`Unblock ${ip}?`)) return;
    try { await api.unblockIP(ip); fetchCoreData(); } catch {}
  };

  const handleToggleFirewall = async (ruleId: string, currentDisabled: boolean) => {
    try { await api.toggleFirewallRule(ruleId, !currentDisabled); fetchMikroTikData(); } catch {}
  };

  const handleAddWhitelist = async () => {
    if (!wlAddress.trim()) return;
    setWlLoading(true);
    try {
      await api.addToWhitelist(wlAddress, wlReason);
      setWhitelistModal(false); setWlAddress(''); setWlReason('');
      fetchCoreData();
    } catch {}
    setWlLoading(false);
  };

  const handleSync = async () => {
    setSyncLoading(true);
    try { await api.syncFromMikroTik(); fetchCoreData(); } catch {}
    setSyncLoading(false);
  };

  const logout = () => { Cookies.remove('sstb_token'); router.push('/login'); };

  const filteredBlocklist = blocklist.filter((b) =>
    !searchFilter || b.address?.includes(searchFilter) || b.source?.includes(searchFilter));
  const filteredLogs = attackLogs.filter((l) =>
    !logFilter || l.source_ip?.includes(logFilter) || l.attack_type?.includes(logFilter));

  // Charts
  const chartDefaults = { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } };
  const gridColor = 'rgba(148,163,184,0.08)';

  const timelineChart = {
    labels: timeline.map((d) => d.date),
    datasets: [
      { label: 'Attacks', data: timeline.map((d) => d.attacks), backgroundColor: 'rgba(239,68,68,0.3)', borderColor: 'rgba(239,68,68,0.8)', borderWidth: 1 },
      { label: 'Blocked', data: timeline.map((d) => d.blocked), backgroundColor: 'rgba(6,182,212,0.3)', borderColor: 'rgba(6,182,212,0.8)', borderWidth: 1 },
    ],
  };

  const heatmapChart = {
    labels: hourlyHeatmap.map((h) => `${h.hour}:00`),
    datasets: [{ label: 'Attacks', data: hourlyHeatmap.map((h) => h.count), borderColor: 'rgba(251,191,36,0.8)', backgroundColor: 'rgba(251,191,36,0.1)', fill: true, tension: 0.4 }],
  };

  const attackTypeChart = protocolStats?.attack_types?.length ? {
    labels: protocolStats.attack_types.map((a: any) => a.type),
    datasets: [{ data: protocolStats.attack_types.map((a: any) => a.count), backgroundColor: ['#ef4444','#f97316','#eab308','#22c55e','#06b6d4','#8b5cf6','#ec4899','#f59e0b','#10b981','#3b82f6'] }],
  } : null;

  const navTabs: { id: Tab; label: string; icon: string; badge?: number }[] = [
    { id: 'overview', label: 'Overview', icon: '📊' },
    { id: 'blocklist', label: 'IP Blocklist', icon: '🚫', badge: blocklist.length },
    { id: 'logs', label: 'Attack Logs', icon: '📋', badge: attackLogs.filter((l) => l.status === 'pending').length },
    { id: 'cve', label: 'CVE Alerts', icon: '🔴', badge: cveAlerts.filter((c: any) => c.is_kev).length },
    { id: 'mikrotik', label: 'MikroTik', icon: '🔧' },
    { id: 'geo', label: 'Geo Analytics', icon: '🌍' },
    { id: 'whitelist', label: 'Whitelist', icon: '✅', badge: whitelist.length },
    { id: 'settings', label: 'Settings', icon: '⚙️' },
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex">
      {/* Sidebar */}
      <aside className="w-64 min-h-screen bg-slate-900 border-r border-slate-800 flex flex-col shrink-0">
        <div className="p-4 border-b border-slate-800">
          <div className="text-cyan-400 font-black text-xl tracking-tight">⚡ SSTB</div>
          <div className="text-slate-500 text-xs">Smart Security & Threat Blocker</div>
          <div className="text-slate-600 text-[10px] mt-0.5">v2.0 — Advanced</div>
        </div>
        <div className="p-3 border-b border-slate-800 space-y-1">
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${stats?.mikrotik_connected ? 'bg-green-400 animate-pulse' : 'bg-red-500'}`} />
            <span className="text-xs text-slate-300">{stats?.mikrotik_connected ? 'Router Online' : 'Router Offline'}</span>
          </div>
          <div className="text-[10px] text-slate-600 font-mono pl-4">{mikrotikStatus?.data?.['board-name'] || '—'}</div>
          {wsConnected && (
            <div className="flex items-center gap-1">
              <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
              <span className="text-[10px] text-cyan-600">Live feed active</span>
            </div>
          )}
        </div>
        <nav className="flex-1 p-2 space-y-0.5 overflow-y-auto">
          {navTabs.map((t) => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition-colors ${
                tab === t.id ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}>
              <span>{t.icon} {t.label}</span>
              {t.badge != null && t.badge > 0 && (
                <span className="bg-cyan-500/20 text-cyan-400 text-[10px] font-bold px-1.5 py-0.5 rounded-full border border-cyan-500/30">{t.badge}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="p-3 border-t border-slate-800 space-y-2">
          <button onClick={fetchCoreData} className="w-full text-xs py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors">🔄 Refresh</button>
          <button onClick={logout} className="w-full text-xs py-2 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 transition-colors">⏏ Logout</button>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-hidden flex flex-col">
        <div className="bg-slate-900 border-b border-slate-800 px-6 py-3 flex items-center justify-between shrink-0">
          <div>
            <h1 className="text-lg font-semibold text-slate-100">{navTabs.find((t) => t.id === tab)?.icon} {tab === 'mikrotik' ? 'MikroTik Monitor' : tab.replace('-', ' ').replace(/\b\w/g, (c) => c.toUpperCase())}</h1>
            {lastUpdated && <div className="text-xs text-slate-500">Updated {lastUpdated}</div>}
          </div>
          <div className="flex items-center gap-2">
            {stats?.auto_block_enabled && <span className="text-xs bg-green-500/10 border border-green-500/30 text-green-400 px-2 py-1 rounded-full">⚡ Auto-Block ON</span>}
            {summaryCounts?.kev_count > 0 && <span className="text-xs bg-red-500/10 border border-red-500/30 text-red-400 px-2 py-1 rounded-full">🚨 {summaryCounts.kev_count} KEV</span>}
            <button
              onClick={() => setShowProfile(true)}
              title="Profile & 2FA"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 transition-colors"
            >
              <span className="w-6 h-6 rounded-full bg-cyan-500/20 border border-cyan-500/40 text-cyan-400 text-xs flex items-center justify-center font-bold">
                {currentUser?.username?.[0]?.toUpperCase() ?? '?'}
              </span>
              <span className="text-xs text-slate-300">{currentUser?.username ?? '...'}</span>
              {currentUser?.totp_enabled && (
                <span className="text-[10px] bg-green-500/20 text-green-400 px-1 rounded border border-green-500/30">2FA</span>
              )}
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-6">
          {loading && <div className="flex items-center justify-center h-64"><div className="text-cyan-400 animate-pulse">Loading SSTB...</div></div>}

          {/* OVERVIEW */}
          {!loading && tab === 'overview' && (
            <div className="space-y-6">
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <StatCard title="Total Blocked" value={stats?.total_blocked ?? 0} subtitle={`+${stats?.blocked_today ?? 0} today`} color="red" icon="🚫" />
                <StatCard title="Threats Detected" value={stats?.threats_detected ?? 0} subtitle={`+${stats?.threats_today ?? 0} today`} color="orange" icon="⚠" />
                <StatCard title="CVE Alerts" value={stats?.active_cve_alerts ?? 0} subtitle={`${stats?.critical_cve_count ?? 0} critical`} color="yellow" icon="🔴" />
                <StatCard title="Router" value={stats?.mikrotik_connected ? 'ONLINE' : 'OFFLINE'} subtitle={mikrotikStatus?.data?.version || '—'} color={stats?.mikrotik_connected ? 'green' : 'red'} icon="🔧" />
              </div>
              {summaryCounts && (
                <div className="grid grid-cols-3 lg:grid-cols-6 gap-3">
                  <StatCard title="Unique Attackers" value={summaryCounts.unique_attackers} color="purple" icon="👤" />
                  <StatCard title="Whitelisted" value={summaryCounts.total_whitelist} color="green" icon="✅" />
                  <StatCard title="KEV Alerts" value={summaryCounts.kev_count} color="red" icon="💥" />
                  <StatCard title="Tor Blocked" value={summaryCounts.tor_exits_blocked} color="purple" icon="🧅" />
                  <StatCard title="Total CVEs" value={summaryCounts.total_cve} color="cyan" icon="📦" />
                  <StatCard title="Active Blocks" value={summaryCounts.total_blocked} color="orange" icon="📋" />
                </div>
              )}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-4">
                  <div className="text-sm font-semibold text-slate-300 mb-4">📈 Attack Timeline (14 days)</div>
                  <div className="h-48">
                    <Bar data={timelineChart} options={{
                      ...chartDefaults,
                      plugins: { legend: { display: true, labels: { color: '#94a3b8', boxWidth: 12 } } },
                      scales: {
                        x: { ticks: { color: '#64748b', font: { size: 9 } }, grid: { color: gridColor } },
                        y: { ticks: { color: '#64748b' }, grid: { color: gridColor } },
                      },
                    }} />
                  </div>
                </div>
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                  <div className="text-sm font-semibold text-slate-300 mb-4">🎯 Attack Types</div>
                  {attackTypeChart ? (
                    <div className="h-48">
                      <Doughnut data={attackTypeChart} options={{
                        ...chartDefaults,
                        plugins: { legend: { display: true, position: 'bottom', labels: { color: '#94a3b8', boxWidth: 10, font: { size: 10 } } } },
                      }} />
                    </div>
                  ) : (
                    <div className="h-48 flex items-center justify-center text-slate-600 text-sm">No data yet</div>
                  )}
                </div>
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                  <div className="text-sm font-semibold text-slate-300 mb-4">🕐 Hourly Heatmap</div>
                  <div className="h-40">
                    <Line data={heatmapChart} options={{
                      ...chartDefaults,
                      scales: {
                        x: { ticks: { color: '#64748b', font: { size: 9 }, maxTicksLimit: 12 }, grid: { color: gridColor } },
                        y: { ticks: { color: '#64748b' }, grid: { color: gridColor } },
                      },
                    }} />
                  </div>
                </div>
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                  <div className="text-sm font-semibold text-slate-300 mb-3">🔝 Top Attackers</div>
                  <div className="space-y-2">
                    {topAttackers.slice(0, 6).map((a) => (
                      <div key={a.ip} className="flex items-center gap-2">
                        <span className="text-lg shrink-0">{api.countryFlagEmoji(a.country_code)}</span>
                        <span className="font-mono text-xs text-cyan-400 w-28 shrink-0">{a.ip}</span>
                        <div className="flex-1 bg-slate-800 rounded-full h-1.5">
                          <div className="bg-red-500 h-1.5 rounded-full" style={{ width: `${Math.min((a.count / (topAttackers[0]?.count || 1)) * 100, 100)}%` }} />
                        </div>
                        <span className="text-xs text-slate-400 w-8 text-right shrink-0">{a.count}</span>
                        <ThreatScoreBadge score={a.max_score} />
                      </div>
                    ))}
                    {topAttackers.length === 0 && <div className="text-slate-600 text-sm text-center py-4">No attackers recorded yet</div>}
                  </div>
                </div>
              </div>
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <div className="text-sm font-semibold text-slate-300 mb-3">🕐 Recent Attack Logs</div>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="text-slate-500 border-b border-slate-800">
                        <th className="text-left pb-2 pr-3">IP</th><th className="text-left pb-2 pr-3">Type</th>
                        <th className="text-left pb-2 pr-3">Port</th><th className="text-left pb-2 pr-3">Country</th>
                        <th className="text-left pb-2 pr-3">Score</th><th className="text-left pb-2">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {attackLogs.slice(0, 8).map((log) => (
                        <tr key={log.id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                          <td className="py-2 pr-3 font-mono text-cyan-400">{log.source_ip}</td>
                          <td className="pr-3 text-slate-300">{log.attack_type || '—'}</td>
                          <td className="pr-3 text-slate-400">{log.target_port || '—'}</td>
                          <td className="pr-3">{log.country_code ? <span>{api.countryFlagEmoji(log.country_code)} {log.country_code}</span> : <span className="text-slate-600">—</span>}</td>
                          <td className="pr-3"><ThreatScoreBadge score={log.threat_score} /></td>
                          <td><span className={`px-1.5 py-0.5 rounded text-[10px] ${log.status === 'blocked' ? 'bg-red-500/20 text-red-400' : log.status === 'analyzing' ? 'bg-yellow-500/20 text-yellow-400' : 'bg-slate-700 text-slate-400'}`}>{log.status}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
              {liveFeed.length > 0 && (
                <div className="bg-slate-900 border border-cyan-500/20 rounded-xl p-4">
                  <div className="text-sm font-semibold text-cyan-400 mb-3">⚡ Live Feed ({liveFeed.length})</div>
                  <div className="max-h-36 overflow-y-auto space-y-0.5">
                    {liveFeed.map((e, i) => (
                      <div key={i} className="flex items-center gap-2 text-xs py-1 border-b border-slate-800/40">
                        <span className="text-slate-600 shrink-0">{new Date().toLocaleTimeString()}</span>
                        <span className="text-cyan-400 font-mono shrink-0">{e.ip || '—'}</span>
                        <span className="text-slate-400 truncate">{e.message || e.type}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* BLOCKLIST */}
          {!loading && tab === 'blocklist' && (
            <div className="space-y-4">
              <div className="flex flex-wrap gap-3">
                <input value={searchFilter} onChange={(e) => setSearchFilter(e.target.value)} placeholder="Search IP, source..."
                  className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 flex-1 min-w-48" />
                <button onClick={() => setBlockModal(true)} className="bg-red-500 hover:bg-red-600 text-white text-sm px-4 py-2 rounded-lg font-medium transition-colors">🚫 Block IP</button>
                <button onClick={handleSync} disabled={syncLoading} className="bg-cyan-500 hover:bg-cyan-600 text-white text-sm px-4 py-2 rounded-lg font-medium transition-colors disabled:opacity-50">{syncLoading ? '⟳ Syncing...' : '🔄 Sync MikroTik'}</button>
              </div>
              {/* Threat Intel Scan */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <div className="text-sm font-semibold text-slate-300 mb-3">🔬 Threat Intelligence Scan</div>
                <div className="flex gap-3">
                  <input value={scanIPVal} onChange={(e) => setScanIPVal(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleScan()}
                    placeholder="Enter IP to scan (e.g. 1.2.3.4)"
                    className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500" />
                  <button onClick={handleScan} disabled={scanLoading || !scanIPVal.trim()}
                    className="bg-cyan-500 hover:bg-cyan-600 text-white text-sm px-5 py-2 rounded-lg font-medium disabled:opacity-50 transition-colors">
                    {scanLoading ? '⟳ Scanning...' : '🔍 Scan'}
                  </button>
                </div>
                {scanLoading && <div className="mt-2 text-xs text-slate-500 animate-pulse">Querying VirusTotal · AlienVault · ThreatFox · GeoIP...</div>}
              </div>
              {/* Blocklist table */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                <div className="text-xs text-slate-500 px-4 py-2 border-b border-slate-800">{filteredBlocklist.length} blocked IPs</div>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="text-slate-500 border-b border-slate-800">
                        <th className="text-left px-4 py-2">IP Address</th>
                        <th className="text-left px-2 py-2">Score</th>
                        <th className="text-left px-2 py-2">Country</th>
                        <th className="text-left px-2 py-2">ISP</th>
                        <th className="text-left px-2 py-2">Categories</th>
                        <th className="text-left px-2 py-2">Source</th>
                        <th className="text-left px-2 py-2">MikroTik</th>
                        <th className="text-left px-2 py-2">Date</th>
                        <th className="text-left px-2 py-2">Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredBlocklist.map((b) => (
                        <tr key={b.id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                          <td className="px-4 py-2">
                            <div className="flex items-center gap-1">
                              <span className="font-mono text-cyan-400">{b.address}</span>
                              {b.is_tor && <span title="Tor Exit Node">🧅</span>}
                              {b.is_proxy && <span title="Proxy/VPN">🌐</span>}
                            </div>
                          </td>
                          <td className="px-2 py-2"><ThreatScoreBadge score={b.threat_score} /></td>
                          <td className="px-2 py-2">{b.country_code ? <span title={b.country}>{api.countryFlagEmoji(b.country_code)} {b.country_code}</span> : <span className="text-slate-600">—</span>}</td>
                          <td className="px-2 py-2 max-w-24 truncate text-slate-400" title={b.isp}>{b.isp || '—'}</td>
                          <td className="px-2 py-2">
                            <div className="flex flex-wrap gap-1">
                              {b.threat_categories?.split(',').filter(Boolean).slice(0, 2).map((c: string) => <CategoryBadge key={c} cat={c.trim()} />)}
                            </div>
                          </td>
                          <td className="px-2 py-2"><span className="px-1.5 py-0.5 rounded bg-slate-700 text-slate-300 text-[10px]">{b.source}</span></td>
                          <td className="px-2 py-2"><span className={`text-[10px] ${b.synced_to_mikrotik ? 'text-green-400' : 'text-yellow-400'}`}>{b.synced_to_mikrotik ? '✓ Synced' : '⚠ Pending'}</span></td>
                          <td className="px-2 py-2 text-slate-500">{new Date(b.blocked_at).toLocaleDateString()}</td>
                          <td className="px-2 py-2">
                            <button onClick={() => handleUnblock(b.address)} className="text-red-400 hover:text-red-300 text-[10px] border border-red-500/30 rounded px-1.5 py-0.5 hover:bg-red-500/10 transition-colors">Unblock</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {filteredBlocklist.length === 0 && <div className="text-center py-8 text-slate-600">No blocked IPs</div>}
                </div>
              </div>
            </div>
          )}

          {/* ATTACK LOGS */}
          {!loading && tab === 'logs' && (
            <div className="space-y-4">
              <div className="flex flex-wrap gap-3">
                <input value={logFilter} onChange={(e) => setLogFilter(e.target.value)} placeholder="Filter by IP or attack type..."
                  className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 flex-1 min-w-48" />
                <div className="text-xs text-slate-500 self-center">{filteredLogs.length} events</div>
              </div>
              <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="text-slate-500 border-b border-slate-800">
                        <th className="text-left px-4 py-2">Source IP</th>
                        <th className="text-left px-2 py-2">Attack Type</th>
                        <th className="text-left px-2 py-2">Port/Proto</th>
                        <th className="text-left px-2 py-2">Country</th>
                        <th className="text-left px-2 py-2">ISP</th>
                        <th className="text-left px-2 py-2">Categories</th>
                        <th className="text-left px-2 py-2">Score</th>
                        <th className="text-left px-2 py-2">Status</th>
                        <th className="text-left px-2 py-2">Time</th>
                        <th className="text-left px-2 py-2">Scan</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredLogs.map((log) => (
                        <tr key={log.id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                          <td className="px-4 py-2 font-mono text-cyan-400">{log.source_ip}</td>
                          <td className="px-2 py-2 text-slate-300">{log.attack_type || '—'}</td>
                          <td className="px-2 py-2 text-slate-400">{log.target_port || ''}{log.protocol ? `/${log.protocol}` : ''}</td>
                          <td className="px-2 py-2">{log.country_code ? <span title={log.country}>{api.countryFlagEmoji(log.country_code)} {log.country_code}</span> : <span className="text-slate-600">—</span>}</td>
                          <td className="px-2 py-2 max-w-24 truncate text-slate-500" title={log.isp}>{log.isp || '—'}</td>
                          <td className="px-2 py-2">
                            <div className="flex gap-1 flex-wrap">
                              {log.threat_categories?.split(',').filter(Boolean).slice(0, 2).map((c: string) => <CategoryBadge key={c} cat={c.trim()} />)}
                            </div>
                          </td>
                          <td className="px-2 py-2"><ThreatScoreBadge score={log.threat_score} /></td>
                          <td className="px-2 py-2">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] ${log.status === 'blocked' ? 'bg-red-500/20 text-red-400' : log.status === 'analyzing' ? 'bg-yellow-500/20 text-yellow-400' : log.status === 'whitelisted' ? 'bg-green-500/20 text-green-400' : 'bg-slate-700 text-slate-400'}`}>{log.status}</span>
                          </td>
                          <td className="px-2 py-2 text-slate-500 whitespace-nowrap">{new Date(log.detected_at).toLocaleString()}</td>
                          <td className="px-2 py-2">
                            <button onClick={() => { setScanIPVal(log.source_ip); setTab('blocklist'); }}
                              className="text-cyan-400 hover:text-cyan-300 text-[10px] border border-cyan-500/30 rounded px-1.5 py-0.5 hover:bg-cyan-500/10 transition-colors">Scan</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {filteredLogs.length === 0 && <div className="text-center py-8 text-slate-600">No logs found</div>}
                </div>
              </div>
            </div>
          )}

          {/* CVE ALERTS */}
          {!loading && tab === 'cve' && (
            <div className="space-y-3">
              {cveAlerts.length === 0 ? (
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center">
                  <div className="text-4xl mb-3">🔍</div>
                  <div className="text-slate-400">No CVE data yet.</div>
                  <div className="text-slate-600 text-xs mt-1">Worker syncs MikroTik CVEs daily at 03:00 UTC</div>
                </div>
              ) : cveAlerts.map((cve: any) => (
                <div key={cve.id} className="bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl p-4 transition-colors">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2 flex-wrap">
                        <span className="font-mono text-cyan-400 font-bold text-sm">{cve.cve_id}</span>
                        <span className={`px-2 py-0.5 rounded text-xs font-bold border ${cve.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-300 border-red-500/40' : cve.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-300 border-orange-500/40' : cve.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40' : 'bg-green-500/20 text-green-300 border-green-500/40'}`}>{cve.severity}</span>
                        {cve.is_kev && <span className="px-2 py-0.5 rounded text-xs font-bold bg-red-600/20 text-red-200 border border-red-600/40 animate-pulse">⚠ KEV</span>}
                        {cve.epss_score > 0 && <span className="px-2 py-0.5 rounded text-xs bg-orange-500/10 text-orange-300 border border-orange-500/30">EPSS {(cve.epss_score * 100).toFixed(1)}%</span>}
                      </div>
                      <p className="text-slate-400 text-xs line-clamp-2">{cve.description}</p>
                      {cve.affected_product && <div className="text-slate-500 text-xs mt-1">📦 {cve.affected_product}</div>}
                    </div>
                    <div className="text-right shrink-0">
                      <div className={`text-2xl font-black ${cve.cvss_score >= 9 ? 'text-red-400' : cve.cvss_score >= 7 ? 'text-orange-400' : cve.cvss_score >= 4 ? 'text-yellow-400' : 'text-green-400'}`}>{cve.cvss_score?.toFixed(1)}</div>
                      <div className="text-slate-600 text-[10px]">CVSS</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* MIKROTIK MONITOR */}
          {!loading && tab === 'mikrotik' && (
            <div className="space-y-4">
              {/* Device Selector */}
              {mtDevices.length > 0 && (
                <div className="flex items-center gap-3 bg-slate-900/60 border border-slate-700 rounded-xl px-4 py-2.5">
                  <span className="text-slate-400 text-xs whitespace-nowrap">📡 Device:</span>
                  <div className="flex gap-2 flex-wrap">
                    <button
                      onClick={() => { setSelectedDeviceId(undefined); fetchMikroTikData(undefined); }}
                      className={`px-3 py-1 rounded-lg text-xs font-medium transition-colors ${selectedDeviceId === undefined ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'}`}
                    >
                      ★ Default
                    </button>
                    {mtDevices.map((dev: any) => (
                      <button
                        key={dev.id}
                        onClick={() => { setSelectedDeviceId(dev.id); fetchMikroTikData(dev.id); }}
                        className={`px-3 py-1 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5 ${selectedDeviceId === dev.id ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'}`}
                      >
                        <span className={`w-1.5 h-1.5 rounded-full ${dev.last_status === 'online' ? 'bg-green-400' : dev.last_status === 'offline' ? 'bg-red-400' : 'bg-slate-500'}`} />
                        {dev.router_identity || dev.name}
                        <span className="text-slate-500 font-mono text-[10px]">{dev.host}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
              {mikrotikStatus?.data && (
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                  {[
                    { label: 'Board', value: mikrotikStatus.data['board-name'] },
                    { label: 'Version', value: mikrotikStatus.data.version },
                    { label: 'Uptime', value: mikrotikStatus.data.uptime },
                    { label: 'CPU Load', value: `${mikrotikStatus.data['cpu-load']}%` },
                    { label: 'Free RAM', value: api.formatBytes(mikrotikStatus.data['free-memory']) },
                    { label: 'Architecture', value: mikrotikStatus.data['architecture-name'] },
                  ].map(({ label, value }) => (
                    <div key={label} className="text-center">
                      <div className="text-slate-500 text-[10px] uppercase tracking-wider">{label}</div>
                      <div className="text-slate-200 text-sm font-medium mt-0.5 truncate" title={String(value)}>{value || '—'}</div>
                    </div>
                  ))}
                </div>
              )}
              <div className="flex gap-1 flex-wrap items-center">
                {[
                  { id: 'interfaces', label: '🔌 Interfaces' },
                  { id: 'firewall', label: '🛡 Firewall' },
                  { id: 'nat', label: '🔄 NAT' },
                  { id: 'dhcp', label: '📡 DHCP' },
                  { id: 'connections', label: '🔗 Connections' },
                  { id: 'logs', label: '📋 System Logs' },
                ].map((t) => (
                  <button key={t.id} onClick={() => setMtTab(t.id as MikroTikTab)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${mtTab === t.id ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'bg-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-700'}`}>
                    {t.label}
                  </button>
                ))}
                <button onClick={() => fetchMikroTikData()} disabled={mtLoading} className="ml-auto px-3 py-1.5 rounded-lg text-xs bg-slate-800 text-slate-400 hover:bg-slate-700 transition-colors disabled:opacity-50">
                  {mtLoading ? '⟳' : '🔄'} Refresh
                </button>
              </div>

              {/* Interfaces */}
              {mtTab === 'interfaces' && (
                <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead><tr className="text-slate-500 border-b border-slate-800">
                        <th className="text-left px-4 py-2">Name</th><th className="text-left px-2 py-2">Type</th>
                        <th className="text-left px-2 py-2">MAC</th><th className="text-left px-2 py-2">Status</th>
                        <th className="text-right px-2 py-2">RX</th><th className="text-right px-2 py-2">TX</th>
                        <th className="text-left px-2 py-2">Comment</th>
                      </tr></thead>
                      <tbody>
                        {mtInterfaces.map((iface: any, i) => (
                          <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                            <td className="px-4 py-2 font-mono text-slate-200">{iface.name}</td>
                            <td className="px-2 py-2 text-slate-400">{iface.type}</td>
                            <td className="px-2 py-2 font-mono text-slate-500 text-[10px]">{iface['mac-address'] || '—'}</td>
                            <td className="px-2 py-2"><span className={`text-[10px] px-1.5 py-0.5 rounded ${iface.disabled ? 'bg-slate-700 text-slate-500' : iface.running ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'}`}>{iface.disabled ? 'disabled' : iface.running ? 'running' : 'down'}</span></td>
                            <td className="px-2 py-2 text-right text-green-400 font-mono">{api.formatBytes(parseInt(iface['rx-byte'] || '0'))}</td>
                            <td className="px-2 py-2 text-right text-blue-400 font-mono">{api.formatBytes(parseInt(iface['tx-byte'] || '0'))}</td>
                            <td className="px-2 py-2 text-slate-600">{iface.comment || ''}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {mtInterfaces.length === 0 && !mtLoading && <div className="text-center py-8 text-slate-600">No interface data — check MikroTik connection</div>}
                  </div>
                </div>
              )}

              {/* Firewall Rules */}
              {mtTab === 'firewall' && (
                <div className="space-y-3">
                  <div className="flex gap-2">
                    {['', 'input', 'forward', 'output'].map((c) => (
                      <button key={c} onClick={() => setMtChain(c)}
                        className={`px-3 py-1 rounded text-xs transition-colors ${mtChain === c ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'}`}>
                        {c || 'All Chains'}
                      </button>
                    ))}
                  </div>
                  <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs">
                        <thead><tr className="text-slate-500 border-b border-slate-800">
                          <th className="text-left px-4 py-2">#</th><th className="text-left px-2 py-2">Chain</th>
                          <th className="text-left px-2 py-2">Action</th><th className="text-left px-2 py-2">Src Address/List</th>
                          <th className="text-left px-2 py-2">Port</th><th className="text-left px-2 py-2">Proto</th>
                          <th className="text-right px-2 py-2">Packets</th><th className="text-left px-2 py-2">Comment</th>
                          <th className="text-left px-2 py-2">Toggle</th>
                        </tr></thead>
                        <tbody>
                          {mtFirewallRules.map((rule: any, i) => (
                            <tr key={i} className={`border-b border-slate-800/50 hover:bg-slate-800/30 ${rule.disabled === 'true' ? 'opacity-40' : ''}`}>
                              <td className="px-4 py-2 text-slate-500">{i + 1}</td>
                              <td className="px-2 py-2"><span className={`px-1.5 py-0.5 rounded text-[10px] ${rule.chain === 'input' ? 'bg-blue-500/20 text-blue-400' : rule.chain === 'forward' ? 'bg-purple-500/20 text-purple-400' : 'bg-slate-700 text-slate-400'}`}>{rule.chain}</span></td>
                              <td className="px-2 py-2"><span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${rule.action === 'drop' || rule.action === 'reject' ? 'bg-red-500/20 text-red-400' : rule.action === 'accept' ? 'bg-green-500/20 text-green-400' : 'bg-slate-700 text-slate-300'}`}>{rule.action}</span></td>
                              <td className="px-2 py-2 font-mono text-slate-300 text-[10px]">{rule['src-address'] || rule['src-address-list'] || '—'}</td>
                              <td className="px-2 py-2 text-slate-400">{rule['dst-port'] || '—'}</td>
                              <td className="px-2 py-2 text-slate-500">{rule.protocol || '—'}</td>
                              <td className="px-2 py-2 text-right font-mono text-slate-400">{parseInt(rule.packets || '0').toLocaleString()}</td>
                              <td className="px-2 py-2 text-slate-600 max-w-32 truncate" title={rule.comment}>{rule.comment || ''}</td>
                              <td className="px-2 py-2">
                                {rule['.id'] && <button onClick={() => handleToggleFirewall(rule['.id'], rule.disabled === 'true')}
                                  className={`text-[10px] border rounded px-1.5 py-0.5 transition-colors ${rule.disabled === 'true' ? 'border-green-500/30 text-green-400 hover:bg-green-500/10' : 'border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/10'}`}>
                                  {rule.disabled === 'true' ? 'Enable' : 'Disable'}
                                </button>}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                      {mtFirewallRules.length === 0 && !mtLoading && <div className="text-center py-8 text-slate-600">No firewall rules</div>}
                    </div>
                  </div>
                </div>
              )}

              {/* NAT */}
              {mtTab === 'nat' && (
                <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead><tr className="text-slate-500 border-b border-slate-800">
                        <th className="text-left px-4 py-2">#</th><th className="text-left px-2 py-2">Chain</th>
                        <th className="text-left px-2 py-2">Action</th><th className="text-left px-2 py-2">Out Interface</th>
                        <th className="text-left px-2 py-2">Dst Address</th><th className="text-left px-2 py-2">To Address</th>
                        <th className="text-left px-2 py-2">Comment</th>
                      </tr></thead>
                      <tbody>
                        {mtNatRules.map((rule: any, i) => (
                          <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                            <td className="px-4 py-2 text-slate-500">{i + 1}</td>
                            <td className="px-2 py-2 text-purple-400">{rule.chain}</td>
                            <td className="px-2 py-2 text-yellow-400">{rule.action}</td>
                            <td className="px-2 py-2 text-slate-300">{rule['out-interface'] || '—'}</td>
                            <td className="px-2 py-2 font-mono text-slate-400">{rule['dst-address'] || '—'}</td>
                            <td className="px-2 py-2 font-mono text-cyan-400">{rule['to-addresses'] || '—'}</td>
                            <td className="px-2 py-2 text-slate-600">{rule.comment || ''}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {mtNatRules.length === 0 && !mtLoading && <div className="text-center py-8 text-slate-600">No NAT rules</div>}
                  </div>
                </div>
              )}

              {/* DHCP */}
              {mtTab === 'dhcp' && (
                <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                  <div className="px-4 py-2 border-b border-slate-800 text-xs text-slate-500">{mtDhcpLeases.length} leases</div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead><tr className="text-slate-500 border-b border-slate-800">
                        <th className="text-left px-4 py-2">IP Address</th><th className="text-left px-2 py-2">MAC</th>
                        <th className="text-left px-2 py-2">Hostname</th><th className="text-left px-2 py-2">Status</th>
                        <th className="text-left px-2 py-2">Expires</th><th className="text-left px-2 py-2">Block</th>
                      </tr></thead>
                      <tbody>
                        {mtDhcpLeases.map((lease: any, i) => (
                          <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                            <td className="px-4 py-2 font-mono text-cyan-400">{lease.address}</td>
                            <td className="px-2 py-2 font-mono text-slate-400 text-[10px]">{lease['mac-address'] || '—'}</td>
                            <td className="px-2 py-2 text-slate-300">{lease['host-name'] || '—'}</td>
                            <td className="px-2 py-2"><span className={`text-[10px] px-1.5 py-0.5 rounded ${lease.status === 'bound' ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'}`}>{lease.status}</span></td>
                            <td className="px-2 py-2 text-slate-500">{lease['expires-after'] || '—'}</td>
                            <td className="px-2 py-2">
                              <button onClick={() => { setBlockAddress(lease.address); setBlockModal(true); }}
                                className="text-red-400 text-[10px] border border-red-500/30 rounded px-1.5 py-0.5 hover:bg-red-500/10 transition-colors">Block</button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {mtDhcpLeases.length === 0 && !mtLoading && <div className="text-center py-8 text-slate-600">No DHCP leases</div>}
                  </div>
                </div>
              )}

              {/* Connections */}
              {mtTab === 'connections' && (
                <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                  <div className="px-4 py-2 border-b border-slate-800 text-xs text-slate-500">{mtConnections.length} active connections</div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead><tr className="text-slate-500 border-b border-slate-800">
                        <th className="text-left px-4 py-2">Source</th><th className="text-left px-2 py-2">Destination</th>
                        <th className="text-left px-2 py-2">Protocol</th><th className="text-left px-2 py-2">State</th>
                      </tr></thead>
                      <tbody>
                        {mtConnections.map((conn: any, i) => (
                          <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                            <td className="px-4 py-1.5 font-mono text-cyan-400">{conn['src-address'] || '—'}</td>
                            <td className="px-2 py-1.5 font-mono text-slate-300">{conn['dst-address'] || '—'}</td>
                            <td className="px-2 py-1.5 text-slate-400">{conn.protocol || '—'}</td>
                            <td className="px-2 py-1.5"><span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-700 text-slate-300">{conn['tcp-state'] || conn.state || '—'}</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {mtConnections.length === 0 && !mtLoading && <div className="text-center py-8 text-slate-600">No active connections</div>}
                  </div>
                </div>
              )}

              {/* System Logs */}
              {mtTab === 'logs' && (
                <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                  <div className="px-4 py-2 border-b border-slate-800 text-xs text-slate-500 flex items-center justify-between">
                    <span>{mtLogs.length} entries</span>
                    <div className="flex gap-1">
                      {['', 'firewall', 'system', 'info', 'error'].map((topic) => (
                        <button key={topic}
                          onClick={() => api.getMikroTikLogs(150, topic || undefined).then((r) => setMtLogs(r.data))}
                          className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 transition-colors">{topic || 'All'}</button>
                      ))}
                    </div>
                  </div>
                  <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
                    <table className="w-full text-xs">
                      <thead className="sticky top-0 bg-slate-900"><tr className="text-slate-500 border-b border-slate-800">
                        <th className="text-left px-4 py-2">Time</th><th className="text-left px-2 py-2">Topics</th><th className="text-left px-2 py-2">Message</th>
                      </tr></thead>
                      <tbody>
                        {[...mtLogs].reverse().map((log: any, i) => (
                          <tr key={i} className="border-b border-slate-800/40 hover:bg-slate-800/30">
                            <td className="px-4 py-1.5 text-slate-500 font-mono whitespace-nowrap">{log.time}</td>
                            <td className="px-2 py-1.5"><span className={`text-[10px] px-1.5 py-0.5 rounded ${log.topics?.includes('error') ? 'bg-red-500/20 text-red-400' : log.topics?.includes('warning') ? 'bg-yellow-500/20 text-yellow-400' : log.topics?.includes('firewall') ? 'bg-orange-500/20 text-orange-400' : 'bg-slate-700 text-slate-400'}`}>{log.topics}</span></td>
                            <td className="px-2 py-1.5 text-slate-300">{log.message}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {mtLogs.length === 0 && !mtLoading && <div className="text-center py-8 text-slate-600">No log entries</div>}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* GEO ANALYTICS */}
          {!loading && tab === 'geo' && (
            <div className="space-y-6">
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <div className="text-sm font-semibold text-slate-300 mb-4">🌍 Top Attacking Countries</div>
                {geoStats.length === 0 ? (
                  <div className="text-center py-8 text-slate-600">No geographic data yet. IPs are geolocated on detection.</div>
                ) : (
                  <div className="space-y-2">
                    {geoStats.map((g) => {
                      const maxCount = geoStats[0]?.attack_count || 1;
                      return (
                        <div key={g.country_code} className="flex items-center gap-3">
                          <span className="text-2xl w-8 shrink-0">{api.countryFlagEmoji(g.country_code)}</span>
                          <div className="w-32 shrink-0">
                            <div className="text-sm text-slate-200 font-medium truncate">{g.country}</div>
                            <div className="text-[10px] text-slate-500">{g.unique_ips} unique IPs</div>
                          </div>
                          <div className="flex-1 bg-slate-800 rounded-full h-2">
                            <div className={`h-2 rounded-full ${g.avg_score >= 7 ? 'bg-red-500' : g.avg_score >= 4 ? 'bg-orange-500' : 'bg-cyan-500'}`}
                              style={{ width: `${(g.attack_count / maxCount) * 100}%` }} />
                          </div>
                          <span className="text-sm text-slate-300 w-14 text-right font-mono">{g.attack_count.toLocaleString()}</span>
                          <ThreatScoreBadge score={g.avg_score} />
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {protocolStats && (
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                    <div className="text-sm font-semibold text-slate-300 mb-4">🔌 Protocol Breakdown</div>
                    <div className="space-y-2">
                      {protocolStats.protocols?.map((p: any) => (
                        <div key={p.protocol} className="flex items-center gap-2">
                          <span className="text-slate-400 text-xs w-16">{p.protocol}</span>
                          <div className="flex-1 bg-slate-800 rounded-full h-1.5">
                            <div className="bg-cyan-500 h-1.5 rounded-full" style={{ width: `${(p.count / (protocolStats.protocols[0]?.count || 1)) * 100}%` }} />
                          </div>
                          <span className="text-slate-300 text-xs w-8 text-right">{p.count}</span>
                        </div>
                      ))}
                    </div>
                    <div className="mt-4 text-xs font-semibold text-slate-400">Top Target Ports</div>
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {protocolStats.target_ports?.map((p: any) => (
                        <span key={p.port} className="px-2 py-1 rounded bg-slate-800 text-slate-300 text-xs font-mono">:{p.port} <span className="text-slate-500">({p.count})</span></span>
                      ))}
                    </div>
                  </div>
                )}
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                  <div className="text-sm font-semibold text-slate-300 mb-4">🕐 Attacks by Hour (UTC, 30 days)</div>
                  <div className="h-48">
                    <Bar data={{
                      labels: hourlyHeatmap.map((h) => `${h.hour}h`),
                      datasets: [{ data: hourlyHeatmap.map((h) => h.count), backgroundColor: hourlyHeatmap.map((h) => h.count > (Math.max(...hourlyHeatmap.map((x) => x.count)) * 0.7) ? 'rgba(239,68,68,0.7)' : 'rgba(6,182,212,0.4)') }],
                    }} options={{
                      ...chartDefaults,
                      scales: { x: { ticks: { color: '#64748b', font: { size: 9 } }, grid: { color: gridColor } }, y: { ticks: { color: '#64748b' }, grid: { color: gridColor } } },
                    }} />
                  </div>
                </div>
              </div>
              {protocolStats?.attack_types?.length > 0 && (
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                  <div className="text-sm font-semibold text-slate-300 mb-4">🎯 Attack Type Breakdown</div>
                  <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
                    {protocolStats.attack_types.map((a: any) => (
                      <div key={a.type} className="text-center border border-slate-700 rounded-xl p-3 bg-slate-800/30">
                        <div className="text-lg font-bold text-slate-200">{a.count}</div>
                        <div className="text-xs text-slate-500 mt-0.5 truncate" title={a.type}>{a.type}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* WHITELIST */}
          {!loading && tab === 'whitelist' && (
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <button onClick={() => setWhitelistModal(true)} className="bg-green-500 hover:bg-green-600 text-white text-sm px-4 py-2 rounded-lg font-medium transition-colors">✅ Add to Whitelist</button>
                <button onClick={() => api.syncWhitelist().then(fetchCoreData)} className="bg-slate-700 hover:bg-slate-600 text-slate-200 text-sm px-4 py-2 rounded-lg font-medium transition-colors">🔄 Sync MikroTik</button>
                <div className="text-xs text-slate-500">{whitelist.length} entries</div>
              </div>
              <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                <table className="w-full text-xs">
                  <thead><tr className="text-slate-500 border-b border-slate-800">
                    <th className="text-left px-4 py-2">IP Address</th><th className="text-left px-2 py-2">Reason</th>
                    <th className="text-left px-2 py-2">Added By</th><th className="text-left px-2 py-2">MikroTik</th>
                    <th className="text-left px-2 py-2">Date</th><th className="text-left px-2 py-2">Remove</th>
                  </tr></thead>
                  <tbody>
                    {whitelist.map((w) => (
                      <tr key={w.id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                        <td className="px-4 py-2 font-mono text-green-400">{w.address}</td>
                        <td className="px-2 py-2 text-slate-300">{w.reason || '—'}</td>
                        <td className="px-2 py-2 text-slate-500">{w.added_by || '—'}</td>
                        <td className="px-2 py-2"><span className={`text-[10px] ${w.synced_to_mikrotik ? 'text-green-400' : 'text-yellow-400'}`}>{w.synced_to_mikrotik ? '✓ Synced' : '⚠ Pending'}</span></td>
                        <td className="px-2 py-2 text-slate-500">{new Date(w.added_at).toLocaleDateString()}</td>
                        <td className="px-2 py-2">
                          <button onClick={async () => { if (!confirm(`Remove ${w.address}?`)) return; await api.removeFromWhitelist(w.address); fetchCoreData(); }}
                            className="text-red-400 text-[10px] border border-red-500/30 rounded px-1.5 py-0.5 hover:bg-red-500/10 transition-colors">Remove</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {whitelist.length === 0 && <div className="text-center py-8 text-slate-600">No whitelisted IPs. Add trusted IPs to prevent auto-blocking.</div>}
              </div>
            </div>
          )}

          {/* ── Settings Tab ──────────────────────────────────────────────────── */}
          {!loading && tab === 'settings' && (
            <SettingsTab />
          )}
        </div>
      </main>

      {/* Scan Result Modal */}
      {scanResult && (
        <IPScanDetail result={scanResult}
          onBlock={() => { setBlockAddress(scanResult.ip); setScanResult(null); setBlockModal(true); }}
          onClose={() => setScanResult(null)} />
      )}

      {/* Profile & 2FA Modal */}
      {showProfile && currentUser && (
        <ProfileModal
          user={currentUser}
          onClose={() => setShowProfile(false)}
          onUserUpdate={(u) => setCurrentUser(u)}
        />
      )}

      {/* Block IP Modal */}
      {blockModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl p-6 w-full max-w-md">
            <h3 className="text-lg font-bold text-slate-100 mb-4">🚫 Block IP Address</h3>
            <div className="space-y-3">
              <input value={blockAddress} onChange={(e) => setBlockAddress(e.target.value)} placeholder="IP Address (required)"
                className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-red-500 font-mono" />
              <input value={blockReason} onChange={(e) => setBlockReason(e.target.value)} placeholder="Reason (optional)"
                className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-red-500" />
            </div>
            <div className="flex gap-3 mt-5">
              <button onClick={() => { setBlockModal(false); setBlockAddress(''); setBlockReason(''); }} className="flex-1 bg-slate-700 hover:bg-slate-600 text-white py-2.5 rounded-xl text-sm font-medium transition-colors">Cancel</button>
              <button onClick={handleBlock} disabled={!blockAddress.trim() || blockLoading} className="flex-1 bg-red-500 hover:bg-red-600 text-white py-2.5 rounded-xl text-sm font-bold transition-colors disabled:opacity-50">{blockLoading ? 'Blocking...' : 'Block IP'}</button>
            </div>
          </div>
        </div>
      )}

      {/* Add Whitelist Modal */}
      {whitelistModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl p-6 w-full max-w-md">
            <h3 className="text-lg font-bold text-slate-100 mb-4">✅ Add to Whitelist</h3>
            <div className="space-y-3">
              <input value={wlAddress} onChange={(e) => setWlAddress(e.target.value)} placeholder="IP Address (required)"
                className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-green-500 font-mono" />
              <input value={wlReason} onChange={(e) => setWlReason(e.target.value)} placeholder="Reason (e.g. Internal server, Admin IP)"
                className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-green-500" />
            </div>
            <div className="flex gap-3 mt-5">
              <button onClick={() => { setWhitelistModal(false); setWlAddress(''); setWlReason(''); }} className="flex-1 bg-slate-700 hover:bg-slate-600 text-white py-2.5 rounded-xl text-sm font-medium transition-colors">Cancel</button>
              <button onClick={handleAddWhitelist} disabled={!wlAddress.trim() || wlLoading} className="flex-1 bg-green-500 hover:bg-green-600 text-white py-2.5 rounded-xl text-sm font-bold transition-colors disabled:opacity-50">{wlLoading ? 'Adding...' : 'Add to Whitelist'}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

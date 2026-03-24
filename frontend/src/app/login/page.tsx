'use client';
import { useState, FormEvent } from 'react';
import { useRouter } from 'next/navigation';
import Cookies from 'js-cookie';
import { login, totpVerifyLogin } from '@/lib/api';
import { Shield, Lock, User, AlertCircle, KeyRound } from 'lucide-react';

export default function LoginPage() {
  const router = useRouter();

  // Step 1 — password
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  // Step 2 — TOTP
  const [totpStep, setTotpStep] = useState(false);
  const [totpSession, setTotpSession] = useState('');
  const [totpCode, setTotpCode] = useState('');

  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLoginSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await login(username, password);
      const data = res.data;
      if (data.requires_totp) {
        setTotpSession(data.totp_session);
        setTotpStep(true);
      } else {
        Cookies.set('sstb_token', data.access_token, { expires: 1 });
        router.push('/dashboard');
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Login gagal. Periksa kembali kredensial Anda.');
    } finally {
      setLoading(false);
    }
  };

  const handleTotpSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await totpVerifyLogin(totpSession, totpCode);
      Cookies.set('sstb_token', res.data.access_token, { expires: 1 });
      router.push('/dashboard');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Kode TOTP tidak valid.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-cyber-dark relative overflow-hidden">
      {/* Background grid */}
      <div
        className="absolute inset-0 opacity-10"
        style={{
          backgroundImage: `
            linear-gradient(rgba(0,212,255,0.3) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0,212,255,0.3) 1px, transparent 1px)
          `,
          backgroundSize: '40px 40px',
        }}
      />
      <div className="absolute top-1/4 left-1/4 w-64 h-64 bg-cyber-cyan rounded-full opacity-5 blur-3xl" />
      <div className="absolute bottom-1/4 right-1/4 w-64 h-64 bg-cyber-green rounded-full opacity-5 blur-3xl" />

      <div className="relative z-10 w-full max-w-md px-4">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-cyber-card border border-cyber-cyan/30 mb-4 glow-cyan">
            <Shield className="w-8 h-8 text-cyber-cyan" />
          </div>
          <h1 className="text-2xl font-bold text-white">
            <span className="text-cyber-cyan">SSTB</span> Console
          </h1>
          <p className="text-gray-400 text-sm mt-1">Smart Security & Threat Blocker</p>
        </div>

        <div className="bg-cyber-card border border-cyber-border rounded-xl p-8 scanline">
          {!totpStep ? (
            <>
              <h2 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
                <Lock className="w-4 h-4 text-cyber-cyan" />
                Authentication Required
              </h2>

              {error && (
                <div className="flex items-center gap-2 bg-red-500/10 border border-red-500/30 rounded-lg p-3 mb-4 text-red-400 text-sm">
                  <AlertCircle className="w-4 h-4 flex-shrink-0" />
                  {error}
                </div>
              )}

              <form onSubmit={handleLoginSubmit} className="space-y-4">
                <div>
                  <label className="block text-xs text-gray-400 mb-1 uppercase tracking-wider">Username</label>
                  <div className="relative">
                    <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                    <input
                      type="text"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      className="cyber-input w-full rounded-lg pl-10 pr-4 py-2.5 text-sm"
                      placeholder="admin"
                      required
                      autoComplete="username"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs text-gray-400 mb-1 uppercase tracking-wider">Password</label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                    <input
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="cyber-input w-full rounded-lg pl-10 pr-4 py-2.5 text-sm"
                      placeholder="••••••••"
                      required
                      autoComplete="current-password"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="cyber-btn w-full py-2.5 rounded-lg text-sm font-semibold mt-2 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {loading ? (
                    <span className="flex items-center justify-center gap-2">
                      <span className="w-4 h-4 border-2 border-cyber-cyan/30 border-t-cyber-cyan rounded-full animate-spin" />
                      Authenticating...
                    </span>
                  ) : (
                    'Access System'
                  )}
                </button>
              </form>

              <div className="mt-6 pt-4 border-t border-cyber-border text-center">
                <p className="text-xs text-gray-500">
                  Akun admin dikelola oleh administrator sistem.
                </p>
              </div>
            </>
          ) : (
            <>
              <h2 className="text-lg font-semibold text-white mb-2 flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-cyber-cyan" />
                Two-Factor Authentication
              </h2>
              <p className="text-xs text-gray-400 mb-6">
                Masukkan kode 6 digit dari Google Authenticator.
              </p>

              {error && (
                <div className="flex items-center gap-2 bg-red-500/10 border border-red-500/30 rounded-lg p-3 mb-4 text-red-400 text-sm">
                  <AlertCircle className="w-4 h-4 flex-shrink-0" />
                  {error}
                </div>
              )}

              <form onSubmit={handleTotpSubmit} className="space-y-4">
                <div>
                  <label className="block text-xs text-gray-400 mb-1 uppercase tracking-wider">
                    Verification Code
                  </label>
                  <input
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]{6}"
                    maxLength={6}
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                    className="cyber-input w-full rounded-lg px-4 py-3 text-center text-2xl font-mono tracking-[0.5em]"
                    placeholder="000000"
                    required
                    autoFocus
                    autoComplete="one-time-code"
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading || totpCode.length !== 6}
                  className="cyber-btn w-full py-2.5 rounded-lg text-sm font-semibold mt-2 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {loading ? (
                    <span className="flex items-center justify-center gap-2">
                      <span className="w-4 h-4 border-2 border-cyber-cyan/30 border-t-cyber-cyan rounded-full animate-spin" />
                      Verifying...
                    </span>
                  ) : (
                    'Verify & Login'
                  )}
                </button>

                <button
                  type="button"
                  onClick={() => { setTotpStep(false); setTotpCode(''); setError(''); }}
                  className="w-full text-xs text-gray-500 hover:text-gray-300 transition-colors py-1"
                >
                  ← Kembali ke login
                </button>
              </form>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Users,
  KeyRound,
  Calendar,
  Smartphone,
  Laptop,
  Globe,
  Download,
  RotateCw,
  Search,
  Filter,
  CheckCircle2,
  Copy,
  Check,
  UserPlus,
  LogIn,
  Clock
} from 'lucide-react';
import type { AuthUser, LoginAuditLog, AuditStats, VaultPinResetRequest } from '../types';
import { api } from '../api';
import { fetchAuditLogs, ADMIN_EMAIL, subscribeToAllPinResetRequests, approveVaultPinReset } from '../firebase';

interface AdminAuditViewProps {
  user: AuthUser | null;
}

export const AdminAuditView: React.FC<AdminAuditViewProps> = ({ user }) => {
  const isAdmin = Boolean(user?.email && user.email.toLowerCase() === ADMIN_EMAIL.toLowerCase());

  const [logs, setLogs] = useState<LoginAuditLog[]>([]);
  const [stats, setStats] = useState<AuditStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Filters & Search
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedEventType, setSelectedEventType] = useState<string>('ALL');
  const [selectedPlatform, setSelectedPlatform] = useState<string>('ALL');

  // Copy feedback
  const [copiedUid, setCopiedUid] = useState<string | null>(null);

  // Vault PIN Reset Requests State
  const [pinRequests, setPinRequests] = useState<VaultPinResetRequest[]>([]);
  const [approvingId, setApprovingId] = useState<string | null>(null);
  const [approveSuccessMsg, setApproveSuccessMsg] = useState<string | null>(null);

  const loadAuditData = useCallback(async () => {
    if (!isAdmin || !user?.email) return;
    setLoading(true);
    setErrorMsg(null);
    try {
      const [cloudLogs, statsData] = await Promise.all([
        fetchAuditLogs(user.email),
        api.getAuditStats(user.email).catch(() => null),
      ]);
      setLogs(cloudLogs);
      if (statsData) {
        setStats(statsData);
      } else {
        // Compute local stats from logs
        const unique = new Set((cloudLogs || []).map(l => (l?.email || '').toLowerCase())).size;
        const todayStr = new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });
        const loginsToday = (cloudLogs || []).filter(l => (l?.login_date || '').includes(todayStr)).length;
        const win = (cloudLogs || []).filter(l => (l?.platform || '').includes('Windows')).length;
        const droid = (cloudLogs || []).filter(l => (l?.platform || '').includes('Android')).length;
        const web = (cloudLogs || []).filter(l => (l?.platform || '').includes('Web')).length;
        const signups = (cloudLogs || []).filter(l => l?.event_type === 'NEW_ACCOUNT_SIGNUP').length;
        setStats({
          total_users: unique,
          total_logins: (cloudLogs || []).length,
          logins_today: loginsToday,
          platforms: { windows: win, android: droid, web },
          event_types: { signups, logins: (cloudLogs || []).length - signups },
        });
      }
    } catch (err: any) {
      console.error('Failed to load audit logs:', err);
      setErrorMsg(err.message || 'Failed to load centralized audit logs.');
    } finally {
      setLoading(false);
    }
  }, [isAdmin, user]);

  useEffect(() => {
    if (isAdmin) {
      loadAuditData();
    }
  }, [isAdmin, loadAuditData]);

  // Subscribe to real-time Vault PIN reset requests
  useEffect(() => {
    if (!isAdmin) return;
    const unsub = subscribeToAllPinResetRequests((requests) => {
      setPinRequests(requests);
    });
    return () => unsub();
  }, [isAdmin]);

  const handleApproveReset = async (req: VaultPinResetRequest) => {
    const targetId = req.id || req.uid;
    setApprovingId(targetId);
    setApproveSuccessMsg(null);
    try {
      await approveVaultPinReset(targetId, req.uid);
      setApproveSuccessMsg(`Approved PIN reset for ${req.email}`);
      setTimeout(() => setApproveSuccessMsg(null), 4000);
    } catch (err: any) {
      alert(`Approval failed: ${err.message}`);
    } finally {
      setApprovingId(null);
    }
  };

  // Filtered logs
  const filteredLogs = useMemo(() => {
    return (logs || []).filter(log => {
      if (!log) return false;
      const q = (searchQuery || '').toLowerCase();
      const matchesSearch =
        q === '' ||
        (log.full_name || '').toLowerCase().includes(q) ||
        (log.email || '').toLowerCase().includes(q) ||
        (log.uid || '').toLowerCase().includes(q) ||
        (log.login_date || '').toLowerCase().includes(q) ||
        (log.platform || '').toLowerCase().includes(q);

      const matchesType =
        selectedEventType === 'ALL' || log.event_type === selectedEventType;

      const matchesPlatform =
        selectedPlatform === 'ALL' || (log.platform || '') === selectedPlatform;

      return matchesSearch && matchesType && matchesPlatform;
    });
  }, [logs, searchQuery, selectedEventType, selectedPlatform]);

  // Copy helper
  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedUid(id);
    setTimeout(() => setCopiedUid(null), 2000);
  };

  // CSV Report Generator
  const handleDownloadCsv = () => {
    if (logs.length === 0) return;

    const headers = [
      'Record ID',
      'User Google UID',
      'Google Email',
      'Full Name',
      'Event Type',
      'Platform',
      'Login Date',
      'Login Time',
      'ISO UTC Timestamp',
    ];

    const rows = logs.map(l => [
      l.id || '',
      `"${l.uid}"`,
      `"${l.email}"`,
      `"${l.full_name}"`,
      l.event_type,
      `"${l.platform}"`,
      `"${l.login_date}"`,
      `"${l.login_time}"`,
      l.iso_timestamp,
    ]);

    const csvContent = [
      headers.join(','),
      ...rows.map(r => r.join(',')),
    ].join('\r\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    const today = new Date().toISOString().split('T')[0];
    link.setAttribute('href', url);
    link.setAttribute('download', `SentinelGrid_Login_Audit_Report_${today}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleSeedDemo = async () => {
    if (!user?.email) return;
    try {
      await api.seedAuditDemo(user.email);
      await loadAuditData();
    } catch (e: any) {
      console.warn('Seed demo error:', e);
    }
  };

  // Unauthorized view guard
  if (!isAdmin) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[500px] text-center p-8 bg-[#0F172A]/70 border border-red-500/30 rounded-2xl">
        <div className="w-16 h-16 rounded-2xl bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400 mb-4 shadow-lg shadow-red-500/10">
          <ShieldAlert className="w-8 h-8" />
        </div>
        <h2 className="text-xl font-bold text-white mb-2">Restricted SuperAdmin Area</h2>
        <p className="text-sm text-slate-300 max-w-md mb-6 leading-relaxed">
          Access to the Centralized Google OAuth Login & Device Audit Center is strictly restricted to{' '}
          <span className="text-emerald-400 font-mono font-semibold">{ADMIN_EMAIL}</span>.
        </p>
        <div className="px-4 py-2 rounded-xl bg-[#131A26] border border-[#1F2937] text-xs text-slate-400">
          Current Authenticated Identity: <span className="text-slate-200">{user?.email || 'Anonymous'}</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Header Card */}
      <div className="p-6 rounded-2xl bg-[#0F172A] border border-[#1F2937] flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-xl">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-lg font-bold text-white tracking-tight">Admin Central Audit Center</h1>
            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-purple-500/20 text-purple-300 border border-purple-500/40 flex items-center gap-1">
              <ShieldCheck className="w-3.5 h-3.5 text-purple-400" />
              SuperAdmin Controller
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time Google OAuth & Device Access Registry · Centralized Cloud Audit Database
          </p>
          <div className="flex items-center gap-2 mt-2 text-[11px] text-emerald-400">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Authorized Administrator Identity: <strong className="font-mono text-white">{ADMIN_EMAIL}</strong></span>
          </div>
        </div>

        <div className="flex items-center gap-2.5 shrink-0 flex-wrap">
          <button
            onClick={loadAuditData}
            disabled={loading}
            className="px-3.5 py-2 rounded-xl bg-[#182335] hover:bg-[#202E44] text-slate-200 border border-[#2D3F59] text-xs font-medium flex items-center gap-2 transition-colors disabled:opacity-50"
            title="Refresh latest cloud audit records"
          >
            <RotateCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-emerald-400' : 'text-slate-400'}`} />
            <span>Refresh</span>
          </button>

          <button
            onClick={handleDownloadCsv}
            disabled={logs.length === 0}
            className="px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 text-xs font-semibold flex items-center gap-2 transition-all shadow-md shadow-emerald-500/20 active:scale-95 disabled:opacity-50"
            title="Download full audit log report as CSV"
          >
            <Download className="w-4 h-4" />
            <span>Download CSV Report</span>
          </button>
        </div>
      </div>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-xs text-red-300 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Real-time KPI Stats Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Total Registered Users */}
        <div className="p-4 rounded-2xl bg-[#0F172A] border border-[#1F2937] relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-slate-400">Total Registered Users</span>
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <Users className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold text-white tracking-tight">
            {stats?.total_users ?? 0}
          </div>
          <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-1">
            <span className="text-emerald-400 font-medium">Unique Google UIDs</span> enrolled
          </div>
        </div>

        {/* Card 2: Total Logins */}
        <div className="p-4 rounded-2xl bg-[#0F172A] border border-[#1F2937] relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-slate-400">Total Authentications</span>
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <KeyRound className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold text-white tracking-tight">
            {stats?.total_logins ?? logs.length}
          </div>
          <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-1.5">
            <span className="text-cyan-400 font-medium">{stats?.event_types?.signups ?? 0} sign-ups</span>
            <span>·</span>
            <span className="text-slate-300">{stats?.event_types?.logins ?? 0} logins</span>
          </div>
        </div>

        {/* Card 3: Logins Today */}
        <div className="p-4 rounded-2xl bg-[#0F172A] border border-[#1F2937] relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-slate-400">Logins Today</span>
            <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <Calendar className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold text-white tracking-tight">
            {stats?.logins_today ?? 0}
          </div>
          <div className="text-[11px] text-amber-400/90 mt-1 flex items-center gap-1">
            <span>Live today access count</span>
          </div>
        </div>

        {/* Card 4: Platform Breakdown */}
        <div className="p-4 rounded-2xl bg-[#0F172A] border border-[#1F2937] relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-slate-400">Active Platforms</span>
            <div className="w-8 h-8 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
              <Laptop className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-center gap-3 text-sm font-semibold text-white mt-1">
            <div className="flex items-center gap-1 text-slate-200" title="Windows Desktop Logins">
              <Laptop className="w-3.5 h-3.5 text-blue-400" />
              <span>{stats?.platforms?.windows ?? 0}</span>
            </div>
            <span>·</span>
            <div className="flex items-center gap-1 text-slate-200" title="Android Mobile Logins">
              <Smartphone className="w-3.5 h-3.5 text-emerald-400" />
              <span>{stats?.platforms?.android ?? 0}</span>
            </div>
            <span>·</span>
            <div className="flex items-center gap-1 text-slate-200" title="Web Portal Logins">
              <Globe className="w-3.5 h-3.5 text-amber-400" />
              <span>{stats?.platforms?.web ?? 0}</span>
            </div>
          </div>
          <div className="text-[11px] text-slate-400 mt-1.5 truncate">
            Windows / Android / Web
          </div>
        </div>
      </div>

      {/* SuperAdmin Approval Panel: Vault PIN Reset Requests */}
      <div className="p-5 rounded-2xl bg-[#0E1626] border border-amber-500/30 shadow-lg space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-[#1E2E48]">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <KeyRound className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-white">Vault PIN Reset Requests</h3>
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                  (pinRequests || []).filter(r => r?.status === 'pending').length > 0
                    ? 'bg-amber-950 text-amber-400 border-amber-500/40 animate-pulse'
                    : 'bg-slate-800 text-slate-400 border-slate-700'
                }`}>
                  {(pinRequests || []).filter(r => r?.status === 'pending').length} Pending
                </span>
              </div>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Admin approval for users who forgot their AES-256 Credentials Vault PIN.
              </p>
            </div>
          </div>

          {approveSuccessMsg && (
            <div className="text-xs text-emerald-400 bg-emerald-950/80 border border-emerald-500/30 px-3 py-1 rounded-lg flex items-center gap-1.5 animate-fade-in">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>{approveSuccessMsg}</span>
            </div>
          )}
        </div>

        {(!pinRequests || pinRequests.length === 0) ? (
          <div className="py-4 text-center text-xs text-slate-400 flex items-center justify-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>No pending PIN reset requests. All user vaults are securely operating.</span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead>
                <tr className="border-b border-[#1E2E48] text-[11px] text-slate-400 uppercase tracking-wider font-mono">
                  <th className="py-2 px-3">User / Email</th>
                  <th className="py-2 px-3">Google UID</th>
                  <th className="py-2 px-3">Requested At</th>
                  <th className="py-2 px-3">Status</th>
                  <th className="py-2 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1A2538]">
                {(pinRequests || []).map((req, idx) => (
                  <tr key={req.id || req.uid || idx} className="hover:bg-[#131E30]/50 transition-colors">
                    <td className="py-2.5 px-3">
                      <div className="font-semibold text-white">{req.full_name || 'Operator'}</div>
                      <div className="text-[11px] text-slate-400">{req.email}</div>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400">
                      {req.uid ? `${req.uid.slice(0, 14)}...` : 'N/A'}
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                      {req.requestedAt ? new Date(req.requestedAt).toLocaleString() : 'Just now'}
                    </td>
                    <td className="py-2.5 px-3">
                      {req.status === 'approved' ? (
                        <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-emerald-400 bg-emerald-950/60 border border-emerald-500/30 px-2 py-0.5 rounded-full">
                          <CheckCircle2 className="w-3 h-3" />
                          <span>Approved</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-amber-400 bg-amber-950/60 border border-amber-500/30 px-2 py-0.5 rounded-full">
                          <Clock className="w-3 h-3" />
                          <span>Pending Approval</span>
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      {req.status === 'pending' ? (
                        <button
                          onClick={() => handleApproveReset(req)}
                          disabled={approvingId === (req.id || req.uid)}
                          className="px-3 py-1 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs inline-flex items-center gap-1.5 shadow-sm transition-all disabled:opacity-50"
                        >
                          <Check className="w-3.5 h-3.5" />
                          <span>{approvingId === (req.id || req.uid) ? 'Approving...' : 'Approve Reset'}</span>
                        </button>
                      ) : (
                        <span className="text-[11px] text-slate-500">Reset Enabled</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Search & Filter Toolbar */}
      <div className="p-4 rounded-2xl bg-[#0F172A] border border-[#1F2937] flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by name, email, Google UID, or date..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 rounded-xl bg-[#131A26] border border-[#1F2937] text-xs text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500/60 transition-colors"
          />
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          {/* Event Type Filter */}
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span>Event:</span>
            <select
              value={selectedEventType}
              onChange={(e) => setSelectedEventType(e.target.value)}
              className="px-2.5 py-1.5 rounded-xl bg-[#131A26] border border-[#1F2937] text-xs text-slate-200 focus:outline-none focus:border-emerald-500/60"
            >
              <option value="ALL">All Events</option>
              <option value="NEW_ACCOUNT_SIGNUP">Sign-Ups Only</option>
              <option value="USER_LOGIN">Logins Only</option>
            </select>
          </div>

          {/* Platform Filter */}
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <span>Platform:</span>
            <select
              value={selectedPlatform}
              onChange={(e) => setSelectedPlatform(e.target.value)}
              className="px-2.5 py-1.5 rounded-xl bg-[#131A26] border border-[#1F2937] text-xs text-slate-200 focus:outline-none focus:border-emerald-500/60"
            >
              <option value="ALL">All Platforms</option>
              <option value="Windows Desktop">Windows Desktop</option>
              <option value="Android Mobile">Android Mobile</option>
              <option value="Web Portal">Web Portal</option>
            </select>
          </div>

          {logs.length <= 1 && (
            <button
              onClick={handleSeedDemo}
              className="px-3 py-1.5 rounded-xl bg-[#182335] hover:bg-[#202E44] text-[11px] text-slate-300 border border-[#2D3F59] transition-colors"
              title="Populate test multi-platform logins"
            >
              Seed Demo Data
            </button>
          )}
        </div>
      </div>

      {/* Main Audit Registry Table */}
      <div className="rounded-2xl bg-[#0F172A] border border-[#1F2937] overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-[#131A26] text-slate-400 uppercase text-[10px] tracking-wider border-b border-[#1F2937]">
              <tr>
                <th className="py-3 px-4">Operator / User</th>
                <th className="py-3 px-4">Google Email</th>
                <th className="py-3 px-4">Event Type</th>
                <th className="py-3 px-4">Platform</th>
                <th className="py-3 px-4">Exact Date</th>
                <th className="py-3 px-4">Exact Time</th>
                <th className="py-3 px-4 text-right">Google UID</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1F2937]/50 font-normal">
              {loading && (!logs || logs.length === 0) ? (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-slate-400">
                    <div className="flex flex-col items-center gap-2">
                      <RotateCw className="w-5 h-5 animate-spin text-emerald-400" />
                      <span>Loading Central Cloud Audit Registry...</span>
                    </div>
                  </td>
                </tr>
              ) : (!filteredLogs || filteredLogs.length === 0) ? (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-slate-400">
                    <div className="flex flex-col items-center gap-2">
                      <Users className="w-6 h-6 text-slate-400" />
                      <span className="font-medium text-slate-300">No login audit records match your filter criteria</span>
                      <span className="text-[11px] text-slate-400">Try adjusting your search terms or filter selection.</span>
                    </div>
                  </td>
                </tr>
              ) : (
                (filteredLogs || []).map((item, idx) => {
                  const isSignup = item.event_type === 'NEW_ACCOUNT_SIGNUP';
                  const isWindows = (item.platform || '').includes('Windows');
                  const isAndroid = (item.platform || '').includes('Android');
                  const uniqueId = item.id || `log-${idx}`;

                  return (
                    <tr
                      key={uniqueId}
                      className="hover:bg-[#131A26]/80 transition-colors"
                    >
                      {/* Operator Avatar & Full Name */}
                      <td className="py-3.5 px-4">
                        <div className="flex items-center gap-3">
                          {item.photo_url ? (
                            <img
                              src={item.photo_url}
                              alt={item.full_name || 'Operator'}
                              className="w-8 h-8 rounded-full object-cover border border-[#2D3F59] shrink-0"
                              onError={(e) => {
                                // fallback to initial
                                (e.target as HTMLElement).style.display = 'none';
                              }}
                            />
                          ) : (
                            <div className="w-8 h-8 rounded-full bg-[#182335] border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-bold shrink-0">
                              {(item.full_name || 'U').charAt(0).toUpperCase()}
                            </div>
                          )}
                          <div className="min-w-0">
                            <div className="font-semibold text-white truncate max-w-[150px]">
                              {item.full_name || 'Anonymous Operator'}
                            </div>
                            <div className="text-[10px] text-slate-400 font-mono truncate max-w-[150px]">
                              UID: {(item.uid || '').substring(0, 16)}...
                            </div>
                          </div>
                        </div>
                      </td>

                      {/* Google Email */}
                      <td className="py-3.5 px-4 font-mono text-[11px] text-slate-200">
                        {item.email || 'unknown'}
                      </td>

                      {/* Event Type Badge */}
                      <td className="py-3.5 px-4">
                        {isSignup ? (
                          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                            <UserPlus className="w-3 h-3 text-emerald-400" />
                            NEW ACCOUNT SIGNUP
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                            <LogIn className="w-3 h-3 text-cyan-400" />
                            USER LOGIN
                          </span>
                        )}
                      </td>

                      {/* Platform */}
                      <td className="py-3.5 px-4">
                        <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-lg bg-[#182335] border border-[#26354D] text-[11px] text-slate-200">
                          {isWindows ? (
                            <Laptop className="w-3.5 h-3.5 text-blue-400" />
                          ) : isAndroid ? (
                            <Smartphone className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Globe className="w-3.5 h-3.5 text-amber-400" />
                          )}
                          <span>{item.platform}</span>
                        </div>
                      </td>

                      {/* Exact Date */}
                      <td className="py-3.5 px-4 text-slate-300 whitespace-nowrap">
                        {item.login_date}
                      </td>

                      {/* Exact Time */}
                      <td className="py-3.5 px-4 font-mono text-[11px] text-slate-300 whitespace-nowrap">
                        {item.login_time}
                      </td>

                      {/* Google UID Copy Action */}
                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={() => handleCopy(item.uid, uniqueId)}
                          className="inline-flex items-center gap-1 px-2 py-1 rounded bg-[#182335] hover:bg-[#202E44] text-[10px] font-mono text-slate-300 border border-[#2D3F59] transition-colors"
                          title="Copy full Google UID"
                        >
                          {copiedUid === uniqueId ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-400" />
                              <span className="text-emerald-400">Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3 text-slate-400" />
                              <span>Copy UID</span>
                            </>
                          )}
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Table footer info */}
        <div className="p-4 bg-[#131A26]/60 border-t border-[#1F2937] flex items-center justify-between text-xs text-slate-400">
          <span>
            Showing <strong className="text-white">{filteredLogs.length}</strong> of{' '}
            <strong className="text-white">{logs.length}</strong> total records
          </span>
          <span className="text-[11px] text-slate-400">
            Backed by Cloud Firestore & Centralized Guardian Database
          </span>
        </div>
      </div>
    </div>
  );
};

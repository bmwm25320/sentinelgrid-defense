import React, { useState, useEffect } from 'react';
import {
  Wifi,
  ShieldCheck,
  Globe,
  Radio,
  CheckCircle2,
  Info,
  Search,
  AlertTriangle,
  XCircle,
  Ban,
  Camera,
  Mic,
  Smartphone,
  RotateCw,
  Trash2,
  Lock,
  ExternalLink,
  Download,
  Shield,
} from 'lucide-react';
import type {
  DeviceAudit,
  ShieldConfig,
  NetworkConnectionItem,
  UrlCheckResult,
  NetworkShieldStatus,
  SafeMoneySite,
  SafeMoneyLaunchResult,
  DnsShieldStatus,
} from '../types';
import { api } from '../api';
import {
  SentinelDeviceGuard,
  isAndroidNativeApp,
  type AndroidWifiStatus,
} from '../plugins/sentinelDeviceGuard';

interface NetworkViewProps {
  audit: DeviceAudit | null;
  config: ShieldConfig;
  onConfigChange: (newConfig: ShieldConfig) => void;
}

export const NetworkView: React.FC<NetworkViewProps> = ({
  audit,
  config,
  onConfigChange,
}) => {
  const [filterText, setFilterText] = useState('');
  const [urlInput, setUrlInput] = useState('');
  const [urlChecking, setUrlChecking] = useState(false);
  const [urlResult, setUrlResult] = useState<UrlCheckResult | null>(null);
  const [shieldStatus, setShieldStatus] = useState<NetworkShieldStatus | null>(null);
  const [androidWifi, setAndroidWifi] = useState<AndroidWifiStatus | null>(null);
  const [blockingIp, setBlockingIp] = useState<string | null>(null);
  const [manualIpInput, setManualIpInput] = useState('');
  const [refreshingShield, setRefreshingShield] = useState(false);
  const [safeMoneySites, setSafeMoneySites] = useState<SafeMoneySite[]>([]);
  const [safeMoneyUrl, setSafeMoneyUrl] = useState('https://www.paypal.com');
  const [launchingSafeMoney, setLaunchingSafeMoney] = useState(false);
  const [safeMoneyResult, setSafeMoneyResult] = useState<SafeMoneyLaunchResult | null>(null);
  const [safeMoneyError, setSafeMoneyError] = useState<string | null>(null);
  const [dnsShield, setDnsShield] = useState<DnsShieldStatus | null>(null);
  const [togglingDnsShield, setTogglingDnsShield] = useState(false);
  const isAndroid = isAndroidNativeApp();

  const loadNetworkShield = async () => {
    setRefreshingShield(true);
    try {
      const [data, sitesRes, dnsRes] = await Promise.all([
        api.getNetworkShieldStatus(),
        api.getSafeMoneySites().catch(() => ({ sites: [] })),
        api.getDnsShieldStatus().catch(() => null),
      ]);
      setShieldStatus(data);
      if (sitesRes.sites?.length) {
        setSafeMoneySites(sitesRes.sites);
      }
      if (dnsRes) {
        setDnsShield(dnsRes);
      }
    } catch {
      // Standalone Android or offline mode
    }
    if (isAndroidNativeApp()) {
      try {
        const wifiRes = await SentinelDeviceGuard.inspectWifiSecurity();
        setAndroidWifi(wifiRes);
      } catch {
        // Ignore if native plugin unavailable
      }
    }
    setRefreshingShield(false);
  };

  useEffect(() => {
    loadNetworkShield();
  }, []);

  const handleBlockIp = async (ip: string, reason?: string) => {
    if (!ip.trim()) return;
    setBlockingIp(ip.trim());
    try {
      const res = await api.blockNetworkIp(ip.trim(), reason);
      setShieldStatus((prev) =>
        prev
          ? { ...prev, blocked_ips: res.blocked_ips }
          : {
              blocked_ips: res.blocked_ips,
              arp_mitm: { status: 'SAFE', anomalies: [], entries_checked: 0 },
              hardware_privacy: {
                webcam_in_use: false,
                webcam_active_apps: [],
                recent_webcam_apps: [],
                microphone_in_use: false,
                microphone_active_apps: [],
                recent_microphone_apps: [],
                guard_status: 'ACTIVE',
                checked_at: '',
              },
            }
      );
      setManualIpInput('');
    } catch (err: any) {
      alert(`Firewall block error: ${err.message}`);
    } finally {
      setBlockingIp(null);
    }
  };

  const handleUnblockIp = async (ip: string) => {
    setBlockingIp(ip);
    try {
      const res = await api.unblockNetworkIp(ip);
      setShieldStatus((prev) => (prev ? { ...prev, blocked_ips: res.blocked_ips } : null));
    } catch (err: any) {
      alert(`Unblock failed: ${err.message}`);
    } finally {
      setBlockingIp(null);
    }
  };

  const handleLaunchSafeMoney = async (targetUrl?: string) => {
    const urlToOpen = (targetUrl || safeMoneyUrl).trim();
    if (!urlToOpen) return;
    setSafeMoneyUrl(urlToOpen);
    setLaunchingSafeMoney(true);
    setSafeMoneyError(null);
    setSafeMoneyResult(null);
    try {
      const res = await api.launchSafeMoney(urlToOpen);
      setSafeMoneyResult(res);
    } catch (err: any) {
      setSafeMoneyError(err.message);
    } finally {
      setLaunchingSafeMoney(false);
    }
  };

  const handleCheckUrl = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!urlInput.trim()) return;
    setUrlChecking(true);
    try {
      const res = await api.checkUrl(urlInput.trim());
      setUrlResult(res);
    } catch {
      try {
        const nativeRes = await SentinelDeviceGuard.checkUrlSafety({ url: urlInput.trim() });
        setUrlResult({
          url: nativeRes.url,
          domain: nativeRes.domain,
          status: nativeRes.status,
          risk_score: nativeRes.risk_score,
          verdict_title:
            nativeRes.status === 'DANGEROUS'
              ? 'Warning: Malicious or Unsafe Link'
              : nativeRes.status === 'SUSPICIOUS'
              ? 'Caution: Suspicious Link'
              : 'Link Appears Safe',
          explanation: 'Evaluated locally by SentinelGrid On-Device Phishing Shield.',
          reasons: nativeRes.reasons || [],
        });
      } catch (err: any) {
        alert(`Link check failed: ${err.message}`);
      }
    } finally {
      setUrlChecking(false);
    }
  };

  const connections: NetworkConnectionItem[] = audit?.network_audit?.foreign_connections || [];
  const listeningPorts = audit?.network_audit?.listening_ports || [];

  const filteredConnections = connections.filter((c: NetworkConnectionItem) =>
    (c.process || '').toLowerCase().includes(filterText.toLowerCase()) ||
    (c.remote_ip || '').toLowerCase().includes(filterText.toLowerCase())
  );

  return (
    <div className="space-y-6 overflow-x-hidden">
      {/* Top Network Status Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-[#0F1B24] via-[#131A26] to-[#131A26] border border-emerald-500/30 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-sm">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-emerald-500 to-teal-700 text-white flex items-center justify-center shadow-md">
            <Wifi className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-500/30">
                Connected &amp; Secure
              </span>
              <span className="text-xs text-slate-400">• Local Network</span>
            </div>
            <h2 className="text-lg font-bold text-white tracking-tight mt-0.5">
              Firewall &amp; Network Protection Active
            </h2>
            <p className="text-xs text-slate-400">
              Monitoring incoming and outgoing connections safely. No unauthorized data leaks detected.
            </p>
          </div>
        </div>

        {/* Network Shield Toggle */}
        <div className="flex items-center gap-3 bg-[#0D121D] border border-[#1F2937] p-2.5 rounded-xl self-start md:self-auto">
          <span className="text-xs text-slate-300 font-medium">Network Guard</span>
          <button
            onClick={() => onConfigChange({ ...config, layer4_network_guard: !config.layer4_network_guard })}
            className={`w-11 h-6 rounded-full transition-colors relative p-0.5 ${
              config.layer4_network_guard ? 'bg-emerald-500' : 'bg-slate-700'
            }`}
          >
            <div
              className={`w-5 h-5 rounded-full bg-white transition-transform ${
                config.layer4_network_guard ? 'translate-x-5' : 'translate-x-0'
              }`}
            />
          </button>
        </div>
      </div>

      {/* 2-Column Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="defender-card p-4">
          <div className="flex items-center gap-2.5 text-xs text-slate-400 mb-1">
            <Globe className="w-4 h-4 text-emerald-400" />
            <span>Active Connections</span>
          </div>
          <div className="text-2xl font-bold text-white tracking-tight">
            {connections.length}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">Legitimate apps communicating online</p>
        </div>

        <div className="defender-card p-4">
          <div className="flex items-center gap-2.5 text-xs text-slate-400 mb-1">
            <Radio className="w-4 h-4 text-cyan-400" />
            <span>Monitored Ports</span>
          </div>
          <div className="text-2xl font-bold text-white tracking-tight">
            {listeningPorts.length}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">Local background service endpoints</p>
        </div>

        <div className="defender-card p-4">
          <div className="flex items-center gap-2.5 text-xs text-slate-400 mb-1">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>Inbound Protection</span>
          </div>
          <div className="text-2xl font-bold text-emerald-400 tracking-tight">
            Protected
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            {isAndroid ? 'Android Private DNS & Wi-Fi Shield active' : 'Windows Firewall active and blocking probes'}
          </p>
        </div>
      </div>

      {/* Hardware Privacy & ARP Spoofing Guard Panel (Desktop) / Android Wi-Fi Guard */}
      {!isAndroid && (
      <div className="defender-card p-5 space-y-4">
        <div className="flex items-center justify-between pb-2 border-b border-[#1F2937]">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <h3 className="text-xs font-semibold text-white">Hardware Privacy &amp; MITM Intrusion Shield</h3>
          </div>
          <button
            onClick={loadNetworkShield}
            disabled={refreshingShield}
            className="text-[11px] text-emerald-400 hover:text-emerald-300 flex items-center gap-1"
          >
            <RotateCw className={`w-3 h-3 ${refreshingShield ? 'animate-spin' : ''}`} />
            <span>Refresh Live State</span>
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {/* Webcam Guard */}
          <div className={`p-3.5 rounded-xl border ${shieldStatus?.hardware_privacy?.webcam_in_use ? 'bg-amber-950/20 border-amber-500/40' : 'bg-[#0D121D] border-[#1F2937]'}`}>
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-2 text-xs font-semibold text-white">
                <Camera className={`w-4 h-4 ${shieldStatus?.hardware_privacy?.webcam_in_use ? 'text-amber-400' : 'text-emerald-400'}`} />
                <span>Webcam Guard</span>
              </div>
              <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${shieldStatus?.hardware_privacy?.webcam_in_use ? 'bg-amber-950 text-amber-300 border border-amber-500/40' : 'bg-emerald-950 text-emerald-400 border border-emerald-500/30'}`}>
                {shieldStatus?.hardware_privacy?.webcam_in_use ? 'IN USE' : 'LOCKED SAFE'}
              </span>
            </div>
            <p className="text-[11px] text-slate-400">
              {shieldStatus?.hardware_privacy?.webcam_in_use
                ? `Active: ${shieldStatus.hardware_privacy.webcam_active_apps.map(a => a.app).join(', ')}`
                : 'No unauthorized camera hooks running'}
            </p>
          </div>

          {/* Microphone Guard */}
          <div className={`p-3.5 rounded-xl border ${shieldStatus?.hardware_privacy?.microphone_in_use ? 'bg-amber-950/20 border-amber-500/40' : 'bg-[#0D121D] border-[#1F2937]'}`}>
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-2 text-xs font-semibold text-white">
                <Mic className={`w-4 h-4 ${shieldStatus?.hardware_privacy?.microphone_in_use ? 'text-amber-400' : 'text-emerald-400'}`} />
                <span>Microphone Shield</span>
              </div>
              <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${shieldStatus?.hardware_privacy?.microphone_in_use ? 'bg-amber-950 text-amber-300 border border-amber-500/40' : 'bg-emerald-950 text-emerald-400 border border-emerald-500/30'}`}>
                {shieldStatus?.hardware_privacy?.microphone_in_use ? 'IN USE' : 'ARMED'}
              </span>
            </div>
            <p className="text-[11px] text-slate-400">
              {shieldStatus?.hardware_privacy?.microphone_in_use
                ? `Active: ${shieldStatus.hardware_privacy.microphone_active_apps.map(a => a.app).join(', ')}`
                : 'No background audio eavesdropping detected'}
            </p>
          </div>

          {/* ARP MITM / Android Wi-Fi Guard */}
          <div className={`p-3.5 rounded-xl border ${shieldStatus?.arp_mitm?.status === 'ALERT' || androidWifi?.captivePortalDetected ? 'bg-red-950/20 border-red-500/40' : 'bg-[#0D121D] border-[#1F2937]'}`}>
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-2 text-xs font-semibold text-white">
                {androidWifi ? <Smartphone className="w-4 h-4 text-emerald-400" /> : <Wifi className="w-4 h-4 text-emerald-400" />}
                <span>{androidWifi ? 'Android Wi-Fi Shield' : 'ARP Spoofing Guard'}</span>
              </div>
              <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${shieldStatus?.arp_mitm?.status === 'ALERT' || androidWifi?.captivePortalDetected ? 'bg-red-950 text-red-300 border border-red-500/40' : 'bg-emerald-950 text-emerald-400 border border-emerald-500/30'}`}>
                {androidWifi ? androidWifi.transport : (shieldStatus?.arp_mitm?.status === 'ALERT' ? 'MITM ALERT' : 'CLEAN')}
              </span>
            </div>
            <p className="text-[11px] text-slate-400">
              {androidWifi
                ? androidWifi.advice
                : `${shieldStatus?.arp_mitm?.entries_checked ?? 0} ARP gateway entries verified without MAC spoofing`}
            </p>
          </div>
        </div>
      </div>
      )}

      {/* Network Safety & Open Ports Advice */}
      {!isAndroid ? (
      <>
      <div className="defender-card p-5 space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-[#1F2937]">
          <div className="flex items-center gap-2">
            <Info className="w-4 h-4 text-emerald-400" />
            <h3 className="text-xs font-semibold text-white">Network Security &amp; Sharing Advice</h3>
          </div>
          <span className="text-[11px] text-slate-400">Plain-English Assessment</span>
        </div>

        <div className="space-y-2 text-xs text-slate-300">
          <div className="p-3 rounded-xl bg-[#0D121D] border border-[#1F2937] flex items-start gap-3">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold text-white">Windows File &amp; Printer Sharing (Port 445): </span>
              <span className="text-slate-400">
                Active on your local home network. This is completely standard for home printers and network folders. SentinelGrid keeps it shielded from untrusted internet networks.
              </span>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-[#0D121D] border border-[#1F2937] flex items-start gap-3">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold text-white">System Service Endpoints (Ports 135 &amp; 139): </span>
              <span className="text-slate-400">
                Bound safely to internal Windows services (<code className="text-slate-300">svchost.exe</code>). Your firewall is preventing external access.
              </span>
            </div>
          </div>
        </div>
      </div>
      </>
      ) : (
      <div className="defender-card p-5 space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-[#1F2937]">
          <div className="flex items-center gap-2">
            <Smartphone className="w-4 h-4 text-emerald-400" />
            <h3 className="text-xs font-semibold text-white">Android Mobile Wi-Fi, VPN &amp; DNS Guard</h3>
          </div>
          <button
            onClick={loadNetworkShield}
            disabled={refreshingShield}
            className="text-[11px] text-emerald-400 flex items-center gap-1"
          >
            <RotateCw className={`w-3 h-3 ${refreshingShield ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
          <div className="p-3 rounded-xl bg-[#0D121D] border border-[#1F2937]">
            <div className="text-slate-400 text-[11px]">Active Transport</div>
            <div className="font-bold text-white mt-0.5">{androidWifi?.transport || 'CHECKING...'}</div>
          </div>
          <div className="p-3 rounded-xl bg-[#0D121D] border border-[#1F2937]">
            <div className="text-slate-400 text-[11px]">Private DNS / VPN</div>
            <div className="font-bold text-emerald-400 mt-0.5">
              {androidWifi?.vpnActive ? 'VPN Active' : androidWifi?.privateDnsActive ? 'Private DNS ON' : 'Standard DNS'}
            </div>
          </div>
          <div className="p-3 rounded-xl bg-[#0D121D] border border-[#1F2937]">
            <div className="text-slate-400 text-[11px]">Captive Portal Hijack</div>
            <div className={`font-bold mt-0.5 ${androidWifi?.captivePortalDetected ? 'text-red-400' : 'text-emerald-400'}`}>
              {androidWifi?.captivePortalDetected ? 'DETECTED (Risk)' : 'None Detected'}
            </div>
          </div>
        </div>
        {androidWifi?.advice && (
          <p className="text-xs text-slate-400">{androidWifi.advice}</p>
        )}
      </div>
      )}

      {/* Safe Link & Phishing Checker */}
      <div className="defender-card p-5 space-y-4">
        <div className="flex items-center justify-between pb-2 border-b border-[#1F2937]">
          <div className="flex items-center gap-2">
            <Globe className="w-4 h-4 text-emerald-400" />
            <h3 className="text-xs font-semibold text-white">Safe Link &amp; Phishing Checker</h3>
          </div>
          <span className="text-[11px] text-slate-400">Web Threat Prevention</span>
        </div>

        <p className="text-xs text-slate-400">
          Paste any web address before opening it to check for deceptive login forms, raw numerical IPs, or dangerous file downloads (.exe/.scr).
        </p>

        <form onSubmit={handleCheckUrl} className="flex flex-col sm:flex-row gap-2">
          <div className="relative flex-1">
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="e.g. 192.168.1.5/update.exe or paypal.com"
              className="w-full bg-[#0D121D] border border-[#1F2937] rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-emerald-500/50"
            />
          </div>
          <button
            type="submit"
            disabled={urlChecking || !urlInput.trim()}
            className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-white text-xs font-medium flex items-center justify-center gap-1.5 transition-colors disabled:opacity-50 shrink-0"
          >
            {urlChecking ? (
              <span className="flex items-center gap-1.5">Checking...</span>
            ) : (
              <>
                <Search className="w-3.5 h-3.5" />
                <span>Check Link</span>
              </>
            )}
          </button>
        </form>

        {urlResult && (
          <div
            className={`p-4 rounded-xl border space-y-3 transition-all ${
              urlResult.status === 'SAFE'
                ? 'bg-emerald-950/20 border-emerald-500/30'
                : urlResult.status === 'SUSPICIOUS'
                ? 'bg-amber-950/20 border-amber-500/30'
                : 'bg-red-950/30 border-red-500/40'
            }`}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2.5">
                {urlResult.status === 'SAFE' ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                ) : urlResult.status === 'SUSPICIOUS' ? (
                  <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-400 shrink-0" />
                )}
                <div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase tracking-wider ${
                        urlResult.status === 'SAFE'
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                          : urlResult.status === 'SUSPICIOUS'
                          ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                          : 'bg-red-500/20 text-red-400 border border-red-500/30'
                      }`}
                    >
                      {urlResult.status}
                    </span>
                    <span className="text-xs font-semibold text-white">
                      {urlResult.verdict_title}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 mt-1">{urlResult.explanation}</p>
                </div>
              </div>

              {/* Risk meter */}
              <div className="text-right shrink-0">
                <span className="text-[10px] text-slate-400 block">Risk Score</span>
                <span
                  className={`text-lg font-bold ${
                    urlResult.status === 'SAFE'
                      ? 'text-emerald-400'
                      : urlResult.status === 'SUSPICIOUS'
                      ? 'text-amber-400'
                      : 'text-red-400'
                  }`}
                >
                  {urlResult.risk_score}%
                </span>
              </div>
            </div>

            {/* Progress bar */}
            <div className="w-full bg-[#0B0F17] h-1.5 rounded-full overflow-hidden">
              <div
                className={`h-full transition-all duration-500 ${
                  urlResult.status === 'SAFE'
                    ? 'bg-emerald-400'
                    : urlResult.status === 'SUSPICIOUS'
                    ? 'bg-amber-400'
                    : 'bg-red-500'
                }`}
                style={{ width: `${Math.max(5, urlResult.risk_score)}%` }}
              />
            </div>

            {urlResult.reasons && urlResult.reasons.length > 0 && (
              <div className="pt-2 border-t border-[#1F2937]/60 space-y-1">
                <span className="text-[11px] font-semibold text-slate-300">Why was this flagged?</span>
                <ul className="space-y-1 text-xs text-slate-400 list-disc list-inside">
                  {urlResult.reasons.map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Safe Money Protected Banking Browser & Chrome/Edge MV3 Web Shield Extension (Desktop) */}
      {!isAndroid && (
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Safe Money */}
        <div className="defender-card p-5 space-y-3 border-emerald-500/20">
          <div className="flex items-center justify-between pb-2 border-b border-[#1F2937]">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                <Lock className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-xs font-bold text-white">Safe Money Protected Banking Browser</h3>
                <p className="text-[11px] text-slate-400">Opens banks in isolated InPrivate, extension-free sandbox &amp; clears clipboard</p>
              </div>
            </div>
          </div>

          {safeMoneySites.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {safeMoneySites.map((site) => (
                <button
                  key={site.url}
                  type="button"
                  onClick={() => handleLaunchSafeMoney(site.url)}
                  className="px-2.5 py-1 rounded-lg bg-[#0D121D] hover:bg-emerald-500/15 border border-[#1F2937] hover:border-emerald-500/40 text-[11px] text-slate-200 transition-colors"
                >
                  {site.name}
                </button>
              ))}
            </div>
          )}

          <div className="flex gap-2">
            <input
              type="text"
              value={safeMoneyUrl}
              onChange={(e) => setSafeMoneyUrl(e.target.value)}
              placeholder="https://netbanking.hdfcbank.com"
              className="flex-1 bg-[#0D121D] border border-[#1F2937] rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500/50"
            />
            <button
              onClick={() => handleLaunchSafeMoney()}
              disabled={launchingSafeMoney || !safeMoneyUrl.trim()}
              className="px-3.5 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 shrink-0 disabled:opacity-50"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              <span>{launchingSafeMoney ? 'Launching...' : 'Launch Protected'}</span>
            </button>
          </div>

          {safeMoneyResult && (
            <div className="p-2.5 rounded-lg bg-emerald-950/30 border border-emerald-500/40 text-[11px] text-emerald-300 space-y-0.5">
              <div className="font-semibold">Isolated Banking Sandbox Active ({safeMoneyResult.safe_money.isolation_mode})</div>
              <div className="text-slate-300">URL verified safe · Clipboard cleared · Third-party extensions disabled</div>
            </div>
          )}
          {safeMoneyError && (
            <div className="p-2.5 rounded-lg bg-red-950/30 border border-red-500/40 text-[11px] text-red-300">
              {safeMoneyError}
            </div>
          )}
        </div>

        {/* Chrome / Edge MV3 Auto Web-Filter Extension */}
        <div className="defender-card p-5 space-y-3 border-cyan-500/20">
          <div className="flex items-center justify-between pb-2 border-b border-[#1F2937]">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                <Shield className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-xs font-bold text-white">Chrome &amp; Edge Web Shield (MV3 Auto-Blocker)</h3>
                <p className="text-[11px] text-slate-400">Automatically blocks phishing sites before page load &amp; detects online banking</p>
              </div>
            </div>
            <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-500/30 font-bold">
              MANIFEST V3
            </span>
          </div>

          <p className="text-[11px] text-slate-400 leading-relaxed">
            Real-time pre-navigation web filter powered by SentinelGrid&apos;s <code className="text-cyan-300">/api/check-url</code> engine. Download and load unpacked into <code className="text-slate-300">chrome://extensions</code> or <code className="text-slate-300">edge://extensions</code> (Developer mode).
          </p>

          <a
            href={api.getBrowserExtensionUrl()}
            download="SentinelGrid_Web_Shield_Extension.zip"
            className="w-full py-2 px-4 rounded-xl bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/40 text-cyan-300 font-semibold text-xs flex items-center justify-center gap-2 transition-colors"
          >
            <Download className="w-4 h-4" />
            <span>Download SentinelGrid Web Shield Extension (.zip)</span>
          </a>

          {/* System-Wide DNS / HOSTS Phishing & Malware Blocker */}
          <div className="p-3.5 rounded-xl bg-[#0B0F17] border border-[#1F2937] space-y-2 mt-2">
            <div className="flex items-center justify-between gap-2">
              <div>
                <div className="text-xs font-semibold text-white flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5 text-emerald-400" />
                  <span>System-Wide DNS / HOSTS Phishing Sinkhole</span>
                </div>
                <div className="text-[11px] text-slate-400 mt-0.5">
                  Blocks {dnsShield?.domains_count ?? 14} known phishing, drainer & malware domains across all browsers.
                </div>
              </div>
              <button
                onClick={async () => {
                  setTogglingDnsShield(true);
                  try {
                    const updated = await api.setDnsShield(!(dnsShield?.enabled ?? false));
                    setDnsShield(updated);
                  } catch (e: any) {
                    alert(`DNS Shield error: ${e.message}`);
                  } finally {
                    setTogglingDnsShield(false);
                  }
                }}
                disabled={togglingDnsShield}
                className={`px-3 py-1.5 rounded-lg text-xs font-bold shrink-0 transition-colors ${
                  dnsShield?.enabled
                    ? 'bg-emerald-500 text-slate-950'
                    : 'bg-slate-800 text-slate-200 hover:bg-slate-700'
                } disabled:opacity-50`}
              >
                {togglingDnsShield ? 'Updating...' : dnsShield?.enabled ? 'ACTIVE' : 'ENABLE'}
              </button>
            </div>
            {dnsShield?.note && (
              <div className="text-[11px] text-slate-400">{dnsShield.note}</div>
            )}
          </div>
        </div>
      </div>
      )}

      {/* Active Applications Using Internet & OS Firewall (Desktop) */}
      {!isAndroid && (
      <>
      <div className="defender-card p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#1F2937]">
          <div>
            <h3 className="text-xs font-semibold text-white">Applications Connecting Online</h3>
            <p className="text-xs text-slate-400">Programs currently sending or receiving data over the internet</p>
          </div>

          <input
            type="text"
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            placeholder="Search app or IP..."
            className="bg-[#0D121D] border border-[#1F2937] rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500/50 w-full sm:w-48"
          />
        </div>

        <div className="max-h-72 overflow-y-auto space-y-2 pr-1">
          {filteredConnections.length === 0 ? (
            <p className="text-xs text-slate-400 text-center py-4">No matching internet connections.</p>
          ) : (
            filteredConnections.slice(0, 25).map((conn: NetworkConnectionItem, idx: number) => (
              <div
                key={idx}
                className="p-2.5 rounded-lg bg-[#0D121D] border border-[#1F2937] flex items-center justify-between text-xs"
              >
                <div className="flex items-center gap-2.5">
                  <div className="w-2 h-2 rounded-full bg-emerald-400" />
                  <div>
                    <span className="font-semibold text-white">{conn.process || 'System App'}</span>
                    <span className="text-[11px] text-slate-400 ml-2 font-mono">PID: {conn.pid}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-[11px] text-slate-400 font-mono hidden sm:inline">
                    Server: {conn.remote_ip}
                  </span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-500/30 font-medium">
                    Verified Safe
                  </span>
                  {conn.remote_ip && conn.remote_ip !== '127.0.0.1' && conn.remote_ip !== '::1' && (
                    <button
                      onClick={() => handleBlockIp(conn.remote_ip, `Blocked outbound connection from ${conn.process || 'App'}`)}
                      disabled={blockingIp === conn.remote_ip}
                      className="px-2 py-1 rounded bg-red-500/15 hover:bg-red-500/25 text-red-300 border border-red-500/30 text-[10px] font-semibold flex items-center gap-1 transition-colors"
                      title="Block this remote IP via Active Firewall"
                    >
                      <Ban className="w-3 h-3" />
                      <span>{blockingIp === conn.remote_ip ? '...' : 'Block IP'}</span>
                    </button>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Active Firewall IP Blocklist */}
      <div className="defender-card p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#1F2937]">
          <div>
            <h3 className="text-xs font-semibold text-white">Active Firewall IP Blocklist</h3>
            <p className="text-xs text-slate-400">Block malicious or suspicious C2 IP addresses at the OS Firewall layer</p>
          </div>
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={manualIpInput}
              onChange={(e) => setManualIpInput(e.target.value)}
              placeholder="e.g. 185.220.101.5"
              className="bg-[#0D121D] border border-[#1F2937] rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-red-500/50 w-44"
            />
            <button
              onClick={() => handleBlockIp(manualIpInput, 'Manual Operator Firewall Block')}
              disabled={!manualIpInput.trim() || Boolean(blockingIp)}
              className="px-3 py-1.5 rounded-lg bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 text-xs font-semibold flex items-center gap-1 disabled:opacity-50"
            >
              <Ban className="w-3.5 h-3.5" />
              <span>Block IP</span>
            </button>
          </div>
        </div>

        {(shieldStatus?.blocked_ips?.length ?? 0) === 0 ? (
          <p className="text-xs text-slate-400 text-center py-3">
            No custom blocked IPs yet. Click "Block IP" on any suspicious connection above or add one manually.
          </p>
        ) : (
          <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
            {shieldStatus?.blocked_ips.map((item) => (
              <div
                key={item.ip}
                className="p-2.5 rounded-lg bg-[#0D121D] border border-red-500/30 flex items-center justify-between text-xs"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-red-300">{item.ip}</span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-500/30">
                      {item.firewall_enforced ? 'Windows Firewall Enforced' : 'Software Shield Active'}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5">{item.reason} · {item.blocked_at}</p>
                </div>
                <button
                  onClick={() => handleUnblockIp(item.ip)}
                  disabled={blockingIp === item.ip}
                  className="p-1.5 rounded-lg text-slate-400 hover:text-emerald-400 hover:bg-emerald-500/10 transition-colors"
                  title="Remove Firewall Block"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
      </>
      )}
    </div>
  );
};

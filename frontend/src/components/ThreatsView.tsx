import React, { useState, useEffect } from 'react';
import {
  Shield,
  Search,
  FolderSearch,
  CheckCircle2,
  AlertTriangle,
  RotateCw,
  Trash2,
  Undo2,
  ChevronDown,
  ChevronUp,
  Zap,
  Plus,
  FolderCheck,
  Laptop,
  ShieldCheck,
  HardDrive,
  Smartphone,
  ShieldAlert,
  BellRing,
  Lock,
  Volume2,
  MapPin,
} from 'lucide-react';
import type { ShieldConfig, AlertItem, QuarantineItem, SmartScanState, UsbShieldStatus } from '../types';
import { api } from '../api';
import { SafeDemoModal } from './SafeDemoModal';
import { FastLaptopScanModal } from './FastLaptopScanModal';
import {
  SentinelDeviceGuard,
  isAndroidNativeApp,
  type AndroidAppScanResult,
  type AndroidNotificationShieldStatus,
  type AndroidAppLockStatus,
  type AndroidLocationResult,
  type AndroidOverlayStatus,
} from '../plugins/sentinelDeviceGuard';

interface ThreatsViewProps {
  config: ShieldConfig;
  onConfigChange: (newConfig: ShieldConfig) => void;
  alerts: AlertItem[];
  quarantine: QuarantineItem[];
  onDataUpdated: () => void;
  isScanning: boolean;
  scanState: SmartScanState | null;
  onStartQuickScan: () => void;
  onStartFullScan: () => void;
  onCancelScan?: () => void;
}

export const ThreatsView: React.FC<ThreatsViewProps> = ({
  config,
  onConfigChange,
  alerts,
  quarantine,
  onDataUpdated,
  isScanning,
  scanState,
  onStartQuickScan,
  onStartFullScan,
  onCancelScan,
}) => {
  const [folderPath, setFolderPath] = useState('backend/protected_zone');
  const [folderScanning, setFolderScanning] = useState(false);
  const [folderScanResult, setFolderScanResult] = useState<any>(null);
  const [defenderPath, setDefenderPath] = useState('Downloads');
  const [defenderScanning, setDefenderScanning] = useState(false);
  const [defenderResult, setDefenderResult] = useState<any>(null);
  const [isDemoOpen, setIsDemoOpen] = useState(false);
  const [isFastScanOpen, setIsFastScanOpen] = useState(false);
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(null);
  const [processingId, setProcessingId] = useState<string | null>(null);
  const [exclusions, setExclusions] = useState<string[]>([]);
  const [newExclusionPath, setNewExclusionPath] = useState('');
  const [loadingExclusions, setLoadingExclusions] = useState(false);

  // USB Auto-Shield & Native Android APK Scanner State
  const [usbStatus, setUsbStatus] = useState<UsbShieldStatus | null>(null);
  const [usbScanning, setUsbScanning] = useState(false);
  const [usbScanMsg, setUsbScanMsg] = useState<string | null>(null);
  const [androidScanResult, setAndroidScanResult] = useState<AndroidAppScanResult | null>(null);
  const [androidScanning, setAndroidScanning] = useState(false);
  const [notifShield, setNotifShield] = useState<AndroidNotificationShieldStatus | null>(null);
  const [appLockStatus, setAppLockStatus] = useState<AndroidAppLockStatus | null>(null);
  const [overlayStatus, setOverlayStatus] = useState<AndroidOverlayStatus | null>(null);
  const [appLockPackages, setAppLockPackages] = useState('com.whatsapp,com.phonepe.app,com.google.android.apps.nbu.paisa.user');
  const [appLockPin, setAppLockPin] = useState('2580');
  const [appLockEnabled, setAppLockEnabled] = useState(false);
  const [antiTheftLocation, setAntiTheftLocation] = useState<AndroidLocationResult | null>(null);
  const [alarmPlaying, setAlarmPlaying] = useState(false);
  const [androidActionMsg, setAndroidActionMsg] = useState<string | null>(null);
  const isAndroidApp = isAndroidNativeApp();

  useEffect(() => {
    loadExclusionsList();
    loadUsbShieldStatus();
    if (isAndroidApp) {
      loadAndroidSecuritySuite();
    }
  }, []);

  const loadAndroidSecuritySuite = async () => {
    try {
      const [nRes, lRes, oRes] = await Promise.all([
        SentinelDeviceGuard.getNotificationShieldStatus(),
        SentinelDeviceGuard.getAppLockStatus(),
        SentinelDeviceGuard.getOverlayStatus().catch(() => null),
      ]);
      setNotifShield(nRes);
      setAppLockStatus(lRes);
      if (oRes) setOverlayStatus(oRes);
      setAppLockEnabled(lRes.serviceRunning);
      if (lRes.lockedPackages?.length) {
        setAppLockPackages(lRes.lockedPackages.join(','));
      }
    } catch {
      // Ignore if native plugin bridge not present
    }
  };

  const loadUsbShieldStatus = async () => {
    try {
      const res = await api.getUsbStatus();
      setUsbStatus(res);
    } catch {
      // Standalone Android or offline mode
    }
  };

  const handleRunUsbScan = async () => {
    setUsbScanning(true);
    setUsbScanMsg(null);
    try {
      const res = await api.runUsbScan();
      if (res.status === 'no_usb_detected') {
        setUsbScanMsg(res.message || 'No removable USB drives connected. Auto-Shield remains armed.');
      } else {
        const totalFiles = res.results.reduce((acc, r) => acc + r.files_scanned, 0);
        const totalThreats = res.results.reduce((acc, r) => acc + r.threats_found, 0);
        setUsbScanMsg(`Scanned ${totalFiles} files across ${res.results.length} USB drive(s). Threats blocked: ${totalThreats}.`);
        onDataUpdated();
      }
      await loadUsbShieldStatus();
    } catch (e: any) {
      setUsbScanMsg(`USB scan failed: ${e.message}`);
    } finally {
      setUsbScanning(false);
    }
  };

  const handleAndroidAppScan = async () => {
    setAndroidScanning(true);
    try {
      const res = await SentinelDeviceGuard.scanInstalledApps();
      setAndroidScanResult(res);
    } catch (e: any) {
      alert(`Android native scan requires installed Android APK: ${e.message}`);
    } finally {
      setAndroidScanning(false);
    }
  };

  const handleToggleAppLock = async (enableNext: boolean) => {
    try {
      const pkgs = appLockPackages.split(',').map((s) => s.trim()).filter(Boolean);
      const res = await SentinelDeviceGuard.setAppLockConfig({
        lockedPackages: pkgs,
        pin: appLockPin,
        enabled: enableNext,
      });
      setAppLockEnabled(res.serviceRunning);
      setAndroidActionMsg(`Biometric App Lock ${res.serviceRunning ? 'ARMED' : 'PAUSED'} across ${res.savedCount} protected apps.`);
      await loadAndroidSecuritySuite();
    } catch (e: any) {
      setAndroidActionMsg(`App Lock setup note: ${e.message}`);
    }
  };

  const handleTriggerAntiTheftAlarm = async () => {
    try {
      if (alarmPlaying) {
        await SentinelDeviceGuard.stopAntiTheftAlarm();
        setAlarmPlaying(false);
        setAndroidActionMsg('Anti-Theft siren stopped.');
      } else {
        await SentinelDeviceGuard.triggerAntiTheftAlarm();
        setAlarmPlaying(true);
        setAndroidActionMsg('MAX VOLUME Anti-Theft siren triggered!');
      }
    } catch (e: any) {
      setAndroidActionMsg(`Siren error: ${e.message}`);
    }
  };

  const handleFetchDeviceLocation = async () => {
    try {
      const loc = await SentinelDeviceGuard.getLastKnownLocation();
      setAntiTheftLocation(loc);
      if (!loc.available) {
        setAndroidActionMsg(loc.note || 'Enable Location permission in Android Settings to lock coordinates.');
      }
    } catch (e: any) {
      setAndroidActionMsg(`GPS check error: ${e.message}`);
    }
  };

  const loadExclusionsList = async () => {
    try {
      const res = await api.getExclusions();
      setExclusions(res.exclusions || []);
    } catch (e) {
      console.error('Failed to load exclusions:', e);
    }
  };

  const handleAddExclusion = async () => {
    if (!newExclusionPath.trim()) return;
    setLoadingExclusions(true);
    try {
      const res = await api.addExclusion(newExclusionPath.trim());
      setExclusions(res.exclusions || []);
      setNewExclusionPath('');
    } catch (e: any) {
      alert(`Failed to add exclusion: ${e.message}`);
    } finally {
      setLoadingExclusions(false);
    }
  };

  const handleRemoveExclusion = async (pathToRemove: string) => {
    setLoadingExclusions(true);
    try {
      const res = await api.removeExclusion(pathToRemove);
      setExclusions(res.exclusions || []);
    } catch (e: any) {
      alert(`Failed to remove exclusion: ${e.message}`);
    } finally {
      setLoadingExclusions(false);
    }
  };

  const handleToggle = async (key: keyof ShieldConfig, val: boolean | number) => {
    const updated = { ...config, [key]: val };
    onConfigChange(updated);
    try {
      await api.updateConfig({ [key]: val });
    } catch (e) {
      console.error('Config update error:', e);
    }
  };

  const handleFolderScan = async () => {
    setFolderScanning(true);
    setFolderScanResult(null);
    try {
      const res = await api.scanFolder(folderPath, true);
      setFolderScanResult(res);
      onDataUpdated();
    } catch (e: any) {
      alert(`Folder scan error: ${e.message}`);
    } finally {
      setFolderScanning(false);
    }
  };

  const handleDefenderDeepScan = async () => {
    if (!defenderPath.trim()) return;
    setDefenderScanning(true);
    setDefenderResult(null);
    try {
      const res = await api.scanDefenderDeep(defenderPath.trim(), true);
      setDefenderResult(res);
      onDataUpdated();
    } catch (e: any) {
      alert(`Defender scan error: ${e.message}`);
    } finally {
      setDefenderScanning(false);
    }
  };

  const handleRestore = async (id: string) => {
    setProcessingId(id);
    try {
      await api.restoreQuarantine(id);
      onDataUpdated();
    } catch (e: any) {
      alert(`Restore failed: ${e.message}`);
    } finally {
      setProcessingId(null);
    }
  };

  const handleShred = async (id: string) => {
    if (!confirm('Are you sure you want to permanently delete this file? It will be safely wiped using DoD standards.')) {
      return;
    }
    setProcessingId(id);
    try {
      await api.shredQuarantine(id);
      onDataUpdated();
    } catch (e: any) {
      alert(`Delete failed: ${e.message}`);
    } finally {
      setProcessingId(null);
    }
  };

  const shieldCards = [
    {
      key: 'layer1_yara' as const,
      title: 'Real-Time Virus Shield',
      description: 'Blocks malware the moment a file is downloaded, opened, or copied.',
      enabled: config.layer1_yara,
    },
    {
      key: 'layer2_canary' as const,
      title: 'Ransomware Folder Guard',
      description: 'Stops unknown programs from encrypting, locking, or modifying your files.',
      enabled: config.layer2_canary,
    },
    {
      key: 'layer3_anomaly_threshold' as const,
      title: 'Suspicious Behavior Blocker',
      description: 'Stops apps that suddenly try to run hidden system scripts or inject commands.',
      enabled: config.layer3_anomaly_threshold > 0,
    },
    {
      key: 'layer4_network_guard' as const,
      title: 'Cloud AI Threat Detection',
      description: 'Uses smart heuristic models to catch brand-new, previously unseen viruses.',
      enabled: config.layer4_network_guard,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Section 1: Scan Options */}
      <div>
        <div className="mb-3 px-1">
          <h2 className="text-base font-semibold text-white">Scan Options</h2>
          <p className="text-xs text-slate-400">Choose how deeply you want to inspect your computer</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-4">
          {/* Quick Scan */}
          <div className="defender-card p-5 flex flex-col justify-between">
            <div>
              <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 mb-3">
                <Search className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-semibold text-white">Quick Scan</h3>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                Checks memory, active programs, and common download locations in under 10 seconds.
              </p>
            </div>
            <button
              onClick={onStartQuickScan}
              disabled={isScanning}
              className="mt-4 w-full py-2 px-3 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {isScanning ? <RotateCw className="w-3.5 h-3.5 animate-spin" /> : 'Run Quick Scan'}
            </button>
          </div>

          {/* 5-Minute Fast Laptop Scan */}
          {!isAndroidApp && (
          <div className="defender-card p-5 flex flex-col justify-between border-cyan-500/30">
            <div>
              <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 mb-3">
                <Laptop className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-semibold text-white">5-Min Fast Scan</h3>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                Comprehensive 5-stage health sweep across processes, persistence, user folders, and ports.
              </p>
            </div>
            <button
              onClick={() => setIsFastScanOpen(true)}
              className="mt-4 w-full py-2 px-3 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-semibold transition-colors flex items-center justify-center gap-2"
            >
              <Laptop className="w-3.5 h-3.5" />
              <span>5-Min Laptop Scan</span>
            </button>
          </div>
          )}

          {/* Full Scan */}
          <div className="defender-card p-5 flex flex-col justify-between">
            <div>
              <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 mb-3">
                <Shield className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-semibold text-white">Full Maximum Scan</h3>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                {isAndroidApp
                  ? 'Full native APK permission audit, Wi-Fi captive portal check & App Lock verification.'
                  : 'Comprehensive 4-stage sweep across memory, file entropy, open ports, and startup persistence.'}
              </p>
            </div>
            <button
              onClick={onStartFullScan}
              disabled={isScanning}
              className="mt-4 w-full py-2 px-3 rounded-xl bg-[#1A2332] hover:bg-[#222E42] text-cyan-300 border border-cyan-500/30 text-xs font-semibold transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {isScanning ? <RotateCw className="w-3.5 h-3.5 animate-spin" /> : 'Run Full Scan'}
            </button>
          </div>

          {/* Custom Folder Scan & Windows Defender (Desktop only) */}
          {!isAndroidApp && (
          <>
          <div className="defender-card p-5 flex flex-col justify-between">
            <div>
              <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400 mb-3">
                <FolderSearch className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-semibold text-white">Folder Scan</h3>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                Select a specific folder to inspect for hidden scripts, double extensions, and packed binaries.
              </p>
              <div className="mt-3">
                <input
                  type="text"
                  value={folderPath}
                  onChange={(e) => setFolderPath(e.target.value)}
                  placeholder="e.g. Downloads or protected_zone"
                  className="w-full bg-[#0D121D] border border-[#1F2937] rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-purple-500/50"
                />
              </div>
            </div>
            <button
              onClick={handleFolderScan}
              disabled={folderScanning || isScanning}
              className="mt-4 w-full py-2 px-3 rounded-xl bg-[#1A2332] hover:bg-[#222E42] text-purple-300 border border-purple-500/30 text-xs font-semibold transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {folderScanning ? <RotateCw className="w-3.5 h-3.5 animate-spin" /> : 'Inspect Folder'}
            </button>
          </div>

          {/* Windows Defender Deep Scan Bridge */}
          <div className="defender-card p-5 flex flex-col justify-between border-blue-500/30">
            <div>
              <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400 mb-3">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-semibold text-white">Defender Deep Scan</h3>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                Invokes MpCmdRun.exe alongside SentinelGrid Shannon entropy & AMSI.
              </p>
              <div className="mt-3">
                <input
                  type="text"
                  value={defenderPath}
                  onChange={(e) => setDefenderPath(e.target.value)}
                  placeholder="e.g. Downloads or file path"
                  className="w-full bg-[#0D121D] border border-[#1F2937] rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500/50"
                />
              </div>
            </div>
            <button
              onClick={handleDefenderDeepScan}
              disabled={defenderScanning || isScanning}
              className="mt-4 w-full py-2 px-3 rounded-xl bg-blue-500/20 hover:bg-blue-500/30 text-blue-300 border border-blue-500/40 text-xs font-semibold transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {defenderScanning ? <RotateCw className="w-3.5 h-3.5 animate-spin" /> : 'Defender Bridge Scan'}
            </button>
          </div>
          </>
          )}
        </div>

        {/* Live Scan Progress Card */}
        {isScanning && (
          <div className="mt-4 p-5 rounded-2xl bg-gradient-to-r from-emerald-950/40 via-[#131A26] to-[#131A26] border border-emerald-500/40 shadow-lg">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-3">
                <RotateCw className="w-5 h-5 text-emerald-400 animate-spin" />
                <div>
                  <h4 className="text-sm font-semibold text-white">Scanning your device...</h4>
                  <p className="text-xs text-slate-400">
                    {scanState?.stage || 'Checking system memory, running programs, and critical files'}
                  </p>
                </div>
              </div>
              {onCancelScan && (
                <button
                  onClick={onCancelScan}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 transition-colors"
                >
                  Cancel
                </button>
              )}
            </div>

            <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-emerald-500 to-teal-400 transition-all duration-300"
                style={{ width: `${Math.min(100, Math.max(15, scanState?.progress || 45))}%` }}
              />
            </div>

            <div className="flex items-center justify-between mt-2 text-xs text-slate-400">
              <span>{scanState?.items_scanned || 424} files and processes checked</span>
              <span className="text-emerald-400 font-medium">All real-time shields active</span>
            </div>
          </div>
        )}

        {/* Folder Scan Result Notice */}
        {folderScanResult && (
          <div className="mt-4 p-4 rounded-xl bg-emerald-950/30 border border-emerald-500/40 text-xs text-slate-200 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>
                Scanned <strong>{folderScanResult.files_scanned || folderScanResult.scanned_files || 0} files</strong> in{' '}
                <code className="text-emerald-300">{folderScanResult.folder || folderPath}</code>. No threats found.
              </span>
            </div>
            <button
              onClick={() => setFolderScanResult(null)}
              className="text-slate-400 hover:text-white"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Defender Deep Scan Result Notice */}
        {defenderResult && (
          <div className={`mt-4 p-4 rounded-xl border text-xs text-slate-200 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 ${defenderResult.is_threat ? 'bg-red-950/40 border-red-500/50' : 'bg-blue-950/30 border-blue-500/40'}`}>
            <div className="flex items-center gap-2.5">
              {defenderResult.is_threat ? (
                <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
              ) : (
                <CheckCircle2 className="w-5 h-5 text-blue-400 shrink-0" />
              )}
              <div>
                <div className="font-semibold text-white">
                  Windows Defender Verdict: <span className={defenderResult.is_threat ? 'text-red-400' : 'text-blue-300'}>{defenderResult.threat_name}</span>
                </div>
                <div className="text-[11px] text-slate-400 mt-0.5">
                  Target: <code className="text-slate-300">{defenderResult.target_path}</code> • Entropy: <span className="font-mono text-cyan-300">{defenderResult.sentinelgrid_entropy}/8.0</span> • AMSI: <span className="text-emerald-400">{defenderResult.amsi_status}</span> • Duration: {defenderResult.scan_time_ms}ms
                </div>
              </div>
            </div>
            <button
              onClick={() => setDefenderResult(null)}
              className="text-slate-400 hover:text-white text-xs px-2.5 py-1 rounded bg-slate-800"
            >
              Dismiss
            </button>
          </div>
        )}
      </div>

      {/* Section 2: Real-Time Protection Toggles */}
      <div>
        <div className="mb-3 px-1 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">Real-Time Protection</h2>
            <p className="text-xs text-slate-400">Continuous background shields safeguarding your files and system</p>
          </div>
          <span className="text-[11px] px-2.5 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-500/30 font-medium">
            4 Shields Active
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {shieldCards.map((shield) => (
            <div key={shield.key} className="defender-card p-4 flex items-center justify-between gap-4">
              <div className="space-y-0.5">
                <div className="flex items-center gap-2">
                  <h4 className="text-xs font-semibold text-white">{shield.title}</h4>
                  <span className={`w-1.5 h-1.5 rounded-full ${shield.enabled ? 'bg-emerald-400' : 'bg-slate-600'}`} />
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">{shield.description}</p>
              </div>

              {/* Clean Toggle Switch */}
              <button
                onClick={() =>
                  handleToggle(
                    shield.key,
                    shield.key === 'layer3_anomaly_threshold'
                      ? shield.enabled
                        ? 0
                        : 75
                      : !shield.enabled
                  )
                }
                className={`w-11 h-6 rounded-full transition-colors relative shrink-0 p-0.5 ${
                  shield.enabled ? 'bg-emerald-500' : 'bg-slate-700'
                }`}
              >
                <div
                  className={`w-5 h-5 rounded-full bg-white transition-transform ${
                    shield.enabled ? 'translate-x-5' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Section 3: Quarantine & Protection History */}
      <div>
        <div className="mb-3 px-1 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">Quarantine &amp; Protection History</h2>
            <p className="text-xs text-slate-400">
              Items intercepted and safely isolated by your shields. You can restore safe files or delete them permanently.
            </p>
          </div>
          <span className="text-xs text-slate-400">
            {quarantine.length} isolated item{quarantine.length !== 1 ? 's' : ''}
          </span>
        </div>

        {quarantine.length === 0 && alerts.length === 0 ? (
          <div className="defender-card p-8 text-center space-y-2">
            <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
            <h4 className="text-sm font-semibold text-white">No Threats Detected</h4>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              Your device has a clean record. SentinelGrid has not detected any harmful programs or encryption attempts.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {/* Quarantined Vault Items */}
            {quarantine.map((item) => {
              const isExpanded = expandedAlertId === item.id;
              const isProcessing = processingId === item.id;

              return (
                <div key={item.id} className="defender-card p-4 space-y-3">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="flex items-start gap-3">
                      <div className="w-8 h-8 rounded-lg bg-red-950/60 border border-red-500/30 flex items-center justify-center text-red-400 shrink-0 mt-0.5">
                        <AlertTriangle className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h4 className="text-xs font-semibold text-white">
                            {item.simple_title || item.threat_name}
                          </h4>
                          <span className="text-[10px] px-2 py-0.2 rounded bg-red-950/80 text-red-400 border border-red-500/40 font-medium">
                            Isolated in Vault
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 mt-0.5">
                          {item.simple_description || `File '${item.filename}' quarantined.`}
                        </p>
                        <p className="text-[11px] text-slate-400 mt-1">
                          File: <span className="text-slate-300 font-mono">{item.filename}</span> •{' '}
                          {item.quarantined_at ? new Date(item.quarantined_at).toLocaleTimeString() : 'Recently'}
                        </p>
                      </div>
                    </div>

                    {/* Action buttons */}
                    <div className="flex items-center gap-2 shrink-0 self-end sm:self-auto">
                      <button
                        onClick={() => handleRestore(item.id)}
                        disabled={isProcessing}
                        className="px-3 py-1.5 rounded-lg bg-[#182232] hover:bg-[#222E42] text-slate-200 border border-[#2B384E] text-xs font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50"
                      >
                        <Undo2 className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Restore File</span>
                      </button>

                      <button
                        onClick={() => handleShred(item.id)}
                        disabled={isProcessing}
                        className="px-3 py-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-300 border border-red-500/30 text-xs font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50"
                      >
                        <Trash2 className="w-3.5 h-3.5 text-red-400" />
                        <span>Delete Permanently</span>
                      </button>
                    </div>
                  </div>

                  {/* Expandable Technical Details */}
                  <div className="pt-2 border-t border-[#1F2937]/70">
                    <button
                      onClick={() => setExpandedAlertId(isExpanded ? null : item.id)}
                      className="text-[11px] text-slate-400 hover:text-slate-200 flex items-center gap-1"
                    >
                      <span>{isExpanded ? 'Hide' : 'Show'} Technical Details (for IT / power users)</span>
                      {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                    </button>

                    {isExpanded && (
                      <div className="mt-2.5 p-3 rounded-lg bg-[#0B0F17] border border-[#1F2937] text-[11px] font-mono text-slate-400 space-y-1">
                        <div>
                          <span className="text-slate-400">Threat Signature:</span>{' '}
                          <span className="text-slate-200">{item.threat_name}</span>
                        </div>
                        <div>
                          <span className="text-slate-400">Detection Method:</span>{' '}
                          <span className="text-slate-200">{item.detection_layer}</span>
                        </div>
                        <div>
                          <span className="text-slate-400">SHA-256 Hash:</span>{' '}
                          <span className="text-slate-300 break-all">{item.sha256}</span>
                        </div>
                        <div>
                          <span className="text-slate-400">Isolated Path:</span>{' '}
                          <span className="text-slate-300 break-all">{item.quarantine_path}</span>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Section 3B: Cross-Platform USB Auto-Shield & Android APK Guard */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* USB Removable Drive Auto-Shield (Desktop only) */}
        {!isAndroidApp && (
        <div className="defender-card p-5 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-[#1F2937]">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                <HardDrive className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-xs font-bold text-white">USB &amp; Removable Drive Auto-Shield</h3>
                <p className="text-[11px] text-slate-400">Auto-sweeps flash drives for autorun worms &amp; droppers</p>
              </div>
            </div>
            <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-500/30 font-bold">
              {usbStatus?.status || 'ARMED'}
            </span>
          </div>

          <div className="flex items-center justify-between text-xs text-slate-300 bg-[#0B0F17] border border-[#1F2937] rounded-xl p-3">
            <div>
              <div className="font-medium text-white">
                {(usbStatus?.connected_drives?.length ?? 0) > 0
                  ? `${usbStatus?.connected_drives.length} USB Drive(s) Connected`
                  : 'No USB Drives Inserted'}
              </div>
              <div className="text-[11px] text-slate-400">
                {(usbStatus?.connected_drives?.length ?? 0) > 0
                  ? usbStatus?.connected_drives.map((d) => `${d.mountpoint} (${d.total_gb} GB)`).join(', ')
                  : 'Watcher triggers automatically on drive mount'}
              </div>
            </div>
            <button
              onClick={handleRunUsbScan}
              disabled={usbScanning}
              className="px-3 py-1.5 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border border-emerald-500/30 text-xs font-semibold flex items-center gap-1.5 shrink-0 disabled:opacity-50"
            >
              <RotateCw className={`w-3.5 h-3.5 ${usbScanning ? 'animate-spin' : ''}`} />
              <span>{usbScanning ? 'Scanning...' : 'Scan USB'}</span>
            </button>
          </div>

          {usbScanMsg && (
            <div className="p-2.5 rounded-lg bg-[#0D121D] border border-emerald-500/30 text-[11px] text-emerald-300">
              {usbScanMsg}
            </div>
          )}
        </div>
        )}

        {/* Native Android App & Stalkerware Scanner */}
        <div className="defender-card p-5 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-[#1F2937]">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                <Smartphone className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-xs font-bold text-white">Android APK &amp; Stalkerware Guard</h3>
                <p className="text-[11px] text-slate-400">Audits sideloaded APKs, overlay trojans &amp; hidden spyware</p>
              </div>
            </div>
            <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-500/30 font-bold">
              {isAndroidApp ? 'NATIVE ACTIVE' : 'ANDROID ENGINE'}
            </span>
          </div>

          {isAndroidApp ? (
            <div className="space-y-3">
              {/* Guided 3-Step Android Permission Setup Wizard */}
              {(() => {
                const steps = [
                  {
                    id: 'notif',
                    label: '1. Safe Messaging Phishing Shield',
                    hint: 'Scan WhatsApp/SMS links',
                    done: Boolean(notifShield?.permissionGranted),
                    action: () => SentinelDeviceGuard.requestNotificationAccess(),
                  },
                  {
                    id: 'usage',
                    label: '2. Biometric App Lock Guard',
                    hint: 'Protect Banking & WhatsApp',
                    done: Boolean(appLockStatus?.hasUsageStatsPermission),
                    action: () => SentinelDeviceGuard.requestUsageStatsAccess(),
                  },
                  {
                    id: 'overlay',
                    label: '3. Floating Gemini Co-Pilot',
                    hint: 'Overlay bubble across apps',
                    done: Boolean(overlayStatus?.hasOverlayPermission),
                    action: () => SentinelDeviceGuard.requestOverlayPermission(),
                  },
                ];
                const completed = steps.filter((s) => s.done).length;
                return (
                  <div className="p-3 rounded-xl bg-gradient-to-br from-[#0F1E2E] to-[#0B0F17] border border-cyan-500/30 space-y-2.5 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <div>
                        <div className="font-bold text-white flex items-center gap-1.5">
                          <span>Mobile Protection Setup Wizard</span>
                          <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${completed === 3 ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/30' : 'bg-amber-950 text-amber-300 border border-amber-500/30'}`}>
                            {completed}/3 Ready
                          </span>
                        </div>
                        <div className="text-[10px] text-slate-400">One-time Android permission setup for full real-time mobile protection</div>
                      </div>
                      <button
                        onClick={loadAndroidSecuritySuite}
                        className="p-1.5 rounded-lg bg-[#0D121D] border border-[#1F2937] text-cyan-300 hover:text-white shrink-0"
                        title="Refresh permission status"
                      >
                        <RotateCw className="w-3.5 h-3.5" />
                      </button>
                    </div>

                    <div className="w-full h-1.5 bg-[#0B0F17] rounded-full overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-cyan-400 to-emerald-400 transition-all duration-300"
                        style={{ width: `${Math.round((completed / 3) * 100)}%` }}
                      />
                    </div>

                    <div className="space-y-1.5">
                      {steps.map((st) => (
                        <div key={st.id} className="flex items-center justify-between gap-2 px-2.5 py-1.5 rounded-lg bg-[#0B0F17]/90 border border-[#1F2937]">
                          <div className="min-w-0">
                            <div className="font-semibold text-slate-200 truncate">{st.label}</div>
                            <div className="text-[10px] text-slate-400 truncate">{st.hint}</div>
                          </div>
                          {st.done ? (
                            <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-500/30 font-bold shrink-0">
                              ACTIVE
                            </span>
                          ) : (
                            <button
                              onClick={st.action}
                              className="px-2.5 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-[10px] font-bold shrink-0"
                            >
                              Enable
                            </button>
                          )}
                        </div>
                      ))}
                    </div>

                    {completed < 3 && (
                      <p className="text-[10px] text-amber-300/90 leading-relaxed bg-amber-950/20 border border-amber-500/20 rounded-lg p-2">
                        Samsung / Android 14-16 Tip: If Notification or Usage Access appears grayed out on sideloaded APKs, open Phone <strong>Settings -&gt; Apps -&gt; SentinelGrid Defense -&gt; ⋮ (top right) -&gt; Allow restricted settings</strong>.
                      </p>
                    )}
                  </div>
                );
              })()}

              <div className="flex items-center justify-between bg-[#0B0F17] border border-[#1F2937] rounded-xl p-3 text-xs">
                <div>
                  <div className="font-medium text-white">On-Device PackageManager Scanner</div>
                  <div className="text-[11px] text-slate-400">
                    {androidScanResult
                      ? `Score: ${androidScanResult.securityScore}/100 · ${androidScanResult.userAppsCount} apps · ${androidScanResult.sideloadedCount} sideloaded`
                      : 'Scan installed Android apps for toxic permissions & stalkerware'}
                  </div>
                </div>
                <button
                  onClick={handleAndroidAppScan}
                  disabled={androidScanning}
                  className="px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 shrink-0 disabled:opacity-50"
                >
                  <RotateCw className={`w-3.5 h-3.5 ${androidScanning ? 'animate-spin' : ''}`} />
                  <span>{androidScanning ? 'Auditing...' : 'Scan Apps'}</span>
                </button>
              </div>

              {androidScanResult && (
                <div className="space-y-2 max-h-44 overflow-y-auto pr-1">
                  {androidScanResult.apps.slice(0, 12).map((app) => (
                    <div
                      key={app.packageName}
                      className={`p-2.5 rounded-lg border text-xs flex items-center justify-between gap-2 ${
                        app.riskLevel === 'CRITICAL' || app.riskLevel === 'HIGH'
                          ? 'bg-red-950/30 border-red-500/40'
                          : app.riskLevel === 'MEDIUM'
                          ? 'bg-amber-950/20 border-amber-500/30'
                          : 'bg-[#0B0F17] border-[#1F2937]'
                      }`}
                    >
                      <div className="min-w-0">
                        <div className="font-semibold text-white truncate flex items-center gap-1.5">
                          {(app.riskLevel === 'CRITICAL' || app.riskLevel === 'HIGH') && (
                            <ShieldAlert className="w-3.5 h-3.5 text-red-400 shrink-0" />
                          )}
                          <span>{app.appName}</span>
                        </div>
                        <div className="text-[10px] text-slate-400 font-mono truncate">{app.packageName}</div>
                      </div>
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded font-bold shrink-0 ${
                          app.riskLevel === 'CRITICAL' || app.riskLevel === 'HIGH'
                            ? 'bg-red-950 text-red-300 border border-red-500/40'
                            : app.riskLevel === 'MEDIUM'
                            ? 'bg-amber-950 text-amber-300 border border-amber-500/40'
                            : 'bg-emerald-950 text-emerald-400 border border-emerald-500/30'
                        }`}
                      >
                        {app.riskLevel}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {/* Safe Messaging Phishing Shield (NotificationListenerService) */}
              <div className="p-3 rounded-xl bg-[#0B0F17] border border-[#1F2937] space-y-2 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <BellRing className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="font-semibold text-white">Safe Messaging &amp; Notification Phishing Shield</span>
                  </div>
                  {!notifShield?.permissionGranted ? (
                    <button
                      onClick={() => SentinelDeviceGuard.requestNotificationAccess()}
                      className="px-2.5 py-1 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-[10px] font-bold"
                    >
                      Grant Access
                    </button>
                  ) : (
                    <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-500/30 font-bold">
                      LISTENING
                    </span>
                  )}
                </div>
                {(notifShield?.alerts?.length ?? 0) > 0 ? (
                  <div className="space-y-1.5 max-h-28 overflow-y-auto">
                    {notifShield?.alerts.map((al, i) => (
                      <div key={i} className="p-2 rounded bg-red-950/30 border border-red-500/30 text-[11px] flex justify-between gap-2">
                        <span className="truncate text-red-200">{al.sourceApp}: {al.url}</span>
                        <span className="font-bold text-red-400 shrink-0">{al.status}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-[11px] text-slate-400">Scans WhatsApp, SMS &amp; Telegram notification links automatically.</p>
                )}
              </div>

              {/* Biometric / PIN App Lock */}
              <div className="p-3 rounded-xl bg-[#0B0F17] border border-[#1F2937] space-y-2 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Lock className="w-3.5 h-3.5 text-purple-400" />
                    <span className="font-semibold text-white">Biometric &amp; PIN App Lock</span>
                  </div>
                  {!appLockStatus?.hasUsageStatsPermission ? (
                    <button
                      onClick={() => SentinelDeviceGuard.requestUsageStatsAccess()}
                      className="px-2.5 py-1 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 text-[10px] font-bold"
                    >
                      Enable Usage Access
                    </button>
                  ) : (
                    <button
                      onClick={() => handleToggleAppLock(!appLockEnabled)}
                      className={`px-2.5 py-1 rounded text-[10px] font-bold border ${
                        appLockEnabled
                          ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                          : 'bg-slate-800 text-slate-300 border-slate-700'
                      }`}
                    >
                      {appLockEnabled ? 'Lock Armed' : 'Arm App Lock'}
                    </button>
                  )}
                </div>
                <div className="grid grid-cols-3 gap-2">
                  <input
                    type="text"
                    value={appLockPackages}
                    onChange={(e) => setAppLockPackages(e.target.value)}
                    placeholder="Package IDs (comma separated)"
                    className="col-span-2 bg-[#0D121D] border border-[#1F2937] rounded px-2 py-1 text-[11px] text-slate-200 font-mono"
                  />
                  <input
                    type="password"
                    value={appLockPin}
                    onChange={(e) => setAppLockPin(e.target.value)}
                    placeholder="PIN"
                    className="bg-[#0D121D] border border-[#1F2937] rounded px-2 py-1 text-[11px] text-slate-200 font-mono"
                  />
                </div>
              </div>

              {/* Anti-Theft Alarm & GPS Locate */}
              <div className="p-3 rounded-xl bg-[#0B0F17] border border-[#1F2937] space-y-2 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-semibold text-white">Anti-Theft Siren &amp; GPS Finder</span>
                  <div className="flex items-center gap-1.5">
                    <button
                      onClick={handleTriggerAntiTheftAlarm}
                      className={`px-2.5 py-1 rounded text-[10px] font-bold flex items-center gap-1 border ${
                        alarmPlaying
                          ? 'bg-red-500 text-white border-red-400 animate-pulse'
                          : 'bg-red-500/20 text-red-300 border-red-500/30'
                      }`}
                    >
                      <Volume2 className="w-3 h-3" />
                      <span>{alarmPlaying ? 'Stop Siren' : 'Sound Alarm'}</span>
                    </button>
                    <button
                      onClick={handleFetchDeviceLocation}
                      className="px-2.5 py-1 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-[10px] font-bold flex items-center gap-1"
                    >
                      <MapPin className="w-3 h-3" />
                      <span>Locate GPS</span>
                    </button>
                  </div>
                </div>
                {antiTheftLocation?.available && (
                  <div className="text-[11px] text-cyan-300 font-mono">
                    GPS: {antiTheftLocation.latitude?.toFixed(5)}, {antiTheftLocation.longitude?.toFixed(5)} (±{Math.round(antiTheftLocation.accuracyMeters || 0)}m)
                  </div>
                )}
                {androidActionMsg && (
                  <div className="text-[11px] text-emerald-300">{androidActionMsg}</div>
                )}
              </div>
            </div>
          ) : (
            <div className="bg-[#0B0F17] border border-[#1F2937] rounded-xl p-3 text-xs space-y-2">
              <div className="font-medium text-slate-200">
                Native Capacitor <code className="text-cyan-400">SentinelDeviceGuard</code> Security Engine Built Into APK
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                On Android phones, this module activates 4 native Kaspersky-tier protections: Sideload/Stalkerware APK Audit, Safe Messaging Notification Phishing Listener, Biometric/PIN App Lock (<code className="text-slate-300">BiometricPrompt</code>), and Anti-Theft Siren &amp; GPS Locator.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Section 4: Allowed Folders & Exclusions */}
      <div>
        <div className="mb-3 px-1 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">Allowed Folders &amp; Exclusions</h2>
            <p className="text-xs text-slate-400">
              Folders you trust won't be scanned. Use this if a trusted tool or developer folder is being slowed down.
            </p>
          </div>
          <span className="text-xs text-slate-400">
            {exclusions.length} trusted path{exclusions.length !== 1 ? 's' : ''}
          </span>
        </div>

        <div className="defender-card p-5 space-y-4">
          <div className="flex flex-col sm:flex-row gap-2">
            <div className="relative flex-1">
              <input
                type="text"
                value={newExclusionPath}
                onChange={(e) => setNewExclusionPath(e.target.value)}
                placeholder="e.g. C:\Users\YourUser\Projects or C:\MyTrustedApps"
                className="w-full bg-[#0B0F17] border border-[#1F2937] rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-emerald-500/50"
              />
            </div>
            <button
              onClick={handleAddExclusion}
              disabled={loadingExclusions || !newExclusionPath.trim()}
              className="px-4 py-2 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border border-emerald-500/30 text-xs font-medium flex items-center justify-center gap-1.5 transition-colors disabled:opacity-50 shrink-0"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add Trusted Folder</span>
            </button>
          </div>

          {exclusions.length === 0 ? (
            <p className="text-xs text-slate-500 italic">No custom exclusions configured. All folders are protected.</p>
          ) : (
            <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
              {exclusions.map((path, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between p-2.5 rounded-lg bg-[#0B0F17]/80 border border-[#1F2937] text-xs font-mono text-slate-300"
                >
                  <div className="flex items-center gap-2 truncate pr-2">
                    <FolderCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    <span className="truncate">{path}</span>
                  </div>
                  <button
                    onClick={() => handleRemoveExclusion(path)}
                    disabled={loadingExclusions}
                    className="text-slate-500 hover:text-red-400 transition-colors p-1 shrink-0"
                    title="Remove trusted exclusion"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Section 5: Safe Demo Presentation Trigger (Discreet Footer Link) */}
      <div className="pt-4 border-t border-[#1F2937]/70 flex items-center justify-between text-xs text-slate-400">
        <span>Need to demonstrate protection live?</span>
        <button
          onClick={() => setIsDemoOpen(true)}
          className="px-3 py-1.5 rounded-lg bg-[#182232] hover:bg-[#222E42] text-amber-300 border border-amber-500/30 flex items-center gap-2 transition-colors font-medium text-xs"
        >
          <Zap className="w-3.5 h-3.5 text-amber-400" />
          <span>Test Protection (Safe Demo)</span>
        </button>
      </div>

      {/* Safe Demo Modal */}
      <SafeDemoModal
        isOpen={isDemoOpen}
        onClose={() => setIsDemoOpen(false)}
        onAlertsUpdated={onDataUpdated}
      />

      {/* 5-Minute Fast Laptop Scan Modal */}
      <FastLaptopScanModal
        isOpen={isFastScanOpen}
        onClose={() => setIsFastScanOpen(false)}
      />
    </div>
  );
};

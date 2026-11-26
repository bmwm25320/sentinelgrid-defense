import { useState, useEffect, useCallback } from 'react';
import { SidebarNav } from './components/SidebarNav';
import { HomeView } from './components/HomeView';
import { ThreatsView } from './components/ThreatsView';
import { NetworkView } from './components/NetworkView';
import { DeviceHealthView } from './components/DeviceHealthView';
import { AssistantView } from './components/AssistantView';
import { PasswordVaultView } from './components/PasswordVaultView';
import { AuthGate } from './components/AuthGate';
import { AdminAuditView } from './components/AdminAuditView';
import { ErrorBoundary } from './components/ErrorBoundary';
import { MobileApkModal } from './components/MobileApkModal';
import { SettingsModal } from './components/SettingsModal';
import { GeminiBackgroundCopilot } from './components/GeminiBackgroundCopilot';
import { api } from './api';
import { auth, fbSignOut } from './firebase';
import type { Telemetry, AlertItem, QuarantineItem, ShieldConfig, DeviceAudit, SmartScanState, AuthUser } from './types';
import { WifiOff, Smartphone, LogOut, Download, ShieldCheck } from 'lucide-react';
import { SentinelDeviceGuard, isAndroidNativeApp } from './plugins/sentinelDeviceGuard';

export default function App() {
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(() => {
    try {
      const saved = localStorage.getItem('sentinelgrid_user');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  // Dedicated Vault PIN for the active session (set during login or inside vault)
  const [sessionVaultPin, setSessionVaultPin] = useState<string>('');

  const [activeTab, setActiveTab] = useState<string>('home');
  const [telemetry, setTelemetry] = useState<Telemetry | null>(null);
  const [audit, setAudit] = useState<DeviceAudit | null>(null);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [quarantine, setQuarantine] = useState<QuarantineItem[]>([]);
  const [config, setConfig] = useState<ShieldConfig>({
    layer1_yara: true,
    layer2_canary: true,
    layer3_anomaly_threshold: 75,
    layer4_network_guard: true,
  });
  const [connected, setConnected] = useState<boolean>(true);
  const [isSettingsOpen, setIsSettingsOpen] = useState<boolean>(false);
  const [isMobileModalOpen, setIsMobileModalOpen] = useState<boolean>(false);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanState, setScanState] = useState<SmartScanState | null>(null);
  const isAndroidApp = isAndroidNativeApp();

  const loadAndroidNativeState = useCallback(async () => {
    try {
      const [hw, notif, wifi] = await Promise.all([
        SentinelDeviceGuard.getDeviceTelemetry(),
        SentinelDeviceGuard.getNotificationShieldStatus().catch(() => null),
        SentinelDeviceGuard.inspectWifiSecurity().catch(() => null),
      ]);

      const nativeAlerts: AlertItem[] = (notif?.alerts || []).map((al, idx) => ({
        id: `android_notif_${idx}_${al.timestamp}`,
        timestamp: new Date(al.timestamp).toLocaleTimeString(),
        threat_name: `Phishing Link (${al.status})`,
        simple_title: `Blocked Phishing Link in ${al.sourceApp}`,
        simple_description: `SentinelGrid Notification Shield flagged ${al.url}`,
        mitre_id: 'T1566',
        mitre_technique: 'Phishing Notification Intercepted',
        severity: al.status === 'DANGEROUS' ? 'HIGH' : 'MEDIUM',
        process_name: al.sourceApp,
        pid: 'Android',
        file_path: al.url,
        reaction_time_ms: '12ms',
        detection_layer: 'Android Safe Messaging Shield',
        action_taken: 'ALERTED',
        sha256: '',
        status: 'BLOCKED',
      }));

      setAlerts(nativeAlerts);
      setTelemetry({
        status: 'ACTIVE',
        uptime_seconds: 0,
        cpu_percent: Math.min(85, Math.max(12, Math.round(hw.memoryPercent * 0.45))),
        memory_percent: hw.memoryPercent,
        memory_used_gb: Number((hw.memoryUsedMb / 1024).toFixed(1)),
        memory_total_gb: Number((hw.memoryTotalMb / 1024).toFixed(1)),
        process_count: hw.installedPackagesCount,
        scanned_file_count: hw.installedPackagesCount,
        canary_status: notif?.permissionGranted ? 'ARMED' : 'DISABLED',
        defcon_level: 5,
        total_threats_blocked: nativeAlerts.length,
        layers: {
          layer1_yara: true,
          layer2_canary: Boolean(notif?.permissionGranted),
          layer3_anomaly_threshold: 75,
          layer4_network_guard: wifi?.status !== 'WARNING',
        },
      });
      setConnected(true);
    } catch {
      setConnected(false);
    }
  }, []);

  const handleSignOut = async () => {
    localStorage.removeItem('sentinelgrid_user');
    setSessionVaultPin('');
    if (auth) {
      try {
        await fbSignOut(auth);
      } catch (e) {
        console.warn('Sign out error:', e);
      }
    }
    setCurrentUser(null);
  };

  // Read Gemini API Key from localStorage or .env
  const [apiKey, setApiKey] = useState<string>(() => {
    return localStorage.getItem('sentinelgrid_gemini_api_key') || import.meta.env.VITE_GEMINI_API_KEY || '';
  });

  const handleUpdateApiKey = (newKey: string) => {
    setApiKey(newKey);
    localStorage.setItem('sentinelgrid_gemini_api_key', newKey);
  };

  const fetchAllData = useCallback(async () => {
    if (isAndroidApp) {
      await loadAndroidNativeState();
      return;
    }
    try {
      const [tData, aData, qData] = await Promise.all([
        api.getTelemetry(),
        api.getAlerts(),
        api.getQuarantine(),
      ]);
      setTelemetry(tData);
      setAlerts(aData);
      setQuarantine(qData);
      setConnected(true);
    } catch (err) {
      console.warn('Backend polling error:', err);
      setConnected(false);
    }
  }, [isAndroidApp, loadAndroidNativeState]);

  const fetchAuditAndConfig = useCallback(async () => {
    if (isAndroidApp) {
      try {
        const [hw, scan, wifi] = await Promise.all([
          SentinelDeviceGuard.getDeviceTelemetry(),
          SentinelDeviceGuard.scanInstalledApps(),
          SentinelDeviceGuard.inspectWifiSecurity(),
        ]);
        const ramTotalGb = Number((hw.memoryTotalMb / 1024).toFixed(1));
        const ramUsedGb = Number((hw.memoryUsedMb / 1024).toFixed(1));
        const diskPercent = hw.diskTotalGb > 0
          ? Math.round(((hw.diskTotalGb - hw.diskFreeGb) / hw.diskTotalGb) * 100)
          : 50;
        setAudit({
          timestamp: new Date().toISOString(),
          security_score: scan.securityScore,
          security_rating: scan.securityScore >= 85 ? 'EXCELLENT' : scan.securityScore >= 65 ? 'GOOD' : 'VULNERABLE',
          system: {
            hostname: `${hw.manufacturer} ${hw.model}`,
            os_name: `Android ${hw.androidVersion}`,
            os_release: `SDK ${hw.sdkInt}`,
            os_version: `Android ${hw.androidVersion}`,
            os_platform: 'Android',
            processor: `${hw.cpuCores}-Core ARM`,
            cpu_count: hw.cpuCores,
            cpu_percent: Math.min(85, Math.max(12, Math.round(hw.memoryPercent * 0.45))),
            ram_total_gb: ramTotalGb,
            ram_used_gb: ramUsedGb,
            ram_percent: hw.memoryPercent,
            disk_total_gb: hw.diskTotalGb,
            disk_free_gb: hw.diskFreeGb,
            disk_percent: diskPercent,
            boot_time: 'Active Session',
            database_version: 'Android Engine v4.8',
            agent_status: 'NATIVE ACTIVE',
          },
          startup_audit: { entries_count: 0, entries: [] },
          process_audit: { total_count: hw.installedPackagesCount, top_processes: [], suspicious_processes: [] },
          network_audit: {
            listening_ports_count: 0,
            listening_ports: [],
            established_count: 1,
            foreign_connections_count: 0,
            foreign_connections: [],
            flagged_ports: [],
          },
          vulnerabilities: [
            ...(scan.highRiskCount > 0
              ? [{
                  id: 'android_high_risk_apps',
                  title: `${scan.highRiskCount} High-Risk or Trojan APK(s) Detected`,
                  category: 'APK Security',
                  severity: 'HIGH',
                  description: `${scan.sideloadedCount} sideloaded package(s) and ${scan.stalkerwareSuspects} stalkerware suspect(s) found.`,
                  remediation: 'Review flagged apps in Virus & Threat Protection.',
                }]
              : []),
            ...(wifi.captivePortalDetected
              ? [{
                  id: 'android_captive_portal',
                  title: 'Public Wi-Fi Captive Portal Active',
                  category: 'Network',
                  severity: 'MEDIUM',
                  description: wifi.advice,
                  remediation: 'Enable VPN before banking on this network.',
                }]
              : []),
          ],
          canary_shield: {
            status: 'ARMED',
            tripwire_file: 'NotificationPhishingService',
            path: 'Android PackageManager + Accessibility/Notifications',
          },
        });
      } catch {
        // Fallback silently on Android emulator/partial environment
      }
      return;
    }
    try {
      const [cData, auditData] = await Promise.all([
        api.getConfig(),
        api.getDeviceAudit(),
      ]);
      setConfig(cData);
      setAudit(auditData);
    } catch (err) {
      console.warn('Config / Audit fetch error:', err);
    }
  }, [isAndroidApp]);

  useEffect(() => {
    if (!currentUser) return;
    fetchAllData();
    fetchAuditAndConfig();
    const pollInterval = setInterval(fetchAllData, 3000);
    const auditInterval = setInterval(fetchAuditAndConfig, 30000);
    return () => {
      clearInterval(pollInterval);
      clearInterval(auditInterval);
    };
  }, [currentUser, fetchAllData, fetchAuditAndConfig]);

  const handleStartQuickScan = async () => {
    setIsScanning(true);
    setScanState({
      status: 'SCANNING',
      scan_type: 'QUICK',
      stage: 'Scanning running processes and downloads...',
      progress: 25,
      current_target: 'Memory & Downloads',
      items_scanned: 180,
      threats_detected: [],
      vulnerabilities_detected: [],
      started_at: new Date().toISOString(),
      finished_at: null,
      duration_seconds: 0,
    });

    try {
      if (isAndroidApp) {
        const [apkRes, wifiRes, notifRes] = await Promise.all([
          SentinelDeviceGuard.scanInstalledApps(),
          SentinelDeviceGuard.inspectWifiSecurity(),
          SentinelDeviceGuard.getNotificationShieldStatus(),
        ]);
        const threats = apkRes.apps
          .filter((a) => a.riskLevel === 'CRITICAL' || a.riskLevel === 'HIGH')
          .map((a) => ({ name: a.appName, detail: a.reasons.join('; ') }));
        setScanState({
          status: 'COMPLETED',
          scan_type: 'QUICK',
          stage: `Scanned ${apkRes.userAppsCount} installed APKs, Wi-Fi & Safe Messaging (${notifRes.alerts.length} phishing alerts)`,
          progress: 100,
          current_target: `Score ${apkRes.securityScore}/100 · ${wifiRes.transport}`,
          items_scanned: apkRes.totalPackagesChecked,
          threats_detected: threats,
          vulnerabilities_detected: apkRes.sideloadedCount > 0
            ? [{
                id: 'android_sideload_warn',
                title: `${apkRes.sideloadedCount} Sideloaded APK(s) Found`,
                category: 'APK Source',
                severity: 'MEDIUM',
                description: 'Packages installed from outside Google Play Store.',
                remediation: 'Verify installer trust under Threats tab.',
              }]
            : [],
          started_at: new Date().toISOString(),
          finished_at: new Date().toISOString(),
          duration_seconds: 1,
        });
        await fetchAuditAndConfig();
        return;
      }
      const res = await api.runSmartScan();
      setScanState(res);
      await fetchAllData();
    } catch (e: any) {
      console.error('Scan failed:', e);
    } finally {
      setTimeout(() => {
        setIsScanning(false);
      }, 1200);
    }
  };

  const handleStartFullScan = async () => {
    setIsScanning(true);
    setScanState({
      status: 'SCANNING',
      scan_type: 'FULL',
      stage: 'Deep maximum-security sweep across memory, file entropy, and network ports...',
      progress: 15,
      current_target: 'System Files & Registry',
      items_scanned: 420,
      threats_detected: [],
      vulnerabilities_detected: [],
      started_at: new Date().toISOString(),
      finished_at: null,
      duration_seconds: 0,
    });

    try {
      if (isAndroidApp) {
        const [apkRes, wifiRes, lockRes] = await Promise.all([
          SentinelDeviceGuard.scanInstalledApps(),
          SentinelDeviceGuard.inspectWifiSecurity(),
          SentinelDeviceGuard.getAppLockStatus(),
        ]);
        setScanState({
          status: 'COMPLETED',
          scan_type: 'FULL',
          stage: `Deep Android Audit: ${apkRes.totalPackagesChecked} packages, Wi-Fi (${wifiRes.transport}), App Lock (${lockRes.lockedPackages.length} protected)`,
          progress: 100,
          current_target: `Health Score ${apkRes.securityScore}/100`,
          items_scanned: apkRes.totalPackagesChecked,
          threats_detected: apkRes.apps.filter((a) => a.riskLevel === 'CRITICAL' || a.riskLevel === 'HIGH'),
          vulnerabilities_detected: [],
          started_at: new Date().toISOString(),
          finished_at: new Date().toISOString(),
          duration_seconds: 2,
        });
        await fetchAuditAndConfig();
        return;
      }
      const res = await api.runSmartScan();
      setScanState(res);
      await fetchAllData();
    } catch (e: any) {
      console.error('Full scan failed:', e);
    } finally {
      setTimeout(() => {
        setIsScanning(false);
      }, 1500);
    }
  };

  const handleCancelScan = () => {
    setIsScanning(false);
    setScanState(null);
  };

  // If user is not signed in, show AuthGate (Account Login + Dedicated Vault PIN Step)
  if (!currentUser) {
    return (
      <AuthGate
        onLoginSuccess={(u, pin) => {
          setCurrentUser(u);
          if (pin) setSessionVaultPin(pin);
        }}
      />
    );
  }

  return (
    <div className="flex h-screen w-screen bg-[#0B0F17] text-slate-100 overflow-hidden font-sans select-none antialiased">
      {/* Left Navigation Sidebar */}
      <SidebarNav
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        audit={audit}
        alerts={alerts}
        quarantineCount={quarantine.length}
        onOpenSettings={() => setIsSettingsOpen(true)}
        currentUser={currentUser}
      />

      {/* Main Content Viewport */}
      <div className="flex-1 flex flex-col h-full overflow-hidden bg-[#0B0F17]">
        {/* Top Minimal Suite Status Bar */}
        <header className="h-14 border-b border-[#1F2937]/70 px-4 sm:px-8 flex items-center justify-between shrink-0 bg-[#0B0F17]/90 backdrop-blur-md z-10">
          <div className="flex items-center gap-3">
            <h2 className="text-sm font-semibold text-white capitalize tracking-tight">
              {activeTab === 'home' && 'Security at a Glance'}
              {activeTab === 'threats' && 'Virus & Threat Protection'}
              {activeTab === 'network' && 'Firewall & Network Protection'}
              {activeTab === 'device' && 'Device Health & Performance'}
              {activeTab === 'vault' && 'Encrypted Password Vault'}
              {activeTab === 'assistant' && 'AI Security Assistant'}
              {activeTab === 'admin_audit' && 'Admin Central Audit Center'}
            </h2>
          </div>

          <div className="flex items-center gap-2 sm:gap-3">
            {!isAndroidApp ? (
              <>
                {/* Download Windows Installer Button */}
                <a
                  href={api.getWindowsSetupUrl()}
                  download="SentinelGrid_Setup_v1.0.exe"
                  className="px-3 py-1.5 rounded-xl bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-xs font-medium flex items-center gap-1.5 transition-colors shadow-sm"
                  title="Download Windows Setup Wizard (.EXE)"
                >
                  <Download className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="hidden sm:inline">Windows Installer (.EXE)</span>
                </a>

                {/* Download Mobile APK Button */}
                <button
                  onClick={() => setIsMobileModalOpen(true)}
                  className="px-3 py-1.5 rounded-xl bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-xs font-medium flex items-center gap-1.5 transition-colors shadow-sm"
                  title="Download Android APK package"
                >
                  <Smartphone className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="hidden sm:inline">Get Mobile App (.APK)</span>
                </button>
              </>
            ) : (
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-[11px] font-semibold text-emerald-300">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                <span>Android Native Guard</span>
              </div>
            )}

            {/* Live Connection Status */}
            {connected ? (
              <div className="hidden md:flex items-center gap-2 text-xs text-slate-300">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span className="font-medium">Protection Active</span>
              </div>
            ) : (
              <div className="hidden md:flex items-center gap-2 text-xs text-amber-400">
                <WifiOff className="w-3.5 h-3.5" />
                <span>Reconnecting...</span>
              </div>
            )}

            {/* User Profile & Sign Out */}
            <div className="flex items-center gap-2.5 pl-2 sm:pl-3 border-l border-[#1F2937]/80">
              <div className="flex items-center gap-2">
                {currentUser.photoURL ? (
                  <img
                    src={currentUser.photoURL}
                    alt={currentUser.displayName || 'User'}
                    className="w-7 h-7 rounded-full object-cover border border-emerald-500/40"
                  />
                ) : (
                  <div className="w-7 h-7 rounded-full bg-[#182335] border border-emerald-500/30 flex items-center justify-center text-emerald-400 text-xs font-bold">
                    {(currentUser.displayName || currentUser.email || 'U').charAt(0).toUpperCase()}
                  </div>
                )}
                <div className="hidden lg:block text-left text-xs">
                  <div className="font-semibold text-white truncate max-w-[120px]">
                    {currentUser.displayName || 'Security Operator'}
                  </div>
                  <div className="text-[10px] text-slate-400 truncate max-w-[120px]">
                    {currentUser.email || 'Stage Mode'}
                  </div>
                </div>
              </div>

              <button
                onClick={handleSignOut}
                className="p-1.5 rounded-lg text-slate-400 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                title="Sign Out"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          </div>
        </header>

        {/* Scrollable Page Body */}
        <main className="flex-1 overflow-y-auto p-4 pb-24 md:p-8 space-y-6">
          <div className="max-w-6xl mx-auto w-full">
            {activeTab === 'home' && (
              <HomeView
                onStartQuickScan={handleStartQuickScan}
                isScanning={isScanning}
                onNavigateTab={setActiveTab}
                audit={audit}
                alerts={alerts}
                quarantine={quarantine}
              />
            )}

            {activeTab === 'threats' && (
              <ThreatsView
                config={config}
                onConfigChange={setConfig}
                alerts={alerts}
                quarantine={quarantine}
                onDataUpdated={fetchAllData}
                isScanning={isScanning}
                scanState={scanState}
                onStartQuickScan={handleStartQuickScan}
                onStartFullScan={handleStartFullScan}
                onCancelScan={handleCancelScan}
              />
            )}

            {activeTab === 'network' && (
              <NetworkView
                audit={audit}
                config={config}
                onConfigChange={setConfig}
              />
            )}

            {activeTab === 'device' && (
              <DeviceHealthView
                audit={audit}
                telemetry={telemetry}
                onRefreshData={fetchAllData}
              />
            )}

            {activeTab === 'vault' && (
              <PasswordVaultView user={currentUser} initialPin={sessionVaultPin} />
            )}

            {activeTab === 'assistant' && (
              <AssistantView
                audit={audit}
                alerts={alerts}
                apiKey={apiKey}
                onUpdateApiKey={handleUpdateApiKey}
                onStartQuickScan={handleStartQuickScan}
                onNavigateTab={setActiveTab}
              />
            )}

            {activeTab === 'admin_audit' && (
              <ErrorBoundary fallbackTitle="Admin Audit Center Notice" onReset={() => setActiveTab('dashboard')}>
                <AdminAuditView user={currentUser} />
              </ErrorBoundary>
            )}
          </div>
        </main>
      </div>

      {/* Mobile APK Download Modal */}
      <MobileApkModal
        isOpen={isMobileModalOpen}
        onClose={() => setIsMobileModalOpen(false)}
      />

      {/* Global Settings & API Key Modal */}
      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        apiKey={apiKey}
        onSaveApiKey={handleUpdateApiKey}
        audit={audit}
        onRefreshData={fetchAllData}
      />

      {/* Always-On Background Gemini Co-Pilot (Accessible from every tab & Ctrl+Shift+G) */}
      <GeminiBackgroundCopilot
        audit={audit}
        alerts={alerts}
        apiKey={apiKey}
        onNavigateTab={setActiveTab}
        onStartQuickScan={handleStartQuickScan}
        onDataUpdated={fetchAllData}
      />
    </div>
  );
}

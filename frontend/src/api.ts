import type {
  Telemetry,
  AlertItem,
  QuarantineItem,
  LogEntry,
  ShieldConfig,
  DeviceAudit,
  SmartScanState,
  UrlCheckResult,
  ExclusionsResponse,
  DndStatusResponse,
  RamDiagnostics,
  RamOptimizeResponse,
  FastLaptopScanState,
  VaultAccountItem,
  VaultVerifyResponse,
  VaultStatusResponse,
  LoginAuditLog,
  AuditStats,
  AuditLogsResponse,
  VaultBreachReport,
  NetworkShieldStatus,
  BlockedIpItem,
  HardwarePrivacyStatus,
  UsbShieldStatus,
  UsbScanResult,
  GeminiContextState,
  GeminiTaskPlan,
  GeminiExecuteResult,
  ActiveAppInfo,
  DiskJunkScanResult,
  DiskJunkCleanResult,
  ManagedStartupItem,
  SoftwareScanResult,
  SafeMoneySite,
  SafeMoneyLaunchResult,
} from './types';
import { androidLocalStore } from './utils/androidVault';
import { SentinelDeviceGuard, isAndroidNativeApp } from './plugins/sentinelDeviceGuard';

const BASE_URL =
  import.meta.env.VITE_API_URL ||
  (typeof window !== 'undefined' &&
   window.location.origin &&
   window.location.origin.startsWith('http')
    ? window.location.origin
    : 'http://127.0.0.1:8000');

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`API Error ${res.status}: ${errorText || res.statusText}`);
  }
  return res.json();
}

export const api = {
  getTelemetry: async (): Promise<Telemetry> => {
    const res = await fetch(`${BASE_URL}/api/telemetry`);
    return handleResponse<Telemetry>(res);
  },

  getDeviceAudit: async (): Promise<DeviceAudit> => {
    const res = await fetch(`${BASE_URL}/api/device-audit`);
    return handleResponse<DeviceAudit>(res);
  },

  runSmartScan: async (): Promise<SmartScanState> => {
    const res = await fetch(`${BASE_URL}/api/scan/smart`, {
      method: 'POST',
    });
    return handleResponse<SmartScanState>(res);
  },

  getScanStatus: async (): Promise<SmartScanState> => {
    const res = await fetch(`${BASE_URL}/api/scan/status`);
    return handleResponse<SmartScanState>(res);
  },

  scanFolder: async (folder_path?: string, deep_entropy: boolean = true): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/scan/folder`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ folder_path, deep_entropy }),
    });
    return handleResponse<any>(res);
  },

  scanDefenderDeep: async (target_path: string, quarantine_on_threat: boolean = true): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/scan/defender-deep`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_path, quarantine_on_threat }),
    });
    return handleResponse<any>(res);
  },

  terminateProcess: async (pid: number): Promise<{ status: string; pid: number; name?: string }> => {
    const res = await fetch(`${BASE_URL}/api/process/terminate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pid }),
    });
    return handleResponse<{ status: string; pid: number; name?: string }>(res);
  },

  getAlerts: async (): Promise<AlertItem[]> => {
    const res = await fetch(`${BASE_URL}/api/alerts`);
    return handleResponse<AlertItem[]>(res);
  },

  clearAlerts: async (): Promise<{ status: string }> => {
    const res = await fetch(`${BASE_URL}/api/alerts`, { method: 'DELETE' });
    return handleResponse<{ status: string }>(res);
  },

  getLogs: async (): Promise<LogEntry[]> => {
    const res = await fetch(`${BASE_URL}/api/logs`);
    return handleResponse<LogEntry[]>(res);
  },

  clearLogs: async (): Promise<{ status: string }> => {
    const res = await fetch(`${BASE_URL}/api/logs`, { method: 'DELETE' });
    return handleResponse<{ status: string }>(res);
  },

  getQuarantine: async (): Promise<QuarantineItem[]> => {
    const res = await fetch(`${BASE_URL}/api/quarantine`);
    return handleResponse<QuarantineItem[]>(res);
  },

  restoreQuarantine: async (id: string): Promise<{ status: string; record: QuarantineItem }> => {
    const res = await fetch(`${BASE_URL}/api/quarantine/restore`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    });
    return handleResponse<{ status: string; record: QuarantineItem }>(res);
  },

  shredQuarantine: async (id: string): Promise<{ status: string; id: string }> => {
    const res = await fetch(`${BASE_URL}/api/quarantine/shred/${id}`, {
      method: 'DELETE',
    });
    return handleResponse<{ status: string; id: string }>(res);
  },

  getConfig: async (): Promise<ShieldConfig> => {
    const res = await fetch(`${BASE_URL}/api/config`);
    return handleResponse<ShieldConfig>(res);
  },

  updateConfig: async (config: Partial<ShieldConfig>): Promise<ShieldConfig> => {
    const res = await fetch(`${BASE_URL}/api/config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
    return handleResponse<ShieldConfig>(res);
  },

  simulateAttack: async (attackType: 'ransomware' | 'eicar' | 'macro_injection'): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/simulate/${attackType}`, {
      method: 'POST',
    });
    return handleResponse<any>(res);
  },

  resetProtectedZone: async (): Promise<{ status: string; files: string[] }> => {
    const res = await fetch(`${BASE_URL}/api/protected-zone/reset`, {
      method: 'POST',
    });
    return handleResponse<{ status: string; files: string[] }>(res);
  },

  checkUrl: async (url: string): Promise<UrlCheckResult> => {
    try {
      const res = await fetch(`${BASE_URL}/api/check-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      return handleResponse<UrlCheckResult>(res);
    } catch (err) {
      if (isAndroidNativeApp()) {
        const native = await SentinelDeviceGuard.checkUrlSafety({ url });
        return {
          url: native.url,
          domain: native.domain,
          status: native.status,
          risk_score: native.risk_score,
          verdict_title:
            native.status === 'DANGEROUS'
              ? 'Warning: Malicious or Unsafe Link'
              : native.status === 'SUSPICIOUS'
              ? 'Caution: Suspicious Link'
              : 'Link Appears Safe',
          explanation: native.reasons?.length
            ? native.reasons.join(' ')
            : 'Analyzed locally on Android by SentinelDeviceGuard.',
          reasons: native.reasons || [],
        };
      }
      throw err;
    }
  },

  getExclusions: async (): Promise<ExclusionsResponse> => {
    try {
      const res = await fetch(`${BASE_URL}/api/exclusions`);
      return handleResponse<ExclusionsResponse>(res);
    } catch (err) {
      if (isAndroidNativeApp()) {
        const list = androidLocalStore.getExclusions();
        return { exclusions: list };
      }
      throw err;
    }
  },

  addExclusion: async (path: string): Promise<ExclusionsResponse> => {
    try {
      const res = await fetch(`${BASE_URL}/api/exclusions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path }),
      });
      return handleResponse<ExclusionsResponse>(res);
    } catch (err) {
      if (isAndroidNativeApp()) {
        const list = androidLocalStore.addExclusion(path);
        return { exclusions: list };
      }
      throw err;
    }
  },

  removeExclusion: async (path: string): Promise<ExclusionsResponse> => {
    try {
      const res = await fetch(`${BASE_URL}/api/exclusions`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path }),
      });
      return handleResponse<ExclusionsResponse>(res);
    } catch (err) {
      if (isAndroidNativeApp()) {
        const list = androidLocalStore.removeExclusion(path);
        return { exclusions: list };
      }
      throw err;
    }
  },

  getDnd: async (): Promise<DndStatusResponse> => {
    try {
      const res = await fetch(`${BASE_URL}/api/dnd`);
      return handleResponse<DndStatusResponse>(res);
    } catch (err) {
      if (isAndroidNativeApp()) {
        const enabled = androidLocalStore.getDnd();
        return { dnd_enabled: enabled, mode: enabled ? 'SILENT' : 'STANDARD' };
      }
      throw err;
    }
  },

  setDnd: async (enabled: boolean): Promise<DndStatusResponse> => {
    try {
      const res = await fetch(`${BASE_URL}/api/dnd`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      });
      return handleResponse<DndStatusResponse>(res);
    } catch (err) {
      if (isAndroidNativeApp()) {
        const next = androidLocalStore.setDnd(enabled);
        return { dnd_enabled: next, mode: next ? 'SILENT' : 'STANDARD' };
      }
      throw err;
    }
  },

  getRamDiagnostics: async (): Promise<RamDiagnostics> => {
    try {
      const res = await fetch(`${BASE_URL}/api/ram/diagnostics`);
      return handleResponse<RamDiagnostics>(res);
    } catch (err) {
      if (isAndroidNativeApp()) {
        const hw = await SentinelDeviceGuard.getDeviceTelemetry();
        return {
          total_gb: Number((hw.memoryTotalMb / 1024).toFixed(1)),
          used_gb: Number((hw.memoryUsedMb / 1024).toFixed(1)),
          available_gb: Number((hw.memoryAvailMb / 1024).toFixed(1)),
          percent: hw.memoryPercent,
          recommended_reclaim_mb: Math.round(hw.memoryUsedMb * 0.2),
          safe_count: hw.installedPackagesCount,
          top_apps: [],
          grouped_apps: [],
        };
      }
      throw err;
    }
  },

  optimizeRam: async (
    pids?: number[],
    process_names?: string[],
    kill_all_bloat: boolean = false
  ): Promise<RamOptimizeResponse> => {
    const res = await fetch(`${BASE_URL}/api/ram/optimize`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pids, process_names, kill_all_bloat, trim_working_sets: true }),
    });
    return handleResponse<RamOptimizeResponse>(res);
  },

  killUselessBackgroundApps: async (): Promise<RamOptimizeResponse> => {
    const res = await fetch(`${BASE_URL}/api/ram/kill-bloat`, {
      method: 'POST',
    });
    return handleResponse<RamOptimizeResponse>(res);
  },

  trimStandbyRam: async (): Promise<RamOptimizeResponse> => {
    const res = await fetch(`${BASE_URL}/api/ram/trim`, {
      method: 'POST',
    });
    return handleResponse<RamOptimizeResponse>(res);
  },

  getFastScanStatus: async (): Promise<FastLaptopScanState> => {
    const res = await fetch(`${BASE_URL}/api/scan/fast-laptop/status`);
    return handleResponse<FastLaptopScanState>(res);
  },

  startFastLaptopScan: async (): Promise<{ status: string; message: string }> => {
    const res = await fetch(`${BASE_URL}/api/scan/fast-laptop`, {
      method: 'POST',
    });
    return handleResponse<{ status: string; message: string }>(res);
  },

  getVaultStatus: async (): Promise<VaultStatusResponse> => {
    try {
      const res = await fetch(`${BASE_URL}/api/vault/status`);
      return handleResponse<VaultStatusResponse>(res);
    } catch (err) {
      if (isAndroidNativeApp()) return androidLocalStore.getVaultStatus();
      throw err;
    }
  },

  setupVaultPin: async (pin: string, confirm_pin: string, old_pin?: string, user_id?: string, force_reset: boolean = false): Promise<{ status: string; message: string }> => {
    try {
      const res = await fetch(`${BASE_URL}/api/vault/setup-pin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin, confirm_pin, old_pin, user_id: user_id || 'default', force_reset }),
      });
      return handleResponse<{ status: string; message: string }>(res);
    } catch (err) {
      if (isAndroidNativeApp()) {
        return androidLocalStore.setupVaultPin(pin, confirm_pin, old_pin, user_id || 'default', force_reset);
      }
      throw err;
    }
  },

  verifyVaultPin: async (pin: string, user_id?: string): Promise<VaultVerifyResponse> => {
    try {
      const res = await fetch(`${BASE_URL}/api/vault/verify-pin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin, user_id: user_id || 'default' }),
      });
      return handleResponse<VaultVerifyResponse>(res);
    } catch (err) {
      if (isAndroidNativeApp()) {
        return androidLocalStore.verifyVaultPin(pin, user_id || 'default');
      }
      throw err;
    }
  },

  getVaultEntries: async (pin: string, user_id?: string): Promise<{ entries: VaultAccountItem[]; total: number }> => {
    try {
      const params = new URLSearchParams({ pin, user_id: user_id || 'default' });
      const res = await fetch(`${BASE_URL}/api/vault?${params.toString()}`);
      return handleResponse<{ entries: VaultAccountItem[]; total: number }>(res);
    } catch (err) {
      if (isAndroidNativeApp()) {
        return androidLocalStore.getVaultEntries(pin, user_id || 'default');
      }
      throw err;
    }
  },

  saveVaultEntry: async (pin: string, entry: VaultAccountItem, user_id?: string): Promise<{ status: string; entry: VaultAccountItem }> => {
    try {
      const res = await fetch(`${BASE_URL}/api/vault`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin, user_id: user_id || 'default', entry }),
      });
      return handleResponse<{ status: string; entry: VaultAccountItem }>(res);
    } catch (err) {
      if (isAndroidNativeApp()) {
        return androidLocalStore.saveVaultEntry(pin, entry, user_id || 'default');
      }
      throw err;
    }
  },

  deleteVaultEntry: async (id: string, pin: string, user_id?: string): Promise<{ status: string; id: string }> => {
    try {
      const params = new URLSearchParams({ pin, user_id: user_id || 'default' });
      const res = await fetch(`${BASE_URL}/api/vault/${encodeURIComponent(id)}?${params.toString()}`, {
        method: 'DELETE',
      });
      return handleResponse<{ status: string; id: string }>(res);
    } catch (err) {
      if (isAndroidNativeApp()) {
        return androidLocalStore.deleteVaultEntry(id, pin, user_id || 'default');
      }
      throw err;
    }
  },

  getAndroidApkUrl: (): string => {
    return `${BASE_URL}/api/download/android-apk`;
  },

  getWindowsSetupUrl: (): string => {
    return `${BASE_URL}/api/download/windows-setup`;
  },

  logLoginAudit: async (entry: LoginAuditLog): Promise<{ status: string; log: LoginAuditLog }> => {
    const res = await fetch(`${BASE_URL}/api/audit/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(entry),
    });
    return handleResponse<{ status: string; log: LoginAuditLog }>(res);
  },

  getAuditLogs: async (adminEmail: string): Promise<AuditLogsResponse> => {
    const params = new URLSearchParams({ admin_email: adminEmail });
    const res = await fetch(`${BASE_URL}/api/audit/logs?${params.toString()}`);
    return handleResponse<AuditLogsResponse>(res);
  },

  getAuditStats: async (adminEmail: string): Promise<AuditStats> => {
    const params = new URLSearchParams({ admin_email: adminEmail });
    const res = await fetch(`${BASE_URL}/api/audit/stats?${params.toString()}`);
    return handleResponse<AuditStats>(res);
  },

  seedAuditDemo: async (adminEmail: string): Promise<{ status: string; count: number }> => {
    const res = await fetch(`${BASE_URL}/api/audit/seed`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ admin_email: adminEmail }),
    });
    return handleResponse<{ status: string; count: number }>(res);
  },

  checkVaultBreaches: async (pin: string, user_id?: string): Promise<VaultBreachReport> => {
    try {
      const res = await fetch(`${BASE_URL}/api/vault/check-breaches`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin, user_id: user_id || 'default' }),
      });
      return handleResponse<VaultBreachReport>(res);
    } catch (err) {
      if (isAndroidNativeApp()) {
        return androidLocalStore.checkVaultBreaches(pin, user_id || 'default');
      }
      throw err;
    }
  },

  clearClipboard: async (): Promise<{ status: string; os_cleared: boolean }> => {
    try {
      const res = await fetch(`${BASE_URL}/api/vault/clear-clipboard`, { method: 'POST' });
      return handleResponse<{ status: string; os_cleared: boolean }>(res);
    } catch {
      if (navigator.clipboard?.writeText) {
        try {
          await navigator.clipboard.writeText('');
          return { status: 'cleared', os_cleared: true };
        } catch {
          return { status: 'skipped', os_cleared: false };
        }
      }
      return { status: 'skipped', os_cleared: false };
    }
  },

  getNetworkShieldStatus: async (): Promise<NetworkShieldStatus> => {
    const res = await fetch(`${BASE_URL}/api/network/shield-status`);
    return handleResponse<NetworkShieldStatus>(res);
  },

  blockNetworkIp: async (ip: string, reason?: string): Promise<{ status: string; entry: BlockedIpItem; blocked_ips: BlockedIpItem[] }> => {
    const res = await fetch(`${BASE_URL}/api/network/block-ip`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, reason }),
    });
    return handleResponse<{ status: string; entry: BlockedIpItem; blocked_ips: BlockedIpItem[] }>(res);
  },

  unblockNetworkIp: async (ip: string): Promise<{ status: string; ip: string; blocked_ips: BlockedIpItem[] }> => {
    const params = new URLSearchParams({ ip });
    const res = await fetch(`${BASE_URL}/api/network/block-ip?${params.toString()}`, {
      method: 'DELETE',
    });
    return handleResponse<{ status: string; ip: string; blocked_ips: BlockedIpItem[] }>(res);
  },

  getHardwarePrivacyGuard: async (): Promise<HardwarePrivacyStatus> => {
    const res = await fetch(`${BASE_URL}/api/privacy/hardware-guard`);
    return handleResponse<HardwarePrivacyStatus>(res);
  },

  getUsbStatus: async (): Promise<UsbShieldStatus> => {
    const res = await fetch(`${BASE_URL}/api/usb/status`);
    return handleResponse<UsbShieldStatus>(res);
  },

  runUsbScan: async (target_path?: string): Promise<{ status: string; message?: string; results: UsbScanResult[] }> => {
    const res = await fetch(`${BASE_URL}/api/usb/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_path }),
    });
    return handleResponse<{ status: string; message?: string; results: UsbScanResult[] }>(res);
  },

  getGeminiContext: async (): Promise<GeminiContextState> => {
    const res = await fetch(`${BASE_URL}/api/gemini/context`);
    return handleResponse<GeminiContextState>(res);
  },

  setGeminiBackgroundMode: async (enabled: boolean): Promise<{ background_enabled: boolean; hotkey: string }> => {
    const res = await fetch(`${BASE_URL}/api/gemini/background-mode`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    });
    return handleResponse<{ background_enabled: boolean; hotkey: string }>(res);
  },

  planGeminiTask: async (
    task: string,
    apiKey?: string,
    activeApp?: ActiveAppInfo | null
  ): Promise<GeminiTaskPlan> => {
    const res = await fetch(`${BASE_URL}/api/gemini/plan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ task, api_key: apiKey || '', active_app: activeApp || null }),
    });
    return handleResponse<GeminiTaskPlan>(res);
  },

  executeGeminiOption: async (
    optionId: string,
    actionType: string,
    params?: Record<string, any>
  ): Promise<GeminiExecuteResult> => {
    try {
      const res = await fetch(`${BASE_URL}/api/gemini/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ option_id: optionId, action_type: actionType, params: params || {} }),
      });
      return handleResponse<GeminiExecuteResult>(res);
    } catch (err) {
      if (isAndroidNativeApp()) {
        if (actionType === 'boost_ram' || actionType === 'kill_useless_bloat') {
          const boost = await SentinelDeviceGuard.boostBackgroundMemory();
          return {
            status: 'executed',
            action_type: actionType,
            summary: `Android Boost: Cleared ${boost.killedPackagesCount} background apps · Freed ${boost.freedMb} MB RAM.`,
          };
        }
        if (actionType === 'hardware_privacy_audit') {
          const wifi = await SentinelDeviceGuard.inspectWifiSecurity();
          return {
            status: 'executed',
            action_type: actionType,
            summary: `Android Network (${wifi.transport}): ${wifi.status} — ${wifi.advice}`,
          };
        }
        const scan = await SentinelDeviceGuard.scanInstalledApps();
        return {
          status: 'executed',
          action_type: actionType,
          summary: `Android Security Scan: Score ${scan.securityScore}/100 · ${scan.userAppsCount} apps audited.`,
        };
      }
      throw err;
    }
  },

  scanDiskJunk: async (): Promise<DiskJunkScanResult> => {
    const res = await fetch(`${BASE_URL}/api/system/junk-scan`);
    return handleResponse<DiskJunkScanResult>(res);
  },

  cleanDiskJunk: async (categoryIds?: string[]): Promise<DiskJunkCleanResult> => {
    const res = await fetch(`${BASE_URL}/api/system/junk-clean`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ category_ids: categoryIds || null }),
    });
    return handleResponse<DiskJunkCleanResult>(res);
  },

  listStartupApps: async (): Promise<{ entries: ManagedStartupItem[] }> => {
    const res = await fetch(`${BASE_URL}/api/startup/list`);
    return handleResponse<{ entries: ManagedStartupItem[] }>(res);
  },

  toggleStartupApp: async (name: string, enabled: boolean): Promise<{ name: string; enabled: boolean; status?: string }> => {
    const res = await fetch(`${BASE_URL}/api/startup/toggle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, enabled }),
    });
    return handleResponse<{ name: string; enabled: boolean; status?: string }>(res);
  },

  getBootPersistence: async (): Promise<{ enabled: boolean; command: string | null }> => {
    const res = await fetch(`${BASE_URL}/api/system/persistence`);
    return handleResponse<{ enabled: boolean; command: string | null }>(res);
  },

  setBootPersistence: async (enabled: boolean): Promise<{ enabled: boolean; command: string | null }> => {
    const res = await fetch(`${BASE_URL}/api/system/persistence`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    });
    return handleResponse<{ enabled: boolean; command: string | null }>(res);
  },

  scanSoftwareVulnerabilities: async (refresh = false): Promise<SoftwareScanResult> => {
    const res = await fetch(`${BASE_URL}/api/vulnerabilities/software?refresh=${refresh}`);
    return handleResponse<SoftwareScanResult>(res);
  },

  patchSoftwarePackage: async (packageId: string): Promise<{ status: string; package_id: string; message?: string }> => {
    const res = await fetch(`${BASE_URL}/api/vulnerabilities/patch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package_id: packageId }),
    });
    return handleResponse<{ status: string; package_id: string; message?: string }>(res);
  },

  getSafeMoneySites: async (): Promise<{ sites: SafeMoneySite[] }> => {
    const res = await fetch(`${BASE_URL}/api/safemoney/sites`);
    return handleResponse<{ sites: SafeMoneySite[] }>(res);
  },

  launchSafeMoney: async (url: string): Promise<SafeMoneyLaunchResult> => {
    const res = await fetch(`${BASE_URL}/api/safemoney/launch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    return handleResponse<SafeMoneyLaunchResult>(res);
  },

  getBrowserExtensionUrl: (): string => `${BASE_URL}/api/download/browser-extension`,

  huntBehavioralThreats: async (): Promise<import('./types').ProcessHuntResult> => {
    const res = await fetch(`${BASE_URL}/api/security/process-hunt`);
    return handleResponse<import('./types').ProcessHuntResult>(res);
  },

  scanScheduledTasks: async (): Promise<import('./types').ScheduledTasksResult> => {
    const res = await fetch(`${BASE_URL}/api/security/scheduled-tasks`);
    return handleResponse<import('./types').ScheduledTasksResult>(res);
  },

  getDnsShieldStatus: async (): Promise<import('./types').DnsShieldStatus> => {
    const res = await fetch(`${BASE_URL}/api/network/dns-shield`);
    return handleResponse<import('./types').DnsShieldStatus>(res);
  },

  setDnsShield: async (enabled: boolean): Promise<import('./types').DnsShieldStatus> => {
    const res = await fetch(`${BASE_URL}/api/network/dns-shield`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    });
    return handleResponse<import('./types').DnsShieldStatus>(res);
  },

  listSnapshotBackups: async (): Promise<{ snapshots: import('./types').SnapshotItem[] }> => {
    const res = await fetch(`${BASE_URL}/api/system/snapshots`);
    return handleResponse<{ snapshots: import('./types').SnapshotItem[] }>(res);
  },

  createSnapshotBackup: async (): Promise<import('./types').SnapshotBackupResult> => {
    const res = await fetch(`${BASE_URL}/api/system/snapshot-backup`, {
      method: 'POST',
    });
    return handleResponse<import('./types').SnapshotBackupResult>(res);
  },

  getDeceptionStatus: async (): Promise<import('./types').DeceptionGridStatus> => {
    const res = await fetch(`${BASE_URL}/api/deception/status`);
    return handleResponse<import('./types').DeceptionGridStatus>(res);
  },

  deployHoneyTokens: async (): Promise<import('./types').DeceptionGridStatus> => {
    const res = await fetch(`${BASE_URL}/api/deception/deploy`, { method: 'POST' });
    return handleResponse<import('./types').DeceptionGridStatus>(res);
  },

  simulateDeceptionBreach: async (): Promise<import('./types').SimulateDeceptionResult> => {
    const res = await fetch(`${BASE_URL}/api/deception/simulate-breach`, { method: 'POST' });
    return handleResponse<import('./types').SimulateDeceptionResult>(res);
  },

  auditBinarySignatures: async (): Promise<import('./types').BinarySignatureAuditResult> => {
    const res = await fetch(`${BASE_URL}/api/security/signature-audit`);
    return handleResponse<import('./types').BinarySignatureAuditResult>(res);
  },
};

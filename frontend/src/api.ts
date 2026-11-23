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
  AuditLogsResponse
} from './types';

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

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
    const res = await fetch(`${BASE_URL}/api/check-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    return handleResponse<UrlCheckResult>(res);
  },

  getExclusions: async (): Promise<ExclusionsResponse> => {
    const res = await fetch(`${BASE_URL}/api/exclusions`);
    return handleResponse<ExclusionsResponse>(res);
  },

  addExclusion: async (path: string): Promise<ExclusionsResponse> => {
    const res = await fetch(`${BASE_URL}/api/exclusions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path }),
    });
    return handleResponse<ExclusionsResponse>(res);
  },

  removeExclusion: async (path: string): Promise<ExclusionsResponse> => {
    const res = await fetch(`${BASE_URL}/api/exclusions`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path }),
    });
    return handleResponse<ExclusionsResponse>(res);
  },

  getDnd: async (): Promise<DndStatusResponse> => {
    const res = await fetch(`${BASE_URL}/api/dnd`);
    return handleResponse<DndStatusResponse>(res);
  },

  setDnd: async (enabled: boolean): Promise<DndStatusResponse> => {
    const res = await fetch(`${BASE_URL}/api/dnd`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    });
    return handleResponse<DndStatusResponse>(res);
  },

  getRamDiagnostics: async (): Promise<RamDiagnostics> => {
    const res = await fetch(`${BASE_URL}/api/ram/diagnostics`);
    return handleResponse<RamDiagnostics>(res);
  },

  optimizeRam: async (pids?: number[]): Promise<RamOptimizeResponse> => {
    const res = await fetch(`${BASE_URL}/api/ram/optimize`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pids }),
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
    const res = await fetch(`${BASE_URL}/api/vault/status`);
    return handleResponse<VaultStatusResponse>(res);
  },

  setupVaultPin: async (pin: string, confirm_pin: string, old_pin?: string, user_id?: string): Promise<{ status: string; message: string }> => {
    const res = await fetch(`${BASE_URL}/api/vault/setup-pin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin, confirm_pin, old_pin, user_id: user_id || 'default' }),
    });
    return handleResponse<{ status: string; message: string }>(res);
  },

  verifyVaultPin: async (pin: string, user_id?: string): Promise<VaultVerifyResponse> => {
    const res = await fetch(`${BASE_URL}/api/vault/verify-pin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin, user_id: user_id || 'default' }),
    });
    return handleResponse<VaultVerifyResponse>(res);
  },

  getVaultEntries: async (pin: string, user_id?: string): Promise<{ entries: VaultAccountItem[]; total: number }> => {
    const params = new URLSearchParams({ pin, user_id: user_id || 'default' });
    const res = await fetch(`${BASE_URL}/api/vault?${params.toString()}`);
    return handleResponse<{ entries: VaultAccountItem[]; total: number }>(res);
  },

  saveVaultEntry: async (pin: string, entry: VaultAccountItem, user_id?: string): Promise<{ status: string; entry: VaultAccountItem }> => {
    const res = await fetch(`${BASE_URL}/api/vault`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin, user_id: user_id || 'default', entry }),
    });
    return handleResponse<{ status: string; entry: VaultAccountItem }>(res);
  },

  deleteVaultEntry: async (id: string, pin: string, user_id?: string): Promise<{ status: string; id: string }> => {
    const params = new URLSearchParams({ pin, user_id: user_id || 'default' });
    const res = await fetch(`${BASE_URL}/api/vault/${encodeURIComponent(id)}?${params.toString()}`, {
      method: 'DELETE',
    });
    return handleResponse<{ status: string; id: string }>(res);
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
};

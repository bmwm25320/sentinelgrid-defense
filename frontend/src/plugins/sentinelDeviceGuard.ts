import { Capacitor, registerPlugin } from '@capacitor/core';

export interface AndroidScannedApp {
  appName: string;
  packageName: string;
  versionName: string;
  installer: string;
  isSideloaded: boolean;
  stalkerwareSuspect: boolean;
  riskScore: number;
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'SAFE';
  dangerousPermissions: string[];
  reasons: string[];
}

export interface AndroidAppScanResult {
  totalPackagesChecked: number;
  userAppsCount: number;
  sideloadedCount: number;
  highRiskCount: number;
  stalkerwareSuspects: number;
  securityScore: number;
  deviceInfo: {
    manufacturer: string;
    model: string;
    androidVersion: string;
    sdkInt: number;
    securityPatch?: string;
  };
  apps: AndroidScannedApp[];
}

export interface AndroidWifiStatus {
  status: 'SAFE' | 'WARNING' | 'UNKNOWN';
  transport: string;
  vpnActive: boolean;
  captivePortalDetected: boolean;
  privateDnsActive: boolean;
  advice: string;
}

export interface AndroidOverlayStatus {
  hasOverlayPermission: boolean;
  serviceRunning: boolean;
}

export interface AndroidBoostMemoryResult {
  killedPackagesCount: number;
  availableBeforeMb: number;
  availableAfterMb: number;
  freedMb: number;
  totalMemoryMb: number;
}

export interface AndroidPhishingAlert {
  sourceApp: string;
  url: string;
  status: string;
  riskScore: number;
  timestamp: number;
}

export interface AndroidNotificationShieldStatus {
  permissionGranted: boolean;
  serviceConnected: boolean;
  alerts: AndroidPhishingAlert[];
}

export interface AndroidAppLockStatus {
  hasUsageStatsPermission: boolean;
  serviceRunning: boolean;
  lockedPackages: string[];
}

export interface AndroidLocationResult {
  available: boolean;
  latitude?: number;
  longitude?: number;
  accuracyMeters?: number;
  note?: string;
}

export interface AndroidDeviceTelemetry {
  manufacturer: string;
  model: string;
  androidVersion: string;
  sdkInt: number;
  cpuCores: number;
  memoryTotalMb: number;
  memoryUsedMb: number;
  memoryAvailMb: number;
  memoryPercent: number;
  diskTotalGb: number;
  diskFreeGb: number;
  installedPackagesCount: number;
}

export interface AndroidPrivacyAppEntry {
  appName: string;
  packageName: string;
}

export interface AndroidPrivacyAuditResult {
  cameraCount: number;
  micCount: number;
  bgLocationCount: number;
  smsCount: number;
  accessibilityCount: number;
  cameraApps: AndroidPrivacyAppEntry[];
  micApps: AndroidPrivacyAppEntry[];
  bgLocationApps: AndroidPrivacyAppEntry[];
  smsApps: AndroidPrivacyAppEntry[];
  accessibilityApps: AndroidPrivacyAppEntry[];
}

export interface AndroidClipboardSafetyResult {
  hasText: boolean;
  urlsFound?: number;
  flaggedUrl?: string;
  status: 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS' | 'SENSITIVE';
  riskScore: number;
  summary: string;
}

export interface AndroidInstallGuardAlert {
  appName: string;
  packageName: string;
  riskLevel: string;
  riskScore: number;
  timestamp: number;
}

export interface AndroidDownloadLeftoverFile {
  name: string;
  sizeMb: number;
  isApk: boolean;
}

export interface AndroidDownloadLeftoversResult {
  count: number;
  totalMb: number;
  files: AndroidDownloadLeftoverFile[];
}

export interface AndroidApkCertEntry {
  appName: string;
  packageName: string;
  sha256: string;
  signerCn: string;
  isDebuggable: boolean;
  isDebugKey: boolean;
  riskLevel: 'HIGH' | 'TRUSTED' | string;
  reason: string;
}

export interface AndroidAppCertificatesResult {
  auditedCount: number;
  debugSignedCount: number;
  debuggableCount: number;
  apps: AndroidApkCertEntry[];
}

export interface AndroidScreenSpyStatus {
  activeVirtualDisplays: number;
  screenMirroringDetected: boolean;
  remoteSupportAppsFound: string[];
  displays: {
    displayId: number;
    name: string;
    isDefault: boolean;
    isPresentation: boolean;
    isPrivate: boolean;
  }[];
  riskLevel: 'CRITICAL' | 'MEDIUM' | 'SAFE' | string;
  summary: string;
}

export interface SentinelDeviceGuardPlugin {
  scanInstalledApps(): Promise<AndroidAppScanResult>;
  inspectWifiSecurity(): Promise<AndroidWifiStatus>;
  checkUrlSafety(options: { url: string }): Promise<{
    url: string;
    domain: string;
    status: 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS';
    risk_score: number;
    reasons: string[];
  }>;
  getOverlayStatus(): Promise<AndroidOverlayStatus>;
  requestOverlayPermission(): Promise<void>;
  startBackgroundGemini(options: { apiKey?: string }): Promise<{ started: boolean }>;
  stopBackgroundGemini(): Promise<{ stopped: boolean }>;
  boostBackgroundMemory(): Promise<AndroidBoostMemoryResult>;
  getNotificationShieldStatus(): Promise<AndroidNotificationShieldStatus>;
  requestNotificationAccess(): Promise<void>;
  clearPhishingAlerts(): Promise<void>;
  getAppLockStatus(): Promise<AndroidAppLockStatus>;
  requestUsageStatsAccess(): Promise<void>;
  setAppLockConfig(options: { lockedPackages: string[]; pin?: string; enabled: boolean }): Promise<{ savedCount: number; serviceRunning: boolean }>;
  triggerAntiTheftAlarm(): Promise<{ playing: boolean }>;
  stopAntiTheftAlarm(): Promise<{ playing: boolean }>;
  getLastKnownLocation(): Promise<AndroidLocationResult>;
  getDeviceTelemetry(): Promise<AndroidDeviceTelemetry>;
  auditPrivacyPermissions(): Promise<AndroidPrivacyAuditResult>;
  openAppSettings(options: { packageName: string }): Promise<void>;
  inspectClipboardSafety(): Promise<AndroidClipboardSafetyResult>;
  clearClipboard(): Promise<{ cleared: boolean }>;
  getInstallGuardAlerts(): Promise<{ alerts: AndroidInstallGuardAlert[] }>;
  scanDownloadLeftovers(): Promise<AndroidDownloadLeftoversResult>;
  auditAppCertificates(): Promise<AndroidAppCertificatesResult>;
  inspectScreenSpyStatus(): Promise<AndroidScreenSpyStatus>;
}

export const SentinelDeviceGuard = registerPlugin<SentinelDeviceGuardPlugin>('SentinelDeviceGuard');

export function isAndroidNativeApp(): boolean {
  return Capacitor.isNativePlatform() && Capacitor.getPlatform() === 'android';
}

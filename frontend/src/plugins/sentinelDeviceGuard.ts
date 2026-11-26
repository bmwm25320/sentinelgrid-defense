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
}

export const SentinelDeviceGuard = registerPlugin<SentinelDeviceGuardPlugin>('SentinelDeviceGuard');

export function isAndroidNativeApp(): boolean {
  return Capacitor.isNativePlatform() && Capacitor.getPlatform() === 'android';
}

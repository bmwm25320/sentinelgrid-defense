import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Shield,
  Lock,
  Wifi,
  DownloadCloud,
  Activity,
  Archive,
  ChevronRight,
  Play,
  RotateCw,
  Laptop,
  KeyRound,
} from 'lucide-react';
import type { DeviceAudit, AlertItem, QuarantineItem } from '../types';
import { FastLaptopScanModal } from './FastLaptopScanModal';

interface HomeViewProps {
  onStartQuickScan: () => void;
  isScanning: boolean;
  onNavigateTab: (tab: string) => void;
  audit: DeviceAudit | null;
  alerts: AlertItem[];
  quarantine: QuarantineItem[];
  lastScanTime?: string;
}

export const HomeView: React.FC<HomeViewProps> = ({
  onStartQuickScan,
  isScanning,
  onNavigateTab,
  audit,
  alerts,
  quarantine,
  lastScanTime = 'Today, 4:15 PM',
}) => {
  const [isFastScanOpen, setIsFastScanOpen] = useState(false);
  const activeThreats = alerts.filter(a => a.status === 'BLOCKED');
  const hasThreats = activeThreats.length > 0;
  const vulnCount = audit?.vulnerabilities?.length ?? 0;

  // Determine overall status
  let headline = 'Your device is protected';
  let subline = `Last scan: ${lastScanTime} • Protection updates: Up to date`;
  let statusTone: 'safe' | 'warn' | 'danger' = 'safe';

  if (hasThreats) {
    statusTone = 'danger';
    headline = `${activeThreats.length} Threat${activeThreats.length > 1 ? 's' : ''} Blocked & Neutralized`;
    subline = 'SentinelGrid intercepted unauthorized activity. Your files remain safe.';
  } else if (vulnCount > 0) {
    statusTone = 'warn';
    headline = 'Security recommendations available';
    subline = `${vulnCount} item${vulnCount > 1 ? 's' : ''} suggested for optimal system protection.`;
  }

  const protectionCards = [
    {
      id: 'virus',
      title: 'Virus & Threat Protection',
      description: hasThreats
        ? `${activeThreats.length} threat blocked and quarantined safely.`
        : 'No active threats found. Real-time shield is guarding your files.',
      badge: hasThreats ? 'Threat Neutralized' : 'Protected',
      badgeColor: hasThreats ? 'text-emerald-400 bg-emerald-950/60 border-emerald-500/30' : 'text-emerald-400 bg-emerald-950/60 border-emerald-500/30',
      icon: Shield,
      targetTab: 'threats',
    },
    {
      id: 'ransomware',
      title: 'Ransomware & File Shield',
      description: 'Your personal folders and documents are locked against unauthorized changes.',
      badge: 'Shield Active',
      badgeColor: 'text-emerald-400 bg-emerald-950/60 border-emerald-500/30',
      icon: Lock,
      targetTab: 'threats',
    },
    {
      id: 'network',
      title: 'Firewall & Network Protection',
      description: 'Monitoring incoming and outgoing network traffic safely on this device.',
      badge: 'Safe Network',
      badgeColor: 'text-emerald-400 bg-emerald-950/60 border-emerald-500/30',
      icon: Wifi,
      targetTab: 'network',
    },
    {
      id: 'apps',
      title: 'App & Download Control',
      description: 'Automatically checking new downloads, installers, and unknown software.',
      badge: 'Active',
      badgeColor: 'text-emerald-400 bg-emerald-950/60 border-emerald-500/30',
      icon: DownloadCloud,
      targetTab: 'threats',
    },
    {
      id: 'device',
      title: 'Device Performance & Health',
      description: `System running smoothly. ${audit?.startup_audit?.entries_count ?? audit?.startup_audit?.entries?.length ?? 0} startup programs monitored.`,
      badge: vulnCount > 0 ? 'Tips Available' : 'Good Condition',
      badgeColor: vulnCount > 0 ? 'text-amber-300 bg-amber-950/60 border-amber-500/30' : 'text-emerald-400 bg-emerald-950/60 border-emerald-500/30',
      icon: Activity,
      targetTab: 'device',
    },
    {
      id: 'vault',
      title: 'Password & Credentials Vault',
      description: 'Your saved website accounts and credentials are encrypted locally with AES-256.',
      badge: 'Protected',
      badgeColor: 'text-emerald-400 bg-emerald-950/60 border-emerald-500/30',
      icon: KeyRound,
      targetTab: 'vault',
    },
    {
      id: 'quarantine',
      title: 'Quarantine & History',
      description: quarantine.length > 0
        ? `${quarantine.length} isolated item${quarantine.length > 1 ? 's' : ''} stored safely in vault.`
        : 'Vault is clear. No dangerous files present on your PC.',
      badge: quarantine.length > 0 ? `${quarantine.length} in Vault` : 'All Clear',
      badgeColor: 'text-slate-300 bg-slate-800/80 border-slate-700',
      icon: Archive,
      targetTab: 'threats',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Top Hero Status Banner */}
      <div className={`p-6 sm:p-8 rounded-2xl border transition-all ${
        statusTone === 'safe'
          ? 'bg-gradient-to-r from-[#0E1A1E] via-[#111A24] to-[#131A26] border-emerald-500/30 shadow-safe-glow'
          : statusTone === 'warn'
          ? 'bg-gradient-to-r from-[#1A180E] via-[#1A1714] to-[#131A26] border-amber-500/30 shadow-warn-glow'
          : 'bg-gradient-to-r from-[#201014] via-[#1A1218] to-[#131A26] border-red-500/40 shadow-danger-glow'
      }`}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="flex items-start gap-4 sm:gap-5">
            <div className={`w-14 h-14 sm:w-16 sm:h-16 rounded-2xl flex items-center justify-center shrink-0 shadow-lg ${
              statusTone === 'safe'
                ? 'bg-gradient-to-br from-emerald-500 to-teal-700 text-white shadow-emerald-500/30'
                : statusTone === 'warn'
                ? 'bg-gradient-to-br from-amber-500 to-orange-700 text-white shadow-amber-500/30'
                : 'bg-gradient-to-br from-red-500 to-rose-700 text-white shadow-red-500/30'
            }`}>
              {statusTone === 'safe' ? (
                <ShieldCheck className="w-8 h-8 sm:w-9 sm:h-9" />
              ) : (
                <ShieldAlert className="w-8 h-8 sm:w-9 sm:h-9" />
              )}
            </div>

            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className={`text-[11px] font-semibold tracking-wider uppercase px-2.5 py-0.5 rounded-full border ${
                  statusTone === 'safe'
                    ? 'text-emerald-300 bg-emerald-950/80 border-emerald-500/40'
                    : statusTone === 'warn'
                    ? 'text-amber-300 bg-amber-950/80 border-amber-500/40'
                    : 'text-red-300 bg-red-950/80 border-red-500/40'
                }`}>
                  {statusTone === 'safe' ? 'Security Active' : statusTone === 'warn' ? 'Notice' : 'Action Taken'}
                </span>
                <span className="text-xs text-slate-400">• Real-Time Protection</span>
              </div>
              <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
                {headline}
              </h2>
              <p className="text-xs sm:text-sm text-slate-400 mt-1">
                {subline}
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={() => setIsFastScanOpen(true)}
              className="px-5 py-3 rounded-xl font-medium text-xs sm:text-sm flex items-center justify-center gap-2 bg-[#142032] hover:bg-[#1D2C44] text-cyan-300 border border-cyan-500/40 transition-all shadow-md shrink-0"
            >
              <Laptop className="w-4 h-4 text-cyan-400" />
              <span>5-Min Fast Scan</span>
            </button>

            <button
              onClick={onStartQuickScan}
              disabled={isScanning}
              className={`px-6 py-3 rounded-xl font-medium text-sm flex items-center justify-center gap-2.5 transition-all shadow-md ${
                isScanning
                  ? 'bg-emerald-900/60 text-emerald-200 border border-emerald-500/40 cursor-not-allowed'
                  : 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold shadow-emerald-500/25 hover:shadow-emerald-500/40'
              }`}
            >
              {isScanning ? (
                <>
                  <RotateCw className="w-4 h-4 animate-spin text-emerald-300" />
                  <span>Scanning PC...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Quick Scan</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* 6-Card Protection Grid (Windows Defender Style) */}
      <div>
        <div className="flex items-center justify-between mb-3 px-1">
          <h3 className="text-sm font-semibold text-slate-200">
            Protection Areas
          </h3>
          <span className="text-xs text-slate-400">All 4 defense layers active</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {protectionCards.map((card) => {
            const Icon = card.icon;
            return (
              <div
                key={card.id}
                onClick={() => onNavigateTab(card.targetTab)}
                className="defender-card-interactive p-5 flex flex-col justify-between group"
              >
                <div>
                  <div className="flex items-start justify-between gap-3 mb-3">
                    <div className="w-10 h-10 rounded-xl bg-[#1A2332] border border-[#2B384E] flex items-center justify-center text-emerald-400 group-hover:border-emerald-500/40 transition-colors">
                      <Icon className="w-5 h-5" />
                    </div>
                    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-md border ${card.badgeColor}`}>
                      {card.badge}
                    </span>
                  </div>

                  <h4 className="text-sm font-semibold text-white group-hover:text-emerald-400 transition-colors">
                    {card.title}
                  </h4>
                  <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                    {card.description}
                  </p>
                </div>

                <div className="mt-4 pt-3 border-t border-[#1F2937]/70 flex items-center justify-between text-xs text-slate-400 group-hover:text-slate-200">
                  <span>Manage setting</span>
                  <ChevronRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform text-slate-400" />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 5-Minute Fast Laptop Scan Modal */}
      <FastLaptopScanModal
        isOpen={isFastScanOpen}
        onClose={() => setIsFastScanOpen(false)}
      />
    </div>
  );
};

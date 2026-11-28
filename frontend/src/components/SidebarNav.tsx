import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Home,
  Shield,
  Wifi,
  Activity,
  Sparkles,
  Settings,
  CheckCircle2,
  KeyRound,
  Database,
  Fingerprint,
} from 'lucide-react';
import type { DeviceAudit, AlertItem, AuthUser } from '../types';
import { ADMIN_EMAIL } from '../firebase';

interface SidebarNavProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  audit: DeviceAudit | null;
  alerts: AlertItem[];
  quarantineCount: number;
  onOpenSettings: () => void;
  currentUser?: AuthUser | null;
}

export const SidebarNav: React.FC<SidebarNavProps> = ({
  activeTab,
  setActiveTab,
  audit,
  alerts,
  quarantineCount,
  onOpenSettings,
  currentUser,
}) => {
  const activeThreatsCount = alerts.filter(a => a.status === 'BLOCKED').length;
  const isProtected = activeThreatsCount === 0;
  const isAdmin = Boolean(currentUser?.email && currentUser.email.toLowerCase() === ADMIN_EMAIL.toLowerCase());

  const navItems = [
    {
      id: 'home',
      label: 'Home',
      icon: Home,
      badge: null,
      badgeColor: '',
    },
    {
      id: 'threats',
      label: 'Virus & Threat Protection',
      icon: Shield,
      badge: activeThreatsCount > 0 ? `${activeThreatsCount}` : quarantineCount > 0 ? `${quarantineCount}` : null,
      badgeColor: activeThreatsCount > 0 ? 'bg-red-500/20 text-red-400 border-red-500/40' : 'bg-slate-700 text-slate-300 border-slate-600',
    },
    {
      id: 'network',
      label: 'Firewall & Network',
      icon: Wifi,
      badge: null,
      badgeColor: '',
    },
    {
      id: 'device',
      label: 'Device Health & Startup',
      icon: Activity,
      badge: (audit?.vulnerabilities?.length ?? 0) > 0 ? `${audit?.vulnerabilities?.length}` : null,
      badgeColor: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
    },
    {
      id: 'vault',
      label: 'Password Vault',
      icon: KeyRound,
      badge: 'AES-256',
      badgeColor: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
    },
    {
      id: 'deception',
      label: 'Decoy Traps & Trust',
      icon: Fingerprint,
      badge: 'Traps',
      badgeColor: 'bg-purple-500/20 text-purple-300 border-purple-500/40',
    },
    {
      id: 'assistant',
      label: 'AI Security Assistant',
      icon: Sparkles,
      badge: 'Gemini',
      badgeColor: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
    },
  ];

  // Strictly inject Admin Audit Center ONLY when authenticated as bmwm25320@gmail.com
  if (isAdmin) {
    navItems.push({
      id: 'admin_audit',
      label: 'Admin Audit Center',
      icon: Database,
      badge: 'ADMIN',
      badgeColor: 'bg-purple-500/20 text-purple-300 border-purple-500/40',
    });
  }

  return (
    <>
      <aside className="hidden md:flex w-64 bg-[#0D121D] border-r border-[#1F2937] flex-col justify-between shrink-0 select-none z-20">
        <div>
          {/* Top App Header */}
          <div className="p-5 pb-4 border-b border-[#1F2937]/70">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-emerald-500 to-teal-700 flex items-center justify-center text-white shadow-safe-glow">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-sm font-semibold text-white tracking-tight flex items-center gap-1.5">
                  SentinelGrid
                  <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-400 font-medium border border-emerald-500/30">
                    Suite
                  </span>
                </h1>
                <p className="text-xs text-slate-400">Endpoint Security</p>
              </div>
            </div>

            {/* Quick status pill */}
            <div className="mt-3.5 px-3 py-1.5 rounded-lg bg-[#131A26] border border-[#1F2937] flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${isProtected ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`} />
                <span className="text-slate-300 font-medium">
                  {isProtected ? "You're Protected" : "Threat Intercepted"}
                </span>
              </div>
              {isProtected ? (
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              ) : (
                <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
              )}
            </div>
          </div>

          {/* Main Navigation Items */}
          <nav className="p-3 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-xs font-medium transition-all ${
                    isActive
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-[#131A26]/80 border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className={`w-4 h-4 ${isActive ? 'text-emerald-400' : 'text-slate-400'}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge && (
                    <span className={`text-[10px] px-2 py-0.5 rounded-full border font-semibold ${item.badgeColor}`}>
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Bottom Footer / Settings */}
        <div className="p-3 border-t border-[#1F2937]/70 space-y-2">
          {isAdmin && (
            <div className="px-2.5 py-1.5 rounded-lg bg-purple-500/10 border border-purple-500/30 text-[10px] text-purple-300 flex items-center gap-1.5 font-medium">
              <ShieldCheck className="w-3.5 h-3.5 text-purple-400 shrink-0" />
              <span className="truncate">SuperAdmin: bmwm25320@gmail.com</span>
            </div>
          )}

          <button
            onClick={onOpenSettings}
            className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-xs text-slate-400 hover:text-slate-200 hover:bg-[#131A26] transition-colors"
          >
            <Settings className="w-4 h-4 text-slate-400" />
            <span>Settings &amp; Updates</span>
          </button>

          <div className="px-3 py-1 flex items-center justify-between text-[11px] text-slate-400">
            <span>Security Engine</span>
            <span className="text-emerald-400 font-medium">v4.8 Active</span>
          </div>
        </div>
      </aside>

      {/* Responsive Android / Mobile Bottom Navigation Bar */}
      <nav
        aria-label="Mobile Navigation"
        className="md:hidden fixed bottom-0 inset-x-0 bg-[#0D121D]/95 backdrop-blur-md border-t border-[#1F2937] z-30 flex items-center justify-around gap-0.5 px-1 py-1.5 overflow-x-auto"
      >
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`flex flex-col items-center justify-center px-0.5 py-1 rounded-lg text-[9px] font-medium transition-colors ${
                isActive ? 'text-emerald-400 bg-emerald-500/10' : 'text-slate-400'
              }`}
            >
              <Icon className="w-4 h-4 mb-0.5 shrink-0" />
              <span className="truncate max-w-full">{item.id === 'vault' ? 'Vault' : item.label.split(' ')[0]}</span>
            </button>
          );
        })}
        <button
          onClick={onOpenSettings}
          className="flex flex-col items-center justify-center px-0.5 py-1 rounded-lg text-[9px] font-medium text-slate-400"
        >
          <Settings className="w-4 h-4 mb-0.5 shrink-0" />
          <span className="truncate max-w-full">Settings</span>
        </button>
      </nav>
    </>
  );
};

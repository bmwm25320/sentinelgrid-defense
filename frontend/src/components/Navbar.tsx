import React, { useState, useEffect } from 'react';
import { Shield, ShieldAlert, Activity, Lock, Cpu, AlertOctagon } from 'lucide-react';
import type { Telemetry } from '../types';

interface NavbarProps {
  telemetry: Telemetry | null;
  activeTab: string;
  setActiveTab: (tab: string) => void;
  threatCount: number;
  quarantineCount: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  telemetry,
  activeTab,
  setActiveTab,
  threatCount,
  quarantineCount
}) => {
  const [timeStr, setTimeStr] = useState<string>('');

  useEffect(() => {
    const updateClock = () => {
      const now = new Date();
      setTimeStr(now.toTimeString().split(' ')[0] + '.' + String(Math.floor(now.getMilliseconds() / 100)));
    };
    updateClock();
    const timer = setInterval(updateClock, 100);
    return () => clearInterval(timer);
  }, []);

  const defcon = telemetry?.defcon_level ?? 5;
  const isCanaryArmed = telemetry?.canary_status === 'ARMED';

  const getDefconBadge = () => {
    switch (defcon) {
      case 1:
        return (
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-red-950/80 border border-red-500 text-red-400 text-xs font-mono font-bold animate-pulse">
            <AlertOctagon className="w-3.5 h-3.5 text-red-400" />
            DEFCON 1 // ACTIVE BREACH
          </span>
        );
      case 2:
      case 3:
        return (
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-amber-950/80 border border-amber-500 text-amber-400 text-xs font-mono font-bold">
            <Activity className="w-3.5 h-3.5 text-amber-400" />
            DEFCON {defcon} // ELEVATED
          </span>
        );
      default:
        return (
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-950/80 border border-emerald-500/60 text-emerald-400 text-xs font-mono font-bold">
            <Lock className="w-3.5 h-3.5 text-emerald-400" />
            DEFCON 5 // SECURE
          </span>
        );
    }
  };

  const navItems = [
    { id: 'overview', label: 'Command Overview', icon: Cpu, badge: null },
    { id: 'forensics', label: 'Threat Forensics & AI', icon: ShieldAlert, badge: threatCount > 0 ? threatCount : null, badgeColor: 'bg-red-500 text-white' },
    { id: 'quarantine', label: 'Quarantine Vault', icon: Lock, badge: quarantineCount > 0 ? quarantineCount : null, badgeColor: 'bg-amber-500 text-slate-900' },
    { id: 'config', label: '4-Layer Config', icon: Shield, badge: null }
  ];

  return (
    <header className="sticky top-0 z-40 w-full border-b border-cyber-border bg-obsidian/90 backdrop-blur-md">
      {/* Top Banner / Tactical telemetry line */}
      <div className="flex items-center justify-between px-4 py-1 bg-[#090e1a] border-b border-cyan-950/60 text-[11px] font-mono text-slate-400">
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1 text-cyan-400 font-bold tracking-wider">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping inline-block" />
            SENTINELGRID DEFENSE
          </span>
          <span className="text-slate-600">|</span>
          <span className="text-slate-300">4-LAYER OS GUARDIAN SHIELD</span>
          <span className="text-slate-600">|</span>
          <span className="text-emerald-400">PID GUILLOTINE: ARMED</span>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className="text-slate-500">SYS TIME:</span>
            <span className="text-cyan-300 font-bold">{timeStr}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-slate-500">HOST AGENT:</span>
            <span className="text-emerald-400 font-bold">ONLINE (PORT 8000)</span>
          </div>
        </div>
      </div>

      {/* Main Navbar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <div className="flex items-center gap-3 cursor-pointer" onClick={() => setActiveTab('overview')}>
            <div className="relative p-2 rounded-lg bg-gradient-to-br from-cyan-950 to-blue-950 border border-cyan-500/50 shadow-cyan-glow">
              <Shield className="w-6 h-6 text-cyan-400" />
              <div className="absolute -bottom-1 -right-1 w-2.5 h-2.5 rounded-full bg-emerald-400 ring-2 ring-obsidian" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-lg font-black tracking-widest text-slate-100 font-mono">
                  SENTINEL<span className="text-cyan-400">GRID</span>
                </span>
                <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
                  v2.0 EDR
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-mono tracking-tight">
                Autonomous Endpoint Threat Neutralization
              </p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="flex items-center gap-1 bg-[#091020]/90 p-1 rounded-xl border border-cyber-border">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono font-medium transition-all duration-150 ${
                    isActive
                      ? 'bg-gradient-to-r from-cyan-950/90 to-blue-950/80 text-cyan-300 border border-cyan-500/50 shadow-[0_0_15px_rgba(0,240,255,0.2)]'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                  {item.badge !== null && (
                    <span className={`px-1.5 py-0.2 rounded-full text-[10px] font-bold ${item.badgeColor}`}>
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          {/* Status Badges */}
          <div className="flex items-center gap-3">
            {/* Canary Indicator */}
            <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border font-mono text-xs ${
              isCanaryArmed
                ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300 shadow-emerald-glow'
                : 'bg-red-950/40 border-red-500/40 text-red-300'
            }`}>
              <div className={`w-2.5 h-2.5 rounded-full ${isCanaryArmed ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`} />
              <div className="leading-tight">
                <div className="text-[9px] text-slate-400 uppercase tracking-wider">Canary Decoy</div>
                <div className="font-bold">{isCanaryArmed ? 'ARMED // SUB-10MS' : 'DISARMED'}</div>
              </div>
            </div>

            {/* DEFCON pill */}
            {getDefconBadge()}
          </div>
        </div>
      </div>
    </header>
  );
};

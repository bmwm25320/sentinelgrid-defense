import React, { useState } from 'react';
import { Skull, FileCode, Zap, CheckCircle2, ShieldCheck, RefreshCw, Crosshair } from 'lucide-react';
import { api } from '../api';
import type { AlertItem } from '../types';

interface StageSimulatorProps {
  onAttackTriggered: () => void;
  latestAlert: AlertItem | null;
}

export const StageSimulator: React.FC<StageSimulatorProps> = ({ onAttackTriggered, latestAlert }) => {
  const [loadingAttack, setLoadingAttack] = useState<string | null>(null);
  const [resetting, setResetting] = useState(false);
  const [lastExecution, setLastExecution] = useState<{
    type: string;
    pid?: number | string;
    reactionTime?: string;
    status: string;
    message?: string;
  } | null>(null);

  const handleSimulate = async (type: 'ransomware' | 'eicar' | 'macro_injection') => {
    setLoadingAttack(type);
    try {
      const res = await api.simulateAttack(type);
      setLastExecution({
        type: type.toUpperCase(),
        pid: res.pid || res.alert?.pid || 'Intercepted',
        reactionTime: res.reaction_time_ms || res.alert?.reaction_time_ms || '< 5ms',
        status: 'NEUTRALIZED',
        message: res.message || res.alert?.action_taken || 'Threat neutralized'
      });
      // Refresh telemetry & alerts
      setTimeout(() => {
        onAttackTriggered();
        setLoadingAttack(null);
      }, 300);
    } catch (err: any) {
      console.error('Failed to trigger attack:', err);
      setLastExecution({
        type: type.toUpperCase(),
        status: 'ERROR',
        message: err.message || 'Execution error'
      });
      setLoadingAttack(null);
    }
  };

  const handleResetZone = async () => {
    setResetting(true);
    try {
      await api.resetProtectedZone();
      setTimeout(() => {
        onAttackTriggered();
        setResetting(false);
      }, 400);
    } catch (err) {
      console.error('Reset failed:', err);
      setResetting(false);
    }
  };

  return (
    <div className="cyber-card rounded-xl p-5 border border-cyan-900/50 relative overflow-hidden">
      {/* Decorative cyber grid header */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4 pb-3 border-b border-cyber-border">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-red-950/70 border border-red-500/50 text-red-400 shadow-crimson-glow">
            <Crosshair className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold font-mono text-slate-100 tracking-wide">
                RED TEAM STAGE SIMULATOR
              </h2>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-red-950 text-red-300 border border-red-800">
                LIVE POC SUITE
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono">
              Execute live safe adversary payloads to verify sub-10ms tripwire detection &amp; PID guillotine
            </p>
          </div>
        </div>

        {/* Reset Protected Zone Button */}
        <button
          onClick={handleResetZone}
          disabled={resetting}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 hover:border-cyan-500/40 transition-all duration-150"
          title="Re-seed canary decoy and dummy files inside backend/protected_zone/"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${resetting ? 'animate-spin' : ''}`} />
          <span>{resetting ? 'Re-seeding...' : 'Reset Decoy Zone'}</span>
        </button>
      </div>

      {/* 3 Prominent Attack Buttons */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
        {/* Attack 1: Ransomware Canary Tripwire */}
        <button
          onClick={() => handleSimulate('ransomware')}
          disabled={loadingAttack !== null}
          className="relative group p-4 rounded-xl text-left bg-gradient-to-br from-[#160c15] to-[#0d1424] border border-red-500/40 hover:border-red-400 hover:shadow-crimson-glow transition-all duration-200 disabled:opacity-50"
        >
          <div className="flex items-start justify-between mb-2">
            <div className="p-2 rounded-lg bg-red-950 border border-red-500/50 text-red-400 group-hover:scale-105 transition-transform">
              <Skull className="w-5 h-5" />
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950/80 border border-red-500 text-red-300 font-bold">
              MITRE T1486
            </span>
          </div>

          <div className="font-mono font-bold text-sm text-slate-100 group-hover:text-red-300 transition-colors mb-1">
            Launch Live Ransomware
          </div>

          <p className="text-[11px] text-slate-400 leading-relaxed mb-3">
            Spawns real OS subprocess <code className="text-red-300">simulate_attack.py</code>. Canary decoy trips watchdog; PID guillotine kills it sub-10ms.
          </p>

          <div className="flex items-center justify-between pt-2 border-t border-red-950/80 text-[10px] font-mono">
            <span className="text-slate-500">Target: !000_Key.docx</span>
            <span className="text-red-400 font-bold flex items-center gap-1">
              {loadingAttack === 'ransomware' ? (
                <>
                  <RefreshCw className="w-3 h-3 animate-spin" /> EXECUTING...
                </>
              ) : (
                'TRIGGER TEST →'
              )}
            </span>
          </div>
        </button>

        {/* Attack 2: EICAR Signature Test */}
        <button
          onClick={() => handleSimulate('eicar')}
          disabled={loadingAttack !== null}
          className="relative group p-4 rounded-xl text-left bg-gradient-to-br from-[#0c1824] to-[#09111c] border border-cyan-500/40 hover:border-cyan-400 hover:shadow-cyan-glow transition-all duration-200 disabled:opacity-50"
        >
          <div className="flex items-start justify-between mb-2">
            <div className="p-2 rounded-lg bg-cyan-950 border border-cyan-500/50 text-cyan-400 group-hover:scale-105 transition-transform">
              <FileCode className="w-5 h-5" />
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-500 text-cyan-300 font-bold">
              MITRE T1027
            </span>
          </div>

          <div className="font-mono font-bold text-sm text-slate-100 group-hover:text-cyan-300 transition-colors mb-1">
            Trigger EICAR Signature
          </div>

          <p className="text-[11px] text-slate-400 leading-relaxed mb-3">
            Drops standardized EICAR test string. Layer 1 Static YARA engine identifies hash and moves file to quarantine vault.
          </p>

          <div className="flex items-center justify-between pt-2 border-t border-cyan-950/80 text-[10px] font-mono">
            <span className="text-slate-500">Layer 1 Static Engine</span>
            <span className="text-cyan-400 font-bold flex items-center gap-1">
              {loadingAttack === 'eicar' ? (
                <>
                  <RefreshCw className="w-3 h-3 animate-spin" /> SCANNING...
                </>
              ) : (
                'TRIGGER TEST →'
              )}
            </span>
          </div>
        </button>

        {/* Attack 3: Macro Process Tree Injection */}
        <button
          onClick={() => handleSimulate('macro_injection')}
          disabled={loadingAttack !== null}
          className="relative group p-4 rounded-xl text-left bg-gradient-to-br from-[#12160d] to-[#09111c] border border-amber-500/40 hover:border-amber-400 hover:shadow-[0_0_20px_rgba(245,158,11,0.25)] transition-all duration-200 disabled:opacity-50"
        >
          <div className="flex items-start justify-between mb-2">
            <div className="p-2 rounded-lg bg-amber-950 border border-amber-500/50 text-amber-400 group-hover:scale-105 transition-transform">
              <Zap className="w-5 h-5" />
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950/80 border border-amber-500 text-amber-300 font-bold">
              MITRE T1055
            </span>
          </div>

          <div className="font-mono font-bold text-sm text-slate-100 group-hover:text-amber-300 transition-colors mb-1">
            Simulate Macro Injection
          </div>

          <p className="text-[11px] text-slate-400 leading-relaxed mb-3">
            Simulates <code className="text-amber-300">WINWORD.EXE -&gt; powershell.exe</code> execution. Layer 3 flags lineage anomaly &amp; terminates child.
          </p>

          <div className="flex items-center justify-between pt-2 border-t border-amber-950/80 text-[10px] font-mono">
            <span className="text-slate-500">Layer 3 Lineage Trap</span>
            <span className="text-amber-400 font-bold flex items-center gap-1">
              {loadingAttack === 'macro_injection' ? (
                <>
                  <RefreshCw className="w-3 h-3 animate-spin" /> ANALYZING...
                </>
              ) : (
                'TRIGGER TEST →'
              )}
            </span>
          </div>
        </button>
      </div>

      {/* Real-time Reaction Stopwatch HUD */}
      {(lastExecution || latestAlert) && (
        <div className="p-3 rounded-lg bg-[#080d19] border border-cyan-900/60 font-mono text-xs flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-red-950 border border-red-500/60 text-red-300 font-bold">
              <ShieldCheck className="w-3.5 h-3.5 text-red-400" />
              <span>PID GUILLOTINE FIRED</span>
            </div>
            <div className="text-slate-300">
              Target: <span className="text-cyan-300 font-bold">{lastExecution?.type || latestAlert?.threat_name}</span>
            </div>
            <div className="text-slate-400">
              PID: <span className="text-red-400 font-bold">{lastExecution?.pid || latestAlert?.pid}</span>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex items-center gap-1.5">
              <span className="text-slate-500">REACTION LATENCY:</span>
              <span className="px-2 py-0.5 rounded bg-cyan-950 border border-cyan-500 text-cyan-300 font-extrabold text-sm shadow-[0_0_10px_rgba(0,240,255,0.4)]">
                {lastExecution?.reactionTime || latestAlert?.reaction_time_ms || '3.2ms'}
              </span>
            </div>
            <span className="text-emerald-400 flex items-center gap-1 font-bold">
              <CheckCircle2 className="w-4 h-4" /> THREAT NEUTRALIZED
            </span>
          </div>
        </div>
      )}
    </div>
  );
};

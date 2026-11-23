import React from 'react';
import { Cpu, HardDrive, Activity, FileSearch } from 'lucide-react';
import type { Telemetry } from '../types';

interface TelemetryGaugesProps {
  telemetry: Telemetry | null;
  loading: boolean;
}

export const TelemetryGauges: React.FC<TelemetryGaugesProps> = ({ telemetry }) => {
  const cpu = telemetry?.cpu_percent ?? 0;
  const ram = telemetry?.memory_percent ?? 0;
  const ramUsed = telemetry?.memory_used_gb ?? 0;
  const ramTotal = telemetry?.memory_total_gb ?? 0;
  const pidsCount = telemetry?.process_count ?? 0;
  const scannedFiles = telemetry?.scanned_file_count ?? 0;
  const threatsBlocked = telemetry?.total_threats_blocked ?? 0;

  const getBarColor = (val: number) => {
    if (val >= 80) return 'bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.7)]';
    if (val >= 50) return 'bg-amber-400 shadow-[0_0_10px_rgba(245,158,11,0.5)]';
    return 'bg-cyan-400 shadow-[0_0_10px_rgba(0,240,255,0.6)]';
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* CPU Gauge */}
      <div className="cyber-card rounded-xl p-4 relative overflow-hidden group">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-cyan-950/60 border border-cyan-500/30 text-cyan-400">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <div className="text-xs font-mono text-slate-400 uppercase tracking-wider">Windows CPU Load</div>
              <div className="text-xl font-bold font-mono text-slate-100 flex items-baseline gap-1">
                <span>{cpu.toFixed(1)}</span>
                <span className="text-xs text-cyan-400 font-normal">%</span>
              </div>
            </div>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300">
            {cpu > 75 ? 'HIGH LOAD' : 'NORMAL'}
          </span>
        </div>

        {/* Progress Bar */}
        <div className="w-full bg-slate-900/80 rounded-full h-2.5 overflow-hidden p-0.5 border border-slate-800">
          <div
            className={`h-full rounded-full transition-all duration-300 ${getBarColor(cpu)}`}
            style={{ width: `${Math.min(100, Math.max(5, cpu))}%` }}
          />
        </div>
        <div className="flex justify-between items-center mt-2 text-[10px] font-mono text-slate-500">
          <span>0%</span>
          <span>POLLING: 1000ms</span>
          <span>100%</span>
        </div>
      </div>

      {/* RAM Gauge */}
      <div className="cyber-card rounded-xl p-4 relative overflow-hidden group">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-blue-950/60 border border-blue-500/30 text-blue-400">
              <HardDrive className="w-5 h-5" />
            </div>
            <div>
              <div className="text-xs font-mono text-slate-400 uppercase tracking-wider">System Memory (RAM)</div>
              <div className="text-xl font-bold font-mono text-slate-100 flex items-baseline gap-1">
                <span>{ram.toFixed(1)}</span>
                <span className="text-xs text-blue-400 font-normal">%</span>
              </div>
            </div>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-950 border border-blue-800 text-blue-300">
            {ramUsed} / {ramTotal} GB
          </span>
        </div>

        {/* Progress Bar */}
        <div className="w-full bg-slate-900/80 rounded-full h-2.5 overflow-hidden p-0.5 border border-slate-800">
          <div
            className={`h-full rounded-full transition-all duration-300 ${getBarColor(ram)}`}
            style={{ width: `${Math.min(100, Math.max(5, ram))}%` }}
          />
        </div>
        <div className="flex justify-between items-center mt-2 text-[10px] font-mono text-slate-500">
          <span>COMMIT LIMIT</span>
          <span>ACTIVE GUARDIAN</span>
        </div>
      </div>

      {/* Active Process Count */}
      <div className="cyber-card rounded-xl p-4 relative overflow-hidden group">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-emerald-950/60 border border-emerald-500/30 text-emerald-400">
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <div className="text-xs font-mono text-slate-400 uppercase tracking-wider">Active OS Processes</div>
              <div className="text-xl font-bold font-mono text-emerald-300 flex items-baseline gap-1">
                <span>{pidsCount}</span>
                <span className="text-xs text-slate-400 font-normal">PIDs</span>
              </div>
            </div>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-300 animate-pulse">
            GUILLOTINE READY
          </span>
        </div>

        <div className="text-[11px] font-mono text-slate-400 flex items-center justify-between mt-2 pt-2 border-t border-slate-800/80">
          <span className="text-slate-500">Immune Whitelist:</span>
          <span className="text-cyan-400">24 System Binaries</span>
        </div>
        <div className="flex justify-between items-center mt-1 text-[10px] font-mono text-slate-500">
          <span>HOOK LATENCY</span>
          <span className="text-emerald-400 font-bold">&lt; 5 ms</span>
        </div>
      </div>

      {/* Scanned Files & Neutralized Threats */}
      <div className="cyber-card rounded-xl p-4 relative overflow-hidden group">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-purple-950/60 border border-purple-500/30 text-purple-400">
              <FileSearch className="w-5 h-5" />
            </div>
            <div>
              <div className="text-xs font-mono text-slate-400 uppercase tracking-wider">Tripwire Inspection</div>
              <div className="text-xl font-bold font-mono text-purple-300 flex items-baseline gap-1">
                <span>{scannedFiles.toLocaleString()}</span>
                <span className="text-xs text-slate-400 font-normal">Events</span>
              </div>
            </div>
          </div>
          <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-bold ${
            threatsBlocked > 0 
              ? 'bg-red-950 border-red-500 text-red-300 shadow-[0_0_10px_rgba(239,68,68,0.5)]'
              : 'bg-slate-900 border-slate-700 text-slate-400'
          }`}>
            {threatsBlocked} THREATS BLOCKED
          </span>
        </div>

        <div className="text-[11px] font-mono text-slate-400 flex items-center justify-between mt-2 pt-2 border-t border-slate-800/80">
          <span className="text-slate-500">Canary Decoy Status:</span>
          <span className="text-emerald-400 font-bold">ARMED (!000_Key)</span>
        </div>
        <div className="flex justify-between items-center mt-1 text-[10px] font-mono text-slate-500">
          <span>VAULT ISOLATION</span>
          <span className="text-cyan-400">SHA-256 SECURED</span>
        </div>
      </div>
    </div>
  );
};

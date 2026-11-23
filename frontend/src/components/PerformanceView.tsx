import React, { useState } from 'react';
import {
  Cpu,
  HardDrive,
  Zap,
  AlertTriangle,
  CheckCircle2,
  Search,
  RefreshCw
} from 'lucide-react';
import type { DeviceAudit, Telemetry } from '../types';
import { api } from '../api';

interface PerformanceViewProps {
  telemetry: Telemetry | null;
  audit: DeviceAudit | null;
  onRefresh: () => void;
}

export const PerformanceView: React.FC<PerformanceViewProps> = ({
  telemetry,
  audit,
  onRefresh,
}) => {
  const [terminatingPid, setTerminatingPid] = useState<number | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [notice, setNotice] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const sys = audit?.system;
  const cpu = sys?.cpu_percent ?? telemetry?.cpu_percent ?? 0;
  const ramPct = sys?.ram_percent ?? telemetry?.memory_percent ?? 0;
  const ramUsed = sys?.ram_used_gb ?? telemetry?.memory_used_gb ?? 0;
  const ramTotal = sys?.ram_total_gb ?? telemetry?.memory_total_gb ?? 0;
  const diskPct = sys?.disk_percent ?? 0;
  const diskFree = sys?.disk_free_gb ?? 0;
  const diskTotal = sys?.disk_total_gb ?? 0;

  const processes = audit?.process_audit?.top_processes || [];
  const filteredProcesses = processes.filter(
    (p) =>
      p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      String(p.pid).includes(searchTerm) ||
      p.exe.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const startups = audit?.startup_audit?.entries || [];

  const handleTerminateProcess = async (pid: number, name: string) => {
    if (!confirm(`Are you sure you want to terminate process '${name}' (PID: ${pid})?`)) return;
    setTerminatingPid(pid);
    try {
      await api.terminateProcess(pid);
      setNotice({ type: 'success', message: `Process '${name}' (PID: ${pid}) successfully terminated.` });
      onRefresh();
    } catch (e: any) {
      setNotice({ type: 'error', message: e.message || 'Failed to terminate process.' });
    } finally {
      setTerminatingPid(null);
      setTimeout(() => setNotice(null), 4000);
    }
  };

  return (
    <div className="space-y-6 font-mono">
      {notice && (
        <div className={`p-4 rounded-xl border text-xs flex items-center justify-between ${
          notice.type === 'success' ? 'bg-emerald-950/80 border-kaspersky-emerald text-emerald-300' : 'bg-red-950/80 border-red-500 text-red-300'
        }`}>
          <div className="flex items-center gap-2">
            {notice.type === 'success' ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
            <span>{notice.message}</span>
          </div>
        </div>
      )}

      {/* Hardware Telemetry Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* CPU Card */}
        <div className="kaspersky-panel rounded-2xl p-5 border border-suite-border space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-500/40">
                <Cpu className="w-5 h-5" />
              </div>
              <div>
                <span className="text-[10px] text-slate-400 uppercase">Processor Utilization</span>
                <div className="text-xl font-bold text-slate-100">{cpu.toFixed(1)}%</div>
              </div>
            </div>
            <span className="text-[10px] px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-300">
              {sys?.cpu_count || 8} Cores
            </span>
          </div>

          <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
            <div
              className="h-full bg-cyan-400 transition-all duration-300"
              style={{ width: `${Math.min(100, Math.max(5, cpu))}%` }}
            />
          </div>
          <div className="text-[10px] text-slate-500 truncate">{sys?.processor}</div>
        </div>

        {/* RAM Card */}
        <div className="kaspersky-panel rounded-2xl p-5 border border-suite-border space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-lg bg-emerald-950 text-kaspersky-emerald border border-emerald-500/40">
                <Zap className="w-5 h-5" />
              </div>
              <div>
                <span className="text-[10px] text-slate-400 uppercase">System RAM Load</span>
                <div className="text-xl font-bold text-slate-100">{ramPct.toFixed(1)}%</div>
              </div>
            </div>
            <span className="text-[10px] px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
              {ramUsed} / {ramTotal} GB
            </span>
          </div>

          <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
            <div
              className="h-full bg-kaspersky-emerald transition-all duration-300"
              style={{ width: `${Math.min(100, Math.max(5, ramPct))}%` }}
            />
          </div>
          <div className="flex justify-between text-[10px] text-slate-500">
            <span>Commit Limit</span>
            <span>Real-time Guardian Armed</span>
          </div>
        </div>

        {/* Disk Card */}
        <div className="kaspersky-panel rounded-2xl p-5 border border-suite-border space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-lg bg-purple-950 text-purple-400 border border-purple-500/40">
                <HardDrive className="w-5 h-5" />
              </div>
              <div>
                <span className="text-[10px] text-slate-400 uppercase">System Storage (C:)</span>
                <div className="text-xl font-bold text-slate-100">{diskPct.toFixed(1)}%</div>
              </div>
            </div>
            <span className="text-[10px] px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
              {diskFree} GB Free
            </span>
          </div>

          <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
            <div
              className="h-full bg-purple-400 transition-all duration-300"
              style={{ width: `${Math.min(100, Math.max(5, diskPct))}%` }}
            />
          </div>
          <div className="flex justify-between text-[10px] text-slate-500">
            <span>Total: {diskTotal} GB</span>
            <span>OS Build: {sys?.os_release || 'Windows'}</span>
          </div>
        </div>
      </div>

      {/* Resource Hunter: Top Processes Inspection */}
      <div className="kaspersky-panel rounded-2xl p-6 border border-suite-border space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-suite-border">
          <div>
            <h3 className="text-base font-bold text-slate-100">
              RESOURCE HUNTER &amp; PROCESS AUDITOR
            </h3>
            <p className="text-xs text-slate-400">
              Real running processes with live memory footprint, path inspection, and safe termination
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-3" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search PID, name, path..."
                className="pl-8 pr-3 py-1.5 rounded-lg bg-[#090F1E] border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-400 w-56"
              />
            </div>
            <button
              onClick={onRefresh}
              className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 transition-colors"
              title="Refresh Process List"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Process Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#090E1B] text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">PID</th>
                <th className="py-2.5 px-3">Process Name</th>
                <th className="py-2.5 px-3">Memory (MB)</th>
                <th className="py-2.5 px-3">CPU %</th>
                <th className="py-2.5 px-3">Executable Path</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-900 text-slate-300 text-[11px]">
              {filteredProcesses.map((proc) => (
                <tr key={proc.pid} className="hover:bg-slate-900/50 transition-colors">
                  <td className="py-2.5 px-3 font-bold text-slate-400">{proc.pid}</td>
                  <td className="py-2.5 px-3 font-semibold text-slate-100 flex items-center gap-1.5">
                    <span>{proc.name}</span>
                    {proc.is_immune && (
                      <span className="text-[9px] px-1 py-0.2 rounded bg-slate-800 text-slate-400">CORE</span>
                    )}
                  </td>
                  <td className="py-2.5 px-3 text-cyan-300 font-bold">{proc.memory_mb} MB</td>
                  <td className="py-2.5 px-3 text-slate-300">{proc.cpu_percent}%</td>
                  <td className="py-2.5 px-3 text-slate-400 truncate max-w-md" title={proc.exe}>
                    {proc.exe}
                  </td>
                  <td className="py-2.5 px-3 text-right">
                    {!proc.is_immune && (
                      <button
                        onClick={() => handleTerminateProcess(proc.pid, proc.name)}
                        disabled={terminatingPid === proc.pid}
                        className="px-2.5 py-1 rounded bg-red-950/60 hover:bg-red-900 border border-red-500/50 text-red-300 text-[10px] font-bold transition-colors disabled:opacity-50"
                      >
                        {terminatingPid === proc.pid ? 'Killing...' : 'Terminate'}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Windows Registry Startup Optimizer */}
      <div className="kaspersky-panel rounded-2xl p-6 border border-suite-border space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-suite-border">
          <div>
            <h3 className="text-base font-bold text-slate-100">
              WINDOWS STARTUP &amp; REGISTRY OPTIMIZER
            </h3>
            <p className="text-xs text-slate-400">
              Live inspection of <code className="text-cyan-300">HKCU\Software\Microsoft\Windows\CurrentVersion\Run</code>
            </p>
          </div>
          <span className="text-xs text-kaspersky-emerald font-bold">
            {startups.length} Auto-Run Binaries
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {startups.map((st, i) => (
            <div key={i} className="p-3.5 rounded-xl bg-[#090F1E] border border-slate-800 space-y-1.5 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-100">{st.name}</span>
                <span className={`text-[9px] px-1.5 py-0.2 rounded font-bold ${
                  st.suspicious ? 'bg-amber-950 text-amber-300 border border-amber-600' : 'bg-slate-900 text-slate-400 border border-slate-800'
                }`}>
                  {st.hive.split('_')[1]}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 break-all bg-slate-950 p-2 rounded border border-slate-900">
                {st.command}
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

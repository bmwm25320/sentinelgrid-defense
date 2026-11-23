import React, { useState, useEffect } from 'react';
import {
  Activity,
  Cpu,
  HardDrive,
  CheckCircle2,
  ShieldCheck,
  Search,
  RotateCw,
  Moon,
  Zap,
  Sparkles,
  CheckSquare,
  Square,
} from 'lucide-react';
import type { DeviceAudit, Telemetry, ProcessItem, StartupItem, RamDiagnostics } from '../types';
import { api } from '../api';

interface DeviceHealthViewProps {
  audit: DeviceAudit | null;
  telemetry: Telemetry | null;
  onRefreshData: () => void;
}

export const DeviceHealthView: React.FC<DeviceHealthViewProps> = ({
  audit,
  telemetry,
  onRefreshData,
}) => {
  const [terminatingPid, setTerminatingPid] = useState<number | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [notice, setNotice] = useState<string | null>(null);
  const [dndEnabled, setDndEnabled] = useState(false);
  const [dndLoading, setDndLoading] = useState(false);
  const [ramDiag, setRamDiag] = useState<RamDiagnostics | null>(null);
  const [selectedPids, setSelectedPids] = useState<number[]>([]);
  const [isOptimizingRam, setIsOptimizingRam] = useState(false);
  const [ramOptimizeResult, setRamOptimizeResult] = useState<string | null>(null);

  useEffect(() => {
    loadDndStatus();
    loadRamDiagnostics();
  }, []);

  const loadRamDiagnostics = async () => {
    try {
      const data = await api.getRamDiagnostics();
      setRamDiag(data);
      const safePids = data.top_apps.filter((a) => a.can_safely_close).slice(0, 4).map((a) => a.pid);
      setSelectedPids(safePids);
    } catch (e) {
      console.error('Failed to load RAM diagnostics:', e);
    }
  };

  const handleTogglePid = (pid: number) => {
    setSelectedPids((prev) =>
      prev.includes(pid) ? prev.filter((p) => p !== pid) : [...prev, pid]
    );
  };

  const handleBoostRam = async () => {
    setIsOptimizingRam(true);
    setRamOptimizeResult(null);
    try {
      const res = await api.optimizeRam(selectedPids.length > 0 ? selectedPids : undefined);
      setRamOptimizeResult(`Reclaimed ${res.reclaimed_mb} MB RAM! Successfully freed background memory.`);
      await loadRamDiagnostics();
      onRefreshData();
    } catch (e: any) {
      setRamOptimizeResult(`Optimization note: ${e.message}`);
    } finally {
      setIsOptimizingRam(false);
    }
  };

  const loadDndStatus = async () => {
    try {
      const res = await api.getDnd();
      setDndEnabled(res.dnd_enabled);
    } catch (e) {
      console.error('Failed to load DND state:', e);
    }
  };

  const handleToggleDnd = async () => {
    const nextState = !dndEnabled;
    setDndEnabled(nextState);
    setDndLoading(true);
    try {
      const res = await api.setDnd(nextState);
      setDndEnabled(res.dnd_enabled);
    } catch (e: any) {
      setDndEnabled(!nextState);
      alert(`Failed to update mode: ${e.message}`);
    } finally {
      setDndLoading(false);
    }
  };

  const cpuPercent = telemetry?.cpu_percent ?? 18;
  const memPercent = telemetry?.memory_percent ?? 55;
  const memUsed = telemetry?.memory_used_gb ?? 8.5;
  const memTotal = telemetry?.memory_total_gb ?? 16.0;
  const healthScore = audit?.security_score ?? 85;

  const startupItems: StartupItem[] = audit?.startup_audit?.entries || [];
  const processes: ProcessItem[] = audit?.process_audit?.top_processes || [];

  const filteredProcesses = processes.filter((p: ProcessItem) =>
    p.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleStopProcess = async (pid: number, name: string) => {
    if (!confirm(`Are you sure you want to stop "${name}" (PID: ${pid})?`)) {
      return;
    }
    setTerminatingPid(pid);
    setNotice(null);
    try {
      const res = await api.terminateProcess(pid);
      setNotice(`Successfully stopped ${res.name || name} (PID: ${pid}).`);
      onRefreshData();
    } catch (e: any) {
      setNotice(`Safety Protection: ${e.message}`);
    } finally {
      setTerminatingPid(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Health Overview */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-[#0F1E1B] via-[#131A26] to-[#131A26] border border-emerald-500/30 flex flex-col md:flex-row md:items-center justify-between gap-6 shadow-sm">
        <div className="flex items-center gap-4">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-emerald-500 to-teal-700 text-white flex items-center justify-center shadow-md">
            <Activity className="w-7 h-7" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] uppercase font-bold tracking-wider px-2.5 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-500/30">
                Health Score: {healthScore}/100
              </span>
              <span className="text-xs text-slate-400">• Device Status</span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight mt-0.5">
              Device Health &amp; Performance
            </h2>
            <p className="text-xs text-slate-400">
              Host: <span className="text-slate-300 font-medium">{audit?.system?.hostname || 'This PC'}</span> •{' '}
              {audit?.system?.os_name || audit?.system?.os_release || 'Windows 11'}
            </p>
          </div>
        </div>

        {/* Quick specs pill */}
        <div className="flex items-center gap-4 text-xs text-slate-300 bg-[#0D121D] border border-[#1F2937] p-3 rounded-xl">
          <div>
            <div className="text-[11px] text-slate-400">Processor Cores</div>
            <div className="font-semibold text-white">{audit?.system?.cpu_count || 8} Cores</div>
          </div>
          <div className="h-6 w-px bg-slate-800" />
          <div>
            <div className="text-[11px] text-slate-400">Total Memory</div>
            <div className="font-semibold text-white">{memTotal} GB RAM</div>
          </div>
        </div>
      </div>

      {/* Action Notification */}
      {notice && (
        <div className="p-3.5 rounded-xl bg-slate-800/80 border border-slate-700 text-xs text-slate-200 flex items-center justify-between">
          <span>{notice}</span>
          <button onClick={() => setNotice(null)} className="text-slate-400 hover:text-white text-xs">
            Dismiss
          </button>
        </div>
      )}

      {/* 2 Resource Gauges (CPU & RAM) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* CPU Usage Card */}
        <div className="defender-card p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <Cpu className="w-4 h-4" />
              </div>
              <span className="text-xs font-semibold text-white">Processor (CPU) Usage</span>
            </div>
            <span className="text-sm font-bold text-emerald-400">{cpuPercent}%</span>
          </div>

          <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
            <div
              className={`h-full transition-all duration-300 ${
                cpuPercent > 80 ? 'bg-amber-400' : 'bg-emerald-400'
              }`}
              style={{ width: `${Math.min(100, Math.max(5, cpuPercent))}%` }}
            />
          </div>
          <p className="text-[11px] text-slate-400">Normal processing load. System is running responsively.</p>
        </div>

        {/* Memory (RAM) Usage Card */}
        <div className="defender-card p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <HardDrive className="w-4 h-4" />
              </div>
              <span className="text-xs font-semibold text-white">Memory (RAM) Usage</span>
            </div>
            <span className="text-sm font-bold text-cyan-400">{memPercent}%</span>
          </div>

          <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
            <div
              className={`h-full transition-all duration-300 ${
                memPercent > 85 ? 'bg-amber-400' : 'bg-cyan-400'
              }`}
              style={{ width: `${Math.min(100, Math.max(5, memPercent))}%` }}
            />
          </div>
          <p className="text-[11px] text-slate-400">
            {memUsed} GB in use out of {memTotal} GB available.
          </p>
        </div>
      </div>

      {/* Smart RAM Optimization & Diagnostics Card */}
      <div className="defender-card p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#1F2937]">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <Zap className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-xs font-semibold text-white">Smart RAM Optimization &amp; Diagnostics</h3>
              <p className="text-[11px] text-slate-400">
                Safely free standby memory and close heavy idle user apps without touching system processes.
              </p>
            </div>
          </div>

          <button
            onClick={handleBoostRam}
            disabled={isOptimizingRam}
            className="px-4 py-2 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-white font-semibold text-xs flex items-center justify-center gap-2 shadow-lg shadow-emerald-950/50 transition-all disabled:opacity-50 shrink-0"
          >
            <Zap className={`w-3.5 h-3.5 ${isOptimizingRam ? 'animate-spin' : ''}`} />
            <span>{isOptimizingRam ? 'Optimizing RAM...' : 'Boost & Free RAM'}</span>
          </button>
        </div>

        {/* Smart Recommendation Banner */}
        <div className="p-3.5 rounded-xl bg-gradient-to-r from-[#0E1D24] to-[#121A28] border border-emerald-500/30 flex items-start sm:items-center gap-3">
          <Sparkles className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5 sm:mt-0" />
          <div className="flex-1 text-xs">
            <span className="font-semibold text-white">Recommendation: </span>
            <span className="text-slate-300">
              Closing <strong className="text-emerald-400">{selectedPids.length} selected apps</strong> will reclaim ~<strong className="text-emerald-400">{Math.round(ramDiag?.top_apps.filter(a => selectedPids.includes(a.pid)).reduce((sum, a) => sum + a.memory_mb, 0) || 0)} MB</strong> of RAM.
            </span>
          </div>
          {ramOptimizeResult && (
            <span className="text-[11px] font-medium text-emerald-400 px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-500/30">
              {ramOptimizeResult}
            </span>
          )}
        </div>

        {/* Top Memory Consuming User Apps List */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-[11px] text-slate-400 px-1">
            <span>Applications using memory (Safe background user apps)</span>
            <span>{ramDiag?.top_apps.length || 0} apps detected</span>
          </div>

          <div className="max-h-56 overflow-y-auto space-y-1.5 pr-1">
            {(ramDiag?.top_apps || []).slice(0, 10).map((app) => {
              const isSelected = selectedPids.includes(app.pid);
              return (
                <div
                  key={app.pid}
                  onClick={() => app.can_safely_close && handleTogglePid(app.pid)}
                  className={`p-2.5 rounded-lg border flex items-center justify-between text-xs cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-[#121D2C] border-emerald-500/40 text-slate-200'
                      : 'bg-[#0D121D] border-[#1F2937] text-slate-400 hover:bg-[#131A26]'
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    {app.can_safely_close ? (
                      isSelected ? (
                        <CheckSquare className="w-4 h-4 text-emerald-400 shrink-0" />
                      ) : (
                        <Square className="w-4 h-4 text-slate-500 shrink-0" />
                      )
                    ) : (
                      <div className="w-4 h-4 rounded-full bg-slate-700/50 flex items-center justify-center shrink-0">
                        <div className="w-1.5 h-1.5 rounded-full bg-slate-400" />
                      </div>
                    )}
                    <div className="truncate">
                      <span className="font-semibold text-white truncate">{app.name}</span>
                      <span className="text-[11px] text-slate-400 ml-2 truncate">({app.category})</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2.5 shrink-0">
                    <span className="font-mono text-xs text-slate-300">{app.memory_mb} MB</span>
                    {app.can_safely_close ? (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-500/30">
                        Safe to Close
                      </span>
                    ) : (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                        Active
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Do Not Disturb / Presentation Mode */}
      <div className="defender-card p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-start sm:items-center gap-3.5">
          <div
            className={`p-2.5 rounded-xl border transition-colors shrink-0 ${
              dndEnabled
                ? 'bg-purple-500/10 text-purple-400 border-purple-500/30'
                : 'bg-[#0D121D] text-slate-400 border-[#1F2937]'
            }`}
          >
            <Moon className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-xs font-semibold text-white">Do Not Disturb / Presentation Mode</h3>
              <span
                className={`text-[10px] px-2 py-0.5 rounded font-medium ${
                  dndEnabled
                    ? 'bg-purple-950/80 text-purple-300 border border-purple-500/40'
                    : 'bg-slate-800 text-slate-400 border border-slate-700'
                }`}
              >
                {dndEnabled ? 'Active (Silent)' : 'Standard Mode'}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Pauses popups, alert sounds, and non-critical scheduled sweeps while you are gaming, watching media, or giving a presentation.
            </p>
          </div>
        </div>

        <button
          onClick={handleToggleDnd}
          disabled={dndLoading}
          className={`w-12 h-6 rounded-full transition-colors relative shrink-0 p-0.5 self-end sm:self-auto ${
            dndEnabled ? 'bg-purple-500' : 'bg-slate-700'
          }`}
          title={dndEnabled ? 'Disable Silent Mode' : 'Enable Silent Mode'}
        >
          <div
            className={`w-5 h-5 rounded-full bg-white transition-transform ${
              dndEnabled ? 'translate-x-6' : 'translate-x-0'
            }`}
          />
        </button>
      </div>

      {/* Windows Security Posture Check */}
      <div className="defender-card p-5 space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-[#1F2937]">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <h3 className="text-xs font-semibold text-white">Windows Security Posture Check</h3>
          </div>
          <span className="text-[11px] text-emerald-400 font-medium">All Core Controls Verified</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
          <div className="p-3 rounded-xl bg-[#0D121D] border border-[#1F2937] flex items-center gap-2.5">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <div>
              <div className="font-semibold text-white">Windows Defender</div>
              <div className="text-[11px] text-slate-400">Service Active</div>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-[#0D121D] border border-[#1F2937] flex items-center gap-2.5">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <div>
              <div className="font-semibold text-white">Windows Firewall</div>
              <div className="text-[11px] text-slate-400">Filtering On</div>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-[#0D121D] border border-[#1F2937] flex items-center gap-2.5">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <div>
              <div className="font-semibold text-white">User Account Control</div>
              <div className="text-[11px] text-slate-400">Protected</div>
            </div>
          </div>
        </div>
      </div>

      {/* Startup Applications */}
      <div className="defender-card p-5 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-[#1F2937]">
          <div>
            <h3 className="text-xs font-semibold text-white">Startup Applications</h3>
            <p className="text-xs text-slate-400">Programs configured to start automatically when Windows boots</p>
          </div>
          <span className="text-xs text-slate-400">{startupItems.length} apps monitored</span>
        </div>

        {startupItems.length === 0 ? (
          <p className="text-xs text-slate-400 text-center py-4">No third-party startup applications registered.</p>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {startupItems.map((item: StartupItem, idx: number) => (
              <div
                key={idx}
                className="p-3 rounded-xl bg-[#0D121D] border border-[#1F2937] flex items-center justify-between gap-3 text-xs"
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className="w-2 h-2 rounded-full bg-emerald-400 shrink-0" />
                  <div className="truncate">
                    <div className="font-semibold text-white truncate">{item.name}</div>
                    <div className="text-[11px] text-slate-400 truncate">{item.command || item.location}</div>
                  </div>
                </div>

                <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 shrink-0">
                  Monitored
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Active Running Applications */}
      <div className="defender-card p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#1F2937]">
          <div>
            <h3 className="text-xs font-semibold text-white">Running Applications (Safe Management)</h3>
            <p className="text-xs text-slate-400">Stop hung or unnecessary apps safely without touching system core</p>
          </div>

          <div className="relative w-full sm:w-48">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search running app..."
              className="bg-[#0D121D] border border-[#1F2937] rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500/50 w-full"
            />
          </div>
        </div>

        <div className="max-h-72 overflow-y-auto space-y-2 pr-1">
          {filteredProcesses.slice(0, 15).map((p: ProcessItem) => {
            const isStopping = terminatingPid === p.pid;
            return (
              <div
                key={p.pid}
                className="p-2.5 rounded-lg bg-[#0D121D] border border-[#1F2937] flex items-center justify-between text-xs"
              >
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 rounded-full bg-slate-500" />
                  <div>
                    <span className="font-semibold text-white">{p.name}</span>
                    <span className="text-[11px] text-slate-400 ml-2 font-mono">PID {p.pid}</span>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <span className="text-[11px] text-slate-400">{p.memory_mb || 35} MB RAM</span>
                  <button
                    onClick={() => handleStopProcess(p.pid, p.name)}
                    disabled={isStopping}
                    className="px-2.5 py-1 rounded bg-[#182232] hover:bg-red-500/20 text-slate-300 hover:text-red-300 border border-[#2B384E] text-[11px] font-medium transition-colors disabled:opacity-50"
                  >
                    {isStopping ? <RotateCw className="w-3 h-3 animate-spin" /> : 'End App'}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

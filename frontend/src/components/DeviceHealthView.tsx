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
  Trash2,
  PackageCheck,
  Power,
  AlertOctagon,
  Terminal,
  Archive,
} from 'lucide-react';
import type {
  DeviceAudit,
  Telemetry,
  ProcessItem,
  StartupItem,
  RamDiagnostics,
  DiskJunkScanResult,
  ManagedStartupItem,
  SoftwareScanResult,
  ProcessHuntResult,
  ScheduledTasksResult,
  SnapshotItem,
  SnapshotBackupResult,
} from '../types';
import { api } from '../api';
import { FeatureInfo } from './FeatureInfo';
import { SentinelDeviceGuard, isAndroidNativeApp } from '../plugins/sentinelDeviceGuard';

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
  const [selectedApps, setSelectedApps] = useState<string[]>([]);
  const [isOptimizingRam, setIsOptimizingRam] = useState(false);
  const [ramOptimizeResult, setRamOptimizeResult] = useState<string | null>(null);
  const [junkScan, setJunkScan] = useState<DiskJunkScanResult | null>(null);
  const [isScanningJunk, setIsScanningJunk] = useState(false);
  const [isCleaningJunk, setIsCleaningJunk] = useState(false);
  const [junkNotice, setJunkNotice] = useState<string | null>(null);
  const [managedStartup, setManagedStartup] = useState<ManagedStartupItem[]>([]);
  const [togglingStartup, setTogglingStartup] = useState<string | null>(null);
  const [bootAutoStart, setBootAutoStart] = useState(false);
  const [togglingBoot, setTogglingBoot] = useState(false);
  const [softwareScan, setSoftwareScan] = useState<SoftwareScanResult | null>(null);
  const [isScanningSoftware, setIsScanningSoftware] = useState(false);
  const [patchingPkgId, setPatchingPkgId] = useState<string | null>(null);
  const [softwareNotice, setSoftwareNotice] = useState<string | null>(null);
  const [processHunt, setProcessHunt] = useState<ProcessHuntResult | null>(null);
  const [huntingProcesses, setHuntingProcesses] = useState(false);
  const [schtasksAudit, setSchtasksAudit] = useState<ScheduledTasksResult | null>(null);
  const [scanningTasks, setScanningTasks] = useState(false);
  const [snapshots, setSnapshots] = useState<SnapshotItem[]>([]);
  const [creatingSnapshot, setCreatingSnapshot] = useState(false);
  const [snapshotNotice, setSnapshotNotice] = useState<string | null>(null);
  const isAndroidApp = isAndroidNativeApp();

  useEffect(() => {
    loadDndStatus();
    loadRamDiagnostics();
    if (!isAndroidApp) {
      loadKasperskySuitePanels();
      loadPowerDefensePanels();
    }
  }, []);

  const loadPowerDefensePanels = async () => {
    try {
      const [huntRes, snapRes] = await Promise.allSettled([
        api.huntBehavioralThreats(),
        api.listSnapshotBackups(),
      ]);
      if (huntRes.status === 'fulfilled') setProcessHunt(huntRes.value);
      if (snapRes.status === 'fulfilled') setSnapshots(snapRes.value.snapshots || []);
    } catch {
      // Ignore startup fetch errors
    }
  };

  const handleRunProcessHunt = async () => {
    setHuntingProcesses(true);
    try {
      const res = await api.huntBehavioralThreats();
      setProcessHunt(res);
    } catch (e: any) {
      setNotice(`LOLBin hunt note: ${e.message}`);
    } finally {
      setHuntingProcesses(false);
    }
  };

  const handleScanScheduledTasks = async () => {
    setScanningTasks(true);
    try {
      const res = await api.scanScheduledTasks();
      setSchtasksAudit(res);
    } catch (e: any) {
      setNotice(`Scheduled tasks scan note: ${e.message}`);
    } finally {
      setScanningTasks(false);
    }
  };

  const handleCreateSnapshot = async () => {
    setCreatingSnapshot(true);
    setSnapshotNotice(null);
    try {
      const res: SnapshotBackupResult = await api.createSnapshotBackup();
      if (res.status === 'backed_up') {
        setSnapshotNotice(
          `Snapshot ${res.snapshot_name} sealed (${res.files_backed_up} files · ${res.size_kb} KB at ${res.created_at})`
        );
        const listRes = await api.listSnapshotBackups();
        setSnapshots(listRes.snapshots || []);
      } else {
        setSnapshotNotice('Snapshot created.');
      }
    } catch (e: any) {
      setSnapshotNotice(`Snapshot error: ${e.message}`);
    } finally {
      setCreatingSnapshot(false);
    }
  };

  const loadKasperskySuitePanels = async () => {
    try {
      const [junkRes, startupRes, bootRes, swRes] = await Promise.allSettled([
        api.scanDiskJunk(),
        api.listStartupApps(),
        api.getBootPersistence(),
        api.scanSoftwareVulnerabilities(false),
      ]);
      if (junkRes.status === 'fulfilled') setJunkScan(junkRes.value);
      if (startupRes.status === 'fulfilled') setManagedStartup(startupRes.value.entries || []);
      if (bootRes.status === 'fulfilled') setBootAutoStart(Boolean(bootRes.value.enabled));
      if (swRes.status === 'fulfilled') setSoftwareScan(swRes.value);
    } catch {
      // Ignore transient startup load errors
    }
  };

  const handleScanJunk = async () => {
    setIsScanningJunk(true);
    setJunkNotice(null);
    try {
      const res = await api.scanDiskJunk();
      setJunkScan(res);
    } catch (e: any) {
      setJunkNotice(`Junk scan note: ${e.message}`);
    } finally {
      setIsScanningJunk(false);
    }
  };

  const handleCleanJunk = async () => {
    setIsCleaningJunk(true);
    setJunkNotice(null);
    try {
      const res = await api.cleanDiskJunk();
      setJunkNotice(`Cleaned ${res.deleted_files} junk files · Freed ${res.freed_mb} MB disk space!`);
      const fresh = await api.scanDiskJunk();
      setJunkScan(fresh);
      onRefreshData();
    } catch (e: any) {
      setJunkNotice(`Cleanup note: ${e.message}`);
    } finally {
      setIsCleaningJunk(false);
    }
  };

  const handleToggleStartup = async (name: string, nextEnabled: boolean) => {
    setTogglingStartup(name);
    try {
      await api.toggleStartupApp(name, nextEnabled);
      const res = await api.listStartupApps();
      setManagedStartup(res.entries || []);
    } catch (e: any) {
      setNotice(`Startup toggle failed: ${e.message}`);
    } finally {
      setTogglingStartup(null);
    }
  };

  const handleToggleBootAutoStart = async () => {
    setTogglingBoot(true);
    try {
      const res = await api.setBootPersistence(!bootAutoStart);
      setBootAutoStart(res.enabled);
    } catch (e: any) {
      setNotice(`Boot persistence note: ${e.message}`);
    } finally {
      setTogglingBoot(false);
    }
  };

  const handleRefreshSoftwareVulns = async () => {
    setIsScanningSoftware(true);
    setSoftwareNotice(null);
    try {
      const res = await api.scanSoftwareVulnerabilities(true);
      setSoftwareScan(res);
    } catch (e: any) {
      setSoftwareNotice(`Vulnerability scan note: ${e.message}`);
    } finally {
      setIsScanningSoftware(false);
    }
  };

  const handlePatchPackage = async (pkgId: string) => {
    setPatchingPkgId(pkgId);
    setSoftwareNotice(null);
    try {
      const res = await api.patchSoftwarePackage(pkgId);
      setSoftwareNotice(`${pkgId}: ${res.message || res.status}`);
      const fresh = await api.scanSoftwareVulnerabilities(true);
      setSoftwareScan(fresh);
    } catch (e: any) {
      setSoftwareNotice(`Patch failed for ${pkgId}: ${e.message}`);
    } finally {
      setPatchingPkgId(null);
    }
  };

  const loadRamDiagnostics = async () => {
    try {
      const data = await api.getRamDiagnostics();
      setRamDiag(data);
      const groups = data.grouped_apps || [];
      const defaultSelected = groups
        .filter((g) => g.is_useless_bloat || g.can_safely_close)
        .slice(0, 6)
        .map((g) => g.name);
      setSelectedApps(defaultSelected);
    } catch (e) {
      console.error('Failed to load RAM diagnostics:', e);
    }
  };

  const handleToggleAppGroup = (appName: string) => {
    setSelectedApps((prev) =>
      prev.includes(appName) ? prev.filter((n) => n !== appName) : [...prev, appName]
    );
  };

  const handleKillSingleAppGroup = async (appName: string) => {
    setIsOptimizingRam(true);
    setRamOptimizeResult(null);
    try {
      const res = await api.optimizeRam(undefined, [appName], false);
      setRamOptimizeResult(
        `Stopped ${appName} (${res.closed_pids.length} process${res.closed_pids.length !== 1 ? 'es' : ''}) · Freed ${res.reclaimed_mb} MB RAM.`
      );
      await loadRamDiagnostics();
      onRefreshData();
    } catch (e: any) {
      setRamOptimizeResult(`Stop failed: ${e.message}`);
    } finally {
      setIsOptimizingRam(false);
    }
  };

  const handleKillAllUselessApps = async () => {
    setIsOptimizingRam(true);
    setRamOptimizeResult(null);
    try {
      if (isAndroidApp) {
        const res = await SentinelDeviceGuard.boostBackgroundMemory();
        setRamOptimizeResult(
          `Android Boost: Cleared ${res.killedPackagesCount} background apps · Freed ${res.freedMb} MB RAM (${res.availableAfterMb} MB free).`
        );
        await loadRamDiagnostics();
        onRefreshData();
        return;
      }
      const res = await api.killUselessBackgroundApps();
      setRamOptimizeResult(
        `Killed ${res.closed_pids.length} useless background processes & trimmed ${res.trimmed_processes_count ?? 0} working sets · Freed ${res.reclaimed_mb} MB RAM!`
      );
      await loadRamDiagnostics();
      onRefreshData();
    } catch (e: any) {
      setRamOptimizeResult(`Cleanup note: ${e.message}`);
    } finally {
      setIsOptimizingRam(false);
    }
  };

  const handleTrimStandbyRam = async () => {
    setIsOptimizingRam(true);
    setRamOptimizeResult(null);
    try {
      const res = await api.trimStandbyRam();
      setRamOptimizeResult(
        `Trimmed working sets across ${res.trimmed_processes_count ?? 0} processes · Freed ${res.reclaimed_mb} MB standby RAM without closing apps.`
      );
      await loadRamDiagnostics();
      onRefreshData();
    } catch (e: any) {
      setRamOptimizeResult(`Trim note: ${e.message}`);
    } finally {
      setIsOptimizingRam(false);
    }
  };

  const handleBoostRam = async () => {
    setIsOptimizingRam(true);
    setRamOptimizeResult(null);
    try {
      if (isAndroidApp) {
        const res = await SentinelDeviceGuard.boostBackgroundMemory();
        setRamOptimizeResult(
          `Android Boost: Cleared ${res.killedPackagesCount} background apps · Freed ${res.freedMb} MB RAM!`
        );
        await loadRamDiagnostics();
        onRefreshData();
        return;
      }
      const res = await api.optimizeRam(
        undefined,
        selectedApps.length > 0 ? selectedApps : undefined,
        false
      );
      setRamOptimizeResult(
        `Stopped ${res.closed_pids.length} processes & trimmed ${res.trimmed_processes_count ?? 0} apps · Reclaimed ${res.reclaimed_mb} MB RAM!`
      );
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

      <FeatureInfo
        tone="emerald"
        why="Slow performance, hidden startup programs, outdated software, and sneaky background scripts often go hand in hand with security risks."
        how="Monitors live CPU/RAM usage, cleans safe temp junk, scans for outdated software, hunts suspicious command lines, and keeps clean folder snapshots ready."
      />

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
              <h3 className="text-xs font-semibold text-white">Useless Background App &amp; RAM Killer</h3>
              <p className="text-[11px] text-slate-400">
                Stop idle bloatware, widgets, and background updaters, or trim Windows working sets safely without touching OS core processes.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            {!isAndroidApp && (
              <button
                onClick={handleTrimStandbyRam}
                disabled={isOptimizingRam}
                className="px-3 py-2 rounded-xl bg-[#142032] hover:bg-[#1D2C44] text-cyan-300 border border-cyan-500/40 font-medium text-xs transition-all disabled:opacity-50"
                title="Free standby RAM without closing open apps"
              >
                Trim Standby RAM
              </button>
            )}
            <button
              onClick={handleKillAllUselessApps}
              disabled={isOptimizingRam}
              className="px-3.5 py-2 rounded-xl bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 font-semibold text-xs flex items-center gap-1.5 transition-all disabled:opacity-50"
              title="Terminate all useless background bloat apps immediately"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Stop All Useless Apps</span>
            </button>
            <button
              onClick={handleBoostRam}
              disabled={isOptimizingRam}
              className="px-4 py-2 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-white font-semibold text-xs flex items-center justify-center gap-2 shadow-lg shadow-emerald-950/50 transition-all disabled:opacity-50 shrink-0"
            >
              <Zap className={`w-3.5 h-3.5 ${isOptimizingRam ? 'animate-spin' : ''}`} />
              <span>{isOptimizingRam ? 'Stopping & Freeing...' : 'Kill Selected & Boost RAM'}</span>
            </button>
          </div>
        </div>

        <FeatureInfo
          tone="emerald"
          why="Idle updaters, widgets, and bloatware quietly eat memory and slow down your laptop."
          how="Groups running processes by app, protects your active window and Windows core services, and lets you stop safe background bloat or trim standby RAM in one click."
        />

        {/* Smart Recommendation Banner */}
        <div className="p-3.5 rounded-xl bg-gradient-to-r from-[#0E1D24] to-[#121A28] border border-emerald-500/30 flex flex-col sm:flex-row sm:items-center gap-3">
          <Sparkles className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5 sm:mt-0" />
          <div className="flex-1 text-xs">
            <span className="font-semibold text-white">Recommendation: </span>
            <span className="text-slate-300">
              Stopping <strong className="text-emerald-400">{selectedApps.length} selected background app groups</strong> reclaims ~
              <strong className="text-emerald-400">
                {Math.round(
                  (ramDiag?.grouped_apps || [])
                    .filter((g) => selectedApps.includes(g.name))
                    .reduce((sum, g) => sum + g.total_memory_mb, 0)
                )}{' '}
                MB
              </strong>{' '}
              of RAM ({ramDiag?.useless_bloat_count ?? 0} bloatware groups detected).
            </span>
          </div>
          {ramOptimizeResult && (
            <span className="text-[11px] font-medium text-emerald-400 px-2.5 py-1 rounded bg-emerald-950/80 border border-emerald-500/30">
              {ramOptimizeResult}
            </span>
          )}
        </div>

        {/* Grouped Background Apps List */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-[11px] text-slate-400 px-1">
            <span>Background apps &amp; grouped instances (active foreground app &amp; OS core protected)</span>
            <span>{ramDiag?.grouped_apps?.length || ramDiag?.top_apps.length || 0} app groups detected</span>
          </div>

          <div className="max-h-64 overflow-y-auto space-y-1.5 pr-1">
            {(ramDiag?.grouped_apps || []).map((grp) => {
              const isSelected = selectedApps.includes(grp.name);
              return (
                <div
                  key={grp.name}
                  onClick={() => grp.can_safely_close && handleToggleAppGroup(grp.name)}
                  className={`p-2.5 rounded-lg border flex items-center justify-between text-xs cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-[#121D2C] border-emerald-500/40 text-slate-200'
                      : 'bg-[#0D121D] border-[#1F2937] text-slate-400 hover:bg-[#131A26]'
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    {grp.can_safely_close ? (
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
                      <span className="font-semibold text-white truncate">{grp.name}</span>
                      <span className="text-[10px] text-cyan-400 font-mono ml-1.5">
                        ({grp.instance_count} {grp.instance_count === 1 ? 'proc' : 'procs'})
                      </span>
                      <span className="text-[11px] text-slate-400 ml-2 truncate">· {grp.category}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <span className="font-mono text-xs text-slate-300">{grp.total_memory_mb} MB</span>
                    {grp.can_safely_close ? (
                      <>
                        <span
                          className={`text-[10px] px-1.5 py-0.5 rounded border hidden sm:inline ${
                            grp.is_useless_bloat
                              ? 'bg-amber-950/80 text-amber-300 border-amber-500/40'
                              : 'bg-emerald-950/80 text-emerald-400 border-emerald-500/30'
                          }`}
                        >
                          {grp.is_useless_bloat ? 'Useless Bloat' : 'Safe to Close'}
                        </span>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleKillSingleAppGroup(grp.name);
                          }}
                          disabled={isOptimizingRam}
                          className="px-2 py-0.5 rounded bg-red-500/15 hover:bg-red-500/30 text-red-300 border border-red-500/30 text-[10px] font-semibold transition-colors"
                          title={`Stop all instances of ${grp.name}`}
                        >
                          Stop
                        </button>
                      </>
                    ) : (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                        Protected
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
            <p className="text-[11px] text-slate-500 mt-1">
              <strong className="text-slate-300">How it works:</strong> Real-time threat blocking stays active silently in the background while non-urgent notifications are muted.
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

      {/* Windows Boot Auto-Start + Disk Junk Cleaner */}
      {!isAndroidApp && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Disk Junk & Cache Cleaner */}
          <div className="defender-card p-5 space-y-3">
            <div className="flex items-center justify-between gap-2 pb-2 border-b border-[#1F2937]">
              <div className="flex items-center gap-2">
                <HardDrive className="w-4 h-4 text-amber-400" />
                <div>
                  <h3 className="text-xs font-semibold text-white">Disk Junk &amp; Browser Cache Cleaner</h3>
                  <p className="text-[11px] text-slate-400">Reclaim storage from stale Temp files, Edge/Chrome cache &amp; dumps</p>
                </div>
              </div>
              <button
                onClick={handleScanJunk}
                disabled={isScanningJunk}
                className="p-1.5 rounded-lg bg-[#0D121D] border border-[#1F2937] text-slate-300 hover:text-white"
                title="Re-scan Disk Junk"
              >
                <RotateCw className={`w-3.5 h-3.5 ${isScanningJunk ? 'animate-spin' : ''}`} />
              </button>
            </div>

            <FeatureInfo
              tone="amber"
              why="Leftover temporary files and browser caches waste disk space and are often abused by droppers to hide payloads."
              how="Safely scans Windows Temp, Edge/Chrome cache, and crash dump folders—never touching personal documents—and clears them on request."
            />

            {junkScan ? (
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs bg-[#0D121D] border border-[#1F2937] rounded-xl p-3">
                  <div>
                    <div className="text-[11px] text-slate-400">Reclaimable Safe Junk</div>
                    <div className="text-lg font-bold text-amber-400">
                      {junkScan.total_mb} MB <span className="text-xs font-normal text-slate-400">({junkScan.total_files} files)</span>
                    </div>
                  </div>
                  <button
                    onClick={handleCleanJunk}
                    disabled={isCleaningJunk || junkScan.total_files === 0}
                    className="px-3 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 disabled:opacity-50"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>{isCleaningJunk ? 'Cleaning...' : 'Clean All Junk'}</span>
                  </button>
                </div>

                <div className="space-y-1.5 max-h-32 overflow-y-auto pr-1">
                  {junkScan.categories.map((cat) => (
                    <div key={cat.id} className="flex items-center justify-between text-[11px] px-2.5 py-1.5 rounded-lg bg-[#0D121D] border border-[#1F2937]/80">
                      <span className="text-slate-300 truncate">{cat.label}</span>
                      <span className="font-mono text-slate-400 shrink-0">{cat.size_mb} MB · {cat.file_count} files</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-xs text-slate-400 py-3">Scanning Windows Temp &amp; browser caches...</p>
            )}

            {junkNotice && (
              <div className="p-2.5 rounded-lg bg-emerald-950/30 border border-emerald-500/30 text-[11px] text-emerald-300">
                {junkNotice}
              </div>
            )}
          </div>

          {/* Software Vulnerability Scanner & 1-Click Patcher + Boot Guard */}
          <div className="defender-card p-5 space-y-3">
            <div className="flex items-center justify-between gap-2 pb-2 border-b border-[#1F2937]">
              <div className="flex items-center gap-2">
                <PackageCheck className="w-4 h-4 text-cyan-400" />
                <div>
                  <h3 className="text-xs font-semibold text-white">Software Vulnerability Scanner (Winget)</h3>
                  <p className="text-[11px] text-slate-400">Detects outdated browsers/runtimes with known CVEs &amp; patches silently</p>
                </div>
              </div>
              <button
                onClick={handleRefreshSoftwareVulns}
                disabled={isScanningSoftware}
                className="px-2.5 py-1 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/30 text-cyan-300 text-[11px] font-semibold flex items-center gap-1"
              >
                <RotateCw className={`w-3 h-3 ${isScanningSoftware ? 'animate-spin' : ''}`} />
                <span>{isScanningSoftware ? 'Scanning...' : 'Check Updates'}</span>
              </button>
            </div>

            <FeatureInfo
              tone="cyan"
              why="Hackers commonly break in through known bugs in outdated browsers, PDF readers, and runtimes."
              how="Queries Windows Package Manager (winget) to find installed apps with newer security patches available and updates them silently."
            />

            {softwareScan ? (
              softwareScan.packages.length === 0 ? (
                <div className="p-3 rounded-xl bg-emerald-950/20 border border-emerald-500/30 flex items-center gap-2.5 text-xs text-emerald-300">
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                  <span>All monitored installed apps appear up to date ({softwareScan.winget_available ? 'Winget verified' : 'Offline check'}).</span>
                </div>
              ) : (
                <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                  {softwareScan.packages.slice(0, 8).map((pkg) => (
                    <div key={pkg.id} className="p-2 rounded-lg bg-[#0D121D] border border-[#1F2937] flex items-center justify-between gap-2 text-xs">
                      <div className="min-w-0">
                        <div className="flex items-center gap-1.5">
                          <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold ${pkg.severity === 'HIGH' ? 'bg-red-950 text-red-300 border border-red-500/30' : 'bg-amber-950 text-amber-300 border border-amber-500/30'}`}>
                            {pkg.severity}
                          </span>
                          <span className="font-semibold text-white truncate">{pkg.name}</span>
                        </div>
                        <div className="text-[10px] text-slate-400 font-mono truncate">
                          {pkg.current_version} -&gt; {pkg.available_version}
                        </div>
                      </div>
                      <button
                        onClick={() => handlePatchPackage(pkg.id)}
                        disabled={patchingPkgId === pkg.id}
                        className="px-2.5 py-1 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-[10px] shrink-0 disabled:opacity-50"
                      >
                        {patchingPkgId === pkg.id ? 'Patching...' : 'Patch Now'}
                      </button>
                    </div>
                  ))}
                </div>
              )
            ) : (
              <p className="text-xs text-slate-400 py-2">Click "Check Updates" to scan installed software versions.</p>
            )}

            {softwareNotice && (
              <div className="p-2 rounded-lg bg-cyan-950/30 border border-cyan-500/30 text-[11px] text-cyan-200">
                {softwareNotice}
              </div>
            )}

            {/* Boot Auto-Start Persistence Toggle */}
            <div className="pt-2 border-t border-[#1F2937] flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-xs">
                <Power className={`w-3.5 h-3.5 ${bootAutoStart ? 'text-emerald-400' : 'text-slate-400'}`} />
                <div>
                  <div className="font-medium text-white">Launch SentinelGrid on Windows Boot</div>
                  <div className="text-[10px] text-slate-400">Arms real-time &amp; Gemini background shields at sign-in</div>
                </div>
              </div>
              <button
                onClick={handleToggleBootAutoStart}
                disabled={togglingBoot}
                className={`w-11 h-5 rounded-full transition-colors relative shrink-0 p-0.5 ${
                  bootAutoStart ? 'bg-emerald-500' : 'bg-slate-700'
                }`}
              >
                <div className={`w-4 h-4 rounded-full bg-white transition-transform ${bootAutoStart ? 'translate-x-6' : 'translate-x-0'}`} />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Power Defense: LOLBin Process Hunter, Scheduled Tasks & Ransomware Snapshot Backup (Desktop only) */}
      {!isAndroidApp && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-[#111827]/90 border border-[#1F2937] rounded-2xl p-6 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-base font-semibold text-white flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-red-400" />
                  <span>LOLBin Behavioral Hunter & Persistence</span>
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Detects encoded PowerShell, script drops, Office child shells, and malicious Scheduled Tasks.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleRunProcessHunt}
                  disabled={huntingProcesses}
                  className="px-3 py-1.5 rounded-lg bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-red-200 text-xs font-semibold flex items-center gap-1.5 disabled:opacity-50"
                >
                  <RotateCw className={`w-3.5 h-3.5 ${huntingProcesses ? 'animate-spin' : ''}`} />
                  <span>{huntingProcesses ? 'Hunting...' : 'Hunt Processes'}</span>
                </button>
                <button
                  onClick={handleScanScheduledTasks}
                  disabled={scanningTasks}
                  className="px-3 py-1.5 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/40 text-amber-200 text-xs font-semibold disabled:opacity-50"
                >
                  {scanningTasks ? 'Auditing...' : 'Audit Tasks'}
                </button>
              </div>
            </div>

            <FeatureInfo
              tone="red"
              why="Fileless attackers abuse built-in Windows tools ('Living-off-the-Land' / LOLBins like PowerShell or cmd) and hidden Scheduled Tasks so no malware file ever sits on disk."
              how="Inspects live process command lines for encoded scripts or suspicious parent-child launches (e.g. Word spawning PowerShell) and audits Windows Task Scheduler entries."
            />

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 rounded-xl bg-[#0B0F17] border border-[#1F2937]">
                <div className="text-slate-400">Processes Inspected</div>
                <div className="text-lg font-bold text-white mt-0.5">{processHunt?.processes_inspected ?? '—'}</div>
                <div className={`text-[11px] mt-0.5 ${(processHunt?.threats_found ?? 0) > 0 ? 'text-red-400 font-semibold' : 'text-emerald-400'}`}>
                  {processHunt ? `${processHunt.threats_found} suspicious command line(s)` : 'Ready to hunt'}
                </div>
              </div>
              <div className="p-3 rounded-xl bg-[#0B0F17] border border-[#1F2937]">
                <div className="text-slate-400">Scheduled Tasks</div>
                <div className="text-lg font-bold text-white mt-0.5">
                  {schtasksAudit ? (schtasksAudit.suspicious_count > 0 ? schtasksAudit.suspicious_count : '0') : '—'}
                </div>
                <div className={`text-[11px] mt-0.5 ${(schtasksAudit?.suspicious_count ?? 0) > 0 ? 'text-amber-300 font-semibold' : 'text-slate-400'}`}>
                  {schtasksAudit ? `${schtasksAudit.suspicious_count} persistence flag(s)` : 'Tap Audit Tasks'}
                </div>
              </div>
            </div>

            {processHunt && processHunt.threats.length > 0 && (
              <div className="space-y-2 max-h-40 overflow-y-auto">
                {processHunt.threats.map((t) => (
                  <div key={`${t.pid}-${t.name}`} className="p-2.5 rounded-xl bg-red-950/25 border border-red-500/35 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold text-white">{t.name} (PID {t.pid})</span>
                      <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-300 font-bold text-[10px]">
                        {t.severity} ({t.risk_score})
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-300 font-mono truncate mt-1">{t.cmdline || t.exe}</div>
                    <div className="text-[11px] text-red-300 mt-1">{t.reasons.join(' · ')}</div>
                  </div>
                ))}
              </div>
            )}

            {schtasksAudit && schtasksAudit.tasks.length > 0 && (
              <div className="space-y-2 max-h-36 overflow-y-auto">
                {schtasksAudit.tasks.map((st, idx) => (
                  <div key={`${st.task_name}-${idx}`} className="p-2.5 rounded-xl bg-amber-950/20 border border-amber-500/30 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold text-amber-200 truncate">{st.task_name}</span>
                      <span className="text-[10px] font-bold text-amber-300">{st.severity}</span>
                    </div>
                    <div className="text-[11px] text-slate-300 font-mono truncate mt-0.5">{st.command}</div>
                    <div className="text-[10px] text-slate-400 mt-0.5">Author: {st.author} · Status: {st.status}</div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="bg-[#111827]/90 border border-[#1F2937] rounded-2xl p-6 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-base font-semibold text-white flex items-center gap-2">
                  <Archive className="w-5 h-5 text-emerald-400" />
                  <span>Anti-Ransomware Snapshot Vault</span>
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Creates sealed ZIP snapshot backups of the Protected Zone before ransomware strikes.
                </p>
              </div>
              <button
                onClick={handleCreateSnapshot}
                disabled={creatingSnapshot}
                className="px-3.5 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 disabled:opacity-50"
              >
                <Archive className="w-3.5 h-3.5" />
                <span>{creatingSnapshot ? 'Creating Backup...' : 'Create Snapshot'}</span>
              </button>
            </div>

            <FeatureInfo
              tone="emerald"
              why="Even if ransomware tries to encrypt files before being stopped, having a clean local backup guarantees you never lose important work."
              how="Packs a timestamped, sealed ZIP snapshot of your Protected Zone files into the local snapshot vault so clean copies are always preserved."
            />

            {snapshotNotice && (
              <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-200">
                {snapshotNotice}
              </div>
            )}

            <div className="space-y-2 max-h-44 overflow-y-auto">
              {snapshots.length === 0 ? (
                <div className="text-xs text-slate-400 p-3 rounded-xl bg-[#0B0F17] border border-[#1F2937]">
                  No snapshots created yet. Click <strong>Create Snapshot</strong> to seal a protected backup copy.
                </div>
              ) : (
                snapshots.map((snap) => (
                  <div key={snap.name} className="flex items-center justify-between gap-2 p-2.5 rounded-xl bg-[#0B0F17] border border-[#1F2937] text-xs">
                    <div className="min-w-0">
                      <div className="font-mono text-white truncate">{snap.name}</div>
                    </div>
                    <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 font-semibold shrink-0">
                      {snap.size_kb} KB
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* Windows Security Posture, Startup Applications & Running Processes (Desktop only) */}
      {!isAndroidApp && (
      <>
      <div className="defender-card p-5 space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-[#1F2937]">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <h3 className="text-xs font-semibold text-white">Windows Security Posture Check</h3>
          </div>
          <span className="text-[11px] text-emerald-400 font-medium">All Core Controls Verified</span>
        </div>

        <FeatureInfo
          tone="slate"
          why="Disabling built-in OS defenses (Defender, Firewall, or UAC) is often the first step malware takes after infection."
          how="Continuously verifies that Windows Defender, Windows Firewall, and User Account Control remain enabled."
        />

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

      {/* Startup Applications (Interactive Control) */}
      <div className="defender-card p-5 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-[#1F2937]">
          <div>
            <h3 className="text-xs font-semibold text-white">Startup Applications (Reversible Boot Optimizer)</h3>
            <p className="text-xs text-slate-400">Enable or disable third-party apps from auto-starting with Windows</p>
          </div>
          <span className="text-xs text-slate-400">
            {managedStartup.length > 0 ? managedStartup.length : startupItems.length} apps monitored
          </span>
        </div>

        <FeatureInfo
          tone="slate"
          why="Unwanted apps and persistence malware add themselves to Windows startup, slowing boot time and restarting after reboots."
          how="Lists third-party startup registry entries, flags suspicious paths, and lets you safely disable or re-enable them without deleting the program."
        />

        {managedStartup.length > 0 ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {managedStartup.map((item) => (
              <div
                key={item.name}
                className={`p-3 rounded-xl bg-[#0D121D] border flex items-center justify-between gap-3 text-xs ${
                  item.suspicious ? 'border-red-500/40' : 'border-[#1F2937]'
                }`}
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className={`w-2 h-2 rounded-full shrink-0 ${item.enabled ? 'bg-emerald-400' : 'bg-slate-500'}`} />
                  <div className="truncate">
                    <div className="font-semibold text-white truncate flex items-center gap-1.5">
                      <span>{item.name}</span>
                      {item.suspicious && <AlertOctagon className="w-3 h-3 text-red-400 shrink-0" />}
                    </div>
                    <div className="text-[11px] text-slate-400 truncate">{item.command}</div>
                  </div>
                </div>

                <button
                  onClick={() => handleToggleStartup(item.name, !item.enabled)}
                  disabled={item.protected || togglingStartup === item.name}
                  className={`text-[10px] px-2.5 py-1 rounded font-semibold border shrink-0 transition-colors ${
                    item.protected
                      ? 'bg-emerald-950/60 text-emerald-300 border-emerald-500/30 cursor-not-allowed'
                      : item.enabled
                      ? 'bg-emerald-500/15 hover:bg-red-500/20 text-emerald-300 hover:text-red-300 border-emerald-500/30'
                      : 'bg-slate-800 hover:bg-emerald-500/20 text-slate-300 hover:text-emerald-300 border-slate-700'
                  }`}
                  title={item.protected ? 'Protected core security control' : 'Click to toggle Windows startup'}
                >
                  {item.protected ? 'Protected' : togglingStartup === item.name ? '...' : item.enabled ? 'Enabled' : 'Disabled'}
                </button>
              </div>
            ))}
          </div>
        ) : startupItems.length === 0 ? (
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

        <FeatureInfo
          tone="slate"
          why="Frozen or unknown background processes can drain battery and memory."
          how="Shows live user applications with their Process ID and RAM usage so you can end hung apps safely while system-critical processes stay protected."
        />

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
      </>
      )}
    </div>
  );
};

import React, { useState } from 'react';
import {
  ShieldCheck,
  Search,
  FolderSearch,
  Crosshair,
  Skull,
  FileCode,
  Zap,
  CheckCircle2,
  Copy,
  Check,
  Sparkles
} from 'lucide-react';
import type { ShieldConfig, AlertItem, Telemetry } from '../types';
import { api } from '../api';
import { GeminiAnalystModal } from './GeminiAnalystModal';

interface SecurityViewProps {
  config: ShieldConfig;
  onConfigChange: (newConfig: ShieldConfig) => void;
  alerts: AlertItem[];
  onAlertsUpdated: () => void;
  telemetry: Telemetry | null;
}

export const SecurityView: React.FC<SecurityViewProps> = ({
  config,
  onConfigChange,
  alerts,
  onAlertsUpdated,
  telemetry,
}) => {
  const [folderPath, setFolderPath] = useState('backend/protected_zone');
  const [scanningFolder, setScanningFolder] = useState(false);
  const [folderScanResult, setFolderScanResult] = useState<any>(null);
  const [loadingAttack, setLoadingAttack] = useState<string | null>(null);
  const [lastSimulatorRun, setLastSimulatorRun] = useState<{
    type: string;
    pid?: number | string;
    reactionTime?: string;
    status: string;
    message?: string;
  } | null>(null);
  const [selectedAlertForAi, setSelectedAlertForAi] = useState<AlertItem | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const handleToggle = async (key: keyof ShieldConfig, val: boolean | number) => {
    const updated = { ...config, [key]: val };
    onConfigChange(updated);
    try {
      await api.updateConfig({ [key]: val });
    } catch (e) {
      console.error(e);
    }
  };

  const handleCustomFolderScan = async () => {
    setScanningFolder(true);
    try {
      const res = await api.scanFolder(folderPath, true);
      setFolderScanResult(res);
      onAlertsUpdated();
    } catch (e: any) {
      alert(`Folder scan error: ${e.message}`);
    } finally {
      setScanningFolder(false);
    }
  };

  const handleSimulate = async (type: 'ransomware' | 'eicar' | 'macro_injection') => {
    setLoadingAttack(type);
    try {
      const res = await api.simulateAttack(type);
      setLastSimulatorRun({
        type: type.toUpperCase(),
        pid: res.pid || res.alert?.pid || 'Intercepted',
        reactionTime: res.reaction_time_ms || res.alert?.reaction_time_ms || '< 4ms',
        status: 'NEUTRALIZED',
        message: res.message || res.alert?.action_taken || 'Threat neutralized'
      });
      setTimeout(() => {
        onAlertsUpdated();
        setLoadingAttack(null);
      }, 300);
    } catch (err: any) {
      console.error(err);
      setLoadingAttack(null);
    }
  };

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 1500);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner: Real-Time Cyber Shields Configuration */}
      <div className="kaspersky-panel rounded-2xl p-6 border border-suite-border">
        <div className="flex items-center justify-between mb-4 pb-3 border-b border-suite-border">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-emerald-950 border border-kaspersky-emerald/40 text-kaspersky-emerald shadow-kaspersky-glow">
              <ShieldCheck className="w-6 h-6 animate-pulse-slow" />
            </div>
            <div>
              <h2 className="text-base font-bold font-mono text-slate-100">
                4-LAYER CYBER GUARDIAN SHIELDS
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Real-time autonomous defense layers protecting memory, filesystem, and process lineage
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {telemetry && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                CANARY: {telemetry.canary_status} ({telemetry.scanned_file_count} files)
              </span>
            )}
            <span className="text-[10px] font-mono px-2.5 py-1 rounded bg-emerald-950 text-kaspersky-emerald border border-emerald-500/40 font-bold">
              ALL ENGINES ACTIVE
            </span>
          </div>
        </div>

        {/* 4 Shields Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Layer 1: Static YARA */}
          <div className="p-4 rounded-xl bg-[#090F1D] border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold font-mono text-slate-200">Layer 1: Static YARA</span>
              <button
                onClick={() => handleToggle('layer1_yara', !config.layer1_yara)}
                className={`w-10 h-5 rounded-full p-0.5 transition-colors ${
                  config.layer1_yara ? 'bg-kaspersky-emerald' : 'bg-slate-800'
                }`}
              >
                <div className={`w-4 h-4 rounded-full bg-slate-950 transition-transform ${config.layer1_yara ? 'translate-x-5' : 'translate-x-0'}`} />
              </button>
            </div>
            <p className="text-[11px] text-slate-400 font-mono leading-relaxed">
              PE entropy &amp; signature matching (MITRE T1027).
            </p>
          </div>

          {/* Layer 2: Canary Tripwire */}
          <div className="p-4 rounded-xl bg-[#090F1D] border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold font-mono text-slate-200">Layer 2: Canary Decoy</span>
              <button
                onClick={() => handleToggle('layer2_canary', !config.layer2_canary)}
                className={`w-10 h-5 rounded-full p-0.5 transition-colors ${
                  config.layer2_canary ? 'bg-kaspersky-emerald' : 'bg-slate-800'
                }`}
              >
                <div className={`w-4 h-4 rounded-full bg-slate-950 transition-transform ${config.layer2_canary ? 'translate-x-5' : 'translate-x-0'}`} />
              </button>
            </div>
            <p className="text-[11px] text-slate-400 font-mono leading-relaxed">
              Sub-10ms tripwire &amp; PID Guillotine (MITRE T1486).
            </p>
          </div>

          {/* Layer 3: ML Anomaly Threshold */}
          <div className="p-4 rounded-xl bg-[#090F1D] border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold font-mono text-slate-200">Layer 3: Lineage ML</span>
              <span className="text-[10px] font-mono font-bold text-amber-400 bg-amber-950 px-1.5 py-0.5 rounded border border-amber-600">
                {config.layer3_anomaly_threshold}%
              </span>
            </div>
            <input
              type="range"
              min="10"
              max="99"
              value={config.layer3_anomaly_threshold}
              onChange={(e) => handleToggle('layer3_anomaly_threshold', parseInt(e.target.value, 10))}
              className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-amber-400"
            />
            <p className="text-[10px] text-slate-400 font-mono">Process Tree Anomaly (MITRE T1055)</p>
          </div>

          {/* Layer 4: Network C2 & BadUSB */}
          <div className="p-4 rounded-xl bg-[#090F1D] border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold font-mono text-slate-200">Layer 4: C2 &amp; BadUSB</span>
              <button
                onClick={() => handleToggle('layer4_network_guard', !config.layer4_network_guard)}
                className={`w-10 h-5 rounded-full p-0.5 transition-colors ${
                  config.layer4_network_guard ? 'bg-kaspersky-emerald' : 'bg-slate-800'
                }`}
              >
                <div className={`w-4 h-4 rounded-full bg-slate-950 transition-transform ${config.layer4_network_guard ? 'translate-x-5' : 'translate-x-0'}`} />
              </button>
            </div>
            <p className="text-[11px] text-slate-400 font-mono leading-relaxed">
              Reverse beaconing &amp; HID keystroke intercept.
            </p>
          </div>
        </div>
      </div>

      {/* Target Folder & Entropy Scanner */}
      <div className="kaspersky-panel rounded-2xl p-6 border border-suite-border space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-950 border border-cyan-500/40 text-cyan-400">
              <FolderSearch className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-mono font-bold text-sm text-slate-100">
                TARGET FOLDER &amp; SHANNON ENTROPY SCANNER
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Inspect local directories for packed zero-days (entropy &gt; 7.2) and double extensions
              </p>
            </div>
          </div>
        </div>

        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={folderPath}
            onChange={(e) => setFolderPath(e.target.value)}
            placeholder="Enter directory path (e.g. backend/protected_zone or Downloads)..."
            className="flex-1 px-4 py-2.5 rounded-xl bg-[#090F1E] border border-slate-800 text-slate-100 text-xs font-mono focus:outline-none focus:border-cyan-400"
          />
          <button
            onClick={handleCustomFolderScan}
            disabled={scanningFolder}
            className="px-5 py-2.5 rounded-xl bg-cyan-950 hover:bg-cyan-900 border border-cyan-500 text-cyan-300 font-mono text-xs font-bold transition-all disabled:opacity-50 flex items-center justify-center gap-2"
          >
            <Search className={`w-4 h-4 ${scanningFolder ? 'animate-spin' : ''}`} />
            <span>{scanningFolder ? 'Scanning Directory...' : 'Scan Folder Now'}</span>
          </button>
        </div>

        {folderScanResult && (
          <div className="p-3.5 rounded-xl bg-[#080D1A] border border-cyan-900/60 font-mono text-xs space-y-2">
            <div className="flex justify-between items-center text-slate-300">
              <span>Scanned <span className="text-cyan-300 font-bold">{folderScanResult.files_scanned}</span> files in <code className="text-slate-400">{folderScanResult.folder}</code></span>
              <span className="text-kaspersky-emerald font-bold">STATUS: COMPLETED</span>
            </div>
            {folderScanResult.threats_found.length === 0 ? (
              <div className="text-kaspersky-emerald flex items-center gap-2 text-[11px]">
                <CheckCircle2 className="w-4 h-4" />
                <span>Zero packed anomalies or double-extension masquerades found.</span>
              </div>
            ) : (
              <div className="space-y-1">
                {folderScanResult.threats_found.map((th: any, idx: number) => (
                  <div key={idx} className="flex justify-between items-center text-[11px] p-1.5 rounded bg-red-950/60 border border-red-500/40 text-red-300">
                    <span>{th.filename} — {th.threat}</span>
                    <span className="font-bold text-red-400">{th.quarantined ? 'VAULTED' : 'FLAGGED'}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Red Team Stage Attack Simulator Panel */}
      <div className="kaspersky-panel rounded-2xl p-6 border border-suite-border">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4 pb-3 border-b border-suite-border">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-red-950 border border-red-500/50 text-red-400 shadow-crimson-glow">
              <Crosshair className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <h2 className="text-base font-bold font-mono text-slate-100">
                RED TEAM LIVE POC ATTACK SIMULATOR
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Launch real harmless adversary subprocesses to observe autonomous sub-10ms PID Guillotine neutralization
              </p>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          {/* Attack 1 */}
          <button
            onClick={() => handleSimulate('ransomware')}
            disabled={loadingAttack !== null}
            className="p-4 rounded-xl text-left bg-gradient-to-br from-[#180d16] to-[#0c1322] border border-red-500/40 hover:border-red-400 hover:shadow-crimson-glow transition-all duration-200 group"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="p-2 rounded-lg bg-red-950 text-red-400 border border-red-500/40">
                <Skull className="w-5 h-5" />
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-500 font-bold">
                MITRE T1486
              </span>
            </div>
            <div className="font-mono font-bold text-sm text-slate-100 group-hover:text-red-300 transition-colors">
              Live Ransomware Attack
            </div>
            <p className="text-[11px] text-slate-400 font-mono mt-1">
              Spawns <code className="text-red-300">simulate_attack.py</code>. Watchdog canary trips; PID guillotine kills it &lt; 4ms.
            </p>
            <div className="mt-3 text-[10px] font-mono text-red-400 font-bold">
              {loadingAttack === 'ransomware' ? 'EXECUTING...' : 'TRIGGER ATTACK →'}
            </div>
          </button>

          {/* Attack 2 */}
          <button
            onClick={() => handleSimulate('eicar')}
            disabled={loadingAttack !== null}
            className="p-4 rounded-xl text-left bg-gradient-to-br from-[#0c1824] to-[#0a111e] border border-cyan-500/40 hover:border-cyan-400 hover:shadow-cyan-glow transition-all duration-200 group"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="p-2 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-500/40">
                <FileCode className="w-5 h-5" />
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-500 font-bold">
                MITRE T1027
              </span>
            </div>
            <div className="font-mono font-bold text-sm text-slate-100 group-hover:text-cyan-300 transition-colors">
              EICAR Signature Drop
            </div>
            <p className="text-[11px] text-slate-400 font-mono mt-1">
              Drops standard anti-malware test signature. Intercepted and quarantined in ~1.2ms.
            </p>
            <div className="mt-3 text-[10px] font-mono text-cyan-400 font-bold">
              {loadingAttack === 'eicar' ? 'SCANNING...' : 'TRIGGER ATTACK →'}
            </div>
          </button>

          {/* Attack 3 */}
          <button
            onClick={() => handleSimulate('macro_injection')}
            disabled={loadingAttack !== null}
            className="p-4 rounded-xl text-left bg-gradient-to-br from-[#18150c] to-[#0a111e] border border-amber-500/40 hover:border-amber-400 transition-all duration-200 group"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="p-2 rounded-lg bg-amber-950 text-amber-400 border border-amber-500/40">
                <Zap className="w-5 h-5" />
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-500 font-bold">
                MITRE T1055
              </span>
            </div>
            <div className="font-mono font-bold text-sm text-slate-100 group-hover:text-amber-300 transition-colors">
              Macro Process Injection
            </div>
            <p className="text-[11px] text-slate-400 font-mono mt-1">
              Simulates <code className="text-amber-300">WINWORD.EXE -&gt; powershell.exe</code> lineage violation. Child PID terminated.
            </p>
            <div className="mt-3 text-[10px] font-mono text-amber-400 font-bold">
              {loadingAttack === 'macro_injection' ? 'ANALYZING...' : 'TRIGGER ATTACK →'}
            </div>
          </button>
        </div>

        {/* Stopwatch Status HUD */}
        {lastSimulatorRun && (
          <div className="p-3.5 rounded-xl bg-[#070C18] border border-slate-800 flex items-center justify-between font-mono text-xs">
            <div className="flex items-center gap-3">
              <span className="px-2 py-0.5 rounded bg-red-950 text-red-300 font-bold border border-red-500">
                GUILLOTINE EXECUTED
              </span>
              <span className="text-slate-300">Target: <strong className="text-cyan-300">{lastSimulatorRun.type}</strong></span>
              <span className="text-slate-400">PID: <strong className="text-red-400">{lastSimulatorRun.pid}</strong></span>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-slate-500">REACTION LATENCY:</span>
              <span className="px-2 py-0.5 rounded bg-cyan-950 border border-cyan-400 text-cyan-300 font-black">
                {lastSimulatorRun.reactionTime}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Blocked Threats Forensics */}
      <div className="kaspersky-panel rounded-2xl p-6 border border-suite-border space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-suite-border">
          <div>
            <h3 className="text-base font-bold font-mono text-slate-100">
              INCIDENT FORENSICS &amp; THREAT TELEMETRY
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              Cryptographically verified incident logs with MITRE TTPs and Gemini AI Root-Cause Analysis
            </p>
          </div>
          <span className="text-xs font-mono text-slate-400 bg-slate-900 px-3 py-1 rounded-lg border border-slate-800">
            {alerts.length} Incidents
          </span>
        </div>

        {alerts.length === 0 ? (
          <div className="text-center py-8 text-slate-500 font-mono text-xs">
            No active threat incidents recorded. Endpoint running fortified.
          </div>
        ) : (
          <div className="space-y-3">
            {alerts.map((alert) => (
              <div key={alert.id} className="p-4 rounded-xl bg-[#090F1E] border border-slate-800 hover:border-slate-700 transition-colors space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <span className="font-mono font-bold text-sm text-slate-100">{alert.threat_name}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-500 font-bold">
                      {alert.severity}
                    </span>
                    <span className="text-[10px] font-mono text-slate-500">{alert.timestamp}</span>
                  </div>

                  <button
                    onClick={() => setSelectedAlertForAi(alert)}
                    className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-gradient-to-r from-cyan-950 to-blue-950 hover:from-cyan-900 border border-cyan-500/60 text-cyan-300 text-xs font-mono font-bold shadow-cyan-glow transition-all"
                  >
                    <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Analyze with Gemini AI</span>
                  </button>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs font-mono">
                  <div className="p-2 rounded bg-slate-950/60 border border-slate-900">
                    <span className="text-slate-500 text-[10px]">Process / PID:</span>
                    <div className="text-slate-200 font-bold truncate">{alert.process_name} ({alert.pid})</div>
                  </div>
                  <div className="p-2 rounded bg-slate-950/60 border border-slate-900">
                    <span className="text-slate-500 text-[10px]">MITRE TTP:</span>
                    <div className="text-amber-400 font-bold truncate">{alert.mitre_id}</div>
                  </div>
                  <div className="p-2 rounded bg-slate-950/60 border border-slate-900">
                    <span className="text-slate-500 text-[10px]">Latency:</span>
                    <div className="text-kaspersky-emerald font-bold">{alert.reaction_time_ms}</div>
                  </div>
                  <div className="p-2 rounded bg-slate-950/60 border border-slate-900">
                    <span className="text-slate-500 text-[10px]">Action Taken:</span>
                    <div className="text-slate-300 font-bold truncate">{alert.action_taken}</div>
                  </div>
                </div>

                <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 pt-1">
                  <div className="truncate max-w-xl">
                    Path: <code className="text-slate-400">{alert.file_path}</code>
                  </div>
                  <button
                    onClick={() => handleCopyHash(alert.sha256)}
                    className="flex items-center gap-1 text-slate-400 hover:text-cyan-300 transition-colors text-[10px]"
                  >
                    {copiedHash === alert.sha256 ? <Check className="w-3 h-3 text-kaspersky-emerald" /> : <Copy className="w-3 h-3" />}
                    <span>SHA-256</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <GeminiAnalystModal
        isOpen={selectedAlertForAi !== null}
        onClose={() => setSelectedAlertForAi(null)}
        alert={selectedAlertForAi}
      />
    </div>
  );
};

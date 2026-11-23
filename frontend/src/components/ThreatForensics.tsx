import React, { useState } from 'react';
import { ShieldAlert, Sparkles, Clock, Cpu, Trash2, Copy, Check } from 'lucide-react';
import type { AlertItem } from '../types';
import { GeminiAnalystModal } from './GeminiAnalystModal';
import { api } from '../api';

interface ThreatForensicsProps {
  alerts: AlertItem[];
  onAlertsUpdated: () => void;
  onTriggerSimulator: (type: 'ransomware' | 'eicar' | 'macro_injection') => void;
}

export const ThreatForensics: React.FC<ThreatForensicsProps> = ({ alerts, onAlertsUpdated, onTriggerSimulator }) => {
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 1800);
  };

  const handleClear = async () => {
    try {
      await api.clearAlerts();
      onAlertsUpdated();
    } catch (e) {
      console.error(e);
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return (
          <span className="px-2 py-0.5 rounded bg-red-950 border border-red-500 text-red-400 font-mono text-[10px] font-bold shadow-crimson-glow">
            CRITICAL // SEV-1
          </span>
        );
      case 'HIGH':
        return (
          <span className="px-2 py-0.5 rounded bg-amber-950 border border-amber-500 text-amber-400 font-mono text-[10px] font-bold">
            HIGH // SEV-2
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded bg-blue-950 border border-blue-500 text-blue-400 font-mono text-[10px] font-bold">
            MEDIUM // SEV-3
          </span>
        );
    }
  };

  return (
    <div className="space-y-4">
      {/* Header bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 cyber-card rounded-xl p-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-red-950/80 border border-red-500/50 text-red-400 shadow-crimson-glow">
            <ShieldAlert className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold font-mono text-slate-100 tracking-wide">
                ENDPOINT THREAT FORENSICS &amp; INCIDENT VAULT
              </h2>
              <span className="text-xs font-mono text-cyan-400 px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800">
                {alerts.length} INCIDENTS LOGGED
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono">
              Real-time deep forensics for threats intercepted by PID Guillotine and Watchdog Decoys
            </p>
          </div>
        </div>

        {alerts.length > 0 && (
          <button
            onClick={handleClear}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono bg-slate-900 hover:bg-red-950/60 border border-slate-700 hover:border-red-500/40 text-slate-400 hover:text-red-300 transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear Incident Log</span>
          </button>
        )}
      </div>

      {/* Incident List */}
      {alerts.length === 0 ? (
        <div className="cyber-card rounded-xl p-12 text-center flex flex-col items-center justify-center">
          <div className="p-4 rounded-full bg-cyan-950/40 border border-cyan-500/30 text-cyan-400 mb-3">
            <Cpu className="w-8 h-8" />
          </div>
          <h3 className="text-base font-mono font-bold text-slate-200 mb-1">
            Zero Active Compromises Detected
          </h3>
          <p className="text-xs font-mono text-slate-400 max-w-md mb-6 leading-relaxed">
            The endpoint is currently fortified. Use the stage attack simulator below to trigger live safe POCs and observe real-time sub-10ms incident response.
          </p>
          <div className="flex flex-wrap gap-3 justify-center">
            <button
              onClick={() => onTriggerSimulator('ransomware')}
              className="px-3.5 py-1.5 rounded-lg text-xs font-mono bg-red-950 hover:bg-red-900 border border-red-500 text-red-300 transition-colors shadow-crimson-glow font-bold"
            >
              Test Ransomware Tripwire
            </button>
            <button
              onClick={() => onTriggerSimulator('eicar')}
              className="px-3.5 py-1.5 rounded-lg text-xs font-mono bg-cyan-950 hover:bg-cyan-900 border border-cyan-500 text-cyan-300 transition-colors font-bold"
            >
              Test EICAR Signature
            </button>
            <button
              onClick={() => onTriggerSimulator('macro_injection')}
              className="px-3.5 py-1.5 rounded-lg text-xs font-mono bg-amber-950 hover:bg-amber-900 border border-amber-500 text-amber-300 transition-colors font-bold"
            >
              Test Macro Lineage Anomaly
            </button>
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          {alerts.map((alert) => (
            <div
              key={alert.id}
              className="cyber-card rounded-xl p-5 border border-slate-800 hover:border-cyan-500/50 transition-all duration-200"
            >
              {/* Top Row: Threat name, severity, actions */}
              <div className="flex flex-wrap items-start justify-between gap-3 mb-3 pb-3 border-b border-cyber-border">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-red-950/60 border border-red-500/40 text-red-400">
                    <ShieldAlert className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono font-bold text-sm text-slate-100">
                        {alert.threat_name}
                      </span>
                      {getSeverityBadge(alert.severity)}
                      <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-400 font-mono text-[10px]">
                        {alert.timestamp}
                      </span>
                    </div>
                    <div className="text-xs font-mono text-cyan-400 mt-0.5">
                      {alert.detection_layer}
                    </div>
                  </div>
                </div>

                {/* Analyze with Gemini AI button */}
                <button
                  onClick={() => setSelectedAlert(alert)}
                  className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-950 to-blue-950 hover:from-cyan-900 hover:to-blue-900 border border-cyan-500/60 text-cyan-300 font-mono text-xs font-bold shadow-cyan-glow transition-all duration-150 group"
                >
                  <Sparkles className="w-4 h-4 text-cyan-400 group-hover:rotate-12 transition-transform" />
                  <span>Analyze with Gemini AI</span>
                </button>
              </div>

              {/* Grid of Tactical Indicators */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono mb-4">
                <div className="p-2.5 rounded bg-[#090f1d] border border-slate-800">
                  <div className="text-[10px] text-slate-500 uppercase">Process &amp; PID</div>
                  <div className="font-bold text-slate-200 truncate mt-0.5">
                    {alert.process_name} <span className="text-red-400">(PID: {alert.pid})</span>
                  </div>
                </div>

                <div className="p-2.5 rounded bg-[#090f1d] border border-slate-800">
                  <div className="text-[10px] text-slate-500 uppercase">Reaction Latency</div>
                  <div className="font-bold text-cyan-300 text-sm mt-0.5 flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-cyan-400" />
                    <span>{alert.reaction_time_ms}</span>
                    <span className="text-[9px] text-emerald-400 font-normal">SUB-10MS</span>
                  </div>
                </div>

                <div className="p-2.5 rounded bg-[#090f1d] border border-slate-800">
                  <div className="text-[10px] text-slate-500 uppercase">MITRE ATT&amp;CK TTP</div>
                  <div className="font-bold text-amber-300 truncate mt-0.5">
                    {alert.mitre_id} // {alert.mitre_technique}
                  </div>
                </div>

                <div className="p-2.5 rounded bg-[#090f1d] border border-slate-800">
                  <div className="text-[10px] text-slate-500 uppercase">Action Taken</div>
                  <div className="font-bold text-emerald-400 truncate mt-0.5">
                    {alert.action_taken}
                  </div>
                </div>
              </div>

              {/* Path & SHA-256 footer */}
              <div className="space-y-1.5 font-mono text-[11px] bg-[#050912] p-2.5 rounded-lg border border-slate-900">
                <div className="flex items-center gap-2 text-slate-400">
                  <span className="text-slate-500 w-20">Target Path:</span>
                  <span className="text-slate-300 break-all select-all">{alert.file_path}</span>
                </div>
                <div className="flex items-center justify-between gap-2 text-slate-400">
                  <div className="flex items-center gap-2">
                    <span className="text-slate-500 w-20">SHA-256:</span>
                    <span className="text-cyan-400/90 break-all font-mono">{alert.sha256}</span>
                  </div>
                  <button
                    onClick={() => handleCopyHash(alert.sha256)}
                    className="p-1 text-slate-400 hover:text-cyan-300 transition-colors flex items-center gap-1 text-[10px]"
                    title="Copy SHA-256"
                  >
                    {copiedHash === alert.sha256 ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Gemini AI Analyst Modal */}
      <GeminiAnalystModal
        isOpen={selectedAlert !== null}
        onClose={() => setSelectedAlert(null)}
        alert={selectedAlert}
      />
    </div>
  );
};

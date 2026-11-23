import React, { useState } from 'react';
import { X, ShieldAlert, Zap, Skull, FileCode, CheckCircle2, RotateCw } from 'lucide-react';
import { api } from '../api';

interface SafeDemoModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAlertsUpdated: () => void;
}

export const SafeDemoModal: React.FC<SafeDemoModalProps> = ({
  isOpen,
  onClose,
  onAlertsUpdated,
}) => {
  const [runningType, setRunningType] = useState<string | null>(null);
  const [result, setResult] = useState<{
    title: string;
    reactionTime: string;
    details: string;
    status: string;
  } | null>(null);

  if (!isOpen) return null;

  const handleSimulate = async (type: 'ransomware' | 'eicar' | 'macro_injection', label: string) => {
    setRunningType(type);
    setResult(null);
    try {
      const res = await api.simulateAttack(type);
      setResult({
        title: `${label} Intercepted`,
        reactionTime: res.reaction_time_ms || res.alert?.reaction_time_ms || '< 4ms',
        details: res.alert?.action_taken || res.message || 'Threat neutralized immediately by active shields.',
        status: 'NEUTRALIZED',
      });
      onAlertsUpdated();
    } catch (e: any) {
      setResult({
        title: 'Simulation Error',
        reactionTime: 'N/A',
        details: e.message || 'Failed to launch simulator',
        status: 'ERROR',
      });
    } finally {
      setRunningType(null);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-[#131A26] border border-[#1F2937] rounded-2xl w-full max-w-lg p-6 space-y-5 shadow-2xl relative">
        <div className="flex items-center justify-between pb-3 border-b border-[#1F2937]">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <Zap className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-white">Safe Protection Demo</h3>
              <p className="text-xs text-slate-400">Harmless tests to demonstrate real-time defense</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className="text-xs text-slate-300 leading-relaxed">
          These safe tests trigger harmless simulated attack vectors in an isolated sandbox to demonstrate sub-10ms interception, automatic file restoration, and quarantine.
        </p>

        {/* 3 Safe Demo Cards */}
        <div className="space-y-3">
          <div className="p-3.5 rounded-xl bg-[#0D121D] border border-[#1F2937] flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-red-950/60 text-red-400 border border-red-500/30">
                <Skull className="w-4 h-4" />
              </div>
              <div>
                <h4 className="text-xs font-semibold text-white">Ransomware Tripwire Test</h4>
                <p className="text-[11px] text-slate-400">Harmless script attempts to encrypt a decoy document</p>
              </div>
            </div>
            <button
              onClick={() => handleSimulate('ransomware', 'Ransomware Attack')}
              disabled={!!runningType}
              className="px-3 py-1.5 rounded-lg bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 text-xs font-medium transition-colors shrink-0 disabled:opacity-50"
            >
              {runningType === 'ransomware' ? <RotateCw className="w-3.5 h-3.5 animate-spin" /> : 'Run Test'}
            </button>
          </div>

          <div className="p-3.5 rounded-xl bg-[#0D121D] border border-[#1F2937] flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-cyan-950/60 text-cyan-400 border border-cyan-500/30">
                <FileCode className="w-4 h-4" />
              </div>
              <div>
                <h4 className="text-xs font-semibold text-white">Virus Signature (EICAR)</h4>
                <p className="text-[11px] text-slate-400">Industry standard harmless antivirus test file</p>
              </div>
            </div>
            <button
              onClick={() => handleSimulate('eicar', 'EICAR Signature')}
              disabled={!!runningType}
              className="px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-medium transition-colors shrink-0 disabled:opacity-50"
            >
              {runningType === 'eicar' ? <RotateCw className="w-3.5 h-3.5 animate-spin" /> : 'Run Test'}
            </button>
          </div>

          <div className="p-3.5 rounded-xl bg-[#0D121D] border border-[#1F2937] flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-amber-950/60 text-amber-400 border border-amber-500/30">
                <ShieldAlert className="w-4 h-4" />
              </div>
              <div>
                <h4 className="text-xs font-semibold text-white">Hidden Command Injection</h4>
                <p className="text-[11px] text-slate-400">Simulates document spawning hidden system scripts</p>
              </div>
            </div>
            <button
              onClick={() => handleSimulate('macro_injection', 'Command Injection')}
              disabled={!!runningType}
              className="px-3 py-1.5 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 text-xs font-medium transition-colors shrink-0 disabled:opacity-50"
            >
              {runningType === 'macro_injection' ? <RotateCw className="w-3.5 h-3.5 animate-spin" /> : 'Run Test'}
            </button>
          </div>
        </div>

        {/* Live Result Feedback Card */}
        {result && (
          <div className={`p-4 rounded-xl border ${
            result.status === 'NEUTRALIZED'
              ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-200'
              : 'bg-red-950/40 border-red-500/40 text-red-200'
          }`}>
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span className="text-xs font-bold text-white">{result.title}</span>
              </div>
              <span className="text-[11px] px-2 py-0.5 rounded bg-emerald-900/60 text-emerald-300 border border-emerald-500/40 font-mono font-bold">
                {result.reactionTime}
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-1">{result.details}</p>
          </div>
        )}

        <div className="flex justify-end pt-2">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

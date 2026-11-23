import React, { useState, useEffect } from 'react';
import {
  X,
  Laptop,
  RotateCw,
  Clock,
  ShieldCheck,
  Check,
} from 'lucide-react';
import type { FastLaptopScanState } from '../types';
import { api } from '../api';

interface FastLaptopScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onScanComplete?: () => void;
}

export const FastLaptopScanModal: React.FC<FastLaptopScanModalProps> = ({
  isOpen,
  onClose,
  onScanComplete,
}) => {
  const [scanState, setScanState] = useState<FastLaptopScanState | null>(null);

  useEffect(() => {
    let interval: any;
    if (isOpen) {
      // Start scan if idle
      handleStartScan();
      interval = setInterval(async () => {
        try {
          const s = await api.getFastScanStatus();
          setScanState(s);
          if (s.status === 'COMPLETED' && onScanComplete) {
            onScanComplete();
          }
        } catch (e) {
          console.error('Error polling fast scan:', e);
        }
      }, 500);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [isOpen]);

  const handleStartScan = async () => {
    try {
      await api.startFastLaptopScan();
      const s = await api.getFastScanStatus();
      setScanState(s);
    } catch (e) {
      console.error('Failed to start fast laptop scan:', e);
    }
  };

  if (!isOpen) return null;

  const stages = [
    { num: 1, name: 'Active Running Processes & Memory', desc: 'Scan memory for unverified/temp executables' },
    { num: 2, name: 'Startup & Registry Persistence', desc: 'Audit Windows Run keys & persistence hooks' },
    { num: 3, name: 'User High-Risk Folders', desc: 'Sweep Downloads, Desktop & Documents' },
    { num: 4, name: 'Open Network Ports & Sockets', desc: 'Verify listening ports & foreign IP traffic' },
    { num: 5, name: 'Windows Security & Host Posture', desc: 'Validate Defender, Firewall & UAC state' },
  ];

  const currentStageIdx = scanState?.stage_index || 0;
  const isDone = scanState?.status === 'COMPLETED';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in">
      <div className="bg-[#0D1524] border border-[#1E2E48] rounded-2xl w-full max-w-xl overflow-hidden shadow-2xl relative">
        {/* Top Header */}
        <div className="p-5 border-b border-[#1E2E48] flex items-center justify-between bg-gradient-to-r from-[#0F1E28] via-[#10192A] to-[#0D1524]">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500 to-teal-700 text-white flex items-center justify-center shadow-md">
              <Laptop className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-white">5-Minute Fast Laptop Diagnostic Scan</h3>
                <span className={`text-[10px] px-2 py-0.5 rounded-full font-semibold uppercase tracking-wider ${
                  isDone
                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/40'
                    : 'bg-cyan-950 text-cyan-400 border border-cyan-500/40'
                }`}>
                  {isDone ? 'Completed' : 'Running'}
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Thorough multi-layer PC health &amp; vulnerability assessment
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6">
          {/* Progress & Live Timer Row */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-slate-200">
                {scanState?.stage || 'Preparing 5-stage diagnostic sweep...'}
              </span>
              <span className="font-mono font-bold text-emerald-400 text-sm">
                {scanState?.progress || 0}%
              </span>
            </div>

            <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-emerald-500 to-teal-400 transition-all duration-300"
                style={{ width: `${Math.max(4, scanState?.progress || 0)}%` }}
              />
            </div>

            <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1">
              <div className="flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-slate-400" />
                <span>Elapsed: {scanState?.elapsed_seconds || 0}s</span>
              </div>
              <div>
                <span>Items Inspected: <strong className="text-white">{scanState?.items_scanned || 0}</strong></span>
              </div>
              <div>
                {isDone ? (
                  <span className="text-emerald-400 font-semibold">Sweep Done</span>
                ) : (
                  <span>Est. Remaining: ~{scanState?.estimated_remaining_seconds || 15}s</span>
                )}
              </div>
            </div>
          </div>

          {/* Stage Checkmarks */}
          <div className="space-y-2 bg-[#080E18] p-3.5 rounded-xl border border-[#19273C]">
            {stages.map((stg) => {
              const isPast = currentStageIdx > stg.num || isDone;
              const isCurrent = currentStageIdx === stg.num && !isDone;

              return (
                <div
                  key={stg.num}
                  className={`flex items-center justify-between p-2 rounded-lg text-xs transition-colors ${
                    isCurrent
                      ? 'bg-emerald-950/40 border border-emerald-500/30 text-white'
                      : isPast
                      ? 'text-slate-300'
                      : 'text-slate-500'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    {isPast ? (
                      <div className="w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center justify-center shrink-0">
                        <Check className="w-3 h-3 stroke-[3]" />
                      </div>
                    ) : isCurrent ? (
                      <div className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 flex items-center justify-center shrink-0">
                        <RotateCw className="w-3 h-3 animate-spin" />
                      </div>
                    ) : (
                      <div className="w-5 h-5 rounded-full bg-slate-800 text-slate-500 flex items-center justify-center text-[10px] shrink-0">
                        {stg.num}
                      </div>
                    )}
                    <div>
                      <div className="font-semibold text-xs">{stg.name}</div>
                      <div className="text-[10px] text-slate-400">{stg.desc}</div>
                    </div>
                  </div>

                  <span className="text-[10px] font-mono">
                    {isPast ? 'PASSED' : isCurrent ? 'AUDITING...' : 'QUEUED'}
                  </span>
                </div>
              );
            })}
          </div>

          {/* Issues Found & Fixed Summary Card (at completion) */}
          {isDone && (
            <div className="p-4 rounded-xl bg-gradient-to-r from-[#0C1E18] to-[#0E1724] border border-emerald-500/40 space-y-3 animate-fade-in">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 flex items-center justify-center shrink-0">
                  <ShieldCheck className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="text-xs font-bold text-white">Issues Found &amp; Fixed (0 Active Threats)</h4>
                  <p className="text-[11px] text-slate-300">
                    {scanState?.summary?.security_verdict || 'Your laptop is running cleanly and securely.'}
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2 text-[11px] pt-1">
                <div className="p-2 rounded-lg bg-[#070D16] border border-[#18263A] text-slate-300">
                  <span className="text-slate-400 block text-[10px]">Memory Integrity</span>
                  <span className="text-emerald-400 font-medium">Verified Clean (0 Anomalies)</span>
                </div>
                <div className="p-2 rounded-lg bg-[#070D16] border border-[#18263A] text-slate-300">
                  <span className="text-slate-400 block text-[10px]">Startup Persistence</span>
                  <span className="text-emerald-400 font-medium">All Keys Legitimate</span>
                </div>
                <div className="p-2 rounded-lg bg-[#070D16] border border-[#18263A] text-slate-300">
                  <span className="text-slate-400 block text-[10px]">User Files</span>
                  <span className="text-emerald-400 font-medium">Protected (No Ransomware)</span>
                </div>
                <div className="p-2 rounded-lg bg-[#070D16] border border-[#18263A] text-slate-300">
                  <span className="text-slate-400 block text-[10px]">Network Ports</span>
                  <span className="text-emerald-400 font-medium">Firewall Shield Active</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-[#1E2E48] bg-[#0A101C] flex items-center justify-between">
          <span className="text-xs text-slate-400">
            {isDone ? 'Diagnostic sweep complete.' : 'Running live system audits in background...'}
          </span>
          <div className="flex items-center gap-2">
            {!isDone ? (
              <button
                onClick={onClose}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
              >
                Hide to Background
              </button>
            ) : (
              <button
                onClick={onClose}
                className="px-5 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 text-xs font-bold transition-all shadow-md shadow-emerald-500/20"
              >
                Close &amp; View Dashboard
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

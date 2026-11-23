import React, { useState } from 'react';
import { Shield, Skull, Network, Sliders, CheckCircle2 } from 'lucide-react';
import type { ShieldConfig } from '../types';
import { api } from '../api';

interface EngineConfigProps {
  config: ShieldConfig;
  onConfigChange: (newConfig: ShieldConfig) => void;
}

export const EngineConfig: React.FC<EngineConfigProps> = ({ config, onConfigChange }) => {
  const [savedNotice, setSavedNotice] = useState(false);

  const handleToggle = async (key: keyof ShieldConfig, val: boolean | number) => {
    const updated = { ...config, [key]: val };
    onConfigChange(updated);
    try {
      await api.updateConfig({ [key]: val });
      setSavedNotice(true);
      setTimeout(() => setSavedNotice(false), 2000);
    } catch (e) {
      console.error('Failed to update config:', e);
    }
  };

  return (
    <div className="space-y-4">
      {/* Header bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 cyber-card rounded-xl p-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-cyan-950/80 border border-cyan-500/50 text-cyan-400 shadow-cyan-glow">
            <Shield className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold font-mono text-slate-100 tracking-wide">
                4-LAYER CYBER GUARDIAN ENGINE CONFIGURATION
              </h2>
              {savedNotice && (
                <span className="text-[10px] font-mono text-emerald-300 px-2 py-0.5 rounded bg-emerald-950 border border-emerald-600 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> CONFIG SYNCHRONIZED
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 font-mono">
              Toggle detection layers, calibrate zero-day ML anomaly sensitivity, and manage autonomous containment
            </p>
          </div>
        </div>
      </div>

      {/* 4 Layers Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Layer 1: Static YARA & PE Entropy */}
        <div className="cyber-card rounded-xl p-5 border border-slate-800 hover:border-cyan-500/40 transition-colors">
          <div className="flex items-start justify-between mb-3">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-lg bg-cyan-950 border border-cyan-500/40 text-cyan-400">
                <Shield className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-mono font-bold text-sm text-slate-100">
                  LAYER 1: Static YARA &amp; PE Entropy
                </h3>
                <span className="text-[10px] font-mono text-cyan-400">
                  Pre-Execution Threat Signature Engine
                </span>
              </div>
            </div>

            {/* Toggle */}
            <button
              onClick={() => handleToggle('layer1_yara', !config.layer1_yara)}
              className={`w-12 h-6 rounded-full p-1 transition-colors duration-200 ease-in-out border ${
                config.layer1_yara ? 'bg-cyan-500 border-cyan-400' : 'bg-slate-900 border-slate-700'
              }`}
            >
              <div
                className={`w-4 h-4 rounded-full bg-slate-950 transition-transform duration-200 ease-in-out ${
                  config.layer1_yara ? 'translate-x-6' : 'translate-x-0'
                }`}
              />
            </button>
          </div>

          <p className="text-xs text-slate-400 font-mono leading-relaxed mb-3">
            Performs byte-level inspection against known threat signatures (including EICAR and cryptor headers) and analyzes portable executable section entropy for packed zero-day malware.
          </p>

          <div className="flex items-center justify-between pt-2 border-t border-slate-800 text-[10px] font-mono">
            <span className="text-slate-500">Heuristics Engine:</span>
            <span className={config.layer1_yara ? 'text-cyan-400 font-bold' : 'text-slate-600'}>
              {config.layer1_yara ? 'ENABLED (RULES LOADED)' : 'DISABLED'}
            </span>
          </div>
        </div>

        {/* Layer 2: Ransomware Canary & PID Guillotine */}
        <div className="cyber-card rounded-xl p-5 border border-slate-800 hover:border-red-500/40 transition-colors">
          <div className="flex items-start justify-between mb-3">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-lg bg-red-950 border border-red-500/40 text-red-400">
                <Skull className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-mono font-bold text-sm text-slate-100">
                  LAYER 2: Canary Tripwire &amp; PID Guillotine
                </h3>
                <span className="text-[10px] font-mono text-red-400">
                  Sub-10ms Ransomware Neutralization
                </span>
              </div>
            </div>

            {/* Toggle */}
            <button
              onClick={() => handleToggle('layer2_canary', !config.layer2_canary)}
              className={`w-12 h-6 rounded-full p-1 transition-colors duration-200 ease-in-out border ${
                config.layer2_canary ? 'bg-red-500 border-red-400' : 'bg-slate-900 border-slate-700'
              }`}
            >
              <div
                className={`w-4 h-4 rounded-full bg-slate-950 transition-transform duration-200 ease-in-out ${
                  config.layer2_canary ? 'translate-x-6' : 'translate-x-0'
                }`}
              />
            </button>
          </div>

          <p className="text-xs text-slate-400 font-mono leading-relaxed mb-3">
            Continuously hooks filesystem I/O on decoy files in <code className="text-cyan-300">backend/protected_zone/</code>. The exact millisecond any process touches <code className="text-red-300">!000_System_Key.docx</code>, the PID is immediately killed and payload vaulted.
          </p>

          <div className="flex items-center justify-between pt-2 border-t border-slate-800 text-[10px] font-mono">
            <span className="text-slate-500">Autonomous Guillotine:</span>
            <span className={config.layer2_canary ? 'text-red-400 font-bold' : 'text-slate-600'}>
              {config.layer2_canary ? 'ARMED // UNBLOCKABLE' : 'DISARMED'}
            </span>
          </div>
        </div>

        {/* Layer 3: Zero-Day ML Anomaly Threshold Slider */}
        <div className="cyber-card rounded-xl p-5 border border-slate-800 hover:border-amber-500/40 transition-colors">
          <div className="flex items-start justify-between mb-3">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-lg bg-amber-950 border border-amber-500/40 text-amber-400">
                <Sliders className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-mono font-bold text-sm text-slate-100">
                  LAYER 3: ML Anomaly Threshold
                </h3>
                <span className="text-[10px] font-mono text-amber-400">
                  Process Tree Lineage &amp; Behavioral Model
                </span>
              </div>
            </div>

            <span className="font-mono font-extrabold text-sm px-2.5 py-1 rounded bg-amber-950 border border-amber-600 text-amber-300">
              {config.layer3_anomaly_threshold}%
            </span>
          </div>

          <p className="text-xs text-slate-400 font-mono leading-relaxed mb-3">
            Monitors process spawning behavior (e.g. Office macros creating PowerShell or cmd children). Higher values reduce false positives; lower values tighten defense against stealth living-off-the-land binaries.
          </p>

          {/* Slider */}
          <div className="space-y-1 pt-1">
            <input
              type="range"
              min="10"
              max="99"
              value={config.layer3_anomaly_threshold}
              onChange={(e) => handleToggle('layer3_anomaly_threshold', parseInt(e.target.value, 10))}
              className="w-full h-2 bg-slate-900 rounded-lg appearance-none cursor-pointer accent-amber-400"
            />
            <div className="flex justify-between text-[10px] font-mono text-slate-500">
              <span>AGILE (10%)</span>
              <span>BALANCED (85%)</span>
              <span>STRICT (99%)</span>
            </div>
          </div>
        </div>

        {/* Layer 4: Network C2 & BadUSB HID Guard */}
        <div className="cyber-card rounded-xl p-5 border border-slate-800 hover:border-emerald-500/40 transition-colors">
          <div className="flex items-start justify-between mb-3">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-lg bg-emerald-950 border border-emerald-500/40 text-emerald-400">
                <Network className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-mono font-bold text-sm text-slate-100">
                  LAYER 4: Network C2 &amp; BadUSB Guard
                </h3>
                <span className="text-[10px] font-mono text-emerald-400">
                  Perimeter &amp; Hardware HID Interceptor
                </span>
              </div>
            </div>

            {/* Toggle */}
            <button
              onClick={() => handleToggle('layer4_network_guard', !config.layer4_network_guard)}
              className={`w-12 h-6 rounded-full p-1 transition-colors duration-200 ease-in-out border ${
                config.layer4_network_guard ? 'bg-emerald-500 border-emerald-400' : 'bg-slate-900 border-slate-700'
              }`}
            >
              <div
                className={`w-4 h-4 rounded-full bg-slate-950 transition-transform duration-200 ease-in-out ${
                  config.layer4_network_guard ? 'translate-x-6' : 'translate-x-0'
                }`}
              />
            </button>
          </div>

          <p className="text-xs text-slate-400 font-mono leading-relaxed mb-3">
            Guards against unauthorized socket callbacks, reverse beaconing, and rapid keystroke injections originating from simulated or physical Rubber Ducky / BadUSB keyboard devices.
          </p>

          <div className="flex items-center justify-between pt-2 border-t border-slate-800 text-[10px] font-mono">
            <span className="text-slate-500">Hardware Intercept Filter:</span>
            <span className={config.layer4_network_guard ? 'text-emerald-400 font-bold' : 'text-slate-600'}>
              {config.layer4_network_guard ? 'ACTIVE (BLOCKING SUSPICIOUS HID)' : 'BYPASSED'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

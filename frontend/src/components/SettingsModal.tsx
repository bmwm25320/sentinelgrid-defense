import React, { useState } from 'react';
import { X, Key, Shield, RefreshCw, CheckCircle2, Server, Database } from 'lucide-react';
import { api } from '../api';
import type { DeviceAudit } from '../types';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  apiKey: string;
  onSaveApiKey: (key: string) => void;
  audit: DeviceAudit | null;
  onRefreshData: () => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({
  isOpen,
  onClose,
  apiKey,
  onSaveApiKey,
  audit,
  onRefreshData,
}) => {
  const [keyInput, setKeyInput] = useState(apiKey);
  const [savedNotice, setSavedNotice] = useState(false);
  const [resettingZone, setResettingZone] = useState(false);

  if (!isOpen) return null;

  const handleSave = () => {
    onSaveApiKey(keyInput);
    setSavedNotice(true);
    setTimeout(() => setSavedNotice(false), 2000);
  };

  const handleResetDecoys = async () => {
    setResettingZone(true);
    try {
      await api.resetProtectedZone();
      onRefreshData();
      alert('Protection sandbox decoy files have been reset to pristine condition.');
    } catch (e: any) {
      alert(`Reset failed: ${e.message}`);
    } finally {
      setResettingZone(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
      <div className="bg-[#131A26] rounded-2xl w-full max-w-lg border border-[#1F2937] shadow-2xl overflow-hidden space-y-5 p-6">
        {/* Header */}
        <div className="flex items-center justify-between pb-3 border-b border-[#1F2937]">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-white">
                Settings &amp; Protection Updates
              </h3>
              <p className="text-xs text-slate-400">
                SentinelGrid Defense • Database Version 2026.11.22-v4.8
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Gemini API Key Configuration */}
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <Key className="w-4 h-4 text-emerald-400" />
            <h4 className="text-xs font-semibold text-white">Google Gemini API Key</h4>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Powers the AI Security Assistant with Gemini 2.5 Flash for deep security reasoning and live advice. If left blank, the built-in local assistant engine is used.
          </p>

          <div className="flex items-center gap-2 pt-1">
            <input
              type="password"
              value={keyInput}
              onChange={(e) => setKeyInput(e.target.value)}
              placeholder="Paste your API key here (saved locally)..."
              className="flex-1 bg-[#0D121D] border border-[#1F2937] rounded-xl px-3.5 py-2 text-xs text-slate-200 focus:outline-none focus:border-emerald-500/50"
            />
            <button
              onClick={handleSave}
              className="px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs transition-colors shrink-0"
            >
              {savedNotice ? 'Saved!' : 'Save Key'}
            </button>
          </div>
          {savedNotice && (
            <p className="text-[11px] text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> Key saved successfully in local settings.
            </p>
          )}
        </div>

        {/* Protection Engine & Database Status */}
        <div className="p-4 rounded-xl bg-[#0D121D] border border-[#1F2937] space-y-2 text-xs">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-slate-300">
              <Database className="w-4 h-4 text-emerald-400" />
              <span>Antivirus Signatures</span>
            </div>
            <span className="text-emerald-400 font-medium">Up to Date (v4.8)</span>
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-slate-300">
              <Server className="w-4 h-4 text-cyan-400" />
              <span>Local Device Guardian</span>
            </div>
            <span className="text-white font-medium">
              {audit?.system?.hostname || 'This PC'} ({audit?.system?.os_name || audit?.system?.os_release || 'Windows 11'})
            </span>
          </div>
        </div>

        {/* Presentation Sandbox Reset */}
        <div className="pt-2 border-t border-[#1F2937] flex items-center justify-between">
          <div>
            <div className="text-xs font-semibold text-white">Reset Protection Sandbox</div>
            <div className="text-[11px] text-slate-400">Restore decoy files after test simulations</div>
          </div>
          <button
            onClick={handleResetDecoys}
            disabled={resettingZone}
            className="px-3 py-1.5 rounded-lg bg-[#182232] hover:bg-[#222E42] text-slate-200 border border-[#2B384E] text-xs font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${resettingZone ? 'animate-spin' : ''}`} />
            <span>Reset Decoys</span>
          </button>
        </div>

        {/* Close Button */}
        <div className="flex justify-end pt-1">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 transition-colors"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};

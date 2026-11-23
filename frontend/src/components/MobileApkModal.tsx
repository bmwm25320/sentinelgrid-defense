import React, { useState } from 'react';
import {
  X,
  Smartphone,
  Download,
  ShieldCheck,
  CheckCircle2,
  Monitor,
} from 'lucide-react';
import { api } from '../api';

interface MobileApkModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const MobileApkModal: React.FC<MobileApkModalProps> = ({ isOpen, onClose }) => {
  const [downloadStarted, setDownloadStarted] = useState(false);
  if (!isOpen) return null;

  const apkUrl = api.getAndroidApkUrl();
  const windowsSetupUrl = api.getWindowsSetupUrl();

  const handleDownload = () => {
    setDownloadStarted(true);
    const link = document.createElement('a');
    link.href = apkUrl;
    link.download = 'SentinelGrid_Defense_v1.0.apk';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => setDownloadStarted(false), 4000);
  };

  const handleDownloadWindows = () => {
    const link = document.createElement('a');
    link.href = windowsSetupUrl;
    link.download = 'SentinelGrid_Setup_v1.0.exe';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in">
      <div className="bg-[#0D1524] border border-[#1E2E48] rounded-2xl w-full max-w-lg overflow-hidden shadow-2xl relative">
        {/* Header */}
        <div className="p-5 border-b border-[#1E2E48] flex items-center justify-between bg-gradient-to-r from-[#0E1D2A] via-[#10192A] to-[#0D1524]">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500 to-teal-700 text-white flex items-center justify-center shadow-md">
              <Smartphone className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-white">SentinelGrid Mobile Guardian</h3>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-500/40 font-mono">
                  v1.0 APK
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Cross-Platform Android App built with Capacitor
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
        <div className="p-6 space-y-5">
          {/* Windows Setup Installer Card */}
          <div className="p-5 rounded-xl bg-gradient-to-r from-[#0C1B24] to-[#0E1E33] border border-cyan-500/40 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <Monitor className="w-4 h-4 text-cyan-400" />
                  <h4 className="text-sm font-bold text-white">SentinelGrid_Setup_v1.0.exe</h4>
                </div>
                <p className="text-xs text-slate-300 mt-0.5">
                  Official Windows 10/11 Setup Wizard (64-bit)
                </p>
                <div className="flex items-center gap-3 text-[11px] text-slate-400 mt-2">
                  <span>Native Desktop Window</span>
                  <span>•</span>
                  <span>System Tray Guardian</span>
                  <span>•</span>
                  <span>~34 MB</span>
                </div>
              </div>

              <button
                onClick={handleDownloadWindows}
                className="px-5 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/25 transition-all shrink-0"
              >
                <Download className="w-4 h-4" />
                <span>Download .EXE</span>
              </button>
            </div>
          </div>

          {/* Android APK Download Card */}
          <div className="p-5 rounded-xl bg-gradient-to-r from-[#0C1B24] to-[#0F1728] border border-emerald-500/40 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <Smartphone className="w-4 h-4 text-emerald-400" />
                  <h4 className="text-sm font-bold text-white">SentinelGrid_Defense_v1.0.apk</h4>
                </div>
                <p className="text-xs text-slate-300 mt-0.5">
                  Package ID: <code className="text-emerald-400 font-mono">com.sentinelgrid.defense</code>
                </p>
                <div className="flex items-center gap-3 text-[11px] text-slate-400 mt-2">
                  <span>Android 10+ (API 29-34)</span>
                  <span>•</span>
                  <span>Capacitor Native Shell</span>
                  <span>•</span>
                  <span>~416 KB</span>
                </div>
              </div>

              <button
                onClick={handleDownload}
                className="px-5 py-3 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 shadow-lg shadow-emerald-500/25 transition-all shrink-0"
              >
                <Download className="w-4 h-4" />
                <span>{downloadStarted ? 'Downloading...' : 'Download .APK'}</span>
              </button>
            </div>
          </div>

          {/* Features Available on Mobile */}
          <div className="space-y-2">
            <h5 className="text-xs font-semibold text-slate-300">Included in Mobile Guardian Mode:</h5>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="p-2.5 rounded-lg bg-[#080E18] border border-[#19273C] flex items-center gap-2 text-slate-300">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Encrypted Password Vault</span>
              </div>
              <div className="p-2.5 rounded-lg bg-[#080E18] border border-[#19273C] flex items-center gap-2 text-slate-300">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Google Sign-In Session</span>
              </div>
              <div className="p-2.5 rounded-lg bg-[#080E18] border border-[#19273C] flex items-center gap-2 text-slate-300">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Safe Link Phishing Checker</span>
              </div>
              <div className="p-2.5 rounded-lg bg-[#080E18] border border-[#19273C] flex items-center gap-2 text-slate-300">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>AI Security Copilot</span>
              </div>
            </div>
          </div>

          {/* Sideloading Instructions */}
          <div className="p-3.5 rounded-xl bg-[#080E18] border border-[#19273C] space-y-1.5 text-xs text-slate-400">
            <div className="flex items-center gap-2 font-semibold text-slate-200">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>How to Install on Your Android Device:</span>
            </div>
            <ol className="list-decimal list-inside space-y-1 text-[11px] text-slate-400 pl-1">
              <li>Download <strong className="text-slate-200">SentinelGrid_Defense_v1.0.apk</strong> to your device.</li>
              <li>Open the downloaded APK and tap <strong className="text-slate-200">Install</strong>.</li>
              <li>If prompted, enable <strong className="text-slate-200">"Install Unknown Apps"</strong> for your browser/file manager.</li>
              <li>Launch SentinelGrid Defense and sign in with Google or your Master PIN.</li>
            </ol>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-[#1E2E48] bg-[#0A101C] flex items-center justify-between">
          <span className="text-[11px] text-slate-400 font-mono">
            Host Endpoint: http://localhost:8000
          </span>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

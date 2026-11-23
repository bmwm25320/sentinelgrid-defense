import React, { useState } from 'react';
import { Lock, Unlock, Trash2, RefreshCw, AlertTriangle, CheckCircle2 } from 'lucide-react';
import type { QuarantineItem } from '../types';
import { api } from '../api';

interface QuarantineVaultProps {
  quarantine: QuarantineItem[];
  onRefresh: () => void;
}

export const QuarantineVault: React.FC<QuarantineVaultProps> = ({ quarantine, onRefresh }) => {
  const [processingId, setProcessingId] = useState<string | null>(null);
  const [feedbackMsg, setFeedbackMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const showNotification = (type: 'success' | 'error', text: string) => {
    setFeedbackMsg({ type, text });
    setTimeout(() => setFeedbackMsg(null), 3500);
  };

  const handleRestore = async (item: QuarantineItem) => {
    if (!confirm(`Restore '${item.filename}' from Quarantine back to its original location?`)) return;
    setProcessingId(item.id);
    try {
      await api.restoreQuarantine(item.id);
      showNotification('success', `Restored ${item.filename} successfully to original path.`);
      onRefresh();
    } catch (err: any) {
      showNotification('error', `Restore failed: ${err.message}`);
    } finally {
      setProcessingId(null);
    }
  };

  const handleShred = async (item: QuarantineItem) => {
    if (!confirm(`Permanently SHRED '${item.filename}' using DoD 5220.22-M 3-pass overwrite? This action CANNOT be undone.`)) return;
    setProcessingId(item.id);
    try {
      await api.shredQuarantine(item.id);
      showNotification('success', `Securely shredded ${item.filename} with DoD 5220.22-M overwrite.`);
      onRefresh();
    } catch (err: any) {
      showNotification('error', `Shred failed: ${err.message}`);
    } finally {
      setProcessingId(null);
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  return (
    <div className="space-y-4">
      {/* Header bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 cyber-card rounded-xl p-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-amber-950/80 border border-amber-500/50 text-amber-400 shadow-[0_0_15px_rgba(245,158,11,0.25)]">
            <Lock className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold font-mono text-slate-100 tracking-wide">
                QUARANTINE ISOLATION VAULT
              </h2>
              <span className="text-xs font-mono text-amber-400 px-2 py-0.5 rounded bg-amber-950 border border-amber-800">
                {quarantine.length} PAYLOADS NEUTRALIZED
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono">
              Zero-privilege cryptographically locked storage with DoD 5220.22-M multi-pass shredding
            </p>
          </div>
        </div>

        <button
          onClick={onRefresh}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
          <span>Refresh Vault</span>
        </button>
      </div>

      {/* Notifications */}
      {feedbackMsg && (
        <div className={`p-3 rounded-lg border font-mono text-xs flex items-center gap-2 ${
          feedbackMsg.type === 'success'
            ? 'bg-emerald-950/80 border-emerald-500 text-emerald-300'
            : 'bg-red-950/80 border-red-500 text-red-300'
        }`}>
          {feedbackMsg.type === 'success' ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
          <span>{feedbackMsg.text}</span>
        </div>
      )}

      {/* Vault Table */}
      {quarantine.length === 0 ? (
        <div className="cyber-card rounded-xl p-12 text-center flex flex-col items-center justify-center">
          <div className="p-4 rounded-full bg-slate-900 border border-slate-800 text-slate-500 mb-3">
            <Lock className="w-8 h-8" />
          </div>
          <h3 className="text-base font-mono font-bold text-slate-300 mb-1">
            Quarantine Vault Empty
          </h3>
          <p className="text-xs font-mono text-slate-500 max-w-md">
            Malicious files, locked artifacts, and intercepted test payloads will appear here once blocked by the SentinelGrid OS Guardian.
          </p>
        </div>
      ) : (
        <div className="cyber-card rounded-xl overflow-hidden border border-cyber-border">
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-[#090e1a] text-slate-400 uppercase text-[10px] tracking-wider border-b border-cyber-border">
                <tr>
                  <th className="py-3 px-4">Threat / Target File</th>
                  <th className="py-3 px-4">Detection Layer</th>
                  <th className="py-3 px-4">SHA-256 Fingerprint</th>
                  <th className="py-3 px-4">Size</th>
                  <th className="py-3 px-4">Quarantined At</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-900 text-slate-300">
                {quarantine.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-900/40 transition-colors">
                    {/* Threat & Filename */}
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <Lock className="w-4 h-4 text-amber-400 shrink-0" />
                        <div>
                          <div className="font-bold text-slate-100">{item.filename}</div>
                          <div className="text-[10px] text-red-400">{item.threat_name}</div>
                        </div>
                      </div>
                    </td>

                    {/* Detection Layer */}
                    <td className="py-3 px-4">
                      <div className="text-slate-300">{item.detection_layer}</div>
                      <div className="text-[10px] text-amber-400">{item.mitre_id}</div>
                    </td>

                    {/* SHA-256 */}
                    <td className="py-3 px-4">
                      <span className="text-[11px] text-cyan-400 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">
                        {item.sha256.substring(0, 16)}...
                      </span>
                    </td>

                    {/* Size */}
                    <td className="py-3 px-4 text-slate-400">
                      {formatBytes(item.file_size)}
                    </td>

                    {/* Timestamp */}
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {new Date(item.quarantined_at).toLocaleTimeString()}
                    </td>

                    {/* Status */}
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        item.status === 'RESTORED'
                          ? 'bg-emerald-950 text-emerald-300 border border-emerald-700'
                          : item.status === 'SHREDDED'
                          ? 'bg-slate-900 text-slate-500 border border-slate-800'
                          : 'bg-amber-950 text-amber-300 border border-amber-700'
                      }`}>
                        {item.status}
                      </span>
                    </td>

                    {/* Actions */}
                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        {/* Restore */}
                        {item.status === 'QUARANTINED' && (
                          <button
                            onClick={() => handleRestore(item)}
                            disabled={processingId === item.id}
                            className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 hover:bg-emerald-950/80 border border-slate-700 hover:border-emerald-500 text-slate-300 hover:text-emerald-300 transition-colors disabled:opacity-50 text-[11px]"
                            title="Restore False Positive to original path"
                          >
                            <Unlock className="w-3.5 h-3.5 text-emerald-400" />
                            <span>Restore</span>
                          </button>
                        )}

                        {/* Shred */}
                        <button
                          onClick={() => handleShred(item)}
                          disabled={processingId === item.id}
                          className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 hover:bg-red-950/80 border border-slate-700 hover:border-red-500 text-slate-300 hover:text-red-300 transition-colors disabled:opacity-50 text-[11px]"
                          title="DoD 5220.22-M Permanent Sanitization"
                        >
                          <Trash2 className="w-3.5 h-3.5 text-red-400" />
                          <span>Shred</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

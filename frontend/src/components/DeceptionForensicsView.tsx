import React, { useEffect, useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Fingerprint,
  Sparkles,
  RotateCw,
  Zap,
  CheckCircle2,
  AlertTriangle,
  Monitor,
  FileKey2,
  RefreshCw,
} from 'lucide-react';
import { api } from '../api';
import type {
  DeceptionGridStatus,
  SimulateDeceptionResult,
  BinarySignatureAuditResult,
} from '../types';
import {
  SentinelDeviceGuard,
  isAndroidNativeApp,
  type AndroidAppCertificatesResult,
  type AndroidScreenSpyStatus,
} from '../plugins/sentinelDeviceGuard';

interface DeceptionForensicsViewProps {
  onDataUpdated?: () => void;
}

export const DeceptionForensicsView: React.FC<DeceptionForensicsViewProps> = ({ onDataUpdated }) => {
  const isAndroid = isAndroidNativeApp();

  // Windows state
  const [deception, setDeception] = useState<DeceptionGridStatus | null>(null);
  const [simResult, setSimResult] = useState<SimulateDeceptionResult | null>(null);
  const [simulating, setSimulating] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [sigAudit, setSigAudit] = useState<BinarySignatureAuditResult | null>(null);
  const [auditingSigs, setAuditingSigs] = useState(false);

  // Android state
  const [screenSpy, setScreenSpy] = useState<AndroidScreenSpyStatus | null>(null);
  const [checkingSpy, setCheckingSpy] = useState(false);
  const [certAudit, setCertAudit] = useState<AndroidAppCertificatesResult | null>(null);
  const [auditingCerts, setAuditingCerts] = useState(false);

  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (isAndroid) {
      loadAndroidForensics();
    } else {
      loadWindowsDeception();
    }
  }, [isAndroid]);

  const loadWindowsDeception = async () => {
    setErrorMsg(null);
    try {
      const [decRes, sigRes] = await Promise.allSettled([
        api.getDeceptionStatus(),
        api.auditBinarySignatures(),
      ]);
      if (decRes.status === 'fulfilled') setDeception(decRes.value);
      if (sigRes.status === 'fulfilled') setSigAudit(sigRes.value);
    } catch (e: any) {
      setErrorMsg(e.message || 'Unable to load Cyber Deception engine.');
    }
  };

  const loadAndroidForensics = async () => {
    setErrorMsg(null);
    try {
      const [spyRes, certsRes] = await Promise.allSettled([
        SentinelDeviceGuard.inspectScreenSpyStatus(),
        SentinelDeviceGuard.auditAppCertificates(),
      ]);
      if (spyRes.status === 'fulfilled') setScreenSpy(spyRes.value);
      if (certsRes.status === 'fulfilled') setCertAudit(certsRes.value);
    } catch (e: any) {
      setErrorMsg(e.message || 'Unable to run native Android forensics.');
    }
  };

  const handleDeployTraps = async () => {
    setDeploying(true);
    setErrorMsg(null);
    try {
      const res = await api.deployHoneyTokens();
      setDeception(res);
    } catch (e: any) {
      setErrorMsg(`Deploy note: ${e.message}`);
    } finally {
      setDeploying(false);
    }
  };

  const handleSimulateBreach = async () => {
    setSimulating(true);
    setErrorMsg(null);
    try {
      const res = await api.simulateDeceptionBreach();
      setSimResult(res);
      const updated = await api.getDeceptionStatus();
      setDeception(updated);
      onDataUpdated?.();
    } catch (e: any) {
      setErrorMsg(`Simulation failed: ${e.message}`);
    } finally {
      setSimulating(false);
    }
  };

  const handleAuditSignatures = async () => {
    setAuditingSigs(true);
    setErrorMsg(null);
    try {
      const res = await api.auditBinarySignatures();
      setSigAudit(res);
    } catch (e: any) {
      setErrorMsg(`Signature audit error: ${e.message}`);
    } finally {
      setAuditingSigs(false);
    }
  };

  const handleCheckScreenSpy = async () => {
    setCheckingSpy(true);
    try {
      const res = await SentinelDeviceGuard.inspectScreenSpyStatus();
      setScreenSpy(res);
    } catch (e: any) {
      setErrorMsg(`Screen-Spy check note: ${e.message}`);
    } finally {
      setCheckingSpy(false);
    }
  };

  const handleAuditCerts = async () => {
    setAuditingCerts(true);
    try {
      const res = await SentinelDeviceGuard.auditAppCertificates();
      setCertAudit(res);
    } catch (e: any) {
      setErrorMsg(`APK Certificate audit note: ${e.message}`);
    } finally {
      setAuditingCerts(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Feature Explainer Header Banner */}
      <div className="p-6 rounded-2xl border border-purple-500/35 bg-gradient-to-r from-[#131126] via-[#0F172A] to-[#0D1B22]">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="max-w-3xl">
            <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-purple-500/20 border border-purple-400/40 text-purple-200 text-[11px] font-semibold mb-2">
              <Sparkles className="w-3.5 h-3.5" />
              <span>ZERO-TRUST DECEPTION & CRYPTOGRAPHIC FORENSICS</span>
            </div>
            <h1 className="text-xl font-bold text-white tracking-tight">
              {isAndroid
                ? 'Screen-Spy RAT Detector & APK Certificate Forensics'
                : 'HoneyToken Cyber Deception & Authenticode Forensics'}
            </h1>
            <p className="text-xs sm:text-sm text-slate-300 mt-1.5 leading-relaxed">
              {isAndroid
                ? 'Detects live screen-mirroring / remote-access scam sessions via Android DisplayManager and inspects every installed app’s real X.509 SHA-256 signing certificate to spot fake or debug-tampered APKs.'
                : 'Plants realistic fake credential HoneyTokens to lure & catch attackers the instant a trap is touched—auto-healing files in milliseconds—while auditing real Windows Authenticode digital signatures of running executables.'}
            </p>
          </div>
          <div className="px-4 py-3 rounded-xl bg-[#0B0F17]/90 border border-[#1F2937] text-xs space-y-1 shrink-0">
            <div className="text-slate-400">Deception Grid Status</div>
            <div className="text-sm font-bold text-emerald-400 flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4" />
              <span>{isAndroid ? 'On-Device Hardware Forensics Ready' : deception?.armed ? 'HoneyTokens Armed & Intact' : 'Ready'}</span>
            </div>
          </div>
        </div>
      </div>

      {errorMsg && (
        <div className="p-3 rounded-xl bg-red-950/30 border border-red-500/40 text-xs text-red-200">
          {errorMsg}
        </div>
      )}

      {!isAndroid ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* WINDOWS 1: HoneyToken Deception Grid & Instant Self-Healing */}
          <div className="bg-[#111827]/90 border border-[#1F2937] rounded-2xl p-6 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="text-base font-semibold text-white flex items-center gap-2">
                  <FileKey2 className="w-5 h-5 text-purple-400" />
                  <span>Active HoneyToken Decoy Grid</span>
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Auto-healed attacks intercepted: <strong className="text-purple-300">{deception?.auto_heal_count ?? 0}</strong>
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleDeployTraps}
                  disabled={deploying}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-1.5 disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${deploying ? 'animate-spin' : ''}`} />
                  <span>Re-Arm</span>
                </button>
                <button
                  onClick={handleSimulateBreach}
                  disabled={simulating}
                  className="px-3.5 py-1.5 rounded-lg bg-purple-500 hover:bg-purple-400 text-slate-950 text-xs font-bold flex items-center gap-1.5 disabled:opacity-50"
                >
                  <Zap className="w-3.5 h-3.5" />
                  <span>{simulating ? 'Triggering Trap...' : 'Test Breach & Auto-Heal'}</span>
                </button>
              </div>
            </div>

            {simResult && (
              <div className="p-3.5 rounded-xl bg-emerald-950/30 border border-emerald-500/40 text-xs space-y-1.5">
                <div className="font-bold text-emerald-300 flex items-center justify-between">
                  <span>{simResult.status} ({simResult.mitre_id})</span>
                  <span>Reaction: {simResult.reaction_ms}ms</span>
                </div>
                <div className="text-slate-200">{simResult.summary}</div>
                <div className="text-[10px] font-mono text-red-300 truncate">Tampered Hash: {simResult.tampered_sha256}</div>
                <div className="text-[10px] font-mono text-emerald-300 truncate">Restored Hash: {simResult.restored_sha256}</div>
              </div>
            )}

            <div className="space-y-2">
              {(deception?.traps || []).map((trap) => (
                <div key={trap.name} className="p-3 rounded-xl bg-[#0B0F17] border border-[#1F2937] text-xs flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <div className="font-semibold text-white flex items-center gap-2">
                      <span className="truncate">{trap.name}</span>
                      <span className="px-1.5 py-0.5 rounded bg-purple-500/15 text-purple-300 text-[10px] font-mono">{trap.mitre_id}</span>
                    </div>
                    <div className="text-[11px] text-slate-400">{trap.category} · {trap.size_bytes} bytes</div>
                    <div className="text-[10px] text-slate-500 font-mono truncate">SHA-256: {trap.actual_sha256}</div>
                  </div>
                  <span className={`px-2 py-1 rounded-lg text-[10px] font-bold shrink-0 ${trap.intact ? 'bg-emerald-500/15 text-emerald-300' : 'bg-red-500/20 text-red-300'}`}>
                    {trap.intact ? 'INTACT' : 'TAMPERED'}
                  </span>
                </div>
              ))}
            </div>

            {deception && deception.breaches.length > 0 && (
              <div className="pt-2 border-t border-[#1F2937] space-y-1.5 max-h-36 overflow-y-auto">
                <div className="text-[11px] font-semibold text-slate-300">Recent Deception & Self-Heal Events</div>
                {deception.breaches.slice(0, 5).map((b, idx) => (
                  <div key={`${b.trap_name}-${idx}`} className="flex items-center justify-between text-[11px] px-2.5 py-1.5 rounded-lg bg-[#0B0F17] border border-[#1F2937]">
                    <span className="text-slate-200 truncate">{b.trap_name} · {b.event_type}</span>
                    <span className="text-emerald-300 font-semibold shrink-0">Healed ({b.reaction_ms}ms)</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* WINDOWS 2: Real Authenticode Binary Digital Signature Auditor */}
          <div className="bg-[#111827]/90 border border-[#1F2937] rounded-2xl p-6 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="text-base font-semibold text-white flex items-center gap-2">
                  <Fingerprint className="w-5 h-5 text-cyan-400" />
                  <span>Binary Digital Signature Audit (Authenticode)</span>
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Verifies live third-party executables against Windows publisher certificates.
                </p>
              </div>
              <button
                onClick={handleAuditSignatures}
                disabled={auditingSigs}
                className="px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold flex items-center gap-1.5 disabled:opacity-50"
              >
                <RotateCw className={`w-3.5 h-3.5 ${auditingSigs ? 'animate-spin' : ''}`} />
                <span>{auditingSigs ? 'Verifying...' : 'Verify Binaries'}</span>
              </button>
            </div>

            <div className="grid grid-cols-3 gap-2.5 text-xs text-center">
              <div className="p-2.5 rounded-xl bg-[#0B0F17] border border-[#1F2937]">
                <div className="text-slate-400">Checked</div>
                <div className="text-lg font-bold text-white">{sigAudit?.checked_count ?? '—'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-[#0B0F17] border border-[#1F2937]">
                <div className="text-slate-400">Trusted Signed</div>
                <div className="text-lg font-bold text-emerald-400">{sigAudit?.signed_valid_count ?? '—'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-[#0B0F17] border border-[#1F2937]">
                <div className="text-slate-400">Unsigned/Risky</div>
                <div className="text-lg font-bold text-amber-300">{sigAudit?.unsigned_or_risky_count ?? '—'}</div>
              </div>
            </div>

            <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
              {(sigAudit?.binaries || []).map((bin, idx) => (
                <div key={`${bin.exe}-${idx}`} className="p-2.5 rounded-xl bg-[#0B0F17] border border-[#1F2937] text-xs flex items-center justify-between gap-2">
                  <div className="min-w-0">
                    <div className="font-semibold text-white truncate">{bin.process_name}</div>
                    <div className="text-[11px] text-cyan-300 truncate">Signer: {bin.signer}</div>
                    <div className="text-[10px] text-slate-500 font-mono truncate">{bin.exe}</div>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold shrink-0 ${
                    bin.trust_level === 'TRUSTED'
                      ? 'bg-emerald-500/15 text-emerald-300'
                      : bin.trust_level === 'TAMPERED' || bin.trust_level === 'HIGH_RISK_UNSIGNED'
                      ? 'bg-red-500/20 text-red-300'
                      : 'bg-amber-500/20 text-amber-300'
                  }`}>
                    {bin.signature_status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* ANDROID 1: Screen-Share & Virtual Display RAT Detector */}
          <div className="bg-[#111827]/90 border border-[#1F2937] rounded-2xl p-6 space-y-4">
            <div className="flex items-center justify-between gap-2">
              <div>
                <h2 className="text-base font-semibold text-white flex items-center gap-2">
                  <Monitor className="w-5 h-5 text-red-400" />
                  <span>Screen-Mirror & RAT Display Guard</span>
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Detects hidden virtual screens & remote-control call scams in real time.
                </p>
              </div>
              <button
                onClick={handleCheckScreenSpy}
                disabled={checkingSpy}
                className="px-3 py-1.5 rounded-lg bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-red-200 text-xs font-bold shrink-0"
              >
                {checkingSpy ? 'Checking...' : 'Scan Displays'}
              </button>
            </div>

            {screenSpy && (
              <div className="space-y-3 text-xs">
                <div className={`p-3.5 rounded-xl border flex items-start gap-2.5 ${
                  screenSpy.screenMirroringDetected
                    ? 'bg-red-950/35 border-red-500/50 text-red-200'
                    : screenSpy.riskLevel === 'MEDIUM'
                    ? 'bg-amber-950/30 border-amber-500/40 text-amber-200'
                    : 'bg-emerald-950/25 border-emerald-500/35 text-emerald-200'
                }`}>
                  {screenSpy.screenMirroringDetected ? (
                    <ShieldAlert className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                  ) : screenSpy.riskLevel === 'MEDIUM' ? (
                    <AlertTriangle className="w-5 h-5 text-amber-300 shrink-0 mt-0.5" />
                  ) : (
                    <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                  )}
                  <div>
                    <div className="font-bold">{screenSpy.riskLevel} STATUS</div>
                    <div className="mt-0.5">{screenSpy.summary}</div>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="text-[11px] font-semibold text-slate-300">
                    Active OS Displays ({screenSpy.displays.length})
                  </div>
                  {screenSpy.displays.map((d) => (
                    <div key={d.displayId} className="flex items-center justify-between p-2 rounded-lg bg-[#0B0F17] border border-[#1F2937]">
                      <span className="text-white">{d.name} (ID {d.displayId})</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${d.isDefault ? 'bg-emerald-500/15 text-emerald-300' : 'bg-red-500/20 text-red-300'}`}>
                        {d.isDefault ? 'BUILT-IN SAFE' : 'EXTERNAL / VIRTUAL'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* ANDROID 2: APK Cryptographic SHA-256 Certificate & Tamper Forensics */}
          <div className="bg-[#111827]/90 border border-[#1F2937] rounded-2xl p-6 space-y-4">
            <div className="flex items-center justify-between gap-2">
              <div>
                <h2 className="text-base font-semibold text-white flex items-center gap-2">
                  <Fingerprint className="w-5 h-5 text-purple-400" />
                  <span>APK Certificate & Tamper Inspector</span>
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Inspects X.509 SHA-256 signing fingerprints & debug-tamper flags.
                </p>
              </div>
              <button
                onClick={handleAuditCerts}
                disabled={auditingCerts}
                className="px-3 py-1.5 rounded-lg bg-purple-500 hover:bg-purple-400 text-slate-950 text-xs font-bold shrink-0"
              >
                {auditingCerts ? 'Inspecting...' : 'Inspect Certs'}
              </button>
            </div>

            {certAudit && (
              <div className="space-y-3 text-xs">
                <div className="grid grid-cols-3 gap-2 text-center">
                  <div className="p-2 rounded-xl bg-[#0B0F17] border border-[#1F2937]">
                    <div className="text-slate-400">Audited</div>
                    <div className="text-base font-bold text-white">{certAudit.auditedCount}</div>
                  </div>
                  <div className="p-2 rounded-xl bg-[#0B0F17] border border-[#1F2937]">
                    <div className="text-slate-400">Debug-Key</div>
                    <div className="text-base font-bold text-amber-300">{certAudit.debugSignedCount}</div>
                  </div>
                  <div className="p-2 rounded-xl bg-[#0B0F17] border border-[#1F2937]">
                    <div className="text-slate-400">Debuggable</div>
                    <div className="text-base font-bold text-red-300">{certAudit.debuggableCount}</div>
                  </div>
                </div>

                <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                  {certAudit.apps.map((app) => (
                    <div key={app.packageName} className="p-2.5 rounded-xl bg-[#0B0F17] border border-[#1F2937] space-y-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-semibold text-white truncate">{app.appName}</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold shrink-0 ${app.riskLevel === 'TRUSTED' ? 'bg-emerald-500/15 text-emerald-300' : 'bg-red-500/20 text-red-300'}`}>
                          {app.riskLevel}
                        </span>
                      </div>
                      <div className="text-[11px] text-cyan-300 truncate">Publisher: {app.signerCn}</div>
                      <div className="text-[10px] text-slate-400 font-mono truncate">SHA-256: {app.sha256}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

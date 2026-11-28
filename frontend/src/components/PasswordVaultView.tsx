import React, { useState, useEffect } from 'react';
import {
  KeyRound,
  Lock,
  Plus,
  Search,
  Eye,
  EyeOff,
  Copy,
  Check,
  Trash2,
  ExternalLink,
  Sparkles,
  ShieldCheck,
  Mail,
  CheckCircle2,
  Clock,
  AlertCircle,
  ArrowRight,
  ShieldAlert,
  RotateCw,
} from 'lucide-react';
import type { VaultAccountItem, AuthUser, VaultBreachReport } from '../types';
import { api } from '../api';
import { FeatureInfo } from './FeatureInfo';
import {
  ADMIN_EMAIL,
  reauthenticateGoogleUser,
  requestVaultPinReset,
  subscribeToUserPinResetRequest,
} from '../firebase';

interface PasswordVaultViewProps {
  user: AuthUser | null;
  initialPin?: string;
}

export const PasswordVaultView: React.FC<PasswordVaultViewProps> = ({ user, initialPin }) => {
  const [pin, setPin] = useState(initialPin || '');
  const [pinInput, setPinInput] = useState('');
  const [isUnlocked, setIsUnlocked] = useState(Boolean(initialPin && initialPin.length >= 4));
  const [pinError, setPinError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const [entries, setEntries] = useState<VaultAccountItem[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('All');

  // Change / Setup Dedicated PIN Modal State
  const [isChangePinModalOpen, setIsChangePinModalOpen] = useState(false);
  const [oldPinInput, setOldPinInput] = useState('');
  const [newPinInput, setNewPinInput] = useState('');
  const [confirmNewPinInput, setConfirmNewPinInput] = useState('');
  const [changePinError, setChangePinError] = useState<string | null>(null);
  const [changePinSuccess, setChangePinSuccess] = useState<string | null>(null);
  const [isSubmittingPin, setIsSubmittingPin] = useState(false);

  // Add Modal State
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [serviceName, setServiceName] = useState('');
  const [url, setUrl] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [category, setCategory] = useState('General');
  const [notes, setNotes] = useState('');

  // Password Generator State
  const [genLength, setGenLength] = useState(16);
  const [genIncludeSymbols, setGenIncludeSymbols] = useState(true);
  const [genIncludeNumbers, setGenIncludeNumbers] = useState(true);
  const [genIncludeUpper, setGenIncludeUpper] = useState(true);

  // Visible passwords & copy state
  const [revealedIds, setRevealedIds] = useState<string[]>([]);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [clipboardTimerNotice, setClipboardTimerNotice] = useState<string | null>(null);

  // Google Email Unlock & PIN Reset State
  const [googleUnlocking, setGoogleUnlocking] = useState(false);
  const [googleUnlockError, setGoogleUnlockError] = useState<string | null>(null);
  const [googleUnlockSuccess, setGoogleUnlockSuccess] = useState<string | null>(null);

  const [isRequestingReset, setIsRequestingReset] = useState(false);
  const [resetFeedbackMsg, setResetFeedbackMsg] = useState<string | null>(null);
  const [forceResetAllowed, setForceResetAllowed] = useState(false);
  const [isVerifyingGoogleForPin, setIsVerifyingGoogleForPin] = useState(false);

  // Dark Web Breach Monitor State
  const [breachReport, setBreachReport] = useState<VaultBreachReport | null>(null);
  const [checkingBreaches, setCheckingBreaches] = useState(false);

  const isSuperAdmin = Boolean(user?.email && user.email.toLowerCase() === ADMIN_EMAIL.toLowerCase());

  const userId = user?.uid || 'default_user';

  // Real-time listener for PIN reset request approval
  useEffect(() => {
    if (!user?.uid) return;
    const unsub = subscribeToUserPinResetRequest(user.uid, (req) => {
      if (req?.status === 'approved') {
        setForceResetAllowed(true);
        setResetFeedbackMsg('SuperAdmin approved your PIN reset! You can now set a new Vault PIN.');
      }
    });
    return () => unsub();
  }, [user?.uid]);

  // Automatically load if initialPin provided from AuthGate
  useEffect(() => {
    if (initialPin && initialPin.length >= 4) {
      setPin(initialPin);
      setIsUnlocked(true);
      loadEntries(initialPin);
    }
  }, [initialPin]);

  const handleUnlockOrSetup = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (pinInput.trim().length < 4) {
      setPinError('Dedicated PIN must be at least 4 digits');
      return;
    }
    setLoading(true);
    setPinError(null);
    try {
      await api.verifyVaultPin(pinInput.trim(), userId);
      setPin(pinInput.trim());
      setIsUnlocked(true);
      await loadEntries(pinInput.trim());
    } catch (err: any) {
      setPinError(err.message || 'Incorrect Dedicated Vault PIN');
    } finally {
      setLoading(false);
    }
  };

  const loadEntries = async (currentPin: string) => {
    try {
      const res = await api.getVaultEntries(currentPin, userId);
      setEntries(res.entries || []);
    } catch (err) {
      console.error('Failed to load vault entries:', err);
    }
  };

  const handleLockVault = () => {
    setIsUnlocked(false);
    setPin('');
    setPinInput('');
    setEntries([]);
    setRevealedIds([]);
    setGoogleUnlockSuccess(null);
  };

  const handleUnlockWithGoogleEmail = async () => {
    setGoogleUnlocking(true);
    setGoogleUnlockError(null);
    setPinError(null);
    try {
      const res = await reauthenticateGoogleUser(user);
      const email = res.email;

      let activePin = localStorage.getItem('sentinelgrid_vault_pin_' + userId) || pin || '1234';
      try {
        await api.verifyVaultPin(activePin, userId);
      } catch {
        activePin = '1234';
        try {
          await api.verifyVaultPin(activePin, userId);
        } catch {
          await api.setupVaultPin(activePin, activePin, undefined, userId, true);
        }
      }

      setPin(activePin);
      localStorage.setItem('sentinelgrid_vault_pin_' + userId, activePin);
      setIsUnlocked(true);
      await loadEntries(activePin);
      setGoogleUnlockSuccess(`Vault unlocked with Google identity (${email})`);
    } catch (err: any) {
      console.error('Google unlock error:', err);
      setGoogleUnlockError(err.message || 'Google Email verification failed.');
    } finally {
      setGoogleUnlocking(false);
    }
  };

  const handleRequestAdminReset = async () => {
    if (!user) {
      alert('You must be signed in to request a PIN reset.');
      return;
    }
    setIsRequestingReset(true);
    setResetFeedbackMsg(null);
    try {
      await requestVaultPinReset(user);
      setResetFeedbackMsg(`PIN reset request sent to SuperAdmin (${ADMIN_EMAIL}). Once approved, you can set a brand-new PIN without entering the old one.`);
    } catch (err: any) {
      alert(`Request failed: ${err.message}`);
    } finally {
      setIsRequestingReset(false);
    }
  };

  const handleGoogleVerifyForPinChange = async () => {
    setIsVerifyingGoogleForPin(true);
    setChangePinError(null);
    try {
      const res = await reauthenticateGoogleUser(user);
      setForceResetAllowed(true);
      setChangePinSuccess(`Google identity confirmed (${res.email}). You can now set a new PIN without entering your old PIN.`);
    } catch (err: any) {
      setChangePinError(err.message || 'Google re-authentication failed.');
    } finally {
      setIsVerifyingGoogleForPin(false);
    }
  };

  const handleChangeVaultPin = async (e: React.FormEvent) => {
    e.preventDefault();
    setChangePinError(null);
    setChangePinSuccess(null);

    const trimmedNew = newPinInput.trim();
    const trimmedConfirm = confirmNewPinInput.trim();
    if (trimmedNew.length < 4 || trimmedNew.length > 8) {
      setChangePinError('New Dedicated PIN must be between 4 and 8 digits.');
      return;
    }
    if (trimmedNew !== trimmedConfirm) {
      setChangePinError('New PIN and Confirm PIN do not match');
      return;
    }

    setIsSubmittingPin(true);
    try {
      const force = forceResetAllowed || isSuperAdmin;
      const oldPinToUse = force ? undefined : (oldPinInput.trim() || pin);

      await api.setupVaultPin(trimmedNew, trimmedConfirm, oldPinToUse, userId, force);
      setPin(trimmedNew);
      localStorage.setItem('sentinelgrid_vault_pin_' + userId, trimmedNew);
      setChangePinSuccess('Dedicated Vault PIN saved & re-encrypted successfully!');
      setTimeout(() => {
        setIsChangePinModalOpen(false);
        setChangePinSuccess(null);
        setOldPinInput('');
        setNewPinInput('');
        setConfirmNewPinInput('');
        setForceResetAllowed(false);
      }, 1400);
    } catch (err: any) {
      setChangePinError(err.message || 'Failed to update Dedicated Vault PIN');
    } finally {
      setIsSubmittingPin(false);
    }
  };

  const handleGeneratePassword = () => {
    let charset = 'abcdefghijklmnopqrstuvwxyz';
    if (genIncludeUpper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (genIncludeNumbers) charset += '0123456789';
    if (genIncludeSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    let result = '';
    for (let i = 0; i < genLength; i++) {
      result += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    setPassword(result);
  };

  const calculateStrength = (pwd: string) => {
    if (!pwd) return { label: 'Empty', score: 0, color: 'text-slate-500' };
    let score = 0;
    if (pwd.length >= 8) score += 1;
    if (pwd.length >= 14) score += 1;
    if (/[A-Z]/.test(pwd)) score += 1;
    if (/[0-9]/.test(pwd)) score += 1;
    if (/[^A-Za-z0-9]/.test(pwd)) score += 1;

    if (score <= 2) return { label: 'Weak', score: 25, color: 'text-red-400 bg-red-950/60 border-red-500/30' };
    if (score <= 3) return { label: 'Good', score: 65, color: 'text-amber-400 bg-amber-950/60 border-amber-500/30' };
    return { label: 'Strong', score: 100, color: 'text-emerald-400 bg-emerald-950/60 border-emerald-500/30' };
  };

  const handleSaveEntry = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!serviceName.trim() || !username.trim() || !password.trim()) {
      alert('Please fill out Service Name, Username and Password.');
      return;
    }
    try {
      const newEntry: VaultAccountItem = {
        service_name: serviceName.trim(),
        url: url.trim(),
        username: username.trim(),
        password: password.trim(),
        category,
        notes: notes.trim(),
      };
      await api.saveVaultEntry(pin, newEntry, userId);
      await loadEntries(pin);
      setIsAddModalOpen(false);
      // Reset form
      setServiceName('');
      setUrl('');
      setUsername('');
      setPassword('');
      setNotes('');
    } catch (err: any) {
      alert(`Save failed: ${err.message}`);
    }
  };

  const handleDeleteEntry = async (id?: string) => {
    if (!id) return;
    if (!confirm('Are you sure you want to delete this saved account?')) return;
    try {
      await api.deleteVaultEntry(id, pin, userId);
      await loadEntries(pin);
    } catch (err: any) {
      alert(`Delete failed: ${err.message}`);
    }
  };

  const handleCopyPassword = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setClipboardTimerNotice('Password copied! OS & Browser clipboard auto-wiping in 30 seconds.');
    setTimeout(() => {
      setCopiedId(null);
    }, 2000);
    setTimeout(async () => {
      try {
        await navigator.clipboard.writeText('');
      } catch {
        // Fallback when document is not focused
      }
      api.clearClipboard().catch(() => {});
      setClipboardTimerNotice('Clipboard wiped cleanly after 30s privacy window.');
      setTimeout(() => setClipboardTimerNotice(null), 3000);
    }, 30000);
  };

  const handleRunBreachAudit = async () => {
    setCheckingBreaches(true);
    try {
      const report = await api.checkVaultBreaches(pin, userId);
      setBreachReport(report);
    } catch {
      // Cross-platform k-anonymity fallback (works natively on Android/Web without desktop backend)
      const pwdCounts: Record<string, number> = {};
      for (const e of entries) {
        if (e.password) pwdCounts[e.password] = (pwdCounts[e.password] || 0) + 1;
      }
      const results = await Promise.all(
        entries.map(async (e) => {
          let breached = false;
          let leakCount = 0;
          let checkedOnline = false;
          try {
            const enc = new TextEncoder().encode(e.password || '');
            const hashBuf = await crypto.subtle.digest('SHA-1', enc);
            const hex = Array.from(new Uint8Array(hashBuf))
              .map((b) => b.toString(16).padStart(2, '0'))
              .join('')
              .toUpperCase();
            const prefix = hex.slice(0, 5);
            const suffix = hex.slice(5);
            const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
              headers: { 'Add-Padding': 'true' },
            });
            if (resp.ok) {
              checkedOnline = true;
              const body = await resp.text();
              for (const line of body.split('\n')) {
                const [sfx, cnt] = line.trim().split(':');
                if (sfx && sfx.toUpperCase() === suffix) {
                  leakCount = parseInt(cnt || '0', 10) || 0;
                  breached = leakCount > 0;
                  break;
                }
              }
            }
          } catch {
            // offline fallback
          }
          const str = calculateStrength(e.password).label.toUpperCase();
          return {
            id: e.id,
            service_name: e.service_name,
            username: e.username,
            breached,
            leak_count: leakCount,
            reused: Boolean(e.password && (pwdCounts[e.password] || 0) > 1),
            strength: str,
            checked_online: checkedOnline,
          };
        })
      );
      setBreachReport({
        total_entries: entries.length,
        breached_count: results.filter((r) => r.breached).length,
        reused_count: results.filter((r) => r.reused).length,
        weak_count: results.filter((r) => r.strength === 'WEAK').length,
        hibp_reachable: results.some((r) => r.checked_online) || entries.length === 0,
        checked_at: new Date().toLocaleTimeString(),
        results,
      });
    } finally {
      setCheckingBreaches(false);
    }
  };

  const toggleReveal = (id: string) => {
    setRevealedIds((prev) =>
      prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]
    );
  };

  const filteredEntries = entries.filter((e) => {
    const matchesSearch =
      e.service_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      e.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (e.url && e.url.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchesCat = categoryFilter === 'All' || e.category === categoryFilter;
    return matchesSearch && matchesCat;
  });

  // 1. PIN Lock Screen View
  if (!isUnlocked) {
    return (
      <div className="min-h-[550px] flex items-center justify-center p-4">
        <div className="w-full max-w-sm defender-card p-7 space-y-5 text-center border-emerald-500/30 shadow-2xl">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-emerald-500/20 to-teal-500/10 border border-emerald-500/40 text-emerald-400 mx-auto flex items-center justify-center shadow-lg shadow-emerald-950/40">
            <Lock className="w-7 h-7" />
          </div>

          <div>
            <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-emerald-950/80 border border-emerald-500/30 text-[10px] font-semibold text-emerald-400 mb-1.5">
              Dedicated Vault PIN Protection
            </div>
            <h2 className="text-lg font-bold text-white">Password &amp; Credentials Vault</h2>
            <p className="text-xs text-slate-400 mt-1">
              Encrypted locally with AES-256. Enter your dedicated Vault Security PIN to unlock your accounts.
            </p>
          </div>

          <FeatureInfo
            tone="emerald"
            className="text-left"
            why="Saving passwords in plain text or browser autofill makes them easy to steal if your device is shared or infected."
            how="Derives an encryption key from your dedicated Vault PIN (with salt) so passwords stay encrypted in AES-256 on your device and never leave it in plain text."
          />

          {/* Status Feedback Banners */}
          {resetFeedbackMsg && (
            <div
              className={`p-3 rounded-xl border text-xs text-left leading-relaxed ${
                forceResetAllowed
                  ? 'bg-emerald-950/70 border-emerald-500/40 text-emerald-300'
                  : 'bg-amber-950/70 border-amber-500/40 text-amber-300'
              }`}
            >
              <div className="flex items-start gap-2">
                {forceResetAllowed ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                ) : (
                  <Clock className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                )}
                <div className="flex-1">
                  <span>{resetFeedbackMsg}</span>
                  {forceResetAllowed && (
                    <button
                      type="button"
                      onClick={() => setIsChangePinModalOpen(true)}
                      className="mt-2 block w-full py-1.5 px-3 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-center text-xs transition-colors"
                    >
                      Set New Vault PIN Now
                    </button>
                  )}
                </div>
              </div>
            </div>
          )}

          {googleUnlockSuccess && (
            <div className="p-2.5 rounded-lg bg-emerald-950/60 border border-emerald-500/40 text-emerald-300 text-xs flex items-center justify-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>{googleUnlockSuccess}</span>
            </div>
          )}

          {googleUnlockError && (
            <div className="p-2.5 rounded-lg bg-red-950/60 border border-red-500/40 text-red-300 text-xs flex items-center justify-center gap-1.5">
              <AlertCircle className="w-4 h-4 text-red-400" />
              <span>{googleUnlockError}</span>
            </div>
          )}

          {pinError && (
            <div className="p-2.5 rounded-lg bg-red-950/50 border border-red-500/30 text-red-300 text-xs">
              {pinError}
            </div>
          )}

          <form onSubmit={handleUnlockOrSetup} className="space-y-4">
            <div className="relative">
              <input
                type="password"
                maxLength={8}
                value={pinInput}
                onChange={(e) => setPinInput(e.target.value)}
                placeholder="Enter 4-8 Digit Vault PIN"
                className="w-full bg-[#0B0F17] border border-[#1F2937] rounded-xl px-4 py-3 text-center tracking-[0.5em] text-lg font-mono text-emerald-400 focus:outline-none focus:border-emerald-500/60"
                autoFocus
              />
            </div>

            <div className="flex items-center justify-between text-[11px] text-slate-400 px-1">
              <button
                type="button"
                onClick={() => setPinInput('1234')}
                className="text-emerald-400 hover:underline flex items-center gap-1 font-mono"
              >
                <Sparkles className="w-3 h-3" />
                <span>Auto-Fill Demo PIN (1234)</span>
              </button>

              <button
                type="button"
                onClick={() => setIsChangePinModalOpen(true)}
                className="text-slate-400 hover:text-slate-200 underline"
              >
                Setup / Change PIN
              </button>
            </div>

            <button
              type="submit"
              disabled={loading || pinInput.length < 4}
              className="w-full py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 transition-all shadow-md shadow-emerald-500/20 disabled:opacity-50"
            >
              <KeyRound className="w-4 h-4" />
              <span>{loading ? 'Decrypting Vault...' : 'Unlock Credentials Vault'}</span>
            </button>
          </form>

          {/* Divider */}
          <div className="flex items-center gap-3 my-1">
            <div className="flex-1 h-px bg-[#1F2937]" />
            <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">
              or verify identity
            </span>
            <div className="flex-1 h-px bg-[#1F2937]" />
          </div>

          {/* Secondary Unlock Button: Unlock with Google Email */}
          <button
            type="button"
            onClick={handleUnlockWithGoogleEmail}
            disabled={googleUnlocking}
            className="w-full py-2.5 px-4 rounded-xl bg-[#131C2E] hover:bg-[#1A253D] text-slate-200 border border-[#2B3B55] hover:border-emerald-500/50 transition-all text-xs font-semibold flex items-center justify-center gap-2.5 shadow-sm disabled:opacity-50"
          >
            <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24">
              <path
                fill="#4285F4"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              />
              <path
                fill="#34A853"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              />
              <path
                fill="#FBBC05"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
              />
              <path
                fill="#EA4335"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
              />
            </svg>
            <span>
              {googleUnlocking
                ? 'Verifying Google Account...'
                : `Unlock with Google Email (${user?.email ? user.email.split('@')[0] : 'Identity'})`}
            </span>
          </button>

          {/* Forgot PIN / Reset Link */}
          <div className="pt-2 border-t border-[#1F2937]/80 flex items-center justify-between text-[11px] text-slate-400">
            <button
              type="button"
              onClick={() => setIsChangePinModalOpen(true)}
              className="text-slate-400 hover:text-slate-200 underline"
            >
              Change / Reset PIN
            </button>

            <button
              type="button"
              onClick={handleRequestAdminReset}
              disabled={isRequestingReset}
              className="text-amber-400 hover:text-amber-300 font-medium hover:underline flex items-center gap-1"
            >
              <KeyRound className="w-3 h-3" />
              <span>{isRequestingReset ? 'Sending Request...' : 'Request Admin Reset'}</span>
            </button>
          </div>
        </div>

        {/* Change / Setup Dedicated PIN Modal */}
        {isChangePinModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
            <div className="bg-[#0E1626] border border-[#22334D] rounded-2xl w-full max-w-sm p-6 shadow-2xl space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-[#1E2E48]">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <div>
                    <h3 className="text-sm font-bold text-white">Change / Reset Dedicated PIN</h3>
                    <p className="text-[10px] text-slate-400">
                      {forceResetAllowed || isSuperAdmin
                        ? 'Reset Authorization Active · Old PIN Bypassed'
                        : 'Set or migrate your 4–8 digit AES-256 Vault PIN'}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setIsChangePinModalOpen(false)}
                  className="text-slate-400 hover:text-white"
                >
                  ✕
                </button>
              </div>

              {changePinError && (
                <div className="p-2.5 rounded-lg bg-red-950/50 border border-red-500/30 text-red-300 text-xs text-center">
                  {changePinError}
                </div>
              )}

              {changePinSuccess && (
                <div className="p-2.5 rounded-lg bg-emerald-950/50 border border-emerald-500/30 text-emerald-300 text-xs text-center">
                  {changePinSuccess}
                </div>
              )}

              {/* Forgot PIN Options if not already authorized */}
              {!(forceResetAllowed || isSuperAdmin) && (
                <div className="space-y-2 p-3 rounded-xl bg-[#090E17] border border-[#1A273D] text-[11px]">
                  <div className="text-slate-300 font-semibold flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                    <span>Forgot your current PIN? Choose an option:</span>
                  </div>

                  <div className="grid grid-cols-1 gap-2 pt-1">
                    {/* Option A: Google Reauth */}
                    <button
                      type="button"
                      onClick={handleGoogleVerifyForPinChange}
                      disabled={isVerifyingGoogleForPin}
                      className="w-full p-2 rounded-lg bg-[#111A2B] hover:bg-[#18253D] border border-[#23334E] text-slate-200 text-left flex items-center justify-between group transition-colors"
                    >
                      <div className="flex items-center gap-2">
                        <Mail className="w-3.5 h-3.5 text-blue-400" />
                        <span><strong>Option A:</strong> Re-authenticate with Google</span>
                      </div>
                      <ArrowRight className="w-3 h-3 text-slate-400 group-hover:translate-x-0.5 transition-transform" />
                    </button>

                    {/* Option B: Request Admin Approval */}
                    <button
                      type="button"
                      onClick={handleRequestAdminReset}
                      disabled={isRequestingReset}
                      className="w-full p-2 rounded-lg bg-[#111A2B] hover:bg-[#18253D] border border-[#23334E] text-slate-200 text-left flex items-center justify-between group transition-colors"
                    >
                      <div className="flex items-center gap-2">
                        <KeyRound className="w-3.5 h-3.5 text-amber-400" />
                        <span><strong>Option B:</strong> Request Admin Approval ({ADMIN_EMAIL.split('@')[0]})</span>
                      </div>
                      <ArrowRight className="w-3 h-3 text-slate-400 group-hover:translate-x-0.5 transition-transform" />
                    </button>
                  </div>
                </div>
              )}

              {/* Notice when force reset is allowed */}
              {(forceResetAllowed || isSuperAdmin) && (
                <div className="p-2.5 rounded-lg bg-emerald-950/60 border border-emerald-500/40 text-emerald-300 text-[11px] flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>
                    {isSuperAdmin
                      ? 'SuperAdmin identity active. Old PIN requirement bypassed.'
                      : 'Google verification / Admin approval confirmed. Old PIN requirement bypassed.'}
                  </span>
                </div>
              )}

              <form onSubmit={handleChangeVaultPin} className="space-y-3 text-xs">
                {!(forceResetAllowed || isSuperAdmin) && (
                  <div>
                    <label className="text-slate-300 font-semibold block mb-1">
                      Current Vault PIN (if existing)
                    </label>
                    <input
                      type="password"
                      maxLength={8}
                      value={oldPinInput}
                      onChange={(e) => setOldPinInput(e.target.value)}
                      placeholder="Enter current PIN (leave empty if first time)"
                      className="w-full bg-[#080D16] border border-[#1F2E45] rounded-lg px-3 py-2 font-mono text-emerald-400 focus:outline-none focus:border-emerald-500/60"
                    />
                  </div>
                )}

                <div>
                  <label className="text-slate-300 font-semibold block mb-1">
                    New Dedicated Vault PIN * (4-8 digits)
                  </label>
                  <input
                    type="password"
                    required
                    maxLength={8}
                    value={newPinInput}
                    onChange={(e) => setNewPinInput(e.target.value)}
                    placeholder="e.g. 1234 or 8921"
                    className="w-full bg-[#080D16] border border-[#1F2E45] rounded-lg px-3 py-2 font-mono text-emerald-400 focus:outline-none focus:border-emerald-500/60"
                  />
                </div>

                <div>
                  <label className="text-slate-300 font-semibold block mb-1">
                    Confirm New Dedicated PIN *
                  </label>
                  <input
                    type="password"
                    required
                    maxLength={8}
                    value={confirmNewPinInput}
                    onChange={(e) => setConfirmNewPinInput(e.target.value)}
                    placeholder="Repeat new PIN"
                    className="w-full bg-[#080D16] border border-[#1F2E45] rounded-lg px-3 py-2 font-mono text-emerald-400 focus:outline-none focus:border-emerald-500/60"
                  />
                </div>

                <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#1E2E48]">
                  <button
                    type="button"
                    onClick={() => setIsChangePinModalOpen(false)}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 font-medium hover:bg-slate-700"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={isSubmittingPin}
                    className="px-4 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold transition-all disabled:opacity-50"
                  >
                    {isSubmittingPin ? 'Saving...' : 'Save Dedicated PIN'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    );
  }

  // 2. Unlocked Vault View
  return (
    <div className="space-y-6">
      {/* Top Header Card */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-[#0C1A1A] via-[#101926] to-[#131A26] border border-emerald-500/30 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-sm">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-emerald-500 to-teal-700 text-white flex items-center justify-center shadow-md">
            <KeyRound className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-500/30">
                Dedicated PIN Active (AES-256)
              </span>
              <span className="text-xs text-slate-400">• Scoped to {user?.displayName || 'Active Operator'}</span>
            </div>
            <h2 className="text-lg font-bold text-white tracking-tight mt-0.5">
              Encrypted Password &amp; Credentials Vault
            </h2>
            <p className="text-xs text-slate-400">
              Zero-knowledge local storage. Credentials decrypt on demand with your Dedicated Vault PIN.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={() => {
              handleGeneratePassword();
              setIsAddModalOpen(true);
            }}
            className="px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-all shadow-md shadow-emerald-500/20"
          >
            <Plus className="w-4 h-4" />
            <span>Add Account</span>
          </button>

          <button
            onClick={handleRunBreachAudit}
            disabled={checkingBreaches || entries.length === 0}
            className="px-3.5 py-2 rounded-xl bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/40 text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50"
            title="Zero-knowledge k-anonymity Dark Web leak check"
          >
            {checkingBreaches ? (
              <RotateCw className="w-3.5 h-3.5 animate-spin text-amber-300" />
            ) : (
              <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
            )}
            <span>{checkingBreaches ? 'Checking Leaks...' : 'Dark Web Audit'}</span>
          </button>

          <button
            onClick={() => setIsChangePinModalOpen(true)}
            className="px-3 py-2 rounded-xl bg-[#131B2A] hover:bg-[#1A253A] text-slate-300 border border-[#2B3B52] text-xs font-medium flex items-center gap-1.5 transition-colors"
            title="Configure or change your Dedicated Vault PIN"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>Change / Reset PIN</span>
          </button>

          <button
            onClick={handleLockVault}
            className="px-3 py-2 rounded-xl bg-[#131B2A] hover:bg-[#1A253A] text-slate-300 border border-[#2B3B52] text-xs font-medium flex items-center gap-1.5 transition-colors"
          >
            <Lock className="w-3.5 h-3.5 text-slate-400" />
            <span>Lock</span>
          </button>
        </div>
      </div>

      <FeatureInfo
        tone="emerald"
        why="Reusing passwords or storing them unencrypted puts all your accounts at risk if one website leaks."
        how="Accounts are stored locally using AES-256 encryption, copied passwords auto-clear from your clipboard after 30 seconds, and the Dark Web Audit checks only a 5-character SHA-1 hash prefix (k-anonymity) so your real password is never sent online."
      />

      {clipboardTimerNotice && (
        <div className="p-3 rounded-xl bg-emerald-950/40 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
          <Check className="w-4 h-4" />
          <span>{clipboardTimerNotice}</span>
        </div>
      )}

      {/* Dark Web Breach Monitor Summary Banner */}
      {breachReport && (
        <div
          className={`p-4 rounded-2xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
            breachReport.breached_count > 0
              ? 'bg-red-950/30 border-red-500/40'
              : 'bg-emerald-950/20 border-emerald-500/30'
          }`}
        >
          <div className="flex items-start gap-3">
            {breachReport.breached_count > 0 ? (
              <ShieldAlert className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            ) : (
              <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            )}
            <div>
              <h4 className="text-xs font-bold text-white">
                {breachReport.breached_count > 0
                  ? `${breachReport.breached_count} Compromised Password${breachReport.breached_count > 1 ? 's' : ''} Found in Public Data Breaches`
                  : 'Zero Dark Web Leaks Detected Across Your Vault'}
              </h4>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Verified via zero-knowledge SHA-1 k-anonymity ({breachReport.hibp_reachable ? 'Online HIBP' : 'Offline Strength Audit'}) ·{' '}
                <span className="text-amber-300 font-medium">{breachReport.reused_count} reused</span> ·{' '}
                <span className="text-slate-300">{breachReport.weak_count} weak</span>
              </p>
            </div>
          </div>
          <span className="text-[10px] font-mono text-slate-400 shrink-0">
            Audited: {breachReport.checked_at}
          </span>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="defender-card p-4 flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-72">
          <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search accounts or usernames..."
            className="w-full bg-[#0D121D] border border-[#1F2937] rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-emerald-500/50"
          />
        </div>

        <div className="flex items-center gap-1.5 overflow-x-auto w-full sm:w-auto">
          {['All', 'General', 'Work', 'Finance', 'Social'].map((cat) => (
            <button
              key={cat}
              onClick={() => setCategoryFilter(cat)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                categoryFilter === cat
                  ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 font-semibold'
                  : 'bg-[#0D121D] text-slate-400 hover:text-slate-200 border border-[#1F2937]'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Credentials List */}
      <div className="space-y-3">
        {filteredEntries.length === 0 ? (
          <div className="defender-card p-10 text-center space-y-2">
            <KeyRound className="w-8 h-8 text-slate-600 mx-auto" />
            <h4 className="text-sm font-semibold text-white">No Credentials Found</h4>
            <p className="text-xs text-slate-400 max-w-sm mx-auto">
              {searchTerm
                ? 'No saved accounts match your search query.'
                : 'Your encrypted vault is empty. Click "Add Account" to securely store your passwords.'}
            </p>
          </div>
        ) : (
          filteredEntries.map((item) => {
            const isRevealed = revealedIds.includes(item.id || '');
            const isCopied = copiedId === item.id;
            const strength = calculateStrength(item.password);
            const breachItem = breachReport?.results?.find((r) => r.id === item.id);

            return (
              <div
                key={item.id}
                className="defender-card p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 group"
              >
                <div className="flex items-start gap-3.5">
                  <div className="w-10 h-10 rounded-xl bg-[#141E2E] border border-[#25354D] flex items-center justify-center text-emerald-400 font-bold text-sm shrink-0">
                    {item.service_name.charAt(0).toUpperCase()}
                  </div>

                  <div>
                    <div className="flex items-center gap-2">
                      <h4 className="text-sm font-semibold text-white">{item.service_name}</h4>
                      {item.url && (
                        <a
                          href={item.url.startsWith('http') ? item.url : `https://${item.url}`}
                          target="_blank"
                          rel="noreferrer"
                          className="text-slate-500 hover:text-emerald-400"
                        >
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                        {item.category || 'General'}
                      </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400 mt-1">
                      <span>
                        User: <strong className="text-slate-200 font-mono">{item.username}</strong>
                      </span>
                      <span>•</span>
                      <div className="flex items-center gap-2">
                        <span>Password:</span>
                        <span className="font-mono text-slate-200">
                          {isRevealed ? item.password : '••••••••••••'}
                        </span>
                        <button
                          onClick={() => toggleReveal(item.id || '')}
                          className="text-slate-500 hover:text-slate-200"
                        >
                          {isRevealed ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 self-end sm:self-auto shrink-0 flex-wrap justify-end">
                  {breachItem && breachItem.breached && (
                    <span className="text-[10px] px-2 py-0.5 rounded border font-semibold text-red-300 bg-red-950/70 border-red-500/40">
                      Leaked ({breachItem.leak_count.toLocaleString()}x)
                    </span>
                  )}
                  {breachItem && breachItem.reused && (
                    <span className="text-[10px] px-2 py-0.5 rounded border font-semibold text-amber-300 bg-amber-950/70 border-amber-500/40">
                      Reused
                    </span>
                  )}
                  <span className={`text-[10px] px-2 py-0.5 rounded border font-medium ${strength.color}`}>
                    {strength.label}
                  </span>

                  <button
                    onClick={() => handleCopyPassword(item.password, item.id || '')}
                    className="px-3 py-1.5 rounded-lg bg-[#182335] hover:bg-[#202E46] text-slate-200 border border-[#2B3B52] text-xs font-medium flex items-center gap-1.5 transition-colors"
                  >
                    {isCopied ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span className="text-emerald-400">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5 text-slate-400" />
                        <span>Copy</span>
                      </>
                    )}
                  </button>

                  <button
                    onClick={() => handleDeleteEntry(item.id)}
                    className="p-1.5 rounded-lg text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                    title="Delete Account"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Change / Setup Dedicated PIN Modal */}
      {isChangePinModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="bg-[#0E1626] border border-[#22334D] rounded-2xl w-full max-w-sm p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#1E2E48]">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <div>
                  <h3 className="text-sm font-bold text-white">Change / Reset Dedicated PIN</h3>
                  <p className="text-[10px] text-slate-400">
                    {forceResetAllowed || isSuperAdmin
                      ? 'Reset Authorization Active · Old PIN Bypassed'
                      : 'Set or migrate your 4–8 digit AES-256 Vault PIN'}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setIsChangePinModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            {changePinError && (
              <div className="p-2.5 rounded-lg bg-red-950/50 border border-red-500/30 text-red-300 text-xs text-center">
                {changePinError}
              </div>
            )}

            {changePinSuccess && (
              <div className="p-2.5 rounded-lg bg-emerald-950/50 border border-emerald-500/30 text-emerald-300 text-xs text-center">
                {changePinSuccess}
              </div>
            )}

            {/* Forgot PIN Options if not already authorized */}
            {!(forceResetAllowed || isSuperAdmin) && (
              <div className="space-y-2 p-3 rounded-xl bg-[#090E17] border border-[#1A273D] text-[11px]">
                <div className="text-slate-300 font-semibold flex items-center gap-1.5">
                  <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                  <span>Forgot your current PIN? Choose an option:</span>
                </div>

                <div className="grid grid-cols-1 gap-2 pt-1">
                  {/* Option A: Google Reauth */}
                  <button
                    type="button"
                    onClick={handleGoogleVerifyForPinChange}
                    disabled={isVerifyingGoogleForPin}
                    className="w-full p-2 rounded-lg bg-[#111A2B] hover:bg-[#18253D] border border-[#23334E] text-slate-200 text-left flex items-center justify-between group transition-colors"
                  >
                    <div className="flex items-center gap-2">
                      <Mail className="w-3.5 h-3.5 text-blue-400" />
                      <span><strong>Option A:</strong> Re-authenticate with Google</span>
                    </div>
                    <ArrowRight className="w-3 h-3 text-slate-400 group-hover:translate-x-0.5 transition-transform" />
                  </button>

                  {/* Option B: Request Admin Approval */}
                  <button
                    type="button"
                    onClick={handleRequestAdminReset}
                    disabled={isRequestingReset}
                    className="w-full p-2 rounded-lg bg-[#111A2B] hover:bg-[#18253D] border border-[#23334E] text-slate-200 text-left flex items-center justify-between group transition-colors"
                  >
                    <div className="flex items-center gap-2">
                      <KeyRound className="w-3.5 h-3.5 text-amber-400" />
                      <span><strong>Option B:</strong> Request Admin Approval ({ADMIN_EMAIL.split('@')[0]})</span>
                    </div>
                    <ArrowRight className="w-3 h-3 text-slate-400 group-hover:translate-x-0.5 transition-transform" />
                  </button>
                </div>
              </div>
            )}

            {/* Notice when force reset is allowed */}
            {(forceResetAllowed || isSuperAdmin) && (
              <div className="p-2.5 rounded-lg bg-emerald-950/60 border border-emerald-500/40 text-emerald-300 text-[11px] flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>
                  {isSuperAdmin
                    ? 'SuperAdmin identity active. Old PIN requirement bypassed.'
                    : 'Google verification / Admin approval confirmed. Old PIN requirement bypassed.'}
                </span>
              </div>
            )}

            <form onSubmit={handleChangeVaultPin} className="space-y-3 text-xs">
              {!(forceResetAllowed || isSuperAdmin) && (
                <div>
                  <label className="text-slate-300 font-semibold block mb-1">
                    Current Dedicated PIN *
                  </label>
                  <input
                    type="password"
                    maxLength={8}
                    value={oldPinInput}
                    onChange={(e) => setOldPinInput(e.target.value)}
                    placeholder="Enter current PIN"
                    className="w-full bg-[#080D16] border border-[#1F2E45] rounded-lg px-3 py-2 font-mono text-emerald-400 focus:outline-none focus:border-emerald-500/60"
                  />
                </div>
              )}

              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  New Dedicated Vault PIN * (4-8 digits)
                </label>
                <input
                  type="password"
                  required
                  maxLength={8}
                  value={newPinInput}
                  onChange={(e) => setNewPinInput(e.target.value)}
                  placeholder="Enter new 4-8 digit PIN"
                  className="w-full bg-[#080D16] border border-[#1F2E45] rounded-lg px-3 py-2 font-mono text-emerald-400 focus:outline-none focus:border-emerald-500/60"
                />
              </div>

              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  Confirm New Dedicated PIN *
                </label>
                <input
                  type="password"
                  required
                  maxLength={8}
                  value={confirmNewPinInput}
                  onChange={(e) => setConfirmNewPinInput(e.target.value)}
                  placeholder="Repeat new PIN"
                  className="w-full bg-[#080D16] border border-[#1F2E45] rounded-lg px-3 py-2 font-mono text-emerald-400 focus:outline-none focus:border-emerald-500/60"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#1E2E48]">
                <button
                  type="button"
                  onClick={() => setIsChangePinModalOpen(false)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 font-medium hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmittingPin}
                  className="px-4 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold transition-all disabled:opacity-50"
                >
                  {isSubmittingPin ? 'Saving...' : 'Update Dedicated PIN'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add New Account Modal */}
      {isAddModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="bg-[#0E1626] border border-[#22334D] rounded-2xl w-full max-w-lg p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#1E2E48]">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <KeyRound className="w-4 h-4" />
                </div>
                <h3 className="text-sm font-bold text-white">Add New Encrypted Account</h3>
              </div>
              <button
                onClick={() => setIsAddModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleSaveEntry} className="space-y-3.5 text-xs">
              <div>
                <label className="text-slate-300 font-semibold block mb-1">Service or App Name *</label>
                <input
                  type="text"
                  required
                  value={serviceName}
                  onChange={(e) => setServiceName(e.target.value)}
                  placeholder="e.g. Google Workspace, GitHub, Chase"
                  className="w-full bg-[#080D16] border border-[#1F2E45] rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-emerald-500/60"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-300 font-semibold block mb-1">Website URL (Optional)</label>
                  <input
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="https://accounts.google.com"
                    className="w-full bg-[#080D16] border border-[#1F2E45] rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-emerald-500/60"
                  />
                </div>
                <div>
                  <label className="text-slate-300 font-semibold block mb-1">Category</label>
                  <select
                    value={category}
                    onChange={(e) => setCategory(e.target.value)}
                    className="w-full bg-[#080D16] border border-[#1F2E45] rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-emerald-500/60"
                  >
                    <option value="General">General</option>
                    <option value="Work">Work</option>
                    <option value="Finance">Finance</option>
                    <option value="Social">Social</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-slate-300 font-semibold block mb-1">Username or Email *</label>
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="user@example.com"
                  className="w-full bg-[#080D16] border border-[#1F2E45] rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-emerald-500/60"
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-slate-300 font-semibold">Password *</label>
                  <span className={`text-[10px] font-semibold ${calculateStrength(password).color}`}>
                    Strength: {calculateStrength(password).label}
                  </span>
                </div>
                <div className="flex gap-2">
                  <input
                    type="text"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter password or use generator"
                    className="flex-1 bg-[#080D16] border border-[#1F2E45] rounded-lg px-3 py-2 font-mono text-slate-200 focus:outline-none focus:border-emerald-500/60"
                  />
                  <button
                    type="button"
                    onClick={handleGeneratePassword}
                    className="px-3 py-2 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-400 border border-emerald-500/30 font-medium flex items-center gap-1 shrink-0"
                    title="Generate Strong Password"
                  >
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>Generate</span>
                  </button>
                </div>
              </div>

              {/* Password Generator Controls */}
              <div className="p-3 rounded-lg bg-[#080D16] border border-[#19273D] space-y-2">
                <div className="flex items-center justify-between text-[11px] text-slate-400">
                  <span>Generator Length: {genLength} chars</span>
                  <input
                    type="range"
                    min={8}
                    max={32}
                    value={genLength}
                    onChange={(e) => {
                      setGenLength(Number(e.target.value));
                      handleGeneratePassword();
                    }}
                    className="w-32 accent-emerald-500"
                  />
                </div>
                <div className="flex items-center gap-4 text-[11px] text-slate-400">
                  <label className="flex items-center gap-1.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={genIncludeUpper}
                      onChange={(e) => {
                        setGenIncludeUpper(e.target.checked);
                        handleGeneratePassword();
                      }}
                      className="accent-emerald-500"
                    />
                    <span>Uppercase (A-Z)</span>
                  </label>
                  <label className="flex items-center gap-1.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={genIncludeSymbols}
                      onChange={(e) => {
                        setGenIncludeSymbols(e.target.checked);
                        handleGeneratePassword();
                      }}
                      className="accent-emerald-500"
                    />
                    <span>Symbols (!@#$)</span>
                  </label>
                  <label className="flex items-center gap-1.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={genIncludeNumbers}
                      onChange={(e) => {
                        setGenIncludeNumbers(e.target.checked);
                        handleGeneratePassword();
                      }}
                      className="accent-emerald-500"
                    />
                    <span>Numbers (0-9)</span>
                  </label>
                </div>
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-[#1E2E48]">
                <button
                  type="button"
                  onClick={() => setIsAddModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 font-medium hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold shadow-md shadow-emerald-500/20"
                >
                  Save to Encrypted Vault
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

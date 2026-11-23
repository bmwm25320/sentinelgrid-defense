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
} from 'lucide-react';
import type { VaultAccountItem, AuthUser } from '../types';
import { api } from '../api';

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

  const userId = user?.uid || 'default_user';

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
  };

  const handleChangeVaultPin = async (e: React.FormEvent) => {
    e.preventDefault();
    setChangePinError(null);
    setChangePinSuccess(null);

    const trimmedNew = newPinInput.trim();
    const trimmedConfirm = confirmNewPinInput.trim();
    if (trimmedNew.length < 4) {
      setChangePinError('New Dedicated PIN must be at least 4 digits');
      return;
    }
    if (trimmedNew !== trimmedConfirm) {
      setChangePinError('New PIN and Confirm PIN do not match');
      return;
    }

    setIsSubmittingPin(true);
    try {
      await api.setupVaultPin(trimmedNew, trimmedConfirm, oldPinInput.trim() || pin, userId);
      setPin(trimmedNew);
      setChangePinSuccess('Dedicated Vault PIN saved & re-encrypted successfully!');
      setTimeout(() => {
        setIsChangePinModalOpen(false);
        setChangePinSuccess(null);
        setOldPinInput('');
        setNewPinInput('');
        setConfirmNewPinInput('');
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
    setClipboardTimerNotice('Password copied! Clipboard auto-clearing in 30 seconds.');
    setTimeout(() => {
      setCopiedId(null);
    }, 2000);
    setTimeout(() => {
      setClipboardTimerNotice(null);
    }, 30000);
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
        <div className="w-full max-w-sm defender-card p-7 space-y-6 text-center border-emerald-500/30 shadow-2xl">
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

          <p className="text-[11px] text-slate-500">
            Dedicated Vault PIN is configured separately from your Windows or Google account.
          </p>
        </div>

        {/* Change / Setup Dedicated PIN Modal */}
        {isChangePinModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
            <div className="bg-[#0E1626] border border-[#22334D] rounded-2xl w-full max-w-sm p-6 shadow-2xl space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-[#1E2E48]">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <h3 className="text-sm font-bold text-white">Setup Dedicated Vault PIN</h3>
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

              <form onSubmit={handleChangeVaultPin} className="space-y-3 text-xs">
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
            onClick={() => setIsChangePinModalOpen(true)}
            className="px-3 py-2 rounded-xl bg-[#131B2A] hover:bg-[#1A253A] text-slate-300 border border-[#2B3B52] text-xs font-medium flex items-center gap-1.5 transition-colors"
            title="Configure or change your Dedicated Vault PIN"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>Change PIN</span>
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

      {clipboardTimerNotice && (
        <div className="p-3 rounded-xl bg-emerald-950/40 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
          <Check className="w-4 h-4" />
          <span>{clipboardTimerNotice}</span>
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

                <div className="flex items-center gap-2 self-end sm:self-auto shrink-0">
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
                <h3 className="text-sm font-bold text-white">Change Dedicated Vault PIN</h3>
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

            <form onSubmit={handleChangeVaultPin} className="space-y-3 text-xs">
              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  Current Dedicated PIN *
                </label>
                <input
                  type="password"
                  required
                  maxLength={8}
                  value={oldPinInput}
                  onChange={(e) => setOldPinInput(e.target.value)}
                  placeholder="Enter current PIN"
                  className="w-full bg-[#080D16] border border-[#1F2E45] rounded-lg px-3 py-2 font-mono text-emerald-400 focus:outline-none focus:border-emerald-500/60"
                />
              </div>

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

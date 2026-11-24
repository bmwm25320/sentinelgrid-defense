import React, { useState, useEffect } from 'react';
import {
  Shield,
  CheckCircle2,
  Lock,
  ArrowRight,
  UserCheck,
  KeyRound,
  Eye,
  EyeOff,
  ArrowLeft,
  Sparkles,
} from 'lucide-react';
import type { AuthUser } from '../types';
import { Capacitor } from '@capacitor/core';
import { SocialLogin } from '@capgo/capacitor-social-login';
import {
  signInWithPopup,
  signInWithCredential,
  GoogleAuthProvider,
  googleProvider,
  getAdditionalUserInfo,
  recordLoginAuditLog,
  handleGoogleRedirectResult,
  signInWithGoogleRedirect,
  isFirebaseConfigured,
  auth,
  onAuthStateChanged,
  GOOGLE_WEB_CLIENT_ID,
} from '../firebase';
import { api } from '../api';

interface AuthGateProps {
  onLoginSuccess: (user: AuthUser, initialVaultPin?: string) => void;
}

export const AuthGate: React.FC<AuthGateProps> = ({ onLoginSuccess }) => {
  // Step 1: Account Sign In, Step 2: Vault Access PIN
  const [step, setStep] = useState<'account' | 'vault_pin'>('account');
  const [pendingUser, setPendingUser] = useState<AuthUser | null>(null);

  const [loading, setLoading] = useState(false);
  const [redirectChecking, setRedirectChecking] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Vault PIN state
  const [vaultPin, setVaultPin] = useState('');
  const [confirmPin, setConfirmPin] = useState('');
  const [isSettingNewPin, setIsSettingNewPin] = useState(false);
  const [showPin, setShowPin] = useState(false);
  const [pinNotice, setPinNotice] = useState<string | null>(null);

  const completeLogin = (user: AuthUser, initialPin?: string) => {
    setPendingUser(user);
    localStorage.setItem('sentinelgrid_user', JSON.stringify(user));
    onLoginSuccess(user, initialPin);
  };

  // Check for persistent auth state on page load or session restoration
  useEffect(() => {
    let active = true;

    // Initialize native Google Sign-In plugin on mobile platforms
    if (Capacitor.isNativePlatform()) {
      SocialLogin.initialize({
        google: {
          webClientId: GOOGLE_WEB_CLIENT_ID,
          mode: 'online',
        },
      }).catch((err) => {
        console.warn('Native SocialLogin.initialize notice:', err);
      });
    }

    if (!auth) {
      setRedirectChecking(false);
      return;
    }

    // 0. If user is already authenticated in Firebase, advance immediately to dashboard
    if (auth.currentUser) {
      const u = auth.currentUser;
      const existingUser: AuthUser = {
        uid: u.uid,
        email: u.email,
        displayName: u.displayName || 'Google User',
        photoURL: u.photoURL,
        isDemo: false,
      };
      completeLogin(existingUser);
      setRedirectChecking(false);
      return;
    }

    // 1. Process getRedirectResult if returning from an OAuth redirect
    handleGoogleRedirectResult()
      .then((result) => {
        if (result && active) {
          completeLogin(result.user);
        }
      })
      .catch((err: any) => {
        if (active) {
          console.warn('Redirect auth handler warning:', err);
          if (err?.code !== 'auth/popup-closed-by-user') {
            setErrorMsg(err.message || 'Google Redirect callback processing failed.');
          }
        }
      })
      .finally(() => {
        if (active) setRedirectChecking(false);
      });

    // 2. Attach onAuthStateChanged listener to catch sessions restored from storage or popup completion
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      if (!active) return;
      if (firebaseUser) {
        const authUser: AuthUser = {
          uid: firebaseUser.uid,
          email: firebaseUser.email,
          displayName: firebaseUser.displayName || 'Google User',
          photoURL: firebaseUser.photoURL,
          isDemo: false,
        };

        try {
          await recordLoginAuditLog(authUser, false);
        } catch (e) {
          console.warn('Audit record warning:', e);
        }

        if (active) {
          completeLogin(authUser);
          setRedirectChecking(false);
        }
      } else {
        if (active) setRedirectChecking(false);
      }
    });

    setRedirectChecking(false);

    return () => {
      active = false;
      unsubscribe();
    };
  }, []);

  const handleGoogleSignIn = async () => {
    if (!auth || !isFirebaseConfigured) {
      setErrorMsg(
        'Real Google OAuth requires VITE_FIREBASE_* keys in your .env file. See .env.example. You can use Standard User Demo Sign-In below for evaluation.'
      );
      return;
    }

    setLoading(true);
    setErrorMsg(null);

    // Case 1: Native Android (Capacitor Native Platform)
    // Avoids Chromium WebView's partitioned storage / missing initial state bug entirely
    if (Capacitor.isNativePlatform()) {
      try {
        await SocialLogin.initialize({
          google: {
            webClientId: GOOGLE_WEB_CLIENT_ID,
            mode: 'online',
          },
        }).catch(() => {});

        const loginRes = await SocialLogin.login({
          provider: 'google',
          options: {},
        });

        const idToken = (loginRes?.result as any)?.idToken;
        if (!idToken) {
          throw new Error('Google native authentication did not return an ID token.');
        }

        const credential = GoogleAuthProvider.credential(idToken);
        const cred = await signInWithCredential(auth, credential);
        if (cred && cred.user) {
          const u = cred.user;
          const additionalInfo = getAdditionalUserInfo ? getAdditionalUserInfo(cred) : null;
          const isNewUser = Boolean(additionalInfo?.isNewUser);

          const authUser: AuthUser = {
            uid: u.uid,
            email: u.email,
            displayName: u.displayName || 'Google User',
            photoURL: u.photoURL,
            isDemo: false,
          };

          try {
            await recordLoginAuditLog(authUser, isNewUser, 'Android Mobile');
          } catch (auditErr) {
            console.warn('Audit record warning:', auditErr);
          }

          completeLogin(authUser);
        }
      } catch (err: any) {
        console.error('Native Google Sign-In error:', err);
        if (err?.message?.includes('USER_CANCELLED') || err?.code === 'USER_CANCELLED') {
          setErrorMsg('Sign-in was cancelled.');
        } else {
          const code = err?.code ? `[${err.code}] ` : '';
          const msg = err?.message || 'Native Google Sign-In failed.';
          setErrorMsg(`${code}${msg}`);
        }
      } finally {
        setLoading(false);
      }
      return;
    }

    // Case 2: Web Browser & Windows Desktop App
    // Calls signInWithPopup directly inside user gesture onClick handler
    signInWithPopup(auth, googleProvider)
      .then(async (cred) => {
        if (cred && cred.user) {
          const u = cred.user;
          const additionalInfo = getAdditionalUserInfo ? getAdditionalUserInfo(cred) : null;
          const isNewUser = Boolean(additionalInfo?.isNewUser);

          const authUser: AuthUser = {
            uid: u.uid,
            email: u.email,
            displayName: u.displayName || 'Google User',
            photoURL: u.photoURL,
            isDemo: false,
          };

          try {
            await recordLoginAuditLog(authUser, isNewUser);
          } catch (auditErr) {
            console.warn('Audit record warning:', auditErr);
          }

          completeLogin(authUser);
        }
      })
      .catch(async (err: any) => {
        console.error('Google sign-in popup error:', err);
        if (err?.code === 'auth/popup-closed-by-user' || err?.code === 'auth/cancelled-popup-request') {
          setErrorMsg('Sign-in was cancelled.');
        } else if (err?.code === 'auth/popup-blocked') {
          // If popup is blocked, attempt redirect fallback
          setErrorMsg('Popup was blocked. Redirecting to Google Sign-In...');
          try {
            await signInWithGoogleRedirect();
          } catch (rErr: any) {
            setErrorMsg(`Google Redirect failed: ${rErr?.message || rErr}`);
          }
        } else {
          const code = err?.code ? `[${err.code}] ` : '';
          const msg = err?.message || 'Google sign-in failed.';
          setErrorMsg(`${code}${msg}`);
        }
      })
      .finally(() => {
        setLoading(false);
      });
  };

  // Demo Security Operator Sign-In
  const handleDemoSignIn = async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const demoUser: AuthUser = {
        uid: 'google_oauth_sumit_783109',
        email: 'sumit.security@sentinelgrid.ai',
        displayName: 'Sumit (Security Lead)',
        photoURL: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=120&auto=format&fit=crop&q=80',
        isDemo: true,
      };
      await recordLoginAuditLog(demoUser, false);
      completeLogin(demoUser, '1234');
    } catch (e: any) {
      setErrorMsg(e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOrSetupVaultPin = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!pendingUser) return;

    const trimmedPin = vaultPin.trim();
    if (trimmedPin.length < 4) {
      setPinNotice('Vault PIN must be at least 4 digits');
      return;
    }

    if (isSettingNewPin && trimmedPin !== confirmPin.trim()) {
      setPinNotice('PIN confirmation does not match');
      return;
    }

    setLoading(true);
    setPinNotice(null);

    try {
      if (isSettingNewPin) {
        await api.setupVaultPin(trimmedPin, confirmPin.trim(), undefined, pendingUser.uid);
      } else {
        await api.verifyVaultPin(trimmedPin, pendingUser.uid);
      }

      localStorage.setItem('sentinelgrid_user', JSON.stringify(pendingUser));
      onLoginSuccess(pendingUser, trimmedPin);
    } catch (err: any) {
      console.warn('Vault PIN error:', err);
      if (!isSettingNewPin && err.message?.includes('401')) {
        setPinNotice('Incorrect Vault PIN. If this is your first time, check "Set a new PIN".');
      } else {
        localStorage.setItem('sentinelgrid_user', JSON.stringify(pendingUser));
        onLoginSuccess(pendingUser, trimmedPin);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSkipVaultPin = () => {
    if (!pendingUser) return;
    localStorage.setItem('sentinelgrid_user', JSON.stringify(pendingUser));
    onLoginSuccess(pendingUser);
  };

  return (
    <div className="fixed inset-0 z-50 bg-[#070B12] flex items-center justify-center p-4 select-none overflow-y-auto">
      {/* Background glow effects */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 left-1/3 w-80 h-80 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md relative z-10 my-auto">
        {/* Brand Shield & Title */}
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-br from-emerald-500 to-teal-700 shadow-xl shadow-emerald-500/20 mb-3 border border-emerald-400/30">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center justify-center gap-2">
            SentinelGrid Defense
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 font-semibold border border-emerald-500/30">
              v4.8 Suite
            </span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Developed by Sumit Shewale · Centralized Google OAuth Audit Protected
          </p>
        </div>

        {/* STEP 1: Account Authentication Card */}
        {step === 'account' && (
          <div className="bg-[#0E1626]/90 backdrop-blur-xl border border-[#1E293B] rounded-2xl p-7 shadow-2xl shadow-black/80 space-y-5 animate-fade-in">
            <div className="text-center space-y-1">
              <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-emerald-950/80 border border-emerald-500/30 text-[11px] font-semibold text-emerald-400 mb-1">
                Step 1 of 2: Google Identity Authentication
              </div>
              <h2 className="text-base font-semibold text-white">Sign In to SentinelGrid</h2>
              <p className="text-xs text-slate-400">
                Official Google OAuth · Central Audit Protected
              </p>
            </div>

            {redirectChecking && (
              <div className="p-3 rounded-xl bg-cyan-950/40 border border-cyan-500/30 text-cyan-300 text-xs text-center flex items-center justify-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                <span>Checking authentication status...</span>
              </div>
            )}

            {errorMsg && (
              <div className="p-3.5 rounded-xl bg-amber-950/60 border border-amber-500/40 text-amber-300 text-xs text-left font-mono break-words leading-relaxed shadow-lg">
                <span className="font-semibold text-amber-200 block mb-0.5">Authentication Error:</span>
                {errorMsg}
              </div>
            )}

            <div className="space-y-3">
              {/* Real Google OAuth Button */}
              <button
                onClick={handleGoogleSignIn}
                disabled={loading || redirectChecking}
                className="w-full flex items-center justify-center gap-3 py-3 px-4 rounded-xl bg-[#131C2E] hover:bg-[#1A253D] text-slate-100 border border-[#2B3B55] hover:border-emerald-500/50 transition-all duration-200 text-xs font-semibold shadow-md group disabled:opacity-50"
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
                <span>{loading ? 'Authenticating with Google...' : 'Sign in with Google'}</span>
              </button>

              {/* Divider */}
              <div className="flex items-center gap-3 my-2">
                <div className="flex-1 h-px bg-[#1E293B]" />
                <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">
                  or instant demo access
                </span>
                <div className="flex-1 h-px bg-[#1E293B]" />
              </div>

              {/* Operator Demo Sign-In Button */}
              <button
                type="button"
                onClick={handleDemoSignIn}
                disabled={loading}
                className="w-full flex items-center justify-between py-2.5 px-4 rounded-xl bg-[#131C2E]/70 hover:bg-[#182338] text-slate-300 hover:text-white border border-[#23334A] transition-all text-xs font-medium group disabled:opacity-50"
              >
                <div className="flex items-center gap-2">
                  <UserCheck className="w-4 h-4 text-emerald-400" />
                  <span>Standard User Demo Sign-In</span>
                </div>
                <ArrowRight className="w-3.5 h-3.5 text-slate-400 group-hover:translate-x-0.5 transition-transform" />
              </button>
            </div>

            {/* Architecture Highlights */}
            <div className="pt-4 border-t border-[#1E293B]/80 space-y-2">
              <div className="flex items-center gap-2 text-[11px] text-slate-300">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Redirect OAuth with Cross-Platform Deep-Linking</span>
              </div>
              <div className="flex items-center gap-2 text-[11px] text-slate-300">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Centralized Cloud Audit Database with Role-Based Security Rules</span>
              </div>
              <div className="flex items-center gap-2 text-[11px] text-slate-300">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Dedicated PIN Protected AES-256 Credentials Vault</span>
              </div>
            </div>
          </div>
        )}

        {/* STEP 2: Dedicated Vault PIN Access Card */}
        {step === 'vault_pin' && pendingUser && (
          <div className="bg-[#0E1626]/90 backdrop-blur-xl border border-emerald-500/40 rounded-2xl p-7 shadow-2xl shadow-black/80 space-y-5 animate-fade-in">
            {/* Authenticated user badge */}
            <div className="flex items-center justify-between p-3 rounded-xl bg-[#080D18] border border-[#19273C]">
              <div className="flex items-center gap-2.5">
                {pendingUser.photoURL ? (
                  <img
                    src={pendingUser.photoURL}
                    alt={pendingUser.displayName || 'User'}
                    className="w-8 h-8 rounded-full border border-emerald-500/40 object-cover"
                  />
                ) : (
                  <div className="w-8 h-8 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center justify-center font-bold text-xs">
                    {(pendingUser.displayName || 'U').charAt(0)}
                  </div>
                )}
                <div>
                  <div className="text-xs font-semibold text-white flex items-center gap-1.5">
                    <span>{pendingUser.displayName || 'Security Operator'}</span>
                    <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                  </div>
                  <div className="text-[10px] text-slate-400 truncate max-w-[180px]">
                    {pendingUser.email}
                  </div>
                </div>
              </div>

              <button
                onClick={() => setStep('account')}
                className="text-[11px] text-slate-400 hover:text-white flex items-center gap-1 transition-colors"
                title="Switch Account"
              >
                <ArrowLeft className="w-3 h-3" />
                <span>Switch</span>
              </button>
            </div>

            {/* Header info */}
            <div className="text-center space-y-1">
              <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-emerald-950/80 border border-emerald-500/30 text-[11px] font-semibold text-emerald-400 mb-1">
                Step 2 of 2: Dedicated Vault Security PIN
              </div>
              <h2 className="text-base font-semibold text-white">Unlock Credentials Vault</h2>
              <p className="text-xs text-slate-400">
                {isSettingNewPin
                  ? 'Set your dedicated 4-8 digit Vault PIN to encrypt all saved credentials'
                  : 'Enter your dedicated Vault PIN to unlock your accounts for this session'}
              </p>
            </div>

            {pinNotice && (
              <div className="p-2.5 rounded-xl bg-red-950/50 border border-red-500/30 text-red-300 text-xs text-center">
                {pinNotice}
              </div>
            )}

            {/* Dedicated Vault PIN Form */}
            <form onSubmit={handleVerifyOrSetupVaultPin} className="space-y-4">
              <div>
                <label className="text-xs text-slate-300 font-medium block mb-1">
                  {isSettingNewPin ? 'New Dedicated Vault PIN (4-8 digits)' : 'Dedicated Vault PIN'}
                </label>
                <div className="relative">
                  <input
                    type={showPin ? 'text' : 'password'}
                    maxLength={8}
                    value={vaultPin}
                    onChange={(e) => setVaultPin(e.target.value)}
                    placeholder="Enter 4-8 Digit PIN"
                    className="w-full bg-[#080D18] border border-[#1E2E48] rounded-xl px-4 py-2.5 text-center tracking-[0.4em] font-mono text-emerald-400 text-base focus:outline-none focus:border-emerald-500/60"
                    autoFocus
                  />
                  <button
                    type="button"
                    onClick={() => setShowPin(!showPin)}
                    className="absolute right-3 top-3 text-slate-500 hover:text-slate-300"
                  >
                    {showPin ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {isSettingNewPin && (
                <div>
                  <label className="text-xs text-slate-300 font-medium block mb-1">
                    Confirm Dedicated Vault PIN
                  </label>
                  <input
                    type={showPin ? 'text' : 'password'}
                    maxLength={8}
                    value={confirmPin}
                    onChange={(e) => setConfirmPin(e.target.value)}
                    placeholder="Confirm PIN"
                    className="w-full bg-[#080D18] border border-[#1E2E48] rounded-xl px-4 py-2.5 text-center tracking-[0.4em] font-mono text-emerald-400 text-base focus:outline-none focus:border-emerald-500/60"
                  />
                </div>
              )}

              {/* Demo PIN helper chip */}
              <div className="flex items-center justify-between text-[11px] text-slate-400 px-1">
                <button
                  type="button"
                  onClick={() => setVaultPin('1234')}
                  className="text-emerald-400 hover:underline flex items-center gap-1 font-mono"
                >
                  <Sparkles className="w-3 h-3" />
                  <span>Use Stage Demo PIN (1234)</span>
                </button>

                <button
                  type="button"
                  onClick={() => setIsSettingNewPin(!isSettingNewPin)}
                  className="text-slate-400 hover:text-slate-200 underline"
                >
                  {isSettingNewPin ? 'I have an existing PIN' : 'Set a new PIN'}
                </button>
              </div>

              {/* Action Buttons */}
              <div className="space-y-2 pt-2">
                <button
                  type="submit"
                  disabled={loading || vaultPin.length < 4}
                  className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 shadow-lg shadow-emerald-500/25 transition-all disabled:opacity-50"
                >
                  <KeyRound className="w-4 h-4" />
                  <span>
                    {loading
                      ? 'Verifying Security PIN...'
                      : isSettingNewPin
                      ? 'Save PIN & Enter Dashboard'
                      : 'Unlock Vault & Enter Dashboard'}
                  </span>
                </button>

                <button
                  type="button"
                  onClick={handleSkipVaultPin}
                  className="w-full py-2 px-4 rounded-xl bg-[#131C2E] hover:bg-[#1A253D] text-slate-400 hover:text-slate-200 border border-[#2B3B55] text-xs font-medium transition-colors"
                >
                  Enter Dashboard (Keep Vault Locked)
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Footer info */}
        <div className="text-center mt-6 space-y-1">
          <div className="inline-flex items-center gap-1.5 text-[11px] text-slate-500">
            <Lock className="w-3 h-3 text-emerald-400" />
            <span>Local OS Guardian Agent v4.8 • Host: LAPTOP-448IQDC5</span>
          </div>
        </div>
      </div>
    </div>
  );
};

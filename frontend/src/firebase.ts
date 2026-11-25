import { initializeApp, getApps, type FirebaseApp } from 'firebase/app';
import {
  getAuth,
  GoogleAuthProvider,
  signInWithRedirect,
  signInWithPopup,
  signInWithCredential,
  reauthenticateWithPopup,
  reauthenticateWithCredential,
  getRedirectResult,
  onAuthStateChanged,
  signOut as fbSignOut,
  getAdditionalUserInfo,
  type Auth,
  type UserCredential
} from 'firebase/auth';
import {
  getFirestore,
  collection,
  doc,
  addDoc,
  updateDoc,
  getDocs,
  query,
  where,
  orderBy,
  limit,
  onSnapshot,
  serverTimestamp,
  type Firestore
} from 'firebase/firestore';
import { Capacitor } from '@capacitor/core';
import { SocialLogin } from '@capgo/capacitor-social-login';
import type { AuthUser, LoginAuditLog, VaultPinResetRequest } from './types';
import { api } from './api';

export const ADMIN_EMAIL = 'bmwm25320@gmail.com';
export const GOOGLE_WEB_CLIENT_ID = '693966093694-s9sa9fuhdbbl197a7461sml1u5bleq6s.apps.googleusercontent.com';

const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY || '',
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || '',
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || '',
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET || '',
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID || '',
  appId: import.meta.env.VITE_FIREBASE_APP_ID || '',
};

let app: FirebaseApp | null = null;
let auth: Auth | null = null;
let db: Firestore | null = null;

export const googleProvider = new GoogleAuthProvider();
googleProvider.setCustomParameters({
  prompt: 'select_account',
});

export const isFirebaseConfigured = Boolean(
  firebaseConfig.apiKey &&
  firebaseConfig.apiKey !== 'YOUR_FIREBASE_API_KEY' &&
  firebaseConfig.projectId
);

if (isFirebaseConfigured) {
  try {
    app = getApps().length === 0 ? initializeApp(firebaseConfig) : getApps()[0];
    auth = getAuth(app);
    db = getFirestore(app);
  } catch (err) {
    console.warn('Firebase initialization skipped/failed:', err);
  }
}

/**
 * Detect client execution platform for audit logging:
 * "Windows Desktop" | "Android Mobile" | "Web Portal"
 */
export function detectPlatform(): 'Windows Desktop' | 'Android Mobile' | 'Web Portal' {
  if (typeof window === 'undefined') return 'Web Portal';
  
  // Capacitor Android detection
  const win = window as any;
  const isCapacitorAndroid = Boolean(
    win.Capacitor?.isNativePlatform?.() || 
    win.Capacitor?.platform === 'android'
  );
  if (isCapacitorAndroid) return 'Android Mobile';

  const ua = navigator.userAgent || '';
  if (/android/i.test(ua)) return 'Android Mobile';
  if (/windows/i.test(ua) || /win32/i.test(ua)) return 'Windows Desktop';
  return 'Web Portal';
}

/**
 * Formats exact human date & timestamp with timezone:
 * e.g. login_date: "November 23, 2026", login_time: "08:24:26 PM IST"
 */
export function formatLoginDateTime(date: Date = new Date()) {
  const login_date = date.toLocaleDateString('en-US', {
    month: 'long',
    day: 'numeric',
    year: 'numeric',
  });

  const timeStr = date.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true,
  });

  let tz = 'IST';
  try {
    const parts = date.toLocaleTimeString('en-US', { timeZoneName: 'short' }).split(' ');
    tz = parts[parts.length - 1] || 'IST';
  } catch {
    tz = 'IST';
  }

  const login_time = `${timeStr} ${tz}`;
  const iso_timestamp = date.toISOString();

  return { login_date, login_time, iso_timestamp };
}

/**
 * Initiates Google OAuth Sign-In via Popup.
 * Calling signInWithPopup directly ensures compatibility with WebView2 child popup windows
 * and web browsers without encountering third-party cross-origin storage blocking.
 */
export async function signInWithGoogle(): Promise<AuthUser | null> {
  if (!auth) {
    throw new Error('Firebase Auth is not initialized. Please configure VITE_FIREBASE_* keys.');
  }

  const cred: UserCredential = await signInWithPopup(auth, googleProvider);
  if (cred && cred.user) {
    const u = cred.user;
    const additionalInfo = getAdditionalUserInfo(cred);
    const isNewUser = Boolean(additionalInfo?.isNewUser);

    const authUser: AuthUser = {
      uid: u.uid,
      email: u.email,
      displayName: u.displayName || 'Google User',
      photoURL: u.photoURL,
      isDemo: false,
    };

    await recordLoginAuditLog(authUser, isNewUser);
    return authUser;
  }
  return null;
}

/**
 * Signs in using native Google Sign-In on mobile (Capacitor Android/iOS)
 * using an ID token passed to signInWithCredential.
 */
export async function signInWithGoogleNative(idToken: string): Promise<AuthUser | null> {
  if (!auth) {
    throw new Error('Firebase Auth is not initialized. Please configure VITE_FIREBASE_* keys.');
  }

  const credential = GoogleAuthProvider.credential(idToken);
  const cred: UserCredential = await signInWithCredential(auth, credential);
  if (cred && cred.user) {
    const u = cred.user;
    const additionalInfo = getAdditionalUserInfo(cred);
    const isNewUser = Boolean(additionalInfo?.isNewUser);

    const authUser: AuthUser = {
      uid: u.uid,
      email: u.email,
      displayName: u.displayName || 'Google User',
      photoURL: u.photoURL,
      isDemo: false,
    };

    await recordLoginAuditLog(authUser, isNewUser, 'Android Mobile');
    return authUser;
  }
  return null;
}

/**
 * Initiates real Google OAuth Redirect Sign-In
 * Redirects the browser window to accounts.google.com
 */
export async function signInWithGoogleRedirect(): Promise<void> {
  if (!auth) {
    throw new Error('Firebase Auth is not initialized. Please configure VITE_FIREBASE_* keys.');
  }
  await signInWithRedirect(auth, googleProvider);
}

/**
 * Handles redirect result on page load / app startup
 */
export async function handleGoogleRedirectResult(): Promise<{
  user: AuthUser;
  isNewUser: boolean;
  auditLog: LoginAuditLog;
} | null> {
  if (!auth) return null;

  try {
    const cred: UserCredential | null = await getRedirectResult(auth);
    if (!cred || !cred.user) return null;

    const u = cred.user;
    const additionalInfo = getAdditionalUserInfo(cred);
    const isNewUser = Boolean(additionalInfo?.isNewUser);

    const authUser: AuthUser = {
      uid: u.uid,
      email: u.email,
      displayName: u.displayName || 'Google User',
      photoURL: u.photoURL,
      isDemo: false,
    };

    // Record audit log both into Firestore and Backend Guardian
    const auditLog = await recordLoginAuditLog(authUser, isNewUser);

    return { user: authUser, isNewUser, auditLog };
  } catch (err) {
    console.warn('Error processing Google Redirect result:', err);
    throw err;
  }
}

/**
 * Centralized Login & Sign-Up Audit Logger
 * Inserts record into cloud Firestore collection 'login_audit_logs'
 * and mirrors to backend Guardian database
 */
export async function recordLoginAuditLog(
  user: AuthUser,
  isNewUser: boolean = false,
  customPlatform?: 'Windows Desktop' | 'Android Mobile' | 'Web Portal'
): Promise<LoginAuditLog> {
  const { login_date, login_time, iso_timestamp } = formatLoginDateTime();
  const platform = customPlatform || detectPlatform();

  const auditEntry: LoginAuditLog = {
    uid: user.uid,
    email: user.email || 'unknown@user.com',
    full_name: user.displayName || 'Google Operator',
    photo_url: user.photoURL || null,
    event_type: isNewUser ? 'NEW_ACCOUNT_SIGNUP' : 'USER_LOGIN',
    login_date,
    login_time,
    iso_timestamp,
    platform,
  };

  // 1. Cloud Firestore insertion (if connected) with safety timeout
  if (db) {
    try {
      const writePromise = addDoc(collection(db, 'login_audit_logs'), {
        ...auditEntry,
        created_at: serverTimestamp(),
      });
      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('Firestore write timeout')), 2000)
      );
      const docRef = await Promise.race([writePromise, timeoutPromise]);
      if (docRef?.id) {
        auditEntry.id = docRef.id;
      }
    } catch (cloudErr) {
      console.warn('Firestore cloud audit write notice:', cloudErr);
    }
  }

  // 2. Centralized SentinelGrid backend logging
  try {
    await api.logLoginAudit(auditEntry);
  } catch (backErr) {
    console.warn('Backend audit mirror warning:', backErr);
  }

  return auditEntry;
}

/**
 * Fetch all audit logs for the SuperAdmin (bmwm25320@gmail.com)
 * Tries cloud Firestore first, falls back to SentinelGrid backend guardian
 */
export async function fetchAuditLogs(adminEmail: string): Promise<LoginAuditLog[]> {
  if (adminEmail.toLowerCase() !== ADMIN_EMAIL.toLowerCase()) {
    throw new Error(`Unauthorized: Audit logs are restricted to SuperAdmin (${ADMIN_EMAIL})`);
  }

  // Try Firestore first
  if (db) {
    try {
      const q = query(collection(db, 'login_audit_logs'), orderBy('iso_timestamp', 'desc'), limit(150));
      const snap = await getDocs(q);
      const cloudLogs: LoginAuditLog[] = [];
      snap.forEach(docSnap => {
        const d = docSnap.data();
        cloudLogs.push({
          id: docSnap.id,
          uid: d.uid,
          email: d.email,
          full_name: d.full_name,
          photo_url: d.photo_url || null,
          event_type: d.event_type || 'USER_LOGIN',
          login_date: d.login_date,
          login_time: d.login_time,
          iso_timestamp: d.iso_timestamp,
          platform: d.platform,
        });
      });
      if (cloudLogs.length > 0) {
        return cloudLogs;
      }
    } catch (err) {
      console.warn('Firestore query failed, reading from SentinelGrid backend store:', err);
    }
  }

  // Fallback to backend API
  const res = await api.getAuditLogs(adminEmail);
  return res.logs;
}

/**
 * Re-authenticate the currently active Google user
 * Works on Desktop/Web via reauthenticateWithPopup and on Capacitor Android via SocialLogin
 */
export async function reauthenticateGoogleUser(
  currentUser: AuthUser | null
): Promise<{ success: boolean; email: string }> {
  // Demo or simulated user support
  if (!currentUser || currentUser.isDemo || !auth?.currentUser) {
    if (currentUser?.email) {
      return { success: true, email: currentUser.email };
    }
    throw new Error('No active authenticated user session found.');
  }

  // Capacitor Android platform
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
        throw new Error('Native Google authentication did not return an ID token.');
      }

      const credential = GoogleAuthProvider.credential(idToken);
      const res = await reauthenticateWithCredential(auth.currentUser, credential);
      const email = res.user.email || currentUser.email || '';
      return { success: true, email };
    } catch (err: any) {
      console.error('Native Google re-authentication error:', err);
      throw new Error(err.message || 'Google Native re-authentication failed.');
    }
  }

  // Desktop WebView2 & Web Browser
  try {
    const cred = await reauthenticateWithPopup(auth.currentUser, googleProvider);
    const email = cred.user.email || currentUser.email || '';
    return { success: true, email };
  } catch (err: any) {
    console.error('Google re-authentication popup error:', err);
    if (err?.code === 'auth/popup-closed-by-user' || err?.code === 'auth/cancelled-popup-request') {
      throw new Error('Google re-authentication was cancelled.');
    }
    throw new Error(err.message || 'Google re-authentication failed.');
  }
}

/**
 * Request a Vault PIN reset from the SuperAdmin (bmwm25320@gmail.com).
 * Writes a record to Firestore collection 'vault_pin_requests' with status 'pending'.
 */
export async function requestVaultPinReset(user: AuthUser): Promise<string> {
  const reqData: VaultPinResetRequest = {
    uid: user.uid,
    email: user.email || 'unknown@user.com',
    full_name: user.displayName || 'Security Operator',
    status: 'pending',
    requestedAt: new Date().toISOString(),
  };

  // Local storage fallback for offline / demo
  try {
    const localRequests: VaultPinResetRequest[] = JSON.parse(
      localStorage.getItem('sentinelgrid_vault_pin_requests') || '[]'
    );
    // Remove previous requests for this user
    const filtered = localRequests.filter((r) => r.uid !== user.uid);
    filtered.unshift(reqData);
    localStorage.setItem('sentinelgrid_vault_pin_requests', JSON.stringify(filtered));
  } catch {}

  if (db) {
    try {
      const docRef = await addDoc(collection(db, 'vault_pin_requests'), {
        ...reqData,
        created_at: serverTimestamp(),
      });
      return docRef.id;
    } catch (err) {
      console.warn('Firestore requestVaultPinReset failed, using local fallback:', err);
    }
  }
  return 'local_' + Date.now();
}

/**
 * Real-time listener for an active user's PIN reset request.
 * Fires callback when status changes to 'approved'.
 */
export function subscribeToUserPinResetRequest(
  uid: string,
  callback: (req: VaultPinResetRequest | null) => void
): () => void {
  let unsubFirestore: (() => void) | null = null;

  if (db) {
    try {
      const q = query(
        collection(db, 'vault_pin_requests'),
        where('uid', '==', uid)
      );
      unsubFirestore = onSnapshot(
        q,
        (snapshot) => {
          let latest: VaultPinResetRequest | null = null;
          snapshot.forEach((docSnap) => {
            const d = docSnap.data();
            const reqItem: VaultPinResetRequest = {
              id: docSnap.id,
              uid: d.uid,
              email: d.email,
              full_name: d.full_name,
              status: d.status || 'pending',
              requestedAt: d.requestedAt || '',
              approvedAt: d.approvedAt,
              approvedBy: d.approvedBy,
            };
            if (!latest || reqItem.requestedAt > latest.requestedAt) {
              latest = reqItem;
            }
          });
          if (latest) {
            callback(latest);
          }
        },
        (err) => {
          console.warn('Firestore PIN reset subscription warning:', err);
        }
      );
    } catch (e) {
      console.warn('subscribeToUserPinResetRequest init error:', e);
    }
  }

  // Also poll localStorage for demo / local testing sync across tabs
  const interval = setInterval(() => {
    try {
      const localRequests: VaultPinResetRequest[] = JSON.parse(
        localStorage.getItem('sentinelgrid_vault_pin_requests') || '[]'
      );
      const userReq = localRequests.find((r) => r.uid === uid);
      if (userReq) {
        callback(userReq);
      }
    } catch {}
  }, 2000);

  return () => {
    if (unsubFirestore) unsubFirestore();
    clearInterval(interval);
  };
}

/**
 * SuperAdmin real-time listener for pending PIN reset requests.
 */
export function subscribeToAllPinResetRequests(
  callback: (requests: VaultPinResetRequest[]) => void
): () => void {
  let unsubFirestore: (() => void) | null = null;

  if (db) {
    try {
      const q = query(collection(db, 'vault_pin_requests'));
      unsubFirestore = onSnapshot(
        q,
        (snapshot) => {
          const list: VaultPinResetRequest[] = [];
          snapshot.forEach((docSnap) => {
            const d = docSnap.data();
            list.push({
              id: docSnap.id,
              uid: d.uid,
              email: d.email,
              full_name: d.full_name,
              status: d.status || 'pending',
              requestedAt: d.requestedAt || '',
              approvedAt: d.approvedAt,
              approvedBy: d.approvedBy,
            });
          });
          list.sort((a, b) => (b.requestedAt || '').localeCompare(a.requestedAt || ''));
          callback(list);
        },
        (err) => {
          console.warn('Firestore all PIN reset requests subscription warning:', err);
        }
      );
    } catch (e) {
      console.warn('subscribeToAllPinResetRequests init error:', e);
    }
  }

  // Polling localStorage fallback
  const interval = setInterval(() => {
    try {
      const localRequests: VaultPinResetRequest[] = JSON.parse(
        localStorage.getItem('sentinelgrid_vault_pin_requests') || '[]'
      );
      if (localRequests.length > 0) {
        callback(localRequests);
      }
    } catch {}
  }, 2000);

  return () => {
    if (unsubFirestore) unsubFirestore();
    clearInterval(interval);
  };
}

/**
 * SuperAdmin approves a user's Vault PIN reset request.
 */
export async function approveVaultPinReset(
  requestId: string,
  userUid?: string
): Promise<void> {
  const adminEmail = ADMIN_EMAIL;
  // Update in localStorage fallback
  try {
    const localRequests: VaultPinResetRequest[] = JSON.parse(
      localStorage.getItem('sentinelgrid_vault_pin_requests') || '[]'
    );
    const updated = localRequests.map((r) => {
      if (r.id === requestId || r.uid === userUid || (!r.id && requestId.startsWith('local_'))) {
        return {
          ...r,
          status: 'approved' as const,
          approvedAt: new Date().toISOString(),
          approvedBy: adminEmail,
        };
      }
      return r;
    });
    localStorage.setItem('sentinelgrid_vault_pin_requests', JSON.stringify(updated));
  } catch {}

  // Update in Firestore
  if (db && !requestId.startsWith('local_')) {
    try {
      const ref = doc(db, 'vault_pin_requests', requestId);
      await updateDoc(ref, {
        status: 'approved',
        approvedAt: serverTimestamp(),
        approvedBy: adminEmail,
      });
    } catch (err) {
      console.warn('Firestore approveVaultPinReset warning:', err);
    }
  }
}

export {
  auth,
  db,
  fbSignOut,
  onAuthStateChanged,
  signInWithPopup,
  signInWithRedirect,
  signInWithCredential,
  reauthenticateWithPopup,
  reauthenticateWithCredential,
  GoogleAuthProvider,
  getAdditionalUserInfo
};


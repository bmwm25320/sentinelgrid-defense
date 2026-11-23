import { initializeApp, getApps, type FirebaseApp } from 'firebase/app';
import {
  getAuth,
  GoogleAuthProvider,
  signInWithRedirect,
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
  addDoc,
  getDocs,
  query,
  orderBy,
  limit,
  serverTimestamp,
  type Firestore
} from 'firebase/firestore';
import type { AuthUser, LoginAuditLog } from './types';
import { api } from './api';

export const ADMIN_EMAIL = 'bmwm25320@gmail.com';

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

  // 1. Cloud Firestore insertion (if connected)
  if (db) {
    try {
      const docRef = await addDoc(collection(db, 'login_audit_logs'), {
        ...auditEntry,
        created_at: serverTimestamp(),
      });
      auditEntry.id = docRef.id;
    } catch (cloudErr) {
      console.warn('Firestore cloud audit write warning:', cloudErr);
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

export { auth, db, fbSignOut, onAuthStateChanged };

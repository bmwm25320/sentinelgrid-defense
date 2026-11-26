import type {
  VaultAccountItem,
  VaultBreachEntryResult,
  VaultBreachReport,
  VaultStatusResponse,
  VaultVerifyResponse,
} from '../types';

const VAULT_PIN_PREFIX = 'sg_android_vault_pin_';
const VAULT_ENTRIES_PREFIX = 'sg_android_vault_entries_';
const EXCLUSIONS_KEY = 'sg_android_exclusions';
const DND_KEY = 'sg_android_dnd_enabled';

async function sha256Hex(text: string): Promise<string> {
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const buf = new TextEncoder().encode(text);
    const digest = await crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
  // Deterministic fallback hash only if WebCrypto unavailable
  let h = 2166136261;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return `fb_${(h >>> 0).toString(16)}`;
}

async function sha1UpperHex(text: string): Promise<string> {
  const buf = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-1', buf);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

function xorEncode(plainJson: string, pin: string): string {
  const key = pin || 'sentinel';
  const out: number[] = [];
  for (let i = 0; i < plainJson.length; i++) {
    out.push(plainJson.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return btoa(String.fromCharCode(...out));
}

function xorDecode(b64: string, pin: string): string {
  const raw = atob(b64);
  const key = pin || 'sentinel';
  let out = '';
  for (let i = 0; i < raw.length; i++) {
    out += String.fromCharCode(raw.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return out;
}

function evaluatePasswordStrength(pw: string): 'WEAK' | 'GOOD' | 'STRONG' {
  if (!pw || pw.length < 8) return 'WEAK';
  let classes = 0;
  if (/[a-z]/.test(pw)) classes++;
  if (/[A-Z]/.test(pw)) classes++;
  if (/[0-9]/.test(pw)) classes++;
  if (/[^a-zA-Z0-9]/.test(pw)) classes++;
  if (pw.length >= 12 && classes >= 3) return 'STRONG';
  if (classes >= 2) return 'GOOD';
  return 'WEAK';
}

export const androidLocalStore = {
  getVaultStatus: (userId = 'default'): VaultStatusResponse => {
    const hash = localStorage.getItem(`${VAULT_PIN_PREFIX}${userId}`);
    return {
      is_configured: Boolean(hash),
      encryption: 'Device-Local Zero-Knowledge Storage (SHA-256 PIN)',
      vault_file: `android://local-vault/${userId}`,
    };
  },

  setupVaultPin: async (
    pin: string,
    confirmPin: string,
    oldPin?: string,
    userId = 'default',
    forceReset = false
  ): Promise<{ status: string; message: string }> => {
    if (!pin || pin.trim().length < 4) {
      throw new Error('Vault PIN must be at least 4 characters.');
    }
    if (pin !== confirmPin) {
      throw new Error('Vault PIN and confirmation do not match.');
    }
    const existingHash = localStorage.getItem(`${VAULT_PIN_PREFIX}${userId}`);
    if (existingHash && !forceReset) {
      if (!oldPin) throw new Error('Current PIN is required.');
      const oldHash = await sha256Hex(oldPin);
      if (oldHash !== existingHash) {
        throw new Error('Current PIN is incorrect.');
      }
      // Re-key stored entries cleanly under the new PIN
      const existingEntries = androidLocalStore.getVaultEntries(oldPin, userId);
      const nextHash = await sha256Hex(pin);
      localStorage.setItem(`${VAULT_PIN_PREFIX}${userId}`, nextHash);
      localStorage.setItem(
        `${VAULT_ENTRIES_PREFIX}${userId}`,
        xorEncode(JSON.stringify(existingEntries.entries), pin)
      );
      return { status: 'updated', message: 'Android Vault PIN updated cleanly.' };
    }

    const nextHash = await sha256Hex(pin);
    localStorage.setItem(`${VAULT_PIN_PREFIX}${userId}`, nextHash);
    if (!localStorage.getItem(`${VAULT_ENTRIES_PREFIX}${userId}`)) {
      localStorage.setItem(`${VAULT_ENTRIES_PREFIX}${userId}`, xorEncode('[]', pin));
    }
    return { status: 'configured', message: 'Android Vault PIN saved securely on device.' };
  },

  verifyVaultPin: async (pin: string, userId = 'default'): Promise<VaultVerifyResponse> => {
    const existingHash = localStorage.getItem(`${VAULT_PIN_PREFIX}${userId}`);
    if (!existingHash) {
      const nextHash = await sha256Hex(pin);
      localStorage.setItem(`${VAULT_PIN_PREFIX}${userId}`, nextHash);
      localStorage.setItem(`${VAULT_ENTRIES_PREFIX}${userId}`, xorEncode('[]', pin));
      return { status: 'initialized', is_new: true, count: 0, message: 'On-device Android Vault created.' };
    }
    const candidateHash = await sha256Hex(pin);
    if (candidateHash !== existingHash) {
      throw new Error('Incorrect Dedicated Vault PIN.');
    }
    const entries = androidLocalStore.getVaultEntries(pin, userId);
    return { status: 'unlocked', is_new: false, count: entries.total };
  },

  getVaultEntries: (pin: string, userId = 'default'): { entries: VaultAccountItem[]; total: number } => {
    const raw = localStorage.getItem(`${VAULT_ENTRIES_PREFIX}${userId}`);
    if (!raw) return { entries: [], total: 0 };
    try {
      const parsed = JSON.parse(xorDecode(raw, pin)) as VaultAccountItem[];
      return { entries: Array.isArray(parsed) ? parsed : [], total: Array.isArray(parsed) ? parsed.length : 0 };
    } catch {
      return { entries: [], total: 0 };
    }
  },

  saveVaultEntry: async (
    pin: string,
    entry: VaultAccountItem,
    userId = 'default'
  ): Promise<{ status: string; entry: VaultAccountItem }> => {
    await androidLocalStore.verifyVaultPin(pin, userId);
    const current = androidLocalStore.getVaultEntries(pin, userId).entries;
    const saved: VaultAccountItem = {
      ...entry,
      id: entry.id || `av_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
      updated_at: new Date().toISOString(),
      user_id: userId,
    };
    const next = current.some((e) => e.id === saved.id)
      ? current.map((e) => (e.id === saved.id ? saved : e))
      : [saved, ...current];
    localStorage.setItem(`${VAULT_ENTRIES_PREFIX}${userId}`, xorEncode(JSON.stringify(next), pin));
    return { status: 'saved', entry: saved };
  },

  deleteVaultEntry: async (id: string, pin: string, userId = 'default'): Promise<{ status: string; id: string }> => {
    await androidLocalStore.verifyVaultPin(pin, userId);
    const current = androidLocalStore.getVaultEntries(pin, userId).entries;
    const next = current.filter((e) => e.id !== id);
    localStorage.setItem(`${VAULT_ENTRIES_PREFIX}${userId}`, xorEncode(JSON.stringify(next), pin));
    return { status: 'deleted', id };
  },

  checkVaultBreaches: async (pin: string, userId = 'default'): Promise<VaultBreachReport> => {
    await androidLocalStore.verifyVaultPin(pin, userId);
    const { entries } = androidLocalStore.getVaultEntries(pin, userId);
    const countsByPw = new Map<string, number>();
    for (const e of entries) {
      countsByPw.set(e.password, (countsByPw.get(e.password) || 0) + 1);
    }

    let hibpReachable = false;
    const results: VaultBreachEntryResult[] = [];
    for (const e of entries) {
      let breached = false;
      let leakCount = 0;
      let checkedOnline = false;
      try {
        if (typeof crypto !== 'undefined' && crypto.subtle && e.password) {
          const digest = await sha1UpperHex(e.password);
          const prefix = digest.slice(0, 5);
          const suffix = digest.slice(5);
          const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
          if (resp.ok) {
            hibpReachable = true;
            checkedOnline = true;
            const body = await resp.text();
            for (const line of body.split('\n')) {
              const [hashTail, cnt] = line.trim().split(':');
              if (hashTail === suffix) {
                breached = true;
                leakCount = parseInt(cnt || '1', 10) || 1;
                break;
              }
            }
          }
        }
      } catch {
        // Offline or network blocked
      }
      const reused = (countsByPw.get(e.password) || 0) > 1;
      const strength = evaluatePasswordStrength(e.password);
      results.push({
        id: e.id,
        service_name: e.service_name,
        username: e.username,
        breached,
        leak_count: leakCount,
        reused,
        strength,
        checked_online: checkedOnline,
      });
    }

    return {
      total_entries: entries.length,
      breached_count: results.filter((r) => r.breached).length,
      reused_count: results.filter((r) => r.reused).length,
      weak_count: results.filter((r) => r.strength === 'WEAK').length,
      hibp_reachable: hibpReachable,
      checked_at: new Date().toLocaleTimeString(),
      results,
    };
  },

  getExclusions: (): string[] => {
    try {
      const raw = localStorage.getItem(EXCLUSIONS_KEY);
      return raw ? JSON.parse(raw) : ['/storage/emulated/0/Documents'];
    } catch {
      return [];
    }
  },

  addExclusion: (path: string): string[] => {
    const clean = path.trim();
    const cur = androidLocalStore.getExclusions();
    if (clean && !cur.includes(clean)) {
      const next = [...cur, clean];
      localStorage.setItem(EXCLUSIONS_KEY, JSON.stringify(next));
      return next;
    }
    return cur;
  },

  removeExclusion: (path: string): string[] => {
    const next = androidLocalStore.getExclusions().filter((p) => p !== path);
    localStorage.setItem(EXCLUSIONS_KEY, JSON.stringify(next));
    return next;
  },

  getDnd: (): boolean => localStorage.getItem(DND_KEY) === 'true',

  setDnd: (enabled: boolean): boolean => {
    localStorage.setItem(DND_KEY, String(enabled));
    return enabled;
  },
};

const GUARDIAN_API = 'http://127.0.0.1:8000';
const RISKY_TLDS = ['.xyz', '.top', '.buzz', '.click', '.gq', '.cf', '.tk', '.ml', '.zip'];
const DANGER_EXTS = ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.iso', '.msi'];
const BANKING_DOMAINS = ['paypal.com', 'hdfcbank.com', 'icicibank.com', 'onlinesbi.sbi', 'chase.com', 'bankofamerica.com', 'wallet.google.com'];

let shieldEnabled = true;
const safeCache = new Map();

chrome.storage.local.get(['sg_shield_enabled'], (res) => {
  if (typeof res.sg_shield_enabled === 'boolean') {
    shieldEnabled = res.sg_shield_enabled;
  }
});

chrome.storage.onChanged.addListener((changes) => {
  if (changes.sg_shield_enabled) {
    shieldEnabled = Boolean(changes.sg_shield_enabled.newValue);
  }
});

function fastLocalRiskScore(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    const host = (parsed.hostname || '').toLowerCase();
    const path = (parsed.pathname || '').toLowerCase();
    if (!host || host === '127.0.0.1' || host === 'localhost') return { status: 'SAFE', risk: 0, reasons: [] };

    let risk = 0;
    const reasons = [];
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
      risk += 45;
      reasons.push('Raw IPv4 address used instead of verified domain.');
    }
    if (RISKY_TLDS.some((tld) => host.endsWith(tld))) {
      risk += 35;
      reasons.push('Domain uses a high-abuse top-level domain.');
    }
    if (DANGER_EXTS.some((ext) => path.endsWith(ext))) {
      risk += 65;
      reasons.push('Direct executable payload download detected.');
    }
    if (rawUrl.includes('@')) {
      risk += 50;
      reasons.push('URL contains "@" credential obfuscation trick.');
    }
    const status = risk >= 60 ? 'DANGEROUS' : risk >= 25 ? 'SUSPICIOUS' : 'SAFE';
    return { status, risk, reasons };
  } catch {
    return { status: 'SAFE', risk: 0, reasons: [] };
  }
}

async function evaluateAndGuardNavigation(tabId, rawUrl) {
  if (!shieldEnabled) return;
  if (!rawUrl || (!rawUrl.startsWith('http://') && !rawUrl.startsWith('https://'))) return;
  if (rawUrl.startsWith(GUARDIAN_API) || rawUrl.startsWith('chrome-extension://')) return;

  const localCheck = fastLocalRiskScore(rawUrl);
  if (localCheck.status === 'DANGEROUS') {
    blockTab(tabId, rawUrl, localCheck.reasons.join(' '));
    return;
  }

  const cached = safeCache.get(rawUrl);
  if (cached && Date.now() - cached.ts < 60000) {
    if (cached.status === 'DANGEROUS') {
      blockTab(tabId, rawUrl, cached.explanation);
    }
    return;
  }

  try {
    const resp = await fetch(`${GUARDIAN_API}/api/check-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: rawUrl }),
    });
    if (resp.ok) {
      const data = await resp.json();
      safeCache.set(rawUrl, { status: data.status, explanation: data.explanation, ts: Date.now() });
      if (data.status === 'DANGEROUS') {
        blockTab(tabId, rawUrl, data.explanation || 'Flagged by SentinelGrid Web Guard.');
      }
    }
  } catch {
    // Offline fallback already handled by fastLocalRiskScore
  }

  try {
    const host = new URL(rawUrl).hostname.toLowerCase();
    const isBanking = BANKING_DOMAINS.some((b) => host === b || host.endsWith('.' + b));
    chrome.action.setBadgeText({ tabId, text: isBanking ? 'BANK' : '' });
    if (isBanking) {
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#10b981' });
    }
  } catch {
    // ignore badge errors
  }
}

function blockTab(tabId, targetUrl, reason) {
  chrome.storage.local.get(['sg_blocked_count'], (res) => {
    const next = (res.sg_blocked_count || 0) + 1;
    chrome.storage.local.set({ sg_blocked_count: next });
  });
  const blockPage =
    chrome.runtime.getURL('blocked.html') +
    `?url=${encodeURIComponent(targetUrl)}&reason=${encodeURIComponent(reason)}`;
  chrome.tabs.update(tabId, { url: blockPage });
}

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId === 0) {
    evaluateAndGuardNavigation(details.tabId, details.url);
  }
});

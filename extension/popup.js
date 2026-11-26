const GUARDIAN_API = 'http://127.0.0.1:8000';

document.addEventListener('DOMContentLoaded', () => {
  const statusBadge = document.getElementById('statusBadge');
  const blockedCount = document.getElementById('blockedCount');
  const currentHost = document.getElementById('currentHost');
  const safeMoneyBtn = document.getElementById('safeMoneyBtn');
  const toggleBtn = document.getElementById('toggleBtn');

  let activeUrl = '';
  let enabled = true;

  function renderToggle() {
    statusBadge.textContent = enabled ? 'ACTIVE' : 'PAUSED';
    statusBadge.style.color = enabled ? '#34d399' : '#f87171';
    toggleBtn.textContent = enabled ? 'Pause Web Shield' : 'Resume Web Shield';
  }

  chrome.storage.local.get(['sg_shield_enabled', 'sg_blocked_count'], (res) => {
    if (typeof res.sg_shield_enabled === 'boolean') enabled = res.sg_shield_enabled;
    blockedCount.textContent = String(res.sg_blocked_count || 0);
    renderToggle();
  });

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0] && tabs[0].url) {
      activeUrl = tabs[0].url;
      try {
        currentHost.textContent = `Tab: ${new URL(activeUrl).hostname}`;
      } catch {
        currentHost.textContent = 'Protected local page';
      }
    }
  });

  toggleBtn.addEventListener('click', () => {
    enabled = !enabled;
    chrome.storage.local.set({ sg_shield_enabled: enabled }, renderToggle);
  });

  safeMoneyBtn.addEventListener('click', async () => {
    if (!activeUrl || !activeUrl.startsWith('http')) return;
    try {
      await fetch(`${GUARDIAN_API}/api/safemoney/launch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: activeUrl }),
      });
      safeMoneyBtn.textContent = 'Safe Money Window Launched!';
    } catch {
      safeMoneyBtn.textContent = 'Start SentinelGrid Desktop App first';
    }
  });
});

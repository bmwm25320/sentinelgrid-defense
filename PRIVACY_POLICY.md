# SentinelGrid Defense — Privacy Policy

**Effective Date:** November 27, 2026  
**Developer Contact:** `bmwm25320@gmail.com`  
**Package ID:** `com.sentinelgrid.defense`

SentinelGrid Defense is a personal endpoint security and mobile antivirus application designed to protect user devices locally with transparent permission usage.

## 1. Sensitive Permissions & Exact Purpose

- **`QUERY_ALL_PACKAGES` (Installed Apps Inventory):**  
  Used strictly on-device as SentinelGrid's core antivirus and anti-stalkerware scanner to audit installed apps for unknown installers, dangerous permission combinations (e.g., overlay + SMS interception), and hidden surveillance apps. The list of installed apps is **never** sold, shared with advertisers, or uploaded for profiling.
- **`BIND_NOTIFICATION_LISTENER_SERVICE` (Safe Messaging Shield):**  
  Opt-in permission used solely on-device to scan URLs inside incoming notifications for phishing links and APK dropper URLs. Notification body content is never stored off-device or sent to third parties.
- **`PACKAGE_USAGE_STATS` & `USE_BIOMETRIC` (Biometric App Lock):**  
  Opt-in feature used strictly locally to detect launches of user-selected protected apps and present the Android `BiometricPrompt` / PIN gate.
- **`SYSTEM_ALERT_WINDOW` (Display Over Other Apps):**  
  Opt-in permission used to show the user-triggered Always-On Gemini Co-Pilot security assistant overlay.
- **`ACCESS_FINE_LOCATION` / `ACCESS_COARSE_LOCATION` (Anti-Theft Locator):**  
  Accessed only when the user explicitly clicks **Locate GPS** inside Anti-Theft controls.

## 2. Password Vault, AI Assistant & Breach Checks

- **Local Password Vault:** Stored encrypted locally behind your Dedicated Vault PIN.
- **Dark Web Breach Audit:** Uses k-anonymity against Have I Been Pwned (`api.pwnedpasswords.com`), sending **only the first 5 characters of a SHA-1 hash**; plaintext passwords never leave the device.
- **Google Authentication:** Provided via Firebase Auth solely to identify your session and Admin Audit Log preferences.
- **Gemini AI Assistant:** Sends only the prompt you submit to Google Gemini API using your configured API key.

## 3. Data Deletion & Contact

Users can delete local Vault entries and clear notification alerts directly inside the app, uninstall SentinelGrid to remove all local storage, or email `bmwm25320@gmail.com` for account deletion requests.

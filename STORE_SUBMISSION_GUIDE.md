# SentinelGrid Defense — Store Publishing & Free Distribution Guide

This repository now builds **both** signed Release artifacts for app stores and free beta distribution:

- **Google Play Store App Bundle (`.aab`):** `frontend/android/app/build/outputs/bundle/release/app-release.aab`
- **Signed Release APK (Samsung Galaxy Store / Indus Appstore / Firebase):** `frontend/android/app/build/outputs/apk/release/app-release.apk`

## Signing Certificate Details (`sentinelgrid-release.keystore`)
- **Package ID:** `com.sentinelgrid.defense`
- **Key Alias:** `sentinelgrid`
- **SHA-1:** `7A:DA:0A:7E:D4:2B:4C:A8:44:AF:22:29:0D:AB:BF:72:77:F0:50:AA`
- **SHA-256:** `F2:7D:CD:1E:5D:EB:1A:99:6F:0C:F3:53:F4:7C:97:F5:CE:8A:57:89:43:07:23:07:89:AC:F6:F4:EB:1F:E3:33`

> Make sure both **SHA-1** and **SHA-256** above (and Play App Signing's SHA-1 once Google Play Console signs it) are added to **Firebase Console → Project Settings → Android App** so Google Sign-In works seamlessly inside store builds.

---

## Option 1 — Completely Free ($0): Samsung Galaxy Store & Indus Appstore

1. **Samsung Galaxy Store Seller Portal (Free signup, $0 listing):**
   - Sign in at `seller.samsungapps.com` and complete Seller identity verification.
   - Upload `frontend/android/app/build/outputs/apk/release/app-release.apk`.
   - Link your hosted Privacy Policy (`PRIVACY_POLICY.md` / GitHub URL / `/privacy-policy`).
   - Apps installed from Galaxy Store are store-trusted on Samsung devices, avoiding Samsung Auto Blocker sideload warnings.
2. **Indus Appstore (Free signup, $0 listing — India):**
   - Register at `indusappstore.com/developers` and upload the same signed `app-release.apk`.

---

## Option 2 — Completely Free ($0): Firebase App Distribution (Beta / Direct Users)

1. Open Firebase Console (`sentinelgrid-defense`) → **Build → App Distribution** → click **Get started** and add an Android app (`com.sentinelgrid.defense`) if not already listed.
2. Copy the **Android App ID** (`1:693966093694:android:...`).
3. Log into Firebase CLI once and run the included helper script:
   ```powershell
   npx firebase-tools login
   .\distribute_firebase.ps1 -FirebaseAppId "1:693966093694:android:YOUR_ANDROID_APP_ID" -Testers "tester@example.com"
   ```

---

## Option 3 — Google Play Store ($25 One-Time Fee)

1. Upload `frontend/android/app/build/outputs/bundle/release/app-release.aab` in **Google Play Console**.
2. **Permissions Declaration (`App content → Sensitive permissions`):**
   - **`QUERY_ALL_PACKAGES` Justification (copy-paste):**  
     *"SentinelGrid Defense is a dedicated mobile antivirus and anti-malware utility. Broad installed package visibility (`QUERY_ALL_PACKAGES`) is strictly required on-device for the core App & Stalkerware Scanner to inspect installed APKs for untrusted install sources, banking trojan overlay+SMS permission combinations, and hidden spyware without launcher icons. Package inventories are processed locally on-device and never shared or used for advertising."*
   - **YouTube/Drive Demo Video Checklist (15–30 seconds):**
     1. Open SentinelGrid Defense on a real Android phone.
     2. Navigate to **Virus & Threat Protection**.
     3. Tap **Scan Apps** inside **Android APK & Stalkerware Guard** and show the scanned package risk list appearing on screen.
3. **Closed Testing (New Personal Accounts):** Share your Play Console closed-test opt-in link with **12+ testers for 14 consecutive days**, then click **Apply for production**.

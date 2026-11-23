# SentinelGrid Defense // Cyber-HUD EDR & Antivirus

An open-source, full-stack **Endpoint Detection & Response (EDR) and Next-Generation Antivirus (NGAV)** application designed for real-time endpoint threat neutralization, ransomware canary tripwire defense, and AI-augmented incident forensics.

![SentinelGrid Defense HUD](https://img.shields.io/badge/Architecture-FastAPI%20%2B%20React%20%2B%20Tailwind-00F0FF?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-EF4444?style=for-the-badge)
![Latency](https://img.shields.io/badge/Reaction%20Latency-Sub--10ms-10B981?style=for-the-badge)

---

## 🏛️ System Architecture

SentinelGrid Defense implements a decoupled two-part security architecture:

```
techcarnival project/
├── backend/
│   ├── engine.py                 # FastAPI OS Guardian agent, Watchdog tripwire & PID Guillotine
│   ├── simulate_attack.py        # Safe standalone ransomware POC payload
│   ├── requirements.txt          # fastapi, uvicorn, watchdog, psutil, pydantic
│   ├── protected_zone/           # Auto-seeded sandbox repository with Canary Decoys
│   │   ├── !000_System_Key.docx  # Priority tripwire canary (alphabetically first)
│   │   ├── financial_report.pdf
│   │   ├── passwords_backup.txt
│   │   └── project_plans.docx
│   └── quarantine_vault/         # Cryptographically isolated vault with DoD 5220.22-M shredder
│       └── quarantine_index.json
└── frontend/
    ├── package.json              # React 19, TypeScript, Tailwind CSS, Lucide icons, @google/genai
    ├── vite.config.ts            # Vite dev server running on http://localhost:5173
    ├── tailwind.config.js        # Obsidian/Cyber aesthetic theme (#070B14, #00F0FF, #10B981, #EF4444)
    └── src/
        ├── App.tsx               # Cyber-HUD master container & 1.5s real-time telemetry polling
        ├── api.ts                # REST API client connecting to backend http://localhost:8000
        ├── types.ts              # Telemetry, Alert, Quarantine, and Config interfaces
        └── components/
            ├── Navbar.tsx            # Top status bar, DEFCON indicator, Armed Canary badge
            ├── TelemetryGauges.tsx   # Live Windows CPU %, RAM %, PID count, event counter
            ├── StageSimulator.tsx    # Red Team POC trigger panel (Ransomware, EICAR, Macro)
            ├── LiveLogTerminal.tsx   # Scrolling audit log terminal with auto-scroll & level filters
            ├── ThreatForensics.tsx   # Incident cards with MITRE TTPs & SHA-256 fingerprints
            ├── GeminiAnalystModal.tsx# Gemini AI + local heuristic root-cause & remediation report
            ├── QuarantineVault.tsx   # Quarantined threat table with Restore & DoD Shredding
            └── EngineConfig.tsx      # 4-Layer shield switches & ML Anomaly Threshold slider
```

---

## 🛡️ 4-Layer Cyber Defense Engine

| Layer | Engine Component | Target Attack Vector | MITRE ATT&CK TTP | Reaction Latency |
|---|---|---|---|---|
| **Layer 1** | **Static YARA & PE Entropy** | Pre-execution signatures, packed zero-day binaries | `MITRE T1027` (Obfuscated Files) | **~1.2 ms** |
| **Layer 2** | **Ransomware Canary & PID Guillotine** | Bulk filesystem encryption traversal | `MITRE T1486` (Data Encrypted for Impact) | **< 4 ms** |
| **Layer 3** | **Zero-Day ML Anomaly Threshold** | Process lineage anomalies (`WINWORD.EXE -> powershell.exe`) | `MITRE T1055` (Process Injection) | **~28 ms** |
| **Layer 4** | **Network C2 & BadUSB Guard** | Reverse beaconing & automated keystroke injection | `MITRE T1071` / `MITRE T1200` | Real-time Guard |

---

## ⚡ Quickstart Guide

### 1. Backend Agent (`localhost:8000`)
```powershell
# Navigate to backend
cd backend

# Install Python dependencies
pip install -r requirements.txt

# Launch FastAPI OS Guardian
python -m uvicorn engine:app --app-dir . --host 0.0.0.0 --port 8000
```

### 2. Frontend Cyber-HUD (`localhost:5173`)
```powershell
# Navigate to frontend
cd frontend

# Install npm dependencies
npm install

# Start Vite dev server
npm run dev
```

Visit **`http://localhost:5173`** to access the live dashboard.

---

## 🎯 Red Team Stage Simulator Demo

Click any of the 3 prominent buttons on the **Command Overview** to demonstrate autonomous neutralization live on stage:
1. **Launch Live Ransomware Attack:** Spawns `simulate_attack.py` as a real OS subprocess. As soon as it touches `!000_System_Key.docx`, SentinelGrid's Watchdog catches it in **< 4ms**, executes the PID Guillotine to terminate the process, restores the canary file, and quarantines the encrypted artifact.
2. **Trigger EICAR Signature Test:** Drops an industry-standard anti-malware verification string; Layer 1 Static YARA engine intercepts and moves it to the Quarantine Vault in **~1.2ms**.
3. **Simulate Macro Injection:** Generates an anomalous Office macro child interpreter; Layer 3 flags the process tree violation and terminates the child process.

---

## 🧠 Gemini AI Forensic Analyst

Click **"Analyze with Gemini AI"** on any threat card:
- Reads `VITE_GEMINI_API_KEY` from `frontend/.env` (or via the in-HUD API key input).
- Generates an executive root-cause breakdown, MITRE ATT&CK kill chain analysis, and SOC remediation playbook.
- If no API key is configured, seamlessly falls back to SentinelGrid's **Local Cyber Heuristics Engine** with comprehensive tactical forensics.

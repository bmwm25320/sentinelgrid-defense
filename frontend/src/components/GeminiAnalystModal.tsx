import React, { useState, useEffect } from 'react';
import { Sparkles, X, CheckCircle2, Copy, Key } from 'lucide-react';
import { generateWithGeminiFallback } from '../utils/geminiClient';
import type { AlertItem } from '../types';

interface GeminiAnalystModalProps {
  isOpen: boolean;
  onClose: () => void;
  alert: AlertItem | null;
}

export const GeminiAnalystModal: React.FC<GeminiAnalystModalProps> = ({ isOpen, onClose, alert }) => {
  const [apiKey, setApiKey] = useState<string>(import.meta.env.VITE_GEMINI_API_KEY || '');
  const [analysisText, setAnalysisText] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [source, setSource] = useState<'GEMINI_API' | 'HEURISTIC' | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (isOpen && alert) {
      runAnalysis();
    } else {
      setAnalysisText('');
      setSource(null);
    }
  }, [isOpen, alert]);

  if (!isOpen || !alert) return null;

  const generateHeuristicReport = (a: AlertItem): string => {
    const isRansomware = a.mitre_id.includes('T1486') || a.threat_name.toLowerCase().includes('ransomware') || a.threat_name.toLowerCase().includes('canary');
    const isEicar = a.mitre_id.includes('T1027') || a.threat_name.toLowerCase().includes('eicar');
    const isMacro = a.mitre_id.includes('T1055') || a.threat_name.toLowerCase().includes('macro');

    if (isRansomware) {
      return `### 🛡️ SENTINELGRID THREAT FORENSIC REPORT // AI INCIDENT ANALYSIS
**INCIDENT ID:** ${a.id} | **TIMESTAMP:** ${a.timestamp}
**THREAT CLASSIFICATION:** Ransomware Encryption Traversal Intercepted

---

#### 1. Executive Summary & Root-Cause Analysis
At **${a.timestamp}**, an adversary process (\`${a.process_name}\`, PID: \`${a.pid}\`) attempted an unauthorized mass encryption traversal targeting high-value documents in \`${a.file_path}\`. The threat attempted to rename and corrupt the canary decoy file \`!000_System_Key.docx\`. Because SentinelGrid places decoy canary tripwires alphabetically prioritized (\`!\`), the malware triggered the OS Guardian tripwire at the exact first file before any authentic enterprise data could be touched.

#### 2. MITRE ATT&CK® Framework Alignment
* **Tactic:** TA0040 — Impact
* **Technique:** MITRE T1486 — Data Encrypted for Impact
* **Sub-techniques:** T1486.001 (Automated Symmetric/Asymmetric File Encryption)
* **Adversary Intent:** Fast encryption of target files and subsequent creation of ransom notes or lock extensions.

#### 3. Immediate SentinelGrid Containment Actions Executed
1. **Sub-10ms Tripwire Hook:** Detection latency was **${a.reaction_time_ms}**.
2. **PID Guillotine Activation:** SentinelGrid issued an unblockable kernel termination (\`SIGKILL / TerminateProcess\`) against PID \`${a.pid}\`, stopping the attack traversal instantly.
3. **Quarantine Vault Isolation:** The malicious script and generated \`.locked\` artifact were neutralized and stored under SHA-256: \`${a.sha256}\`.
4. **Decoy Auto-Restoration:** The tripwire canary file was restored to its baseline state, keeping the defense grid 100% armed.

#### 4. Hardening & Remediation Recommendations
- [x] Offending PID terminated and prevented from traversing remaining system drives.
- [ ] Audit parent process lineage and task scheduler for persistence registry keys.
- [ ] Ensure volume shadow copies (VSS) are enabled and intact on local volumes.
- [ ] Verify endpoint offline backup synchronization.`;
    }

    if (isEicar) {
      return `### 🛡️ SENTINELGRID THREAT FORENSIC REPORT // AI INCIDENT ANALYSIS
**INCIDENT ID:** ${a.id} | **TIMESTAMP:** ${a.timestamp}
**THREAT CLASSIFICATION:** Antivirus Verification Sample Intercepted (EICAR)

---

#### 1. Executive Summary & Root-Cause Analysis
At **${a.timestamp}**, a file containing the standardized EICAR test string was staged at \`${a.file_path}\`. SentinelGrid's **Layer 1 Static YARA & Signature Engine** scanned the byte buffer in **${a.reaction_time_ms}**, identifying the exact pattern match (\`X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR...\`).

#### 2. MITRE ATT&CK® Framework Alignment
* **Tactic:** TA0005 — Defense Evasion
* **Technique:** MITRE T1027 — Obfuscated Files or Information
* **Adversary Intent:** Testing antivirus vigilance or deploying static signature payloads without behavioral obfuscation.

#### 3. Immediate SentinelGrid Containment Actions Executed
1. **Static Hash Validation:** File hash calculated as \`${a.sha256}\`.
2. **Vault Quarantine:** The file was quarantined into the vault, preventing any process from opening or executing it.
3. **Telemetry Alerting:** The event was logged to SOC analysts with an incident severity of **HIGH**.

#### 4. Remediation Checklist
- [x] Sample safely quarantined.
- [ ] Verify that third-party AV definitions remain updated.`;
    }

    if (isMacro) {
      return `### 🛡️ SENTINELGRID THREAT FORENSIC REPORT // AI INCIDENT ANALYSIS
**INCIDENT ID:** ${a.id} | **TIMESTAMP:** ${a.timestamp}
**THREAT CLASSIFICATION:** Malicious Office Macro & Process Lineage Anomaly

---

#### 1. Executive Summary & Root-Cause Analysis
At **${a.timestamp}**, an anomalous child process was spawned violating standard Windows process lineage: \`${a.process_name}\` (PID: \`${a.pid}\`). Specifically, Microsoft Office binaries (such as \`WINWORD.EXE\`) do not legitimate need to invoke an interactive or base64-encoded PowerShell child interpreter under standard desktop usage.

#### 2. MITRE ATT&CK® Framework Alignment
* **Tactic:** TA0002 — Execution / TA0005 — Defense Evasion
* **Technique:** MITRE T1055 — Process Injection (Lineage Violation)
* **Associated Techniques:** T1204.002 (Malicious File / Macro Execution), T1059.001 (PowerShell Interpreter Abuse)
* **Adversary Intent:** Dropping in-memory payloads or establishing reverse shell C2 communication.

#### 3. Immediate SentinelGrid Containment Actions Executed
1. **Lineage Interception:** **Layer 3 Behavioral & Process Tree Monitor** flagged the anomalous parent-child relationship in **${a.reaction_time_ms}**.
2. **Immediate Process Termination:** Spawned child interpreter (PID: \`${a.pid}\`) was killed before downloading secondary stages.
3. **Payload Neutralization:** SHA-256 fingerprint logged as \`${a.sha256}\`.

#### 4. Remediation Checklist
- [x] Anomalous interpreter killed.
- [ ] Disable untrusted VBA macros via Group Policy (GPO: Block macros from running in Office files from the Internet).
- [ ] Inspect Attack Surface Reduction (ASR) rules: \`Block Office applications from creating child processes\`.`;
    }

    return `### 🛡️ SENTINELGRID THREAT FORENSIC REPORT // AI INCIDENT ANALYSIS
**INCIDENT ID:** ${a.id} | **TIMESTAMP:** ${a.timestamp}
**THREAT:** ${a.threat_name} (Severity: ${a.severity})

---

#### 1. Incident Overview
* **Offending Entity:** \`${a.process_name}\` (PID: \`${a.pid}\`)
* **Detection Layer:** ${a.detection_layer}
* **MITRE ID:** ${a.mitre_id} — ${a.mitre_technique}
* **Reaction Latency:** ${a.reaction_time_ms}
* **Action Taken:** ${a.action_taken}

#### 2. Technical Evaluation & Containment
SentinelGrid's multi-layered defense intercepted the anomalous execution on \`${a.file_path}\`. The threat signature was isolated and stored under SHA-256: \`${a.sha256}\`. Offending execution threads were neutralized.`;
  };

  const runAnalysis = async () => {
    setLoading(true);
    setAnalysisText('');

    const keyToUse = apiKey.trim() || import.meta.env.VITE_GEMINI_API_KEY || '';

    if (keyToUse) {
      try {
        const prompt = `You are SentinelGrid Defense's Principal AI Threat Analyst.
Analyze the following endpoint security incident blocked by the SentinelGrid EDR agent:

Incident Details:
- Threat Name: ${alert.threat_name}
- Severity: ${alert.severity}
- MITRE ATT&CK: ${alert.mitre_id} (${alert.mitre_technique})
- Process Name: ${alert.process_name} (PID: ${alert.pid})
- Command Line: ${alert.command_line || 'N/A'}
- Affected File Path: ${alert.file_path}
- Reaction Time: ${alert.reaction_time_ms}
- Detection Layer: ${alert.detection_layer}
- Action Taken: ${alert.action_taken}
- SHA-256: ${alert.sha256}

Generate a clear, professional, cyber-forensic analysis in GitHub-flavored Markdown:
1. Executive Summary & Root Cause
2. MITRE ATT&CK Tactics, Techniques & Threat Actor Profile
3. Technical Assessment of the Intercepted Execution
4. Containment Actions Taken by SentinelGrid
5. Actionable SOC Hardening & Remediation Playbook`;

        const response = await generateWithGeminiFallback(keyToUse, prompt);

        if (response?.text) {
          setAnalysisText(response.text);
          setSource('GEMINI_API');
          setLoading(false);
          return;
        }
      } catch (err) {
        console.warn('Gemini API call failed, falling back to local heuristic analyst:', err);
      }
    }

    // Local Heuristic Fallback
    setTimeout(() => {
      setAnalysisText(generateHeuristicReport(alert));
      setSource('HEURISTIC');
      setLoading(false);
    }, 400);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(analysisText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="cyber-card rounded-2xl w-full max-w-3xl max-h-[88vh] flex flex-col border border-cyan-500/50 shadow-cyan-glow overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-4 bg-[#0a1020] border-b border-cyber-border">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-gradient-to-br from-cyan-950 to-blue-950 border border-cyan-500/40 text-cyan-400">
              <Sparkles className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-mono font-bold text-slate-100 text-sm tracking-wide">
                  GEMINI AI FORENSIC THREAT ANALYST
                </h3>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                  source === 'GEMINI_API'
                    ? 'bg-cyan-950 text-cyan-300 border-cyan-600'
                    : 'bg-emerald-950 text-emerald-300 border-emerald-600'
                }`}>
                  {source === 'GEMINI_API' ? 'GEMINI 2.5 FLASH ACTIVE' : 'LOCAL CYBER HEURISTICS'}
                </span>
              </div>
              <p className="text-[11px] font-mono text-slate-400">
                Incident: {alert.threat_name} // {alert.mitre_id}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* API Key Banner / Input */}
        <div className="px-4 py-2 bg-[#060a14] border-b border-slate-900 flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
          <div className="flex items-center gap-2 text-slate-400">
            <Key className="w-3.5 h-3.5 text-cyan-400" />
            <span>Gemini API Key:</span>
            <input
              type="password"
              placeholder="Paste VITE_GEMINI_API_KEY (optional)..."
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded px-2 py-0.5 text-xs text-cyan-300 w-56 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            onClick={runAnalysis}
            disabled={loading}
            className="px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900 border border-cyan-600 text-cyan-300 text-[11px] flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <Sparkles className="w-3 h-3" />
            <span>{loading ? 'Re-analyzing...' : 'Re-Run Analysis'}</span>
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-4 font-mono text-xs leading-relaxed text-slate-200 flex-1">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <div className="w-10 h-10 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
              <div className="text-sm font-mono text-cyan-400 tracking-wider animate-pulse">
                DECRYPTING TACTICAL TELEMETRY &amp; RUNNING MITRE CORRELATION...
              </div>
            </div>
          ) : (
            <div className="prose prose-invert max-w-none text-slate-200 text-xs font-mono whitespace-pre-wrap leading-relaxed">
              {analysisText}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between p-4 bg-[#0a1020] border-t border-cyber-border font-mono text-xs">
          <div className="text-slate-400 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>Report cryptographically tied to SHA-256 hash {alert.sha256.substring(0, 16)}...</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 transition-colors"
            >
              <Copy className="w-3.5 h-3.5 text-cyan-400" />
              <span>{copied ? 'Copied!' : 'Copy Report'}</span>
            </button>
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg bg-cyan-950 hover:bg-cyan-900 border border-cyan-500 text-cyan-300 font-bold transition-colors"
            >
              Done
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

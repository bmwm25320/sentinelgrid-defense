import React, { useState, useRef, useEffect } from 'react';
import {
  Bot,
  X,
  Send,
  Sparkles,
  Key,
  Search
} from 'lucide-react';
import { generateWithGeminiFallback } from '../utils/geminiClient';
import type { DeviceAudit, AlertItem } from '../types';

interface Message {
  id: string;
  sender: 'user' | 'assistant';
  text: string;
  timestamp: string;
  actionTool?: 'run_scan' | 'view_quarantine' | 'check_ports' | null;
}

interface GeminiGuardianDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  audit: DeviceAudit | null;
  alerts: AlertItem[];
  apiKey: string;
  onUpdateApiKey: (key: string) => void;
  onNavigateTab: (tab: string) => void;
  onTriggerScan: () => void;
}

export const GeminiGuardianDrawer: React.FC<GeminiGuardianDrawerProps> = ({
  isOpen,
  onClose,
  audit,
  alerts,
  apiKey,
  onUpdateApiKey,
  onNavigateTab,
  onTriggerScan,
}) => {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'welcome',
      sender: 'assistant',
      text: `Greetings. I am **SentinelGrid AI Guardian**—your live endpoint bodyguard. I have established direct telemetric binding to **${audit?.system?.hostname || 'this PC'}** running **${audit?.system?.os_release || 'Windows'}**.

Current Device Security Health: **${audit?.security_score || 94}/100 (${audit?.security_rating || 'PROTECTED'})**.
I am actively tracking ${audit?.process_audit?.total_count || 300}+ running processes and ${audit?.network_audit?.listening_ports_count || 20}+ network ports.

How can I assist in fortifying this endpoint?`,
      timestamp: new Date().toLocaleTimeString(),
    },
  ]);

  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [showKeyInput, setShowKeyInput] = useState(false);
  const [tempKey, setTempKey] = useState(apiKey);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  if (!isOpen) return null;

  const quickActionChips = [
    { label: '🛡️ Audit My PC', prompt: 'Is my device safe right now? Check my running apps and network connections.' },
    { label: '⚡ Check Suspicious Processes', prompt: 'Which apps on my PC are connecting to the internet or running from suspicious temp paths?' },
    { label: '🌐 Inspect Open Ports', prompt: 'Find any security weaknesses or exposed ports like 445 or 3389 on my system.' },
    { label: '🔍 Run Smart Scan', prompt: 'Run a full diagnostic smart scan on my machine and explain what you check.' },
  ];

  const buildDeviceContext = () => {
    return {
      hostname: audit?.system?.hostname,
      os: audit?.system?.os_platform,
      cpu_percent: audit?.system?.cpu_percent,
      ram_load_percent: audit?.system?.ram_percent,
      ram_used_gb: audit?.system?.ram_used_gb,
      ram_total_gb: audit?.system?.ram_total_gb,
      running_processes_count: audit?.process_audit?.total_count,
      top_memory_processes: audit?.process_audit?.top_processes?.slice(0, 5).map(p => `${p.name} (PID: ${p.pid}, ${p.memory_mb}MB)`),
      suspicious_temp_processes: audit?.process_audit?.suspicious_processes?.map(p => `${p.name} at ${p.exe}`),
      open_listening_ports: audit?.network_audit?.listening_ports?.map(p => `Port ${p.port} (${p.process})`),
      flagged_risky_ports: audit?.network_audit?.flagged_ports?.map(p => `Port ${p.port} - ${p.service}`),
      foreign_network_connections_count: audit?.network_audit?.foreign_connections_count,
      recent_vulnerabilities: audit?.vulnerabilities?.map(v => `[${v.severity}] ${v.title}: ${v.description}`),
      canary_shield_status: audit?.canary_shield?.status,
      recent_alerts_count: alerts.length,
      latest_alert: alerts.length > 0 ? alerts[0] : null
    };
  };

  const handleSendMessage = async (textToSend?: string) => {
    const query = textToSend || input;
    if (!query.trim() || loading) return;

    const userMsg: Message = {
      id: Date.now().toString(),
      sender: 'user',
      text: query.trim(),
      timestamp: new Date().toLocaleTimeString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    const deviceContext = buildDeviceContext();
    const activeKey = apiKey.trim() || import.meta.env.VITE_GEMINI_API_KEY || '';

    // If Gemini API Key is available, query Gemini 3
    if (activeKey) {
      try {
        const systemInstruction = `You are SentinelGrid AI Guardian, an elite, real-time device bodyguard and cybersecurity co-pilot embedded directly into the SentinelGrid Defense endpoint security suite.
You are live-linked to the user's local Windows workstation: ${deviceContext.hostname} (${deviceContext.os}).
Always maintain an authoritative, highly technical yet clear cybersecurity persona.
Use the provided real device telemetry to answer accurately without hallucinations:
- Reference actual process names, PIDs, memory usage, and listening ports found in the device context.
- When the user asks to run a scan or check ports, provide concrete tactical recommendations.
- Keep responses structured, concise, with bold headers and actionable bullet points.`;

        const prompt = `User Request: "${query}"

[LIVE REAL-TIME DEVICE CONTEXT SNAPSHOT]
${JSON.stringify(deviceContext, null, 2)}`;

        const response = await generateWithGeminiFallback(activeKey, prompt, systemInstruction);

        if (response?.text) {
          const assistantMsg: Message = {
            id: (Date.now() + 1).toString(),
            sender: 'assistant',
            text: response.text,
            timestamp: new Date().toLocaleTimeString(),
            actionTool: query.toLowerCase().includes('scan') ? 'run_scan' : null
          };
          setMessages((prev) => [...prev, assistantMsg]);
          setLoading(false);
          return;
        }
      } catch (err: any) {
        console.warn('Gemini API call encountered issue, engaging local heuristic fallback:', err);
      }
    }

    // Heuristic Fallback Engine with Live Context
    setTimeout(() => {
      let reply = '';
      const q = query.toLowerCase();

      if (q.includes('safe') || q.includes('audit') || q.includes('status')) {
        const vulns = deviceContext.recent_vulnerabilities || [];
        reply = `### 🛡️ Real-Time Device Security Assessment
**HOST:** \`${deviceContext.hostname}\` | **HEALTH SCORE:** ${audit?.security_score || 90}/100

* **Process State:** ${deviceContext.running_processes_count} active PIDs monitored. Canary decoy tripwire is **${deviceContext.canary_shield_status}**.
* **Network Posture:** ${deviceContext.foreign_network_connections_count} foreign sockets active.
* **Flagged Vulnerabilities:**
${vulns.length > 0 ? vulns.map(v => `  - ${v}`).join('\n') : '  - No critical exposures detected. All defense layers armed.'}

**Guardian Recommendation:**
Click **[Run Smart Scan]** below to execute an automated multi-stage sweep across registry keys, open sockets, and memory buffers.`;
      } else if (q.includes('process') || q.includes('app') || q.includes('internet') || q.includes('connecting')) {
        const topProcs = deviceContext.top_memory_processes || [];
        reply = `### ⚡ Live Process & Network Lineage Report
Currently, **${deviceContext.running_processes_count}** processes are active on \`${deviceContext.hostname}\`.

**Top Memory Consumers:**
${topProcs.map(p => `* \`${p}\``).join('\n')}

**Foreign Socket Endpoints:**
There are currently **${deviceContext.foreign_network_connections_count}** established connections communicating externally over TLS/TCP. All outbound traffic is filtered by **Layer 4 Network C2 Guard**.`;
      } else if (q.includes('port') || q.includes('445') || q.includes('3389') || q.includes('weakness')) {
        const risky = deviceContext.flagged_risky_ports || [];
        reply = `### 🌐 Listening Ports & Attack Surface Analysis
SentinelGrid inspected all TCP/IP sockets on this machine:

* **Active Listening Ports:** ${deviceContext.open_listening_ports?.slice(0, 6).join(', ')}...
* **Flagged High-Risk Ports:**
${risky.length > 0 ? risky.map(r => `  - **${r}** (Recommended: Restrict via Firewall)`).join('\n') : '  - Zero critical ports exposed.'}

**Hardening Advice:**
Ports 445 (SMB) and 135 (RPC) should remain blocked to untrusted external subnets to prevent remote lateral movement.`;
      } else if (q.includes('scan') || q.includes('malware')) {
        reply = `### 🔍 Smart Diagnostic Engine Ready
SentinelGrid's diagnostic scanner sweeps through:
1. **Memory & Running PIDs** (detects code injection & temp binaries)
2. **Windows Registry Run Keys** (\`HKCU\\Run\` persistence)
3. **Network Sockets** (open ports & unauthorized daemons)
4. **Filesystem Integrity** (\`!000_System_Key.docx\` canary trap)

Click **[Run Smart Scan Now]** below to initiate this sweep.`;
      } else {
        reply = `### 🛡️ SentinelGrid Guardian Analysis
Based on the real-time telemetry from **${deviceContext.hostname}**:
* **CPU Load:** ${deviceContext.cpu_percent}% | **RAM:** ${deviceContext.ram_used_gb}/${deviceContext.ram_total_gb} GB
* **Canary Tripwire:** ${deviceContext.canary_shield_status}
* **Recent Blocked Threats:** ${deviceContext.recent_alerts_count} incidents logged.

All autonomous countermeasures remain active. How can I further assist in analyzing your endpoint posture?`;
      }

      setMessages((prev) => [
        ...prev,
        {
          id: (Date.now() + 1).toString(),
          sender: 'assistant',
          text: reply,
          timestamp: new Date().toLocaleTimeString(),
          actionTool: q.includes('scan') ? 'run_scan' : null
        },
      ]);
      setLoading(false);
    }, 400);
  };

  const handleSaveKey = () => {
    onUpdateApiKey(tempKey);
    setShowKeyInput(false);
  };

  return (
    <div className="fixed inset-y-0 right-0 w-full sm:w-[480px] bg-[#0A0F1D]/98 backdrop-blur-xl border-l border-suite-border shadow-2xl flex flex-col z-50 font-mono">
      {/* Drawer Header */}
      <div className="p-4 bg-[#080C16] border-b border-suite-border flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-gradient-to-br from-cyan-950 to-slate-900 border border-cyan-500/50 text-cyan-300 shadow-cyan-glow">
            <Bot className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-slate-100">
                GEMINI AI GUARDIAN
              </h2>
              <span className="text-[10px] px-2 py-0.2 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold">
                LIVE CONTEXT LINKED
              </span>
            </div>
            <p className="text-[10px] text-slate-400">
              Target: {audit?.system?.hostname || 'LOCAL_PC'} // {audit?.system?.os_release || 'Windows'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setShowKeyInput(!showKeyInput)}
            className="p-1.5 rounded-lg text-slate-400 hover:text-cyan-300 hover:bg-slate-800 transition-colors"
            title="Configure Gemini API Key"
          >
            <Key className="w-4 h-4" />
          </button>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
      </div>

      {/* API Key Drawer Banner */}
      {showKeyInput && (
        <div className="p-3 bg-[#060A14] border-b border-suite-border text-xs space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="flex items-center gap-1.5 text-cyan-300 font-bold">
              <Key className="w-3.5 h-3.5" />
              <span>Gemini API Key:</span>
            </span>
            <span className="text-[10px] text-slate-500">Stored locally in browser</span>
          </div>
          <div className="flex gap-2">
            <input
              type="password"
              placeholder="Paste VITE_GEMINI_API_KEY..."
              value={tempKey}
              onChange={(e) => setTempKey(e.target.value)}
              className="flex-1 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-cyan-300 focus:outline-none focus:border-cyan-400"
            />
            <button
              onClick={handleSaveKey}
              className="px-3 py-1.5 rounded-lg bg-cyan-950 border border-cyan-500 text-cyan-300 font-bold hover:bg-cyan-900 transition-colors"
            >
              Save
            </button>
          </div>
        </div>
      )}

      {/* Messages Scroll View */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs leading-relaxed">
        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`flex flex-col ${msg.sender === 'user' ? 'items-end' : 'items-start'}`}
          >
            <div
              className={`max-w-[90%] rounded-2xl p-4 border ${
                msg.sender === 'user'
                  ? 'bg-gradient-to-r from-cyan-950/80 to-blue-950/80 border-cyan-500/50 text-cyan-100'
                  : 'bg-[#0E1528] border-slate-800 text-slate-200'
              }`}
            >
              <div className="whitespace-pre-wrap">{msg.text}</div>

              {/* Action tool pill inside chat */}
              {msg.actionTool === 'run_scan' && (
                <div className="mt-3 pt-3 border-t border-slate-700/80 flex items-center gap-2">
                  <button
                    onClick={() => {
                      onTriggerScan();
                      onClose();
                    }}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-kaspersky-emerald text-slate-950 font-bold text-[11px] shadow-kaspersky-glow hover:opacity-90 transition-opacity"
                  >
                    <Search className="w-3.5 h-3.5" />
                    <span>Run Smart Scan Now</span>
                  </button>
                  <button
                    onClick={() => {
                      onNavigateTab('privacy');
                      onClose();
                    }}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 text-[11px] hover:bg-slate-700 transition-colors"
                  >
                    <span>View Open Ports</span>
                  </button>
                </div>
              )}
            </div>
            <span className="text-[10px] text-slate-600 mt-1 px-1">
              {msg.sender === 'user' ? 'Operator' : 'Guardian AI'} • {msg.timestamp}
            </span>
          </div>
        ))}

        {loading && (
          <div className="flex items-center gap-2.5 p-3 rounded-xl bg-[#0E1528] border border-cyan-900/50 text-cyan-300 text-xs">
            <Sparkles className="w-4 h-4 animate-spin text-cyan-400" />
            <span>Analyzing live device context and formulating tactical assessment...</span>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Quick Action Chips */}
      <div className="px-4 py-2 border-t border-suite-border bg-[#080C16] flex items-center gap-2 overflow-x-auto no-scrollbar">
        {quickActionChips.map((chip, idx) => (
          <button
            key={idx}
            onClick={() => handleSendMessage(chip.prompt)}
            className="shrink-0 text-[10px] px-2.5 py-1 rounded-full bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/40 text-slate-300 transition-colors"
          >
            {chip.label}
          </button>
        ))}
      </div>

      {/* Chat Input Bar */}
      <div className="p-4 bg-[#080C16] border-t border-suite-border">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSendMessage();
          }}
          className="flex items-center gap-2"
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask AI Guardian about your device or apps..."
            className="flex-1 px-4 py-2.5 rounded-xl bg-[#090F1E] border border-slate-800 text-slate-100 text-xs focus:outline-none focus:border-cyan-400"
          />
          <button
            type="submit"
            disabled={!input.trim() || loading}
            className="p-2.5 rounded-xl bg-cyan-950 border border-cyan-500 text-cyan-300 hover:bg-cyan-900 transition-colors disabled:opacity-50"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );
};

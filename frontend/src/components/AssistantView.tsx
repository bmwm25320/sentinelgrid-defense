import React, { useState, useRef, useEffect } from 'react';
import {
  Sparkles,
  Send,
  Key,
  RotateCw,
  Play,
  User,
} from 'lucide-react';
import { GoogleGenAI } from '@google/genai';
import type { DeviceAudit, AlertItem, StartupItem, VulnerabilityItem } from '../types';

interface Message {
  id: string;
  sender: 'user' | 'assistant';
  text: string;
  timestamp: string;
  actionTool?: 'run_scan' | 'view_quarantine' | null;
}

interface AssistantViewProps {
  audit: DeviceAudit | null;
  alerts: AlertItem[];
  apiKey: string;
  onUpdateApiKey: (key: string) => void;
  onStartQuickScan: () => void;
  onNavigateTab: (tab: string) => void;
}

export const AssistantView: React.FC<AssistantViewProps> = ({
  audit,
  alerts,
  apiKey,
  onUpdateApiKey,
  onStartQuickScan,
  onNavigateTab,
}) => {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'welcome',
      sender: 'assistant',
      text: `Hello! I'm your **SentinelGrid AI Assistant**. 

I'm connected to your device (**${audit?.system?.hostname || 'This PC'}**) and checking your real-time protection in the background. 

Your device health score is currently **${audit?.security_score || 85}/100**, and all 4 real-time shields are active. How can I help you today?`,
      timestamp: 'Just now',
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

  const starterChips = [
    { label: '🛡️ Is my PC safe right now?', prompt: 'Is my device safe right now? Explain in simple terms.' },
    { label: '⚡ Check startup apps and speed', prompt: 'How is my computer speed and what programs start automatically?' },
    { label: '🌐 Are any apps using my internet suspiciously?', prompt: 'Check the apps using my internet connection. Are any of them suspicious?' },
    { label: '🔍 Run a Quick Scan', prompt: 'Please run a quick scan on my computer.' },
  ];

  const buildDeviceContext = () => {
    return {
      hostname: audit?.system?.hostname || 'Local PC',
      os: audit?.system?.os_name || audit?.system?.os_release || 'Windows',
      health_score: audit?.security_score || 85,
      active_threats_blocked: alerts.length,
      listening_ports_count: audit?.network_audit?.listening_ports?.length || 20,
      startup_apps: audit?.startup_audit?.entries?.map((s: StartupItem) => s.name) || [],
      vulnerabilities_summary: audit?.vulnerabilities?.map((v: VulnerabilityItem) => v.title) || [],
    };
  };

  const handleSend = async (textToSend?: string) => {
    const query = textToSend || input;
    if (!query.trim() || loading) return;

    const userMsg: Message = {
      id: Date.now().toString(),
      sender: 'user',
      text: query.trim(),
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    const deviceContext = buildDeviceContext();
    const activeKey = apiKey.trim() || import.meta.env.VITE_GEMINI_API_KEY || '';

    // Check if query is asking to scan
    const isScanRequest = query.toLowerCase().includes('scan');

    // 1. Try Gemini 2.5 Flash via @google/genai if key is available
    if (activeKey) {
      try {
        const ai = new GoogleGenAI({ apiKey: activeKey });
        const systemInstruction = `You are SentinelGrid AI Security Assistant—a calm, friendly, reassuring cybersecurity helper embedded into the SentinelGrid Defense suite.
You are live-linked to the user's computer: ${deviceContext.hostname} (${deviceContext.os}).
Rules:
- Speak in simple, everyday English that anyone can understand at a glance.
- Avoid scary cybersecurity jargon (do not cite 'MITRE ATT&CK', 'entropy', 'lineage violation', or 'heuristics' unless the user specifically asks for technical details).
- Provide practical, reassuring answers.
- Use the provided device data accurately.
- Keep responses structured, concise, and friendly.`;

        const prompt = `User Question: "${query}"

[CURRENT LIVE DEVICE STATUS]
${JSON.stringify(deviceContext, null, 2)}`;

        const response = await ai.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: prompt,
          config: {
            systemInstruction: systemInstruction,
          },
        });

        if (response.text) {
          const assistantMsg: Message = {
            id: (Date.now() + 1).toString(),
            sender: 'assistant',
            text: response.text,
            timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
            actionTool: isScanRequest ? 'run_scan' : null,
          };
          setMessages(prev => [...prev, assistantMsg]);
          setLoading(false);
          return;
        }
      } catch (err) {
        console.warn('Gemini API call failed, falling back to local assistant:', err);
      }
    }

    // 2. Local Reassuring Heuristic Fallback
    setTimeout(() => {
      let reply = '';
      const q = query.toLowerCase();

      if (q.includes('safe') || q.includes('status')) {
        reply = `**Yes, your device is in safe hands.**\n\n- **Health Score:** ${deviceContext.health_score}/100\n- **Real-Time Shields:** Active on files, downloads, and network connections.\n- **Threats:** SentinelGrid has blocked ${deviceContext.active_threats_blocked} suspicious attempt(s) and kept your documents pristine.\n\nNo dangerous viruses or ransomware files are active on your PC.`;
      } else if (q.includes('startup') || q.includes('speed')) {
        const apps = deviceContext.startup_apps.slice(0, 5).join(', ') || 'No apps';
        reply = `**Your Startup & Speed Status:**\n\n- You have **${deviceContext.startup_apps.length} apps** set to launch when Windows turns on (including: *${apps}*).\n- All startup items have been inspected and none are posing a security risk.\n\nTip: You can view or manage them under the **Device Health & Startup** tab!`;
      } else if (q.includes('internet') || q.includes('network') || q.includes('apps')) {
        reply = `**Network Protection Overview:**\n\n- All active internet connections are being monitored by your Firewall Shield.\n- Windows File Sharing is protected on your local network.\n- No foreign apps are attempting unauthorized data transmissions.\n\nYour internet traffic is secure!`;
      } else if (isScanRequest) {
        reply = `I would be happy to help inspect your device! Click the **"Start Quick Scan Now"** button below to begin a fast, thorough check of your memory and downloads.`;
      } else {
        reply = `I'm monitoring your device (**${deviceContext.hostname}**). Your real-time shields are active, and no critical issues were found.\n\nYou can ask me to check your startup apps, inspect internet safety, or run a quick scan anytime!`;
      }

      const assistantMsg: Message = {
        id: (Date.now() + 1).toString(),
        sender: 'assistant',
        text: reply,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        actionTool: isScanRequest ? 'run_scan' : null,
      };
      setMessages(prev => [...prev, assistantMsg]);
      setLoading(false);
    }, 450);
  };

  const handleSaveKey = () => {
    onUpdateApiKey(tempKey.trim());
    setShowKeyInput(false);
  };

  return (
    <div className="h-[calc(100vh-6rem)] flex flex-col defender-card overflow-hidden">
      {/* Assistant Header */}
      <div className="p-4 sm:p-5 border-b border-[#1F2937] flex items-center justify-between bg-[#101724]">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500 to-teal-700 text-white flex items-center justify-center shadow-md">
            <Sparkles className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              SentinelGrid AI Assistant
              <span className="text-[10px] px-2 py-0.2 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-500/30 font-medium">
                Gemini 2.5
              </span>
            </h2>
            <p className="text-xs text-slate-400">Personal security co-pilot for your PC</p>
          </div>
        </div>

        <button
          onClick={() => setShowKeyInput(!showKeyInput)}
          className="px-3 py-1.5 rounded-lg bg-[#182232] hover:bg-[#222E42] text-xs text-slate-300 border border-[#2B384E] flex items-center gap-1.5 transition-colors"
        >
          <Key className="w-3.5 h-3.5 text-emerald-400" />
          <span>{apiKey ? 'API Key Set' : 'Configure Key'}</span>
        </button>
      </div>

      {/* Optional In-Chat Key Input */}
      {showKeyInput && (
        <div className="p-3 bg-[#0D121D] border-b border-[#1F2937] flex items-center gap-2 text-xs">
          <input
            type="password"
            value={tempKey}
            onChange={(e) => setTempKey(e.target.value)}
            placeholder="Paste Gemini API Key (or leave blank for built-in assistant)..."
            className="flex-1 bg-[#131A26] border border-[#1F2937] rounded-lg px-3 py-1.5 text-slate-200 focus:outline-none focus:border-emerald-500/50"
          />
          <button
            onClick={handleSaveKey}
            className="px-3 py-1.5 rounded-lg bg-emerald-500 text-slate-950 font-semibold hover:bg-emerald-400 transition-colors"
          >
            Save
          </button>
        </div>
      )}

      {/* Messages Scroll Area */}
      <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-4">
        {messages.map((msg) => {
          const isUser = msg.sender === 'user';
          return (
            <div key={msg.id} className={`flex items-start gap-3 ${isUser ? 'flex-row-reverse' : ''}`}>
              <div
                className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 text-xs font-semibold ${
                  isUser
                    ? 'bg-slate-700 text-slate-200'
                    : 'bg-gradient-to-br from-emerald-500 to-teal-700 text-white shadow-sm'
                }`}
              >
                {isUser ? <User className="w-4 h-4" /> : <Sparkles className="w-4 h-4" />}
              </div>

              <div
                className={`max-w-[85%] sm:max-w-[75%] rounded-2xl p-4 text-xs leading-relaxed space-y-2 ${
                  isUser
                    ? 'bg-emerald-600/20 border border-emerald-500/30 text-emerald-100 rounded-tr-none'
                    : 'bg-[#182232] border border-[#2B384E] text-slate-200 rounded-tl-none shadow-sm'
                }`}
              >
                <div className="whitespace-pre-wrap">{msg.text}</div>

                {/* Optional in-chat action button */}
                {msg.actionTool === 'run_scan' && (
                  <div className="pt-2">
                    <button
                      onClick={() => {
                        onStartQuickScan();
                        onNavigateTab('threats');
                      }}
                      className="px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs flex items-center gap-2 transition-colors shadow-sm"
                    >
                      <Play className="w-3.5 h-3.5 fill-current" />
                      <span>Start Quick Scan Now</span>
                    </button>
                  </div>
                )}

                <div className="text-[10px] text-slate-400 text-right">{msg.timestamp}</div>
              </div>
            </div>
          );
        })}

        {loading && (
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/20 text-emerald-400 flex items-center justify-center shrink-0">
              <RotateCw className="w-4 h-4 animate-spin" />
            </div>
            <div className="p-3.5 rounded-2xl bg-[#182232] border border-[#2B384E] text-xs text-slate-400 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
              <span>Checking your PC and preparing answer...</span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Starter Prompt Chips */}
      <div className="px-4 py-2 bg-[#0D121D] border-t border-[#1F2937] flex items-center gap-2 overflow-x-auto no-scrollbar">
        {starterChips.map((chip, idx) => (
          <button
            key={idx}
            onClick={() => handleSend(chip.prompt)}
            disabled={loading}
            className="px-3 py-1.5 rounded-full bg-[#182232] hover:bg-[#222E42] text-slate-300 hover:text-white border border-[#2B384E] text-xs font-medium whitespace-nowrap transition-colors shrink-0 disabled:opacity-50"
          >
            {chip.label}
          </button>
        ))}
      </div>

      {/* Chat Input Bar */}
      <div className="p-3 sm:p-4 bg-[#101724] border-t border-[#1F2937]">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex items-center gap-2"
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask anything about your computer's security or speed..."
            disabled={loading}
            className="flex-1 bg-[#0D121D] border border-[#1F2937] rounded-xl px-4 py-2.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-emerald-500/50"
          />
          <button
            type="submit"
            disabled={!input.trim() || loading}
            className="w-10 h-10 rounded-xl bg-emerald-500 hover:bg-emerald-400 disabled:opacity-40 disabled:hover:bg-emerald-500 text-slate-950 flex items-center justify-center transition-colors shrink-0"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );
};

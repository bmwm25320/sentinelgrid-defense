import React, { useState, useEffect, useRef } from 'react';
import {
  Sparkles,
  X,
  Send,
  Play,
  CheckCircle2,
  RotateCw,
  Laptop,
  Smartphone,
  Minimize2,
  ShieldCheck,
} from 'lucide-react';
import { GoogleGenAI } from '@google/genai';
import { api } from '../api';
import type {
  GeminiContextState,
  GeminiTaskOption,
  DeviceAudit,
  AlertItem,
} from '../types';
import { SentinelDeviceGuard, isAndroidNativeApp } from '../plugins/sentinelDeviceGuard';

interface CopilotFeedItem {
  id: string;
  role: 'user' | 'assistant' | 'execution';
  text: string;
  options?: GeminiTaskOption[];
  executedOptionId?: string;
  timestamp: string;
}

interface GeminiBackgroundCopilotProps {
  audit: DeviceAudit | null;
  alerts: AlertItem[];
  apiKey: string;
  onNavigateTab: (tab: string) => void;
  onStartQuickScan: () => void;
  onDataUpdated: () => void;
}

export const GeminiBackgroundCopilot: React.FC<GeminiBackgroundCopilotProps> = ({
  audit,
  alerts,
  apiKey,
  onNavigateTab,
  onStartQuickScan,
  onDataUpdated,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [contextState, setContextState] = useState<GeminiContextState | null>(null);
  const lastSummonCounterRef = useRef<number>(0);

  // Android floating overlay bubble status
  const isAndroid = isAndroidNativeApp();
  const [androidOverlayActive, setAndroidOverlayActive] = useState(false);
  const [androidOverlayPerm, setAndroidOverlayPerm] = useState(false);

  const [input, setInput] = useState('');
  const [planning, setPlanning] = useState(false);
  const [executingOptId, setExecutingOptId] = useState<string | null>(null);
  const feedEndRef = useRef<HTMLDivElement>(null);

  const [feed, setFeed] = useState<CopilotFeedItem[]>([
    {
      id: 'init',
      role: 'assistant',
      text: 'Always-On Background Gemini Co-Pilot is watching your active app. Tell me any task you want done — I will give you clear options and execute whichever one you choose.',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);

  useEffect(() => {
    feedEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [feed, planning]);

  // Poll Windows active foreground context + Ctrl+Shift+G global hotkey summon signal
  useEffect(() => {
    if (isAndroid) {
      SentinelDeviceGuard.getOverlayStatus()
        .then((st) => {
          setAndroidOverlayPerm(st.hasOverlayPermission);
          setAndroidOverlayActive(st.serviceRunning);
        })
        .catch(() => {});
      return;
    }

    let mounted = true;
    const pollContext = async () => {
      try {
        const ctx = await api.getGeminiContext();
        if (!mounted) return;
        setContextState(ctx);
        if (ctx.summon_counter > lastSummonCounterRef.current) {
          if (lastSummonCounterRef.current > 0) {
            setIsOpen(true);
          }
          lastSummonCounterRef.current = ctx.summon_counter;
        }
      } catch {
        // Standalone mode
      }
    };

    pollContext();
    const timer = setInterval(pollContext, 2500);
    return () => {
      mounted = false;
      clearInterval(timer);
    };
  }, [isAndroid]);

  const handleToggleBackground = async () => {
    if (isAndroid) {
      try {
        const st = await SentinelDeviceGuard.getOverlayStatus();
        if (!st.hasOverlayPermission) {
          await SentinelDeviceGuard.requestOverlayPermission();
          return;
        }
        if (st.serviceRunning) {
          await SentinelDeviceGuard.stopBackgroundGemini();
          setAndroidOverlayActive(false);
        } else {
          await SentinelDeviceGuard.startBackgroundGemini({
            apiKey: apiKey.trim() || import.meta.env.VITE_GEMINI_API_KEY || '',
          });
          setAndroidOverlayActive(true);
        }
      } catch (err: any) {
        alert(`Overlay error: ${err.message}`);
      }
      return;
    }

    const nextEnabled = !(contextState?.background_enabled ?? true);
    try {
      const res = await api.setGeminiBackgroundMode(nextEnabled);
      setContextState((prev) =>
        prev ? { ...prev, background_enabled: res.background_enabled } : null
      );
    } catch {
      // ignore offline
    }
  };

  const clientSidePlanFallback = async (task: string): Promise<{ analysis: string; options: GeminiTaskOption[] }> => {
    const activeKey = apiKey.trim() || import.meta.env.VITE_GEMINI_API_KEY || '';
    if (activeKey) {
      try {
        const ai = new GoogleGenAI({ apiKey: activeKey });
        const prompt = `User task: "${task}". Device alerts: ${alerts.length}, Health Score: ${audit?.security_score ?? 90}/100.
Return ONLY valid JSON:
{"analysis":"short summary","options":[{"id":"opt_1","title":"action title","description":"what it does","impact":"SAFE|FAST|DEEP","action_type":"quick_scan|boost_ram|hardware_privacy_audit|scan_usb|navigate_tab","params":{}}]}`;
        const response = await ai.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: prompt,
        });
        const raw = (response.text || '').replace(/```json|```/g, '').trim();
        const parsed = JSON.parse(raw);
        if (parsed && Array.isArray(parsed.options) && parsed.options.length > 0) {
          return parsed;
        }
      } catch {
        // Fallback below
      }
    }

    const q = task.toLowerCase();
    if (isAndroid) {
      return {
        analysis: 'Gemini Android Co-Pilot prepared native security actions for your phone:',
        options: [
          {
            id: 'opt_and_apps',
            title: 'Scan Installed APKs & Stalkerware',
            description: 'Audits sideloaded apps & dangerous permissions via PackageManager.',
            impact: 'DEEP',
            action_type: 'android_scan_apps',
          },
          {
            id: 'opt_and_wifi',
            title: 'Check Mobile Wi-Fi & DNS Security',
            description: 'Detects public captive portals & Private DNS posture.',
            impact: 'FAST',
            action_type: 'android_check_wifi',
          },
          {
            id: 'opt_and_vault',
            title: 'Open Vault & Dark Web Audit',
            description: 'Check saved credentials for leaks.',
            impact: 'SAFE',
            action_type: 'navigate_tab',
            params: { tab: 'vault' },
          },
        ],
      };
    }

    return {
      analysis: q.includes('slow')
        ? 'I can speed up your system and inspect heavy processes. Pick an option:'
        : 'Select which action you want me to execute right now:',
      options: [
        {
          id: 'opt_scan',
          title: 'Run Smart Virus Scan',
          description: 'Scans memory, running apps & Downloads.',
          impact: 'DEEP',
          action_type: 'quick_scan',
        },
        {
          id: 'opt_ram',
          title: 'Boost & Clean RAM',
          description: 'Safely frees memory bloat without closing your work.',
          impact: 'FAST',
          action_type: 'boost_ram',
        },
        {
          id: 'opt_net',
          title: 'Open Firewall & Privacy Shield',
          description: 'Check Webcam/Mic & active connections.',
          impact: 'SAFE',
          action_type: 'navigate_tab',
          params: { tab: 'network' },
        },
      ],
    };
  };

  const handlePlanTask = async (taskOverride?: string) => {
    const taskText = (taskOverride ?? input).trim();
    if (!taskText || planning) return;

    const nowTime = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    setFeed((prev) => [
      ...prev,
      { id: `u_${Date.now()}`, role: 'user', text: taskText, timestamp: nowTime },
    ]);
    if (!taskOverride) setInput('');
    setPlanning(true);

    try {
      const activeKey = apiKey.trim() || import.meta.env.VITE_GEMINI_API_KEY || '';
      const activeApp = contextState?.last_external_app || contextState?.current_app || null;
      const plan = await api.planGeminiTask(taskText, activeKey, activeApp);
      setFeed((prev) => [
        ...prev,
        {
          id: `a_${Date.now()}`,
          role: 'assistant',
          text: plan.analysis,
          options: plan.options,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    } catch {
      const fallback = await clientSidePlanFallback(taskText);
      setFeed((prev) => [
        ...prev,
        {
          id: `a_${Date.now()}`,
          role: 'assistant',
          text: fallback.analysis,
          options: fallback.options,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    } finally {
      setPlanning(false);
    }
  };

  const handleExecuteOption = async (msgId: string, opt: GeminiTaskOption) => {
    setExecutingOptId(opt.id);
    const nowTime = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    try {
      let summary = '';
      if (opt.action_type === 'android_scan_apps' && isAndroid) {
        const res = await SentinelDeviceGuard.scanInstalledApps();
        summary = `Android APK Scan Complete: Security Score ${res.securityScore}/100 · ${res.userAppsCount} user apps checked · ${res.sideloadedCount} sideloaded · ${res.stalkerwareSuspects} stalkerware suspects.`;
      } else if (opt.action_type === 'android_check_wifi' && isAndroid) {
        const res = await SentinelDeviceGuard.inspectWifiSecurity();
        summary = `Android Network Check (${res.transport}): ${res.status} — ${res.advice}`;
      } else if (opt.action_type === 'navigate_tab') {
        const targetTab = String(opt.params?.tab || 'home');
        onNavigateTab(targetTab);
        summary = `Navigated directly to '${targetTab}' protection workspace.`;
      } else {
        const execRes = await api.executeGeminiOption(opt.id, opt.action_type, opt.params);
        summary = execRes.summary;
        if (execRes.navigate_to) {
          onNavigateTab(execRes.navigate_to);
        } else if (opt.action_type === 'quick_scan') {
          onStartQuickScan();
        }
        onDataUpdated();
      }

      setFeed((prev) =>
        prev
          .map((item) => (item.id === msgId ? { ...item, executedOptionId: opt.id } : item))
          .concat({
            id: `e_${Date.now()}`,
            role: 'execution',
            text: `Executed "${opt.title}": ${summary}`,
            timestamp: nowTime,
          })
      );
    } catch (err: any) {
      setFeed((prev) => [
        ...prev,
        {
          id: `e_${Date.now()}`,
          role: 'execution',
          text: `Action note for "${opt.title}": ${err.message}`,
          timestamp: nowTime,
        },
      ]);
    } finally {
      setExecutingOptId(null);
    }
  };

  const watchedApp =
    contextState?.last_external_app?.process_name ||
    contextState?.current_app?.process_name ||
    (isAndroid ? 'Android Apps' : 'Windows Desktop');

  return (
    <>
      {/* Persistent Always-On Floating Co-Pilot Orb (visible on EVERY tab) */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className="fixed bottom-5 right-5 z-40 group flex items-center gap-2.5 pl-3.5 pr-4 py-2.5 rounded-full bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 font-bold text-xs shadow-2xl shadow-emerald-500/30 border border-white/20 transition-all hover:scale-105 active:scale-95"
          title="Open Always-On Gemini Co-Pilot (Ctrl+Shift+G on Windows)"
        >
          <span className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-slate-950 opacity-60" />
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-slate-950" />
          </span>
          <Sparkles className="w-4 h-4" />
          <span>Gemini Co-Pilot</span>
          <span className="hidden sm:inline text-[10px] px-1.5 py-0.5 rounded-full bg-slate-950/20 font-mono">
            {isAndroid ? (androidOverlayActive ? 'OVERLAY ON' : 'MOBILE') : watchedApp}
          </span>
        </button>
      )}

      {/* Interactive Background Co-Pilot Drawer */}
      {isOpen && (
        <div className="fixed bottom-4 right-4 z-50 w-[calc(100vw-2rem)] sm:w-[440px] max-h-[82vh] bg-[#0B111E]/98 backdrop-blur-xl border border-emerald-500/40 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
          {/* Header */}
          <div className="p-3.5 bg-[#080D18] border-b border-[#1F2937] flex items-center justify-between gap-2">
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-emerald-500 to-cyan-500 text-slate-950 flex items-center justify-center shrink-0">
                <Sparkles className="w-4 h-4" />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-1.5">
                  <h3 className="text-xs font-bold text-white truncate">Gemini Background Co-Pilot</h3>
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-500/30 font-mono font-bold">
                    ALWAYS-ON
                  </span>
                </div>
                <p className="text-[10px] text-slate-400 truncate flex items-center gap-1">
                  {isAndroid ? <Smartphone className="w-3 h-3 text-cyan-400" /> : <Laptop className="w-3 h-3 text-cyan-400" />}
                  <span>
                    {isAndroid
                      ? androidOverlayActive
                        ? 'Cross-App Floating Bubble Active'
                        : 'Enable Floating Bubble for all apps'
                      : `Linked App: ${watchedApp} · Hotkey Ctrl+Shift+G`}
                  </span>
                </p>
              </div>
            </div>

            <div className="flex items-center gap-1 shrink-0">
              <button
                onClick={handleToggleBackground}
                className={`px-2 py-1 rounded-lg text-[10px] font-semibold border transition-colors ${
                  (isAndroid ? androidOverlayActive : contextState?.background_enabled ?? true)
                    ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40'
                    : 'bg-slate-800 text-slate-400 border-slate-700'
                }`}
                title={isAndroid ? 'Toggle Cross-App Floating Bubble' : 'Toggle Background App Watcher'}
              >
                {isAndroid
                  ? androidOverlayActive
                    ? 'Bubble ON'
                    : androidOverlayPerm
                    ? 'Start Bubble'
                    : 'Allow Overlay'
                  : (contextState?.background_enabled ?? true)
                  ? 'BG Active'
                  : 'BG Paused'}
              </button>
              <button
                onClick={() => setIsOpen(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
                title="Minimize Co-Pilot"
              >
                <Minimize2 className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => setIsOpen(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
                title="Close"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Conversation + Clickable Options Feed */}
          <div className="flex-1 overflow-y-auto p-3.5 space-y-3 min-h-[260px]">
            {feed.map((item) => (
              <div
                key={item.id}
                className={`flex flex-col ${item.role === 'user' ? 'items-end' : 'items-start'}`}
              >
                <div
                  className={`max-w-[92%] rounded-xl p-3 text-xs leading-relaxed ${
                    item.role === 'user'
                      ? 'bg-emerald-500/20 border border-emerald-500/30 text-emerald-100'
                      : item.role === 'execution'
                      ? 'bg-cyan-950/50 border border-cyan-500/40 text-cyan-200 flex items-start gap-2'
                      : 'bg-[#131B2B] border border-[#23314A] text-slate-200'
                  }`}
                >
                  {item.role === 'execution' && (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  )}
                  <div className="whitespace-pre-wrap">{item.text}</div>
                </div>

                {/* Clickable Options Returned by Gemini */}
                {item.options && item.options.length > 0 && (
                  <div className="w-full mt-2 space-y-1.5">
                    <div className="text-[10px] font-semibold text-cyan-400 uppercase tracking-wider px-1">
                      Choose an option to execute:
                    </div>
                    {item.options.map((opt) => {
                      const isRunningThis = executingOptId === opt.id;
                      const isDone = item.executedOptionId === opt.id;
                      return (
                        <button
                          key={opt.id}
                          onClick={() => handleExecuteOption(item.id, opt)}
                          disabled={Boolean(executingOptId)}
                          className={`w-full text-left p-2.5 rounded-xl border transition-all flex items-center justify-between gap-2 ${
                            isDone
                              ? 'bg-emerald-950/40 border-emerald-500/50'
                              : 'bg-[#0F172A] hover:bg-[#162238] border-[#26354E] hover:border-emerald-500/50'
                          }`}
                        >
                          <div className="min-w-0">
                            <div className="flex items-center gap-1.5">
                              <span className="text-xs font-semibold text-white truncate">
                                {opt.title}
                              </span>
                              <span className="text-[9px] px-1.5 py-0.2 rounded bg-slate-800 text-cyan-300 border border-slate-700 font-mono">
                                {opt.impact}
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-400 truncate mt-0.5">
                              {opt.description}
                            </p>
                          </div>
                          <span className="px-2.5 py-1 rounded-lg bg-emerald-500 text-slate-950 font-bold text-[10px] flex items-center gap-1 shrink-0">
                            {isRunningThis ? (
                              <RotateCw className="w-3 h-3 animate-spin" />
                            ) : isDone ? (
                              <ShieldCheck className="w-3 h-3" />
                            ) : (
                              <Play className="w-3 h-3 fill-current" />
                            )}
                            <span>{isRunningThis ? 'Working...' : isDone ? 'Ran' : 'Run'}</span>
                          </span>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            ))}

            {planning && (
              <div className="flex items-center gap-2 text-xs text-slate-400 p-2">
                <RotateCw className="w-3.5 h-3.5 animate-spin text-emerald-400" />
                <span>Gemini is analyzing task &amp; preparing options...</span>
              </div>
            )}
            <div ref={feedEndRef} />
          </div>

          {/* Quick Task Chips */}
          <div className="px-3 py-1.5 bg-[#090E18] border-t border-[#1F2937] flex items-center gap-1.5 overflow-x-auto">
            {[
              `Protect ${watchedApp}`,
              'PC feels slow boost RAM',
              'Check camera mic & Wi-Fi',
              'Scan USB & threats',
            ].map((preset) => (
              <button
                key={preset}
                onClick={() => handlePlanTask(preset)}
                disabled={planning}
                className="px-2.5 py-1 rounded-full bg-[#151F32] hover:bg-[#1E2C45] text-[10px] text-slate-300 border border-[#283854] whitespace-nowrap shrink-0"
              >
                {preset}
              </button>
            ))}
          </div>

          {/* Task Input Bar */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handlePlanTask();
            }}
            className="p-3 bg-[#080D18] border-t border-[#1F2937] flex items-center gap-2"
          >
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Tell Gemini any task to get options..."
              disabled={planning}
              className="flex-1 bg-[#111827] border border-[#1F2937] rounded-xl px-3 py-2 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-emerald-500/60"
            />
            <button
              type="submit"
              disabled={!input.trim() || planning}
              className="w-9 h-9 rounded-xl bg-emerald-500 hover:bg-emerald-400 disabled:opacity-40 text-slate-950 flex items-center justify-center shrink-0"
            >
              <Send className="w-4 h-4" />
            </button>
          </form>
        </div>
      )}
    </>
  );
};

import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Trash2, ArrowDownCircle, CheckCircle2 } from 'lucide-react';
import type { LogEntry } from '../types';
import { api } from '../api';

interface LiveLogTerminalProps {
  logs: LogEntry[];
  onLogsCleared: () => void;
}

export const LiveLogTerminal: React.FC<LiveLogTerminalProps> = ({ logs, onLogsCleared }) => {
  const [filter, setFilter] = useState<string>('ALL');
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const logContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (autoScroll && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const filteredLogs = logs.filter((log) => {
    if (filter === 'ALL') return true;
    return log.level === filter;
  });

  const getLevelBadge = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return <span className="text-red-400 font-bold bg-red-950/80 px-1.5 py-0.2 rounded border border-red-800">CRIT</span>;
      case 'WARNING':
        return <span className="text-amber-400 font-bold bg-amber-950/80 px-1.5 py-0.2 rounded border border-amber-800">WARN</span>;
      case 'SUCCESS':
        return <span className="text-emerald-400 font-bold bg-emerald-950/80 px-1.5 py-0.2 rounded border border-emerald-800">SUCC</span>;
      default:
        return <span className="text-cyan-400 font-bold bg-cyan-950/80 px-1.5 py-0.2 rounded border border-cyan-800">INFO</span>;
    }
  };

  const handleClear = async () => {
    try {
      await api.clearLogs();
      onLogsCleared();
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="cyber-card rounded-xl p-4 border border-cyan-900/40 flex flex-col h-[340px]">
      {/* Header bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 mb-3 pb-2 border-b border-cyber-border font-mono text-xs">
        <div className="flex items-center gap-2 text-slate-200">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span className="font-bold tracking-wider">LIVE GUARDIAN AUDIT LOG</span>
          <span className="text-slate-500">({filteredLogs.length} events)</span>
        </div>

        <div className="flex items-center gap-2">
          {/* Filters */}
          <div className="flex items-center gap-1 bg-slate-900/80 p-0.5 rounded border border-slate-800 text-[10px]">
            {['ALL', 'CRITICAL', 'WARNING', 'INFO', 'SUCCESS'].map((lvl) => (
              <button
                key={lvl}
                onClick={() => setFilter(lvl)}
                className={`px-2 py-0.5 rounded transition-colors ${
                  filter === lvl ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-700' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>

          {/* Autoscroll toggle */}
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`p-1 rounded text-[10px] flex items-center gap-1 border ${
              autoScroll ? 'bg-emerald-950/70 border-emerald-500/50 text-emerald-300' : 'bg-slate-900 border-slate-700 text-slate-400'
            }`}
            title="Auto-scroll"
          >
            <ArrowDownCircle className="w-3.5 h-3.5" />
            <span>AUTO</span>
          </button>

          {/* Clear button */}
          <button
            onClick={handleClear}
            className="p-1 rounded text-slate-400 hover:text-red-400 hover:bg-red-950/50 transition-colors"
            title="Clear logs"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Scrolling terminal window */}
      <div
        ref={logContainerRef}
        className="flex-1 overflow-y-auto space-y-1.5 font-mono text-[11px] p-2 bg-[#050811] rounded-lg border border-slate-900"
      >
        {filteredLogs.length === 0 ? (
          <div className="text-slate-600 text-center py-12 flex flex-col items-center gap-2">
            <CheckCircle2 className="w-6 h-6 text-slate-700" />
            <span>No log activity matching filter. System telemetry normal.</span>
          </div>
        ) : (
          filteredLogs.map((log, index) => (
            <div
              key={log.id || index}
              className="flex items-start gap-2.5 leading-relaxed hover:bg-slate-900/50 p-1 rounded transition-colors"
            >
              <span className="text-slate-600 select-none text-[10px] w-6 text-right">
                {index + 1}
              </span>
              <span className="text-slate-500 select-none text-[10px]">{log.timestamp}</span>
              <span>{getLevelBadge(log.level)}</span>
              <span className="text-cyan-300/80 font-semibold text-[10px] px-1 bg-slate-900 rounded">
                [{log.layer}]
              </span>
              <span
                className={`flex-1 break-all ${
                  log.level === 'CRITICAL'
                    ? 'text-red-300 font-semibold'
                    : log.level === 'WARNING'
                    ? 'text-amber-300'
                    : log.level === 'SUCCESS'
                    ? 'text-emerald-300'
                    : 'text-slate-300'
                }`}
              >
                {log.message}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

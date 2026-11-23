import React, { useState } from 'react';
import {
  Globe,
  Lock,
  Camera,
  Mic,
  Search
} from 'lucide-react';
import type { DeviceAudit } from '../types';

interface PrivacyViewProps {
  audit: DeviceAudit | null;
  onRefresh: () => void;
}

export const PrivacyView: React.FC<PrivacyViewProps> = ({ audit }) => {
  const [searchTerm, setSearchTerm] = useState('');

  const listeningPorts = audit?.network_audit?.listening_ports || [];
  const foreignConns = audit?.network_audit?.foreign_connections || [];

  const filteredForeign = foreignConns.filter(
    (c) =>
      c.process.toLowerCase().includes(searchTerm.toLowerCase()) ||
      c.remote_ip.includes(searchTerm) ||
      String(c.remote_port).includes(searchTerm)
  );

  return (
    <div className="space-y-6 font-mono">
      {/* Privacy & Hardware Shield Status Banner */}
      <div className="kaspersky-panel rounded-2xl p-6 border border-suite-border">
        <div className="flex items-center justify-between pb-4 mb-4 border-b border-suite-border">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-950 border border-cyan-500/40 text-cyan-400">
              <Lock className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-100">
                PRIVACY, WEBCAM &amp; NETWORK PORT FIREWALL
              </h2>
              <p className="text-xs text-slate-400">
                Active socket inspection, unauthorized remote listener detection, and hardware perimeter security
              </p>
            </div>
          </div>
          <span className="text-[10px] px-2.5 py-1 rounded bg-cyan-950 text-cyan-300 border border-cyan-600 font-bold">
            FIREWALL ACTIVE
          </span>
        </div>

        {/* 3 Privacy Guard Badges */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-3.5 rounded-xl bg-[#090F1E] border border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <Camera className="w-4 h-4 text-kaspersky-emerald" />
              <div>
                <div className="text-xs font-bold text-slate-200">Webcam Guard</div>
                <div className="text-[10px] text-slate-400">Unauthorized hook block</div>
              </div>
            </div>
            <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-kaspersky-emerald border border-emerald-500/40 font-bold">
              PROTECTED
            </span>
          </div>

          <div className="p-3.5 rounded-xl bg-[#090F1E] border border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <Mic className="w-4 h-4 text-kaspersky-emerald" />
              <div>
                <div className="text-xs font-bold text-slate-200">Microphone Shield</div>
                <div className="text-[10px] text-slate-400">Eavesdropping filter</div>
              </div>
            </div>
            <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-kaspersky-emerald border border-emerald-500/40 font-bold">
              ARMED
            </span>
          </div>

          <div className="p-3.5 rounded-xl bg-[#090F1E] border border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <Globe className="w-4 h-4 text-cyan-400" />
              <div>
                <div className="text-xs font-bold text-slate-200">Outbound C2 Filter</div>
                <div className="text-[10px] text-slate-400">Reverse shell intercept</div>
              </div>
            </div>
            <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-500/40 font-bold">
              BLOCKING C2
            </span>
          </div>
        </div>
      </div>

      {/* Open Listening Ports Auditor */}
      <div className="kaspersky-panel rounded-2xl p-6 border border-suite-border space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-suite-border">
          <div>
            <h3 className="text-base font-bold text-slate-100">
              OPEN LISTENING PORTS &amp; SERVICE ATTACK SURFACES
            </h3>
            <p className="text-xs text-slate-400">
              Local TCP/IP daemons bound in <code className="text-cyan-300">LISTEN</code> mode
            </p>
          </div>
          <span className="text-xs font-bold text-cyan-400">
            {listeningPorts.length} Ports Open
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
          {listeningPorts.map((lp) => (
            <div
              key={lp.port}
              className={`p-3 rounded-xl border text-xs space-y-1.5 transition-all ${
                lp.is_risky
                  ? 'bg-red-950/40 border-red-500 shadow-crimson-glow text-red-200'
                  : 'bg-[#090F1E] border-slate-800 text-slate-300'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-bold font-mono">Port {lp.port}</span>
                {lp.is_risky ? (
                  <span className="text-[9px] px-1.5 py-0.2 rounded bg-red-950 text-red-300 border border-red-500 font-bold animate-pulse">
                    RISK
                  </span>
                ) : (
                  <span className="text-[9px] px-1 py-0.2 rounded bg-slate-900 text-slate-500">
                    OK
                  </span>
                )}
              </div>
              <div className="text-[10px] text-slate-400 truncate" title={lp.process}>
                {lp.process}
              </div>
              {lp.is_risky && (
                <div className="text-[9px] text-red-400 font-semibold leading-tight">
                  {lp.risk_desc}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Outbound External / Foreign Network Connections */}
      <div className="kaspersky-panel rounded-2xl p-6 border border-suite-border space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-suite-border">
          <div>
            <h3 className="text-base font-bold text-slate-100">
              ACTIVE EXTERNAL NETWORK CONNECTIONS (FOREIGN ENDPOINTS)
            </h3>
            <p className="text-xs text-slate-400">
              Sockets actively communicating outside private local networks
            </p>
          </div>

          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-3" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search IP, process, port..."
              className="pl-8 pr-3 py-1.5 rounded-lg bg-[#090F1E] border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-400 w-56"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#090E1B] text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Process</th>
                <th className="py-2.5 px-3">Local Port</th>
                <th className="py-2.5 px-3">Remote IP</th>
                <th className="py-2.5 px-3">Remote Port</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Security Assessment</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-900 text-slate-300 text-[11px]">
              {filteredForeign.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-6 text-slate-500">
                    No foreign connections matching query.
                  </td>
                </tr>
              ) : (
                filteredForeign.map((conn, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/50 transition-colors">
                    <td className="py-2.5 px-3 font-bold text-slate-100">{conn.process}</td>
                    <td className="py-2.5 px-3 text-slate-400 font-mono">:{conn.local_port}</td>
                    <td className="py-2.5 px-3 text-cyan-300 font-bold font-mono">{conn.remote_ip}</td>
                    <td className="py-2.5 px-3 text-slate-400 font-mono">:{conn.remote_port}</td>
                    <td className="py-2.5 px-3">
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950 text-kaspersky-emerald border border-emerald-600 font-bold">
                        {conn.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-400">
                      {conn.remote_port === 443 ? 'Encrypted TLS Traffic' : conn.remote_port === 80 ? 'Plain HTTP' : 'Direct Socket'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

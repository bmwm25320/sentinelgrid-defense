import React from 'react';

export const CyberBackground: React.FC = () => {
  return (
    <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
      {/* Background Cyber Grid */}
      <div className="absolute inset-0 cyber-grid opacity-70" />

      {/* Cyber Scanlines */}
      <div className="absolute inset-0 cyber-scanlines opacity-40" />

      {/* Radial ambient glow orbs */}
      <div className="absolute -top-40 left-1/4 w-[600px] h-[600px] bg-cyan-500/5 rounded-full blur-[140px]" />
      <div className="absolute top-1/2 -right-40 w-[500px] h-[500px] bg-blue-600/5 rounded-full blur-[140px]" />
      <div className="absolute -bottom-40 left-1/3 w-[600px] h-[600px] bg-emerald-500/5 rounded-full blur-[150px]" />

      {/* Corner HUD framing elements */}
      <div className="absolute top-2 left-2 w-8 h-8 border-t-2 border-l-2 border-cyan-500/30" />
      <div className="absolute top-2 right-2 w-8 h-8 border-t-2 border-r-2 border-cyan-500/30" />
      <div className="absolute bottom-2 left-2 w-8 h-8 border-b-2 border-l-2 border-cyan-500/30" />
      <div className="absolute bottom-2 right-2 w-8 h-8 border-b-2 border-r-2 border-cyan-500/30" />
    </div>
  );
};

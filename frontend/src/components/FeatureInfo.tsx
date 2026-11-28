import React, { useState } from 'react';
import { Info, ChevronDown, ChevronUp } from 'lucide-react';

interface FeatureInfoProps {
  why: string;
  how: string;
  tone?: 'emerald' | 'cyan' | 'purple' | 'amber' | 'red' | 'slate';
  collapsible?: boolean;
  defaultOpen?: boolean;
  className?: string;
}

const TONE_CLASSES: Record<NonNullable<FeatureInfoProps['tone']>, string> = {
  emerald: 'bg-emerald-950/20 border-emerald-500/25 text-emerald-300',
  cyan: 'bg-cyan-950/20 border-cyan-500/25 text-cyan-300',
  purple: 'bg-purple-950/20 border-purple-500/25 text-purple-300',
  amber: 'bg-amber-950/20 border-amber-500/25 text-amber-300',
  red: 'bg-red-950/20 border-red-500/25 text-red-300',
  slate: 'bg-[#0B0F17]/80 border-[#1F2937] text-slate-300',
};

const ICON_CLASSES: Record<NonNullable<FeatureInfoProps['tone']>, string> = {
  emerald: 'text-emerald-400',
  cyan: 'text-cyan-400',
  purple: 'text-purple-400',
  amber: 'text-amber-400',
  red: 'text-red-400',
  slate: 'text-slate-400',
};

export const FeatureInfo: React.FC<FeatureInfoProps> = ({
  why,
  how,
  tone = 'slate',
  collapsible = false,
  defaultOpen = true,
  className = '',
}) => {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className={`rounded-xl border px-3.5 py-2.5 text-[11px] leading-relaxed ${TONE_CLASSES[tone]} ${className}`}>
      {collapsible ? (
        <>
          <button
            type="button"
            onClick={() => setOpen((prev) => !prev)}
            className="w-full flex items-center justify-between gap-2 text-left font-semibold text-slate-200 hover:text-white"
          >
            <span className="flex items-center gap-1.5">
              <Info className={`w-3.5 h-3.5 shrink-0 ${ICON_CLASSES[tone]}`} />
              <span>Why this exists &amp; how it works</span>
            </span>
            {open ? (
              <ChevronUp className="w-3.5 h-3.5 text-slate-400 shrink-0" />
            ) : (
              <ChevronDown className="w-3.5 h-3.5 text-slate-400 shrink-0" />
            )}
          </button>
          {open && (
            <div className="mt-2 pt-2 border-t border-white/10 space-y-1 text-slate-300">
              <div>
                <span className="font-semibold text-white">Why it&apos;s here: </span>
                <span>{why}</span>
              </div>
              <div>
                <span className="font-semibold text-white">How it works: </span>
                <span>{how}</span>
              </div>
            </div>
          )}
        </>
      ) : (
        <div className="flex items-start gap-2.5">
          <Info className={`w-3.5 h-3.5 shrink-0 mt-0.5 ${ICON_CLASSES[tone]}`} />
          <div className="space-y-1 text-slate-300">
            <div>
              <span className="font-semibold text-white">Why it&apos;s here: </span>
              <span>{why}</span>
            </div>
            <div>
              <span className="font-semibold text-white">How it works: </span>
              <span>{how}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

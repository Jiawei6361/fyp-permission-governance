import type { ReactNode } from "react";
import type { Classification, ReviewStatus } from "../types";

export function Spinner({ className = "h-4 w-4" }: { className?: string }) {
  return (
    <svg className={`animate-spin ${className}`} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeOpacity="0.25" strokeWidth="4" />
      <path d="M22 12a10 10 0 0 0-10-10" stroke="currentColor" strokeWidth="4" strokeLinecap="round" />
    </svg>
  );
}

type IconName = "shield" | "file" | "alert" | "flow" | "check" | "x" | "play" | "lock" | "sparkle" | "eye" | "undo";

const PATHS: Record<IconName, ReactNode> = {
  shield: <path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z" />,
  file: (
    <>
      <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5z" />
      <path d="M14 3v5h5" />
    </>
  ),
  alert: (
    <>
      <path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" />
      <path d="M12 9v4M12 17h.01" />
    </>
  ),
  flow: (
    <>
      <circle cx="6" cy="6" r="2.5" />
      <circle cx="18" cy="18" r="2.5" />
      <path d="M8.5 6H14a4 4 0 0 1 4 4v5.5" />
    </>
  ),
  check: <path d="M5 12.5l4.5 4.5L19 7.5" />,
  x: <path d="M6 6l12 12M18 6L6 18" />,
  play: <path d="M7 4.5v15l12-7.5-12-7.5z" />,
  lock: (
    <>
      <rect x="5" y="11" width="14" height="10" rx="2" />
      <path d="M8 11V8a4 4 0 0 1 8 0v3" />
    </>
  ),
  undo: (
    <>
      <path d="M9 14L4 9l5-5" />
      <path d="M4 9h10a6 6 0 0 1 0 12h-3" />
    </>
  ),
  sparkle: <path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8L12 3z" />,
  eye: (
    <>
      <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" />
      <circle cx="12" cy="12" r="3" />
    </>
  ),
};

export function Icon({ name, className = "h-4 w-4" }: { name: IconName; className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
         strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {PATHS[name]}
    </svg>
  );
}

const CLASS_STYLE: Record<Classification, { label: string; cls: string }> = {
  BREAKAGE_CRITICAL: { label: "Breakage-Critical", cls: "bg-red-50 text-red-700 ring-red-600/20" },
  SAFE_TO_REVOKE: { label: "Safe to Revoke", cls: "bg-emerald-50 text-emerald-700 ring-emerald-600/20" },
  KEEP_REQUIRED: { label: "Keep (Required)", cls: "bg-slate-100 text-slate-600 ring-slate-500/20" },
};

export function ClassificationBadge({ value }: { value: Classification }) {
  const s = CLASS_STYLE[value];
  return (
    <span className={`chip ${s.cls}`}>
      <Icon name={value === "BREAKAGE_CRITICAL" ? "lock" : value === "SAFE_TO_REVOKE" ? "check" : "shield"}
            className="h-3 w-3" />
      {s.label}
    </span>
  );
}

/** Mirrors backend scanner.risk_band: High >= 75, Medium >= 50 (overshare threshold). */
export function riskTone(score: number): string {
  if (score >= 75) return "bg-red-600 text-white";
  if (score >= 50) return "bg-amber-500 text-white";
  if (score > 0) return "bg-sky-600 text-white";
  return "bg-slate-200 text-slate-600";
}

export function RiskScore({ score, band, stacked = false }: { score: number; band: string; stacked?: boolean }) {
  return (
    <div className={`flex items-center ${stacked ? "flex-col gap-1" : "gap-2"}`} title={`Risk score ${score}/100 (${band})`}>
      <span className={`inline-flex h-9 w-11 items-center justify-center rounded-lg text-sm font-bold tabular-nums ${riskTone(score)}`}>
        {score}
      </span>
      <span className="text-xs font-medium text-slate-500">{band}</span>
    </div>
  );
}

export function SensitivityBadge({ label }: { label: string }) {
  const cls =
    label === "Highly Confidential" ? "bg-fuchsia-50 text-fuchsia-700 ring-fuchsia-600/20"
    : label === "Confidential" ? "bg-violet-50 text-violet-700 ring-violet-600/20"
    : "bg-slate-50 text-slate-600 ring-slate-500/20";
  return <span className={`chip ${cls}`}><Icon name="lock" className="h-3 w-3" />{label}</span>;
}

export function CopilotBadge({ indexed }: { indexed: boolean }) {
  return indexed ? (
    <span className="chip bg-indigo-50 text-indigo-700 ring-indigo-600/20" title="Indexed by Microsoft 365 Copilot">
      <Icon name="sparkle" className="h-3 w-3" />Copilot-indexed
    </span>
  ) : (
    <span className="chip bg-white text-slate-500 ring-slate-300">Not indexed</span>
  );
}

export function ReviewBadge({ status }: { status?: ReviewStatus }) {
  if (!status) return <span className="text-xs text-slate-400">Pending review</span>;
  const cls = status === "Keep Access"
    ? "bg-slate-100 text-slate-700 ring-slate-500/20"
    : "bg-emerald-50 text-emerald-700 ring-emerald-600/30";
  return <span className={`chip ${cls}`}><Icon name="check" className="h-3 w-3" />{status}</span>;
}

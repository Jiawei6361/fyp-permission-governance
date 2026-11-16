import { Icon } from "./ui";

export interface Kpis {
  filesScanned: number;
  permissionsScanned: number;
  oversharedFiles: number;
  oversharedPermissions: number;
  criticalFlows: string[];
  breakageCriticalPermissions: number;
  unknownDependencyPermissions: number;
  safeToRevoke: number;
}

interface CardProps {
  label: string;
  value: number | undefined;
  sub: string;
  icon: "file" | "alert" | "flow" | "check";
  accent: string;
}

function KpiCard({ label, value, sub, icon, accent }: CardProps) {
  return (
    <div className="card relative overflow-hidden p-5">
      <div className={`absolute inset-x-0 top-0 h-1 ${accent}`} />
      <div className="flex items-start justify-between gap-3">
        <p className="text-sm font-medium text-slate-500">{label}</p>
        <span className="rounded-lg bg-slate-100 p-2 text-slate-600"><Icon name={icon} className="h-4 w-4" /></span>
      </div>
      <p className="mt-2 text-3xl font-semibold tabular-nums tracking-tight text-slate-900">
        {value === undefined ? <span className="text-slate-300">—</span> : value}
      </p>
      <p className="mt-1 text-xs text-slate-500">{sub}</p>
    </div>
  );
}

export function KpiBar({ kpis }: { kpis: Kpis | null }) {
  const k = kpis ?? undefined;
  return (
    <section aria-label="Key metrics" className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <KpiCard label="Total Files Scanned" value={k?.filesScanned} icon="file" accent="bg-slate-400"
               sub={k ? `${k.permissionsScanned} Graph permissions evaluated` : "Run a scan to populate"} />
      <KpiCard label="Overshared Files Detected" value={k?.oversharedFiles} icon="alert" accent="bg-amber-500"
               sub={k ? `${k.oversharedPermissions} broad grants (anonymous / org-wide links)` : "Awaiting scan"} />
      <KpiCard label="Critical Power Automate Flows Protected" value={k?.criticalFlows.length} icon="flow"
               accent="bg-red-500"
               sub={k ? `${k.breakageCriticalPermissions} BREAKAGE_CRITICAL permissions held back` +
                 (k.unknownDependencyPermissions ? `, ${k.unknownDependencyPermissions} more as UNKNOWN_DEPENDENCY` : "")
                 : "Awaiting scan"} />
      <KpiCard label="Safe-to-Revoke Stale Permissions" value={k?.safeToRevoke} icon="check" accent="bg-emerald-500"
               sub={k ? "SAFE_TO_REVOKE: no dependent workflow" : "Awaiting scan"} />
    </section>
  );
}

import { Fragment, useMemo, useState } from "react";
import type { AssessmentOut, Classification, ManagerCard, ReviewStatus, ViewRole } from "../types";
import {
  ClassificationBadge, CopilotBadge, Icon, ReviewBadge, RiskScore, SensitivityBadge, riskTone,
} from "./ui";

export type FilterTab = "all" | "BREAKAGE_CRITICAL" | "SAFE_TO_REVOKE";

interface Props {
  role: ViewRole;
  onRoleChange: (r: ViewRole) => void;
  adminItems: AssessmentOut[];
  managerItems: ManagerCard[];
  reviews: Record<number, ReviewStatus>;
  onReview: (id: number, status: ReviewStatus) => void;
  onPreview: (id: number) => void;
}

/** A "finding" is anything the engine flags for revocation; KEEP_REQUIRED is retained access. */
const isFinding = (c: Classification) => c !== "KEEP_REQUIRED";

function matches(tab: FilterTab, c: Classification, includeRetained: boolean) {
  if (tab === "all") return includeRetained || isFinding(c);
  return c === tab;
}

export function FindingsView(props: Props) {
  const { role, onRoleChange, adminItems, managerItems } = props;
  const [tab, setTab] = useState<FilterTab>("all");
  const [includeRetained, setIncludeRetained] = useState(false);

  const source: { classification: Classification }[] = role === "admin" ? adminItems : managerItems;
  const counts = useMemo(() => ({
    all: source.filter((i) => isFinding(i.classification)).length,
    BREAKAGE_CRITICAL: source.filter((i) => i.classification === "BREAKAGE_CRITICAL").length,
    SAFE_TO_REVOKE: source.filter((i) => i.classification === "SAFE_TO_REVOKE").length,
    retained: source.filter((i) => i.classification === "KEEP_REQUIRED").length,
  }), [source]);

  const tabs: { id: FilterTab; label: string }[] = [
    { id: "all", label: "All Findings" },
    { id: "BREAKAGE_CRITICAL", label: "Breakage-Critical (Blocked)" },
    { id: "SAFE_TO_REVOKE", label: "Safe to Revoke" },
  ];

  return (
    <section className="space-y-4">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <RoleToggle role={role} onChange={onRoleChange} />
        <div className="flex flex-wrap items-center gap-3">
          <nav className="flex flex-wrap gap-1 rounded-lg bg-slate-100 p-1" aria-label="Finding filters">
            {tabs.map((t) => (
              <button key={t.id} onClick={() => setTab(t.id)} aria-pressed={tab === t.id}
                      className={`flex items-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium transition ${
                        tab === t.id ? "bg-white text-slate-900 shadow-sm" : "text-slate-600 hover:text-slate-900"}`}>
                {t.label}
                <span className={`rounded-full px-1.5 text-xs tabular-nums ${
                  t.id === "BREAKAGE_CRITICAL" ? "bg-red-100 text-red-700"
                  : t.id === "SAFE_TO_REVOKE" ? "bg-emerald-100 text-emerald-700" : "bg-slate-200 text-slate-700"}`}>
                  {counts[t.id]}
                </span>
              </button>
            ))}
          </nav>
          {tab === "all" && (
            <label className="flex items-center gap-2 text-sm text-slate-600">
              <input type="checkbox" className="h-4 w-4 rounded border-slate-300 text-indigo-600"
                     checked={includeRetained} onChange={(e) => setIncludeRetained(e.target.checked)} />
              Include retained access ({counts.retained})
            </label>
          )}
        </div>
      </div>

      {role === "admin"
        ? <AdminTable {...props} items={adminItems.filter((i) => matches(tab, i.classification, includeRetained))} />
        : <ManagerGrid {...props} items={managerItems.filter((i) => matches(tab, i.classification, includeRetained))} />}
    </section>
  );
}

function RoleToggle({ role, onChange }: { role: ViewRole; onChange: (r: ViewRole) => void }) {
  const opts: { id: ViewRole; label: string; hint: string }[] = [
    { id: "admin", label: "IT Security Admin", hint: "Graph facets, scores, flow IDs" },
    { id: "manager", label: "Business Manager", hint: "Plain-language review" },
  ];
  return (
    <div role="radiogroup" aria-label="Governance view" className="inline-flex rounded-xl border border-slate-200 bg-white p-1 shadow-sm">
      {opts.map((o) => (
        <button key={o.id} role="radio" aria-checked={role === o.id} onClick={() => onChange(o.id)}
                className={`rounded-lg px-4 py-2 text-left transition ${
                  role === o.id ? "bg-slate-900 text-white" : "text-slate-600 hover:bg-slate-50"}`}>
          <span className="block text-sm font-semibold">{o.label}</span>
          <span className={`block text-xs ${role === o.id ? "text-slate-300" : "text-slate-400"}`}>{o.hint}</span>
        </button>
      ))}
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return <div className="card p-10 text-center text-sm text-slate-500">{text}</div>;
}

// ------------------------------------------------------------------ IT Security Admin view
/** Rebuilds the Graph v1.0 permission facets that drove the score (link.scope, grantedToV2, inheritedFrom). */
export function graphFacets(a: AssessmentOut): Record<string, unknown> {
  const identity = { id: a.principal_id, displayName: a.principal_display };
  const grantedToV2 =
    a.principal_type === "link" ? null
    : a.principal_type === "user" ? { user: identity }
    : a.principal_type === "group" ? { group: identity }
    : { siteUser: identity };
  return {
    id: a.permission_id,
    roles: a.roles,
    link: a.link_scope ? { scope: a.link_scope } : null,
    grantedToV2,
    inheritedFrom: a.inherited_from ? { driveId: a.drive_id, id: "root", path: a.inherited_from } : null,
  };
}

function AdminTable({ items, reviews, onPreview }: Props & { items: AssessmentOut[] }) {
  const [open, setOpen] = useState<number | null>(null);
  if (!items.length) return <Empty text="No assessments match this filter." />;
  return (
    <div className="card overflow-hidden">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-slate-200 text-sm">
          <thead className="bg-slate-50 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-4 py-3">Risk</th>
              <th className="px-4 py-3">File</th>
              <th className="px-4 py-3">Exposure (Graph v1.0)</th>
              <th className="px-4 py-3">Labels</th>
              <th className="px-4 py-3">Dependent flows</th>
              <th className="px-4 py-3 text-right">Classification &amp; actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {items.map((a) => {
              const expanded = open === a.id;
              return (
                <Fragment key={a.id}>
                  <tr className={`align-top ${expanded ? "bg-slate-50" : "hover:bg-slate-50/60"}`}>
                    <td className="px-4 py-3"><RiskScore score={a.risk_score} band={a.risk_band} stacked /></td>
                    <td className="max-w-[14rem] px-4 py-3">
                      <p className="font-medium text-slate-900">{a.file_name}</p>
                      <p className="truncate font-mono text-xs text-slate-500" title={a.file_path}>{a.file_path}</p>
                    </td>
                    <td className="px-4 py-3">
                      <dl className="grid min-w-[15rem] grid-cols-[auto_1fr] gap-x-2 gap-y-0.5 font-mono text-xs">
                        <dt className="text-slate-400">link.scope</dt>
                        <dd className={a.link_scope ? "font-semibold text-red-700" : "text-slate-400"}>{a.link_scope ?? "—"}</dd>
                        <dt className="text-slate-400">grantedToV2</dt>
                        <dd className="text-slate-800">{a.principal_type === "link" ? <span className="text-slate-400">—</span> : a.principal_display}</dd>
                        <dt className="text-slate-400">inheritedFrom</dt>
                        <dd className="text-slate-800">{a.inherited_from ?? <span className="text-slate-400">— (direct)</span>}</dd>
                        <dt className="text-slate-400">roles</dt>
                        <dd className="text-slate-800">{a.roles.join(", ")}</dd>
                      </dl>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-col items-start gap-1">
                        <SensitivityBadge label={a.sensitivity_label} />
                        <CopilotBadge indexed={a.is_copilot_indexed} />
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      {a.dependent_flows.length === 0 ? <span className="text-xs text-slate-400">None</span> : (
                        <ul className="space-y-1">
                          {a.dependent_flows.map((d) => (
                            <li key={d.flow_id + d.action_name} className="font-mono text-xs">
                              <span className="font-semibold text-slate-900">{d.flow_id}</span>
                              <span className="text-slate-500"> · {d.action_name} ({d.operation_id})</span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-right">
                      <div className="flex flex-col items-end gap-1.5">
                        <ClassificationBadge value={a.classification} />
                        <ReviewBadge status={reviews[a.id]} />
                        <button className="btn-primary px-2.5 py-1.5 text-xs" onClick={() => onPreview(a.id)}>
                          Preview Remediation
                        </button>
                        <button className="text-xs font-medium text-slate-500 hover:text-slate-800" aria-expanded={expanded}
                                onClick={() => setOpen(expanded ? null : a.id)}>
                          {expanded ? "Hide details ▴" : "Graph & flow details ▾"}
                        </button>
                      </div>
                    </td>
                  </tr>
                  {expanded && (
                    <tr className="bg-slate-50">
                      <td colSpan={6} className="px-4 pb-5 pt-1">
                        <AdminDetail a={a} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function AdminDetail({ a }: { a: AssessmentOut }) {
  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <div>
        <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Score breakdown</h4>
        <ul className="space-y-1.5">
          {Object.entries(a.score_breakdown).map(([k, v]) => (
            <li key={k} className="flex items-center justify-between gap-2 font-mono text-xs">
              <span className="text-slate-700">{k}</span><span className="font-semibold text-slate-900">+{v}</span>
            </li>
          ))}
          <li className="flex items-center justify-between border-t border-slate-200 pt-1.5 text-xs">
            <span className="font-semibold text-slate-700">Total (capped at 100)</span>
            <span className={`rounded px-1.5 font-bold ${riskTone(a.risk_score)}`}>{a.risk_score}</span>
          </li>
        </ul>
        <h4 className="mb-1 mt-4 text-xs font-semibold uppercase tracking-wide text-slate-500">Signals</h4>
        <ul className="list-disc space-y-0.5 pl-4 text-xs text-slate-600">
          {a.reasons.length ? a.reasons.map((r) => <li key={r}>{r}</li>) : <li>No risk factors</li>}
          <li>Last accessed: {a.days_since_access === null ? "never" : `${a.days_since_access} days ago`}</li>
        </ul>
      </div>
      <div>
        <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Permission resource (Graph v1.0 facets)</h4>
        <pre className="code-block">{JSON.stringify(graphFacets(a), null, 2)}</pre>
        <p className="mt-1 font-mono text-[11px] text-slate-500">GET /drives/{a.drive_id}/items/{a.file_id}/permissions/{a.permission_id}</p>
      </div>
      <div>
        <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Power Automate dependencies</h4>
        {a.dependent_flows.length === 0 ? (
          <p className="text-xs text-slate-500">No active flow uses this permission as its access path.</p>
        ) : (
          <ul className="space-y-2">
            {a.dependent_flows.map((d) => (
              <li key={d.flow_id + d.action_name} className="rounded-lg border border-slate-200 bg-white p-3 text-xs">
                <p className="font-semibold text-slate-900">
                  <span className="font-mono">{d.flow_id}</span> · {d.flow_name}
                  {d.is_critical_flow && <span className="chip ml-2 bg-red-50 text-red-700 ring-red-600/20">critical</span>}
                </p>
                <dl className="mt-1.5 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 font-mono text-slate-600">
                  <dt className="text-slate-400">action</dt><dd>{d.action_name}</dd>
                  <dt className="text-slate-400">operationId</dt><dd>{d.operation_id}</dd>
                  <dt className="text-slate-400">requires</dt><dd>{d.required_role}</dd>
                  <dt className="text-slate-400">identity</dt><dd>{d.connection_identity}</dd>
                  <dt className="text-slate-400">connection</dt><dd className="break-all">{d.connection_name ?? "—"}</dd>
                </dl>
              </li>
            ))}
          </ul>
        )}
        {a.mitigation && (
          <p className="mt-2 rounded-lg bg-amber-50 p-2 text-xs text-amber-800 ring-1 ring-inset ring-amber-600/20">
            <strong>Mitigation:</strong> {a.mitigation}
          </p>
        )}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ Business Manager view
const LEVEL_STYLE: Record<string, string> = {
  High: "bg-red-50 text-red-700 ring-red-600/20",
  Medium: "bg-amber-50 text-amber-800 ring-amber-600/20",
  Low: "bg-sky-50 text-sky-700 ring-sky-600/20",
};

function ManagerGrid({ items, reviews, onReview, onPreview }: Props & { items: ManagerCard[] }) {
  if (!items.length) return <Empty text="Nothing needs your review in this category." />;
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {items.map((c) => {
        const status = reviews[c.id];
        const blocked = c.classification === "BREAKAGE_CRITICAL";
        return (
          <article key={c.id} className={`card flex flex-col p-5 ${blocked ? "border-l-4 border-l-red-500" : ""}`}>
            <header className="flex flex-wrap items-center gap-2">
              <span className={`chip ${LEVEL_STYLE[c.risk_level] ?? "bg-slate-100 text-slate-600 ring-slate-500/20"}`}>
                {c.risk_level} risk
              </span>
              <span className="text-xs text-slate-500">{c.site_name} site</span>
              <span className="ml-auto"><ReviewBadge status={status} /></span>
            </header>
            <h3 className="mt-3 text-base font-semibold leading-snug text-slate-900">{c.headline}</h3>
            <dl className="mt-3 space-y-3 text-sm">
              <div>
                <dt className="font-medium text-slate-500">What we found</dt>
                <dd className="text-slate-700">{c.what_we_found}</dd>
              </div>
              <div>
                <dt className="font-medium text-slate-500">Why it matters</dt>
                <dd className="text-slate-700">{c.why_it_matters}</dd>
              </div>
              <div className={`rounded-lg p-3 ${blocked ? "bg-red-50" : c.safe_to_fix_now ? "bg-emerald-50" : "bg-slate-50"}`}>
                <dt className={`font-medium ${blocked ? "text-red-800" : c.safe_to_fix_now ? "text-emerald-800" : "text-slate-600"}`}>
                  Recommended action
                </dt>
                <dd className={blocked ? "text-red-900" : c.safe_to_fix_now ? "text-emerald-900" : "text-slate-700"}>
                  {c.recommended_action}
                </dd>
              </div>
            </dl>
            <footer className="mt-4 flex flex-wrap items-center gap-2 pt-1">
              <button className="btn-success" disabled={!c.safe_to_fix_now || !!status}
                      title={c.safe_to_fix_now ? undefined : "IT must migrate the dependent workflow first"}
                      onClick={() => onReview(c.id, "Approved Safe Cleanup")}>
                <Icon name="check" />Approve Safe Cleanup
              </button>
              <button className="btn-secondary" disabled={!!status} onClick={() => onReview(c.id, "Keep Access")}>
                Keep Access
              </button>
              <button className="ml-auto text-sm font-medium text-indigo-600 hover:text-indigo-800"
                      onClick={() => onPreview(c.id)}>
                Preview Remediation →
              </button>
            </footer>
          </article>
        );
      })}
    </div>
  );
}

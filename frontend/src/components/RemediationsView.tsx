import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { FlowRun, PlanState, RemediationPlan, RemediationStep, StepStatus } from "../types";
import { ClassificationBadge, Icon, Spinner } from "./ui";

interface Props {
  /** Plan to open first, e.g. the one just created from a finding. */
  selectedId: number | null;
  onSelect: (id: number) => void;
  notify: (kind: "success" | "error" | "info", title: string, detail?: string) => void;
}

type Action = "submit" | "approve" | "reject" | "execute" | "rollback";

const STATE_STYLE: Record<PlanState, { label: string; cls: string }> = {
  DRAFT: { label: "Draft", cls: "bg-slate-100 text-slate-700 ring-slate-500/20" },
  PENDING_APPROVAL: { label: "Pending approval", cls: "bg-amber-50 text-amber-800 ring-amber-600/20" },
  APPROVED: { label: "Approved", cls: "bg-indigo-50 text-indigo-700 ring-indigo-600/20" },
  EXECUTING: { label: "Executing", cls: "bg-indigo-50 text-indigo-700 ring-indigo-600/20" },
  COMPLETED: { label: "Completed", cls: "bg-emerald-50 text-emerald-700 ring-emerald-600/20" },
  REJECTED: { label: "Rejected", cls: "bg-slate-100 text-slate-600 ring-slate-500/20" },
  ROLLING_BACK: { label: "Rolling back", cls: "bg-amber-50 text-amber-800 ring-amber-600/20" },
  ROLLED_BACK: { label: "Rolled back", cls: "bg-amber-50 text-amber-800 ring-amber-600/20" },
  ROLLBACK_FAILED: { label: "Rollback failed", cls: "bg-red-50 text-red-700 ring-red-600/20" },
};

const STEP_TEXT: Record<string, { title: string; detail: string }> = {
  SNAPSHOT: { title: "Snapshot", detail: "Save the permission and each dependent flow's connection." },
  PROTECT_FLOW: { title: "Protect flows", detail: "Give each dependent flow another way to reach the file." },
  PREFLIGHT: { title: "Preflight", detail: "Run every dependent flow. All must succeed before anything is removed." },
  REMOVE_BROAD_GRANT: { title: "Remove grant", detail: "Delete the flagged permission. The only step that removes access." },
  POSTFLIGHT: { title: "Postflight", detail: "Run every dependent flow again and confirm the permission is gone." },
};

const STEP_STYLE: Record<StepStatus, { label: string; dot: string; text: string }> = {
  PENDING: { label: "Pending", dot: "bg-white text-slate-400 ring-slate-300", text: "text-slate-500" },
  SUCCEEDED: { label: "Succeeded", dot: "bg-emerald-600 text-white ring-emerald-600", text: "text-emerald-700" },
  FAILED: { label: "Failed", dot: "bg-red-600 text-white ring-red-600", text: "text-red-700" },
  SKIPPED: { label: "Skipped", dot: "bg-slate-100 text-slate-400 ring-slate-300", text: "text-slate-500" },
  ROLLED_BACK: { label: "Rolled back", dot: "bg-amber-500 text-white ring-amber-500", text: "text-amber-700" },
  ROLLBACK_FAILED: { label: "Rollback failed", dot: "bg-red-600 text-white ring-red-600", text: "text-red-700" },
};

const STRATEGY_LABEL: Record<string, string> = {
  service_principal: "Move flows to the service principal",
  scoped_identity_grant: "Scoped grant to the flow's identity",
};

const CONFIRM: Partial<Record<Action, { title: string; body: string; button: string; danger: boolean }>> = {
  execute: {
    title: "Execute this remediation?",
    body: "This changes the simulated tenant: dependent flows are protected, test-run, and then the permission is "
      + "deleted. If any step fails, every change is undone automatically.",
    button: "Execute plan",
    danger: true,
  },
  rollback: {
    title: "Roll back this remediation?",
    body: "The removed permission is restored and each flow goes back to its original connection. "
      + "The file will be exposed again as it was before.",
    button: "Roll back",
    danger: true,
  },
};

function when(iso: string | null): string {
  return iso ? new Date(iso + "Z").toLocaleString() : "";
}

export function StateBadge({ state }: { state: PlanState }) {
  const s = STATE_STYLE[state];
  return <span className={`chip ${s.cls}`}>{s.label}</span>;
}

export function RemediationsView({ selectedId, onSelect, notify }: Props) {
  const [plans, setPlans] = useState<RemediationPlan[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<Action | null>(null);
  const [confirming, setConfirming] = useState<Action | null>(null);

  const load = useCallback(async () => {
    try {
      setPlans((await api.remediations()).items);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const plan = plans?.find((p) => p.id === selectedId) ?? plans?.[0] ?? null;

  const run = async (action: Action) => {
    if (!plan) return;
    setConfirming(null);
    setBusy(action);
    try {
      const updated = await api.remediationAction(plan.id, action);
      setPlans((prev) => prev?.map((p) => (p.id === updated.id ? updated : p)) ?? null);
      const label = STATE_STYLE[updated.state].label;
      const failed = updated.steps.find((s) => s.status === "FAILED" || s.status === "ROLLBACK_FAILED");
      if (updated.state === "ROLLBACK_FAILED") notify("error", `Plan #${updated.id}: ${label}`, failed?.error ?? undefined);
      else if (action === "execute" && updated.state !== "COMPLETED") {
        notify("error", `Plan #${updated.id} failed and was rolled back`, failed?.error ?? undefined);
      } else notify("success", `Plan #${updated.id}: ${label}`, updated.file_name);
    } catch (e) {
      notify("error", `Could not ${action} plan #${plan.id}`, (e as Error).message);
      void load();
    } finally {
      setBusy(null);
    }
  };

  if (error) {
    return <div className="card border-red-200 p-6 text-sm text-red-800">{error}</div>;
  }
  if (!plans) {
    return <div className="card flex items-center gap-3 p-10 text-sm text-slate-500"><Spinner />Loading remediation plans…</div>;
  }
  if (!plans.length || !plan) {
    return (
      <div className="card p-10 text-center">
        <p className="text-base font-semibold text-slate-900">No remediation plans yet</p>
        <p className="mt-1 text-sm text-slate-500">
          Open a finding in the IT Security Admin view, choose “Preview”, then “Create remediation plan”.
        </p>
      </div>
    );
  }

  const confirm = confirming ? CONFIRM[confirming] : undefined;

  return (
    <section className="grid gap-4 lg:grid-cols-[20rem_minmax(0,1fr)]">
      <ul className="space-y-2" aria-label="Remediation plans">
        {plans.map((p) => (
          <li key={p.id}>
            <button onClick={() => onSelect(p.id)} aria-current={p.id === plan.id ? "true" : undefined}
                    className={`card w-full p-3 text-left transition hover:border-indigo-300 ${
                      p.id === plan.id ? "border-indigo-500 ring-1 ring-indigo-500" : ""}`}>
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs text-slate-400">#{p.id}</span>
                <StateBadge state={p.state} />
              </div>
              <p className="mt-1 truncate text-sm font-semibold text-slate-900">{p.file_name}</p>
              <p className="truncate text-xs text-slate-500">{p.principal_display}</p>
            </button>
          </li>
        ))}
      </ul>

      <div className="card min-w-0">
        <header className="space-y-3 border-b border-slate-200 p-5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="text-xs font-semibold uppercase tracking-wide text-indigo-600">Remediation plan #{plan.id}</p>
              <h2 className="truncate text-lg font-semibold text-slate-900">{plan.file_name}</h2>
              <p className="text-sm text-slate-600">
                Remove access for <span className="font-medium text-slate-900">{plan.principal_display}</span>
                <span className="text-slate-400"> · {plan.site_name} · risk {plan.risk_score}</span>
              </p>
            </div>
            <div className="flex items-center gap-2">
              <ClassificationBadge value={plan.classification} />
              <StateBadge state={plan.state} />
            </div>
          </div>

          <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
            <Fact label="Strategy" value={STRATEGY_LABEL[plan.strategy] ?? plan.strategy} />
            <Fact label="Dependent flows"
                  value={plan.dependent_flows.length
                    ? [...new Set(plan.dependent_flows.map((d) => `${d.flow_name} (${d.flow_id})`))].join(", ")
                    : "None"} />
            {plan.override_reason && <Fact label="Override reason (unknown dependency)" value={plan.override_reason} />}
            <Fact label="Created" value={`${plan.created_by} · ${when(plan.created_at)}`} />
            <Fact label="Approved" value={plan.approved_by ? `${plan.approved_by} · ${when(plan.approved_at)}` : "Not yet"} />
            <Fact label="Executed" value={plan.executed_by ? `${plan.executed_by} · ${when(plan.executed_at)}` : "Not yet"} />
            <Fact label="Exposed users (before → after)"
                  value={plan.exposed_before === null && plan.exposed_after === null
                    ? "Not calculated yet" : `${plan.exposed_before ?? "?"} → ${plan.exposed_after ?? "?"}`} />
          </dl>

          <div className="flex flex-wrap items-center gap-2">
            {plan.state === "DRAFT" && (
              <ActionButton cls="btn-primary" busy={busy} action="submit" onClick={run} icon="play" label="Submit for approval" />
            )}
            {plan.state === "PENDING_APPROVAL" && (
              <>
                <ActionButton cls="btn-success" busy={busy} action="approve" onClick={run} icon="check" label="Approve" />
                <ActionButton cls="btn-secondary" busy={busy} action="reject" onClick={run} icon="x" label="Reject" />
              </>
            )}
            {plan.state === "APPROVED" && (
              <ActionButton cls="btn-danger" busy={busy} action="execute" onClick={setConfirming} icon="play" label="Execute" />
            )}
            {plan.state === "COMPLETED" && (
              <ActionButton cls="btn-secondary" busy={busy} action="rollback" onClick={setConfirming} icon="undo" label="Roll back" />
            )}
            {plan.state === "ROLLBACK_FAILED" && (
              <p className="text-sm font-medium text-red-700">
                The rollback did not finish. The tenant needs a manual check; see the failed step below.
              </p>
            )}
          </div>
        </header>

        <ol className="p-5" aria-label="Step timeline">
          {plan.steps.map((s, i) => <StepRow key={s.seq} step={s} last={i === plan.steps.length - 1} />)}
        </ol>
      </div>

      {confirm && confirming && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-slate-900/50 p-4 backdrop-blur-sm"
             onMouseDown={(e) => e.target === e.currentTarget && setConfirming(null)}>
          <div role="alertdialog" aria-modal="true" aria-labelledby="confirm-title"
               className="w-full max-w-md rounded-2xl bg-white p-6 shadow-2xl">
            <h3 id="confirm-title" className="text-lg font-semibold text-slate-900">{confirm.title}</h3>
            <p className="mt-1 text-sm font-medium text-slate-700">Plan #{plan.id} · {plan.file_name}</p>
            <p className="mt-3 text-sm text-slate-600">{confirm.body}</p>
            <div className="mt-6 flex justify-end gap-2">
              <button className="btn-secondary" autoFocus onClick={() => setConfirming(null)}>Cancel</button>
              <button className={confirm.danger ? "btn-danger" : "btn-primary"} onClick={() => run(confirming)}>
                {confirm.button}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="break-words text-slate-900">{value}</dd>
    </div>
  );
}

function ActionButton({ cls, busy, action, onClick, icon, label }: {
  cls: string; busy: Action | null; action: Action; onClick: (a: Action) => void;
  icon: "play" | "check" | "x" | "undo"; label: string;
}) {
  return (
    <button className={cls} disabled={busy !== null} onClick={() => onClick(action)}>
      {busy === action ? <Spinner /> : <Icon name={icon} />}
      {label}
    </button>
  );
}

function StepRow({ step, last }: { step: RemediationStep; last: boolean }) {
  const style = STEP_STYLE[step.status];
  const text = STEP_TEXT[step.action] ?? { title: step.action, detail: "" };
  const runs: FlowRun[] = step.result?.runs ?? [];
  return (
    <li className="relative flex gap-4 pb-6 last:pb-0">
      {!last && <span className="absolute left-4 top-8 -ml-px h-full w-0.5 bg-slate-200" aria-hidden="true" />}
      <span className={`relative flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-sm font-semibold ring-2 ${style.dot}`}>
        {step.status === "SUCCEEDED" ? <Icon name="check" />
          : step.status === "FAILED" || step.status === "ROLLBACK_FAILED" ? <Icon name="x" />
          : step.status === "ROLLED_BACK" ? <Icon name="undo" /> : step.seq}
      </span>
      <div className="min-w-0 flex-1 pt-0.5">
        <div className="flex flex-wrap items-baseline gap-x-3">
          <h3 className="text-sm font-semibold text-slate-900">{step.seq}. {text.title}</h3>
          <span className={`text-xs font-semibold uppercase tracking-wide ${style.text}`}>{style.label}</span>
        </div>
        <p className="text-sm text-slate-600">{text.detail}</p>
        {step.error && (
          <p role="alert" className="mt-2 rounded-lg bg-red-50 p-2.5 text-sm text-red-800 ring-1 ring-inset ring-red-600/20">
            {step.error}
          </p>
        )}
        {runs.length > 0 && (
          <ul className="mt-2 flex flex-wrap gap-1.5">
            {runs.map((r) => (
              <li key={r.flow_id} title={r.error?.message}
                  className={`chip ${r.status === "Succeeded"
                    ? "bg-emerald-50 text-emerald-700 ring-emerald-600/20" : "bg-red-50 text-red-700 ring-red-600/20"}`}>
                <Icon name="flow" className="h-3 w-3" />{r.flow_id}: {r.status}
              </li>
            ))}
          </ul>
        )}
        {step.before_state && (
          <details className="mt-2">
            <summary className="cursor-pointer text-xs font-medium text-slate-500 hover:text-slate-700">
              Saved state for rollback
            </summary>
            <pre className="code-block mt-2 max-h-64">{JSON.stringify(step.before_state, null, 2)}</pre>
          </details>
        )}
      </div>
    </li>
  );
}

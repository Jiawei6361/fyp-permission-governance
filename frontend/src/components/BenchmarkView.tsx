import { useEffect, useState } from "react";
import { api } from "../api";
import type { BenchmarkResults, Confusion, EngineResult } from "../types";
import { Icon, Spinner } from "./ui";

type Task = "revocation_recommendation" | "oversharing_detection" | "flow_dependency_detection";
type EngineKey = "baseline" | "proposed";

const TASKS: { id: Task; label: string; blurb: string }[] = [
  { id: "revocation_recommendation", label: "Revocation recommendation",
    blurb: "Which grants should be removed? Positives are the 23 ground-truth safe-to-revoke grants." },
  { id: "oversharing_detection", label: "Oversharing detection",
    blurb: "Which grants expose sensitive files to anonymous or org-wide audiences?" },
  { id: "flow_dependency_detection", label: "Flow-dependency detection",
    blurb: "Which grants are the only access path for an active Power Automate flow?" },
];

const SERIES: Record<EngineKey, { label: string; short: string; bar: string; dot: string }> = {
  baseline: { label: "Standard Permission-Only Baseline (Purview-style)", short: "Baseline",
              bar: "bg-baseline", dot: "bg-baseline" },
  proposed: { label: "Proposed Context-Aware Engine", short: "Proposed", bar: "bg-proposed", dot: "bg-proposed" },
};

interface MetricRow {
  key: string;
  label: string;
  values: Record<EngineKey, number>; // 0..1
  detail: Record<EngineKey, string>;
}

/** Share of flows put at risk by naive revocation that the engine leaves working. */
function preventionRate(engine: EngineResult, atRisk: number): number {
  if (atRisk === 0) return 1;
  return (atRisk - engine.flows_broken_if_executed.length) / atRisk;
}

function buildRows(b: BenchmarkResults, task: Task): MetricRow[] {
  const { baseline, proposed } = b.engines;
  const c: Record<EngineKey, Confusion> = { baseline: baseline[task], proposed: proposed[task] };
  const cm = (e: EngineKey) => `TP ${c[e].tp} · FP ${c[e].fp} · FN ${c[e].fn}`;
  const atRisk = baseline.flows_broken_if_executed.length;
  const prevented = (e: EngineResult) => `${atRisk - e.flows_broken_if_executed.length} of ${atRisk} at-risk flows keep running`;
  return [
    { key: "precision", label: "Precision", values: { baseline: c.baseline.precision, proposed: c.proposed.precision },
      detail: { baseline: cm("baseline"), proposed: cm("proposed") } },
    { key: "recall", label: "Recall", values: { baseline: c.baseline.recall, proposed: c.proposed.recall },
      detail: { baseline: cm("baseline"), proposed: cm("proposed") } },
    { key: "f1", label: "F1-Score", values: { baseline: c.baseline.f1, proposed: c.proposed.f1 },
      detail: { baseline: cm("baseline"), proposed: cm("proposed") } },
    { key: "prevention", label: "Workflow Breakage Prevention Rate",
      values: { baseline: preventionRate(baseline, atRisk),
                proposed: b.workflow_breakage_prevention_rate_pct / 100 },
      detail: { baseline: prevented(baseline), proposed: prevented(proposed) } },
  ];
}

const pct = (v: number) => `${(v * 100).toFixed(1).replace(/\.0$/, "")}%`;

export function BenchmarkView() {
  const [data, setData] = useState<BenchmarkResults | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [task, setTask] = useState<Task>("revocation_recommendation");

  useEffect(() => {
    api.benchmark().then(setData).catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <div className="card p-6 text-sm text-red-700">{error}</div>;
  if (!data) {
    return <div className="card flex items-center gap-3 p-10 text-sm text-slate-500"><Spinner />Loading benchmark…</div>;
  }

  const { baseline, proposed } = data.engines;
  const rows = buildRows(data, task);
  const taskInfo = TASKS.find((t) => t.id === task)!;

  return (
    <section className="space-y-6">
      <div className="grid gap-4 md:grid-cols-3">
        <div className="card p-5">
          <p className="text-sm font-medium text-slate-500">Workflow Breakage Prevention Rate</p>
          <p className="mt-2 text-4xl font-semibold tabular-nums text-slate-900">{data.workflow_breakage_prevention_rate_pct}%</p>
          <p className="mt-1 text-xs text-slate-500">
            Baseline would break {baseline.flows_broken_if_executed.length} flows
            ({baseline.critical_flows_broken_if_executed.length} business-critical); proposed breaks {proposed.flows_broken_if_executed.length}.
          </p>
        </div>
        <div className="card p-5">
          <p className="text-sm font-medium text-slate-500">Unsafe revocations recommended</p>
          <p className="mt-2 text-4xl font-semibold tabular-nums text-slate-900">
            {baseline.revocation_recommendation.fp} <span className="text-2xl text-slate-400">→</span> {proposed.revocation_recommendation.fp}
          </p>
          <p className="mt-1 text-xs text-slate-500">False positives, baseline → proposed ({baseline.recommended_revocations} vs {proposed.recommended_revocations} recommendations)</p>
        </div>
        <div className="card p-5">
          <p className="text-sm font-medium text-slate-500">Benchmark dataset</p>
          <p className="mt-2 text-4xl font-semibold tabular-nums text-slate-900">{data.ground_truth.permissions_total}</p>
          <p className="mt-1 text-xs text-slate-500">
            permissions · {data.ground_truth.flows_total} flows · seed {data.seed} · {data.ground_truth.safe_to_revoke_positives} safe-to-revoke,
            {" "}{data.ground_truth.workflow_breaking_positives} workflow-breaking positives
          </p>
        </div>
      </div>

      <div className="card p-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <h2 className="text-lg font-semibold text-slate-900">Baseline vs proposed engine</h2>
            <p className="mt-1 max-w-xl text-sm text-slate-500">{taskInfo.blurb}</p>
          </div>
          <nav className="flex flex-wrap gap-1 rounded-lg bg-slate-100 p-1" aria-label="Evaluation task">
            {TASKS.map((t) => (
              <button key={t.id} onClick={() => setTask(t.id)} aria-pressed={task === t.id}
                      className={`rounded-md px-3 py-1.5 text-sm font-medium transition ${
                        task === t.id ? "bg-white text-slate-900 shadow-sm" : "text-slate-600 hover:text-slate-900"}`}>
                {t.label}
              </button>
            ))}
          </nav>
        </div>

        <Legend />
        <div className="mt-6 grid gap-8 xl:grid-cols-[3fr_2fr]">
          <BarChart rows={rows} />
          <MetricsTable rows={rows} />
        </div>
      </div>
    </section>
  );
}

function Legend() {
  return (
    <ul className="mt-5 flex flex-wrap gap-x-6 gap-y-2 text-sm text-slate-700" aria-label="Legend">
      {(Object.keys(SERIES) as EngineKey[]).map((k) => (
        <li key={k} className="flex items-center gap-2">
          <span className={`h-3 w-3 rounded-sm ${SERIES[k].dot}`} />{SERIES[k].label}
        </li>
      ))}
    </ul>
  );
}

function BarChart({ rows }: { rows: MetricRow[] }) {
  const [hover, setHover] = useState<{ row: string; engine: EngineKey } | null>(null);
  const ticks = [0, 0.25, 0.5, 0.75, 1];
  return (
    <figure aria-label="Grouped bar chart comparing baseline and proposed engines">
      <div className="space-y-5">
        {rows.map((r) => (
          <div key={r.key} className="grid grid-cols-[9rem_1fr] items-center gap-3 sm:grid-cols-[13rem_1fr]">
            <span className="text-sm font-medium text-slate-700">{r.label}</span>
            <div className="relative mr-12">
              {/* recessive gridlines */}
              <div className="pointer-events-none absolute inset-0">
                {ticks.map((t) => (
                  <span key={t} className="absolute inset-y-0 w-px bg-slate-100" style={{ left: `${t * 100}%` }} />
                ))}
              </div>
              <div className="relative flex flex-col gap-0.5">
                {(Object.keys(SERIES) as EngineKey[]).map((e) => {
                  const v = r.values[e];
                  const active = hover?.row === r.key && hover.engine === e;
                  return (
                    <div key={e} className="relative flex h-5 items-center"
                         onMouseEnter={() => setHover({ row: r.key, engine: e })}
                         onMouseLeave={() => setHover(null)}>
                      <div className={`h-3.5 rounded-r ${SERIES[e].bar} transition-opacity ${
                             hover && !active ? "opacity-40" : ""}`}
                           style={{ width: `${Math.max(v * 100, 0.6)}%` }} />
                      <span className="absolute text-xs font-semibold tabular-nums text-slate-700"
                            style={{ left: `calc(${Math.max(v * 100, 0.6)}% + 6px)` }}>{pct(v)}</span>
                      {active && (
                        <div role="tooltip"
                             className="absolute bottom-full left-0 z-10 mb-1 whitespace-nowrap rounded-lg bg-slate-900 px-3 py-2 text-xs text-white shadow-lg">
                          <p className="flex items-center gap-1.5 font-semibold">
                            <span className={`h-2 w-2 rounded-sm ${SERIES[e].dot}`} />{SERIES[e].short} · {r.label}
                          </p>
                          <p className="mt-0.5 text-slate-300">{pct(v)} — {r.detail[e]}</p>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        ))}
        <div className="grid grid-cols-[9rem_1fr] gap-3 sm:grid-cols-[13rem_1fr]">
          <span />
          <div className="relative mr-12 h-4 text-[11px] text-slate-400">
            {ticks.map((t) => (
              <span key={t} className="absolute -translate-x-1/2 tabular-nums" style={{ left: `${t * 100}%` }}>
                {t * 100}%
              </span>
            ))}
          </div>
        </div>
      </div>
    </figure>
  );
}

function MetricsTable({ rows }: { rows: MetricRow[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-sm">
        <thead>
          <tr className="border-b border-slate-200 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">
            <th className="py-2 pr-3">Metric</th>
            <th className="py-2 pr-3 text-right">
              <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm bg-baseline" />Baseline</span>
            </th>
            <th className="py-2 pr-3 text-right">
              <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm bg-proposed" />Proposed</span>
            </th>
            <th className="py-2 text-right">Δ</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {rows.map((r) => {
            const delta = r.values.proposed - r.values.baseline;
            return (
              <tr key={r.key}>
                <td className="py-2.5 pr-3">
                  <p className="font-medium text-slate-800">{r.label}</p>
                  <p className="text-xs text-slate-400">{r.detail.proposed}</p>
                </td>
                <td className="py-2.5 pr-3 text-right tabular-nums text-slate-700">{pct(r.values.baseline)}</td>
                <td className="py-2.5 pr-3 text-right font-semibold tabular-nums text-slate-900">{pct(r.values.proposed)}</td>
                <td className="whitespace-nowrap py-2.5 text-right tabular-nums">
                  {Math.abs(delta) < 1e-9 ? <span className="text-slate-400">±0</span> : (
                    <span className={`inline-flex items-center gap-0.5 font-semibold ${delta > 0 ? "text-emerald-700" : "text-red-700"}`}>
                      {delta > 0 && <Icon name="check" className="h-3 w-3" />}
                      {delta > 0 ? "+" : "−"}{(Math.abs(delta) * 100).toFixed(1)} pts
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <p className="mt-3 text-xs text-slate-400">
        Source: <span className="font-mono">GET /api/benchmark</span> (backend/benchmark_results.json, generated by evaluate_benchmark.py).
      </p>
    </div>
  );
}

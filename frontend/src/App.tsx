import { useCallback, useEffect, useMemo, useState } from "react";
import { API_BASE, ApiError, api } from "./api";
import { BenchmarkView } from "./components/BenchmarkView";
import { DryRunModal } from "./components/DryRunModal";
import { FindingsView } from "./components/FindingsView";
import { KpiBar, type Kpis } from "./components/KpiBar";
import { ToastStack, useToasts } from "./components/Toasts";
import { Icon, Spinner } from "./components/ui";
import type { AssessmentOut, ManagerCard, ReviewStatus, ScanSummary, ViewRole } from "./types";

type Page = "findings" | "benchmark";
type LoadState = "loading" | "ready" | "no-scan" | "offline";

const reviewKey = (scanId: string) => `lumira.reviews.${scanId}`;

function loadReviews(scanId: string): Record<number, ReviewStatus> {
  try {
    return JSON.parse(localStorage.getItem(reviewKey(scanId)) ?? "{}");
  } catch {
    return {};
  }
}

/** KPIs come from the scan summary when we ran the scan in this session, otherwise from the latest snapshot. */
function deriveKpis(summary: ScanSummary | null, items: AssessmentOut[]): Kpis | null {
  if (!items.length && !summary) return null;
  const critical = items.filter((a) => a.classification === "BREAKAGE_CRITICAL");
  const flows = [...new Set(critical.flatMap((a) => a.dependent_flows.map((d) => d.flow_id)))].sort();
  return {
    filesScanned: summary?.files_scanned ?? new Set(items.map((a) => a.file_id)).size,
    permissionsScanned: summary?.permissions_scanned ?? items.length,
    oversharedFiles: summary?.overshared_files ?? new Set(items.filter((a) => a.is_overshared).map((a) => a.file_id)).size,
    oversharedPermissions: summary?.overshared_permissions ?? items.filter((a) => a.is_overshared).length,
    criticalFlows: summary?.flows_at_risk ?? flows,
    breakageCriticalPermissions: summary?.by_classification.BREAKAGE_CRITICAL ?? critical.length,
    safeToRevoke: summary?.by_classification.SAFE_TO_REVOKE
      ?? items.filter((a) => a.classification === "SAFE_TO_REVOKE").length,
  };
}

export default function App() {
  const { toasts, push, dismiss } = useToasts();
  // Deep links for demos: #benchmark, ?role=manager, ?preview=<assessment id>
  const params = new URLSearchParams(window.location.search);
  const [page, setPageState] = useState<Page>(window.location.hash === "#benchmark" ? "benchmark" : "findings");
  const [role, setRole] = useState<ViewRole>(params.get("role") === "manager" ? "manager" : "admin");
  const [state, setState] = useState<LoadState>("loading");
  const [scanning, setScanning] = useState(false);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  const [adminItems, setAdminItems] = useState<AssessmentOut[]>([]);
  const [managerItems, setManagerItems] = useState<ManagerCard[]>([]);
  const [reviews, setReviews] = useState<Record<number, ReviewStatus>>({});
  const [previewId, setPreviewId] = useState<number | null>(() => Number(params.get("preview")) || null);

  const setPage = (p: Page) => {
    setPageState(p);
    window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}#${p}`);
  };

  const loadAssessments = useCallback(async () => {
    try {
      const [admin, manager] = await Promise.all([api.adminAssessments(), api.managerAssessments()]);
      setAdminItems(admin.items);
      setManagerItems(manager.items);
      setScanId(admin.scan_id);
      setReviews(loadReviews(admin.scan_id));
      setState("ready");
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) setState("no-scan");
      else {
        setState("offline");
        throw e;
      }
    }
  }, []);

  useEffect(() => {
    loadAssessments().catch((e: Error) => push("error", "Governance API unavailable", e.message));
  }, [loadAssessments, push]);

  const runScan = async () => {
    setScanning(true);
    push("info", "Scan started", "Enumerating SharePoint permissions and Power Automate flow definitions…");
    try {
      const s = await api.runScan();
      setSummary(s);
      await loadAssessments();
      push("success", `Scan ${s.scan_id} complete`,
           `${s.files_scanned} files · ${s.permissions_scanned} permissions · ${s.flagged_for_revocation} flagged ` +
           `(${s.by_classification.BREAKAGE_CRITICAL} blocked, ${s.by_classification.SAFE_TO_REVOKE} safe to revoke).`);
    } catch (e) {
      push("error", "Scan failed", (e as Error).message);
    } finally {
      setScanning(false);
    }
  };

  const setReview = (id: number, status: ReviewStatus) => {
    setReviews((prev) => {
      const next = { ...prev, [id]: status };
      if (scanId) {
        try { localStorage.setItem(reviewKey(scanId), JSON.stringify(next)); } catch { /* storage unavailable */ }
      }
      return next;
    });
    const name = managerItems.find((c) => c.id === id)?.file_name ?? `#${id}`;
    push("success", status, `${name}: decision recorded for this scan (no tenant change).`);
  };

  const kpis = useMemo(() => deriveKpis(summary, adminItems), [summary, adminItems]);
  const previewName = previewId === null ? ""
    : adminItems.find((a) => a.id === previewId)?.file_name ?? managerItems.find((c) => c.id === previewId)?.file_name ?? "";

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 px-4 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-6">
          <div className="flex items-center gap-3">
            <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-600 text-white">
              <Icon name="shield" className="h-5 w-5" />
            </span>
            <div>
              <h1 className="text-lg font-semibold leading-tight text-slate-900">Lumira Governance Console</h1>
              <p className="text-xs text-slate-500">
                SharePoint oversharing &amp; Power Automate dependency guardrails ·{" "}
                <span className="font-mono">{scanId ?? "no scan yet"}</span>
              </p>
            </div>
          </div>
          <button className="btn-primary px-4 py-2.5" onClick={runScan} disabled={scanning || state === "loading"}>
            {scanning ? <Spinner /> : <Icon name="play" />}
            {scanning ? "Scanning tenant…" : "Run M365 Governance Scan"}
          </button>
        </div>
        <nav className="mx-auto flex max-w-7xl gap-6 px-4 sm:px-6" aria-label="Sections">
          {([["findings", "Findings & Remediation"], ["benchmark", "Evaluation & Proof"]] as const).map(([id, label]) => (
            <button key={id} onClick={() => setPage(id)} aria-current={page === id ? "page" : undefined}
                    className={`border-b-2 pb-3 text-sm font-medium transition ${
                      page === id ? "border-indigo-600 text-indigo-700" : "border-transparent text-slate-500 hover:text-slate-800"}`}>
              {label}
            </button>
          ))}
        </nav>
      </header>

      {scanning && (
        <div className="border-b border-indigo-200 bg-indigo-50" role="status">
          <div className="mx-auto flex max-w-7xl items-center gap-2 px-4 py-2 text-sm text-indigo-800 sm:px-6">
            <Spinner />Scan in progress: scoring Graph permissions and tracing flow connection identities…
          </div>
        </div>
      )}

      <main className="mx-auto max-w-7xl space-y-6 px-4 py-6 sm:px-6">
        {page === "findings" ? (
          <>
            <KpiBar kpis={kpis} />
            {state === "loading" && (
              <div className="card flex items-center gap-3 p-10 text-sm text-slate-500"><Spinner />Loading latest scan…</div>
            )}
            {state === "no-scan" && (
              <div className="card p-10 text-center">
                <p className="text-base font-semibold text-slate-900">No scan has been run yet</p>
                <p className="mt-1 text-sm text-slate-500">Run a governance scan to assess the Lumira Trading tenant.</p>
              </div>
            )}
            {state === "offline" && (
              <div className="card border-red-200 p-6 text-sm text-red-800">
                <p className="font-semibold">Cannot reach the governance API at {API_BASE}.</p>
                <p className="mt-1 text-red-700">
                  Start it from the project root with <code className="font-mono">py -m uvicorn backend.main:app --reload</code>, then reload.
                </p>
              </div>
            )}
            {state === "ready" && (
              <FindingsView role={role} onRoleChange={setRole} adminItems={adminItems} managerItems={managerItems}
                            reviews={reviews} onReview={setReview} onPreview={setPreviewId} />
            )}
          </>
        ) : (
          <BenchmarkView />
        )}
      </main>

      {previewId !== null && (
        <DryRunModal assessmentId={previewId} fileName={previewName} role={role} status={reviews[previewId]}
                     onClose={() => setPreviewId(null)}
                     onConfirm={(id) => setReview(id, "Approved (Dry-Run)")} />
      )}
      <ToastStack toasts={toasts} onDismiss={dismiss} />
    </div>
  );
}

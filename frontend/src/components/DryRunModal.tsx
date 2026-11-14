import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import type { DryRunPreview, ReviewStatus, ViewRole } from "../types";
import { ClassificationBadge, Icon, Spinner } from "./ui";

interface Props {
  assessmentId: number;
  fileName: string;
  role: ViewRole;
  status?: ReviewStatus;
  onClose: () => void;
  onConfirm: (id: number) => void;
}

const REQUIRED_MITIGATION = "Migrate flow connection to Service Principal first";

export function DryRunModal({ assessmentId, fileName, role, status, onClose, onConfirm }: Props) {
  const [preview, setPreview] = useState<DryRunPreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const dialogRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let live = true;
    setPreview(null);
    setError(null);
    api.dryRun(assessmentId)
      .then((p) => live && setPreview(p))
      .catch((e: Error) => live && setError(e.message));
    return () => { live = false; };
  }, [assessmentId]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    dialogRef.current?.focus();
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-slate-900/50 p-4 backdrop-blur-sm"
         onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby="dryrun-title"
           className="flex max-h-[90vh] w-full max-w-2xl flex-col overflow-hidden rounded-2xl bg-white shadow-2xl outline-none">
        <header className="flex items-start justify-between gap-4 border-b border-slate-200 px-6 py-4">
          <div className="min-w-0">
            <p className="text-xs font-semibold uppercase tracking-wide text-indigo-600">Remediation dry-run</p>
            <h2 id="dryrun-title" className="truncate text-lg font-semibold text-slate-900">{fileName}</h2>
          </div>
          <button onClick={onClose} className="rounded-lg p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600"
                  aria-label="Close">
            <Icon name="x" className="h-5 w-5" />
          </button>
        </header>

        <div className="flex-1 space-y-4 overflow-y-auto px-6 py-5">
          {!preview && !error && (
            <div className="flex items-center gap-3 py-10 text-sm text-slate-500">
              <Spinner className="h-5 w-5" />Simulating Microsoft Graph request…
            </div>
          )}
          {error && (
            <div className="rounded-lg bg-red-50 p-4 text-sm text-red-800 ring-1 ring-inset ring-red-600/20">{error}</div>
          )}
          {preview && <PreviewBody p={preview} role={role} />}
        </div>

        <footer className="flex flex-wrap items-center justify-end gap-2 border-t border-slate-200 bg-slate-50 px-6 py-4">
          <span className="mr-auto flex items-center gap-1.5 text-xs text-slate-500">
            <Icon name="shield" className="h-3.5 w-3.5" />
            dry_run: true · executed: false (no tenant change)
          </span>
          <button className="btn-secondary" onClick={onClose}>Close</button>
          {preview && !preview.blocked && (
            <button className="btn-success" disabled={!!status} onClick={() => onConfirm(preview.assessment_id)}>
              <Icon name="check" />
              {status ? status : "Confirm Dry-Run Approval"}
            </button>
          )}
          {preview?.blocked && (
            <button className="btn-danger" disabled title="Direct deletion is blocked by the breakage guardrail">
              <Icon name="lock" />Deletion blocked
            </button>
          )}
        </footer>
      </div>
    </div>
  );
}

function PreviewBody({ p, role }: { p: DryRunPreview; role: ViewRole }) {
  const httpText =
    `${p.request.method} ${p.request.url}\n` +
    Object.entries(p.request.headers).map(([k, v]) => `${k}: ${v}`).join("\n") +
    `\n\n# expected response: ${p.request.expected_status} No Content`;

  const request = (
    <div>
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
        {p.blocked ? "Request that would be sent (blocked)" : "Simulated Microsoft Graph request"}
      </h3>
      <pre className={`code-block ${p.blocked ? "opacity-60 line-through decoration-red-400" : ""}`}>{httpText}</pre>
      <h3 className="mb-2 mt-4 text-xs font-semibold uppercase tracking-wide text-slate-500">Target</h3>
      <pre className="code-block">{JSON.stringify(p.target, null, 2)}</pre>
    </div>
  );
  const technical = role === "admin" ? request : (
    <details className="rounded-lg border border-slate-200 p-3">
      <summary className="cursor-pointer text-sm font-medium text-slate-600">Technical details for IT</summary>
      <div className="mt-3">{request}</div>
    </details>
  );

  return (
    <>
      <div className="flex items-center gap-2">
        <ClassificationBadge value={p.classification} />
        <span className="font-mono text-xs text-slate-400">assessment #{p.assessment_id} · {p.scan_id}</span>
      </div>

      {p.classification === "BREAKAGE_CRITICAL" && (
        <div role="alert" className="rounded-xl border-2 border-red-500 bg-red-50 p-4">
          <div className="flex items-start gap-3">
            <Icon name="alert" className="mt-0.5 h-6 w-6 shrink-0 text-red-600" />
            <div className="min-w-0 space-y-3">
              <div>
                <p className="text-base font-bold text-red-800">Breakage guardrail: revocation blocked</p>
                <p className="mt-1 text-sm text-red-900">
                  Removing this permission would break the following active Power Automate workflow
                  {p.breakage.length > 1 ? "s" : ""}:
                </p>
              </div>
              <ul className="space-y-2">
                {p.breakage.map((d) => (
                  <li key={d.flow_id + d.action_name} className="rounded-lg bg-white p-3 ring-1 ring-red-200">
                    <p className="text-sm font-semibold text-slate-900">
                      <span className="font-mono text-red-700">{d.flow_id}</span> · {d.flow_name}
                    </p>
                    {role === "admin" && (
                      <p className="mt-0.5 font-mono text-xs text-slate-600">
                        action {d.action_name} ({d.operation_id}) · needs {d.required_role} · runs as {d.connection_identity}
                      </p>
                    )}
                  </li>
                ))}
              </ul>
              <div className="rounded-lg bg-red-600 p-3 text-white">
                <p className="text-xs font-semibold uppercase tracking-wide text-red-100">Required mitigation step</p>
                <p className="mt-0.5 text-sm font-semibold">{REQUIRED_MITIGATION}</p>
                {role === "admin" && p.preconditions.length > 0 && (
                  <ul className="mt-2 list-disc pl-5 text-xs text-red-50">
                    {p.preconditions.map((c) => <li key={c}>{c}</li>)}
                  </ul>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {p.classification === "KEEP_REQUIRED" && (
        <div className="rounded-xl border border-slate-300 bg-slate-50 p-4 text-sm text-slate-700">
          <p className="font-semibold text-slate-900">Not a revocation candidate</p>
          <p className="mt-1">{p.warning}</p>
        </div>
      )}

      {!p.blocked && (
        <div className="rounded-xl border border-emerald-300 bg-emerald-50 p-4 text-sm text-emerald-900">
          <p className="font-semibold">Safe to revoke</p>
          <p className="mt-1">
            No active Power Automate workflow depends on this permission. Confirming records a dry-run approval in
            this console only; the DELETE below is not sent.
          </p>
        </div>
      )}

      {technical}
    </>
  );
}

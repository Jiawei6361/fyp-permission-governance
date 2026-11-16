import type {
  AssessmentList,
  AssessmentOut,
  BenchmarkResults,
  DryRunPreview,
  ManagerCard,
  RemediationPlan,
  ScanSummary,
  Strategy,
} from "./types";

export const API_BASE: string = (import.meta.env.VITE_API_BASE as string | undefined) ?? "http://127.0.0.1:8000";

// The API has no authentication; these names are only recorded on the plan.
const ACTOR = "it-admin";
const APPROVER = "security-approver";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(API_BASE + path, {
      ...init,
      headers: { Accept: "application/json", ...(init?.body ? { "Content-Type": "application/json" } : {}) },
    });
  } catch {
    throw new ApiError(0, `Cannot reach the governance API at ${API_BASE}. Is uvicorn running?`);
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      if (typeof body?.detail === "string") detail = body.detail;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail);
  }
  return (await res.json()) as T;
}

export const api = {
  runScan: () => request<ScanSummary>("/api/scan/run", { method: "POST" }),
  adminAssessments: () => request<AssessmentList<AssessmentOut>>("/api/assessments?role=admin"),
  managerAssessments: () => request<AssessmentList<ManagerCard>>("/api/assessments?role=manager"),
  dryRun: (id: number) => request<DryRunPreview>(`/api/assessments/${id}/dry-run`, { method: "POST" }),
  benchmark: () => request<BenchmarkResults>("/api/benchmark"),
  remediations: () => request<{ total: number; items: RemediationPlan[] }>("/api/remediations"),
  createRemediation: (assessmentId: number, strategy: Strategy, overrideReason?: string) =>
    request<RemediationPlan>("/api/remediations", {
      method: "POST",
      body: JSON.stringify({
        assessment_id: assessmentId, strategy, created_by: ACTOR, override_reason: overrideReason ?? null,
      }),
    }),
  remediationAction: (id: number, action: "submit" | "approve" | "reject" | "execute" | "rollback") =>
    request<RemediationPlan>(`/api/remediations/${id}/${action}`, {
      method: "POST",
      body: JSON.stringify({ actor: action === "approve" ? APPROVER : ACTOR }),
    }),
};

// Mirrors backend/schemas.py (Milestone 2 API, plus the M3 `inherited_from` field).

export type Classification = "BREAKAGE_CRITICAL" | "UNKNOWN_DEPENDENCY" | "SAFE_TO_REVOKE" | "KEEP_REQUIRED";
export type ViewRole = "admin" | "manager";

export interface FlowDependency {
  flow_id: string;
  flow_name: string;
  action_name: string;
  operation_id: string;
  required_role: string;
  connection_identity: string;
  connection_name: string | null;
  is_critical_flow: boolean;
  mitigation: string;
  /** Set when the action's file could not be worked out (dynamic path, unknown connection). */
  unresolved_reason: string | null;
}

export interface ScanSummary {
  scan_id: string;
  reference_time: string;
  files_scanned: number;
  permissions_scanned: number;
  flows_analysed: number;
  active_delegated_flows: number;
  overshared_permissions: number;
  overshared_files: number;
  stale_permissions: number;
  flagged_for_revocation: number;
  by_classification: Record<string, number>;
  flows_at_risk: string[];
  /** Active flows with an action whose file could not be worked out. */
  flows_unresolved: string[];
}

export interface AssessmentOut {
  id: number;
  scan_id: string;
  permission_id: string;
  file_id: string;
  file_name: string;
  file_path: string;
  site_name: string;
  sensitivity_label: string;
  is_copilot_indexed: boolean;
  drive_id: string;
  principal_id: string;
  principal_type: string;
  principal_display: string;
  roles: string[];
  link_scope: string | null;
  inherited_from: string | null;
  exposure: string | null;
  risk_score: number;
  risk_band: string;
  score_breakdown: Record<string, number>;
  reasons: string[];
  is_overshared: boolean;
  is_stale: boolean;
  days_since_access: number | null;
  classification: Classification;
  dependent_flows: FlowDependency[];
  mitigation: string | null;
}

export interface ManagerCard {
  id: number;
  classification: Classification;
  risk_level: string;
  risk_score: number;
  file_name: string;
  site_name: string;
  headline: string;
  what_we_found: string;
  why_it_matters: string;
  recommended_action: string;
  safe_to_fix_now: boolean;
}

export interface AssessmentList<T> {
  scan_id: string;
  role: ViewRole;
  total: number;
  items: T[];
}

export interface DryRunPreview {
  assessment_id: number;
  scan_id: string;
  classification: Classification;
  dry_run: true;
  executed: false;
  blocked: boolean;
  request: {
    method: "DELETE";
    url: string;
    path: string;
    headers: Record<string, string>;
    expected_status: number;
  };
  target: Record<string, string | null>;
  warning: string | null;
  breakage: FlowDependency[];
  /** Flows that could not be analysed (UNKNOWN_DEPENDENCY). */
  unresolved: FlowDependency[];
  preconditions: string[];
}

export type PlanState =
  | "DRAFT" | "PENDING_APPROVAL" | "APPROVED" | "EXECUTING" | "COMPLETED"
  | "REJECTED" | "ROLLING_BACK" | "ROLLED_BACK" | "ROLLBACK_FAILED";
export type Strategy = "service_principal" | "scoped_identity_grant";
export type StepStatus = "PENDING" | "SUCCEEDED" | "FAILED" | "SKIPPED" | "ROLLED_BACK" | "ROLLBACK_FAILED";

export interface FlowRun {
  flow_id: string;
  status: "Succeeded" | "Failed";
  error: { status: number; code: string; action: string; file_id: string | null; message: string } | null;
}

export interface RemediationStep {
  seq: number;
  action: string;
  status: StepStatus;
  before_state: Record<string, unknown> | null;
  result: { runs?: FlowRun[]; permission_removed?: boolean } | null;
  error: string | null;
}

export interface RemediationPlan {
  id: number;
  state: PlanState;
  assessment_id: number;
  scan_id: string;
  permission_id: string;
  file_id: string;
  file_name: string;
  site_name: string;
  principal_display: string;
  classification: Classification;
  risk_score: number;
  dependent_flows: FlowDependency[];
  strategy: Strategy;
  /** Why the creator went ahead with an UNKNOWN_DEPENDENCY finding. */
  override_reason: string | null;
  exposed_before: number | null;
  exposed_after: number | null;
  created_by: string;
  approved_by: string | null;
  executed_by: string | null;
  created_at: string;
  approved_at: string | null;
  executed_at: string | null;
  finished_at: string | null;
  steps: RemediationStep[];
}

export interface Confusion {
  tp: number;
  fp: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
}

export interface EngineResult {
  name: string;
  revocation_recommendation: Confusion;
  oversharing_detection: Confusion;
  flow_dependency_detection: Confusion;
  recommended_revocations: number;
  flows_broken_if_executed: string[];
  critical_flows_broken_if_executed: string[];
  benign_grants_flagged: string[];
}

export interface BenchmarkResults {
  reference_time: string;
  seed: number;
  ground_truth: {
    safe_to_revoke_positives: number;
    overshared_positives: number;
    workflow_breaking_positives: number;
    permissions_total: number;
    flows_total: number;
  };
  engines: { baseline: EngineResult; proposed: EngineResult };
  unknown_dependency_holds?: {
    permissions_held: number;
    would_break_a_flow: number;
    safe_but_held: number;
    flows_unresolved: string[];
  };
  workflow_breakage_prevention_rate_pct: number;
}

/** Local (browser-only) review decision. Only remediation plans change the tenant. */
export type ReviewStatus = "Approved (Dry-Run)" | "Approved Safe Cleanup" | "Keep Access";

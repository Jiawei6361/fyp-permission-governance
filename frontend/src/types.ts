// Mirrors backend/schemas.py (Milestone 2 API, plus the M3 `inherited_from` field).

export type Classification = "BREAKAGE_CRITICAL" | "SAFE_TO_REVOKE" | "KEEP_REQUIRED";
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
  preconditions: string[];
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
  workflow_breakage_prevention_rate_pct: number;
}

/** Local (browser-only) review decision. Nothing is written to the tenant in M3. */
export type ReviewStatus = "Approved (Dry-Run)" | "Approved Safe Cleanup" | "Keep Access";

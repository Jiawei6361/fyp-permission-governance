"""Milestone 2 benchmark: permission-only baseline vs context-aware engine, scored on ground_truth.json.

    py backend/evaluate_benchmark.py

Read-only against the seeded database (seeds it first only if it is missing). Writes
backend/benchmark_results.json. Output is deterministic: no wall-clock values are recorded.

Tasks
  1. Safe direct-revocation recommendation (primary). Positives are permissions that can be
     revoked directly without breaking anything: overshared grants whose expected_action is
     "remove" plus stale_safe_to_revoke. Recommending revocation of a permission an active flow
     depends on is a false positive.
  2. Oversharing detection. Positives are the 12 planted overshared permissions; the 2 benign
     broad grants are negatives.
  3. Flow-dependency detection. Positives are workflow_breaking_permissions (item-level
     permissions that are the sole access path of an active flow). The baseline does no flow
     analysis.
Workflow breakage is measured by "executing" each engine's recommended revocations against the
ground-truth dependency map, so it does not reuse the engine's own dependency logic.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from sqlalchemy.orm import Session

if __package__ in (None, ""):  # run as `py backend/evaluate_benchmark.py`: make `backend` importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.flow_mapper import BREAKAGE_CRITICAL, SAFE_TO_REVOKE, classify
from backend.models import DB_PATH, make_engine
from backend.scanner import load_snapshot, scan_permissions
from backend.seed import GROUND_TRUTH_PATH, NOW, seed_database

RESULTS_PATH = Path(__file__).resolve().parent / "benchmark_results.json"


def metrics(predicted: set[str], positives: set[str]) -> dict:
    tp, fp, fn = len(predicted & positives), len(predicted - positives), len(positives - predicted)
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4)}


def evaluate(db_path: Path | str = DB_PATH, truth_path: Path | str = GROUND_TRUTH_PATH) -> dict:
    if not Path(db_path).exists():
        seed_database(db_path, truth_path)
    truth = json.loads(Path(truth_path).read_text(encoding="utf-8"))
    with Session(make_engine(db_path)) as s:
        snapshot = load_snapshot(s)
        results = scan_permissions(snapshot, NOW)
        assessed, profiles = classify(results, snapshot)

    gt_overshared = {o["permission_id"] for o in truth["overshared_files"]}
    gt_safe = ({o["permission_id"] for o in truth["overshared_files"] if o["expected_action"] == "remove"}
               | {x["permission_id"] for x in truth["stale_safe_to_revoke"]})
    gt_breaking = {x["permission_id"]: x["flow_ids"] for x in truth["workflow_breaking_permissions"]}
    critical_flows = {fl.id for fl in snapshot.flows if fl.is_critical}

    overshared = {r.permission.permission_id for r in results if r.is_overshared}
    # Baseline (Purview-style, permission-only): every overshared or stale grant -> revoke directly.
    baseline_revoke = {r.permission.permission_id for r in results if r.flagged}
    ours_revoke = {a.risk.permission.permission_id for a in assessed if a.classification == SAFE_TO_REVOKE}
    # Ground truth labels item-level grants only: an inherited site grant cannot be revoked on the
    # item, so the engine's (correct) dependency notes on inherited grants are out of scope here.
    ours_deps = {a.risk.permission.permission_id for a in assessed
                 if (a.classification == BREAKAGE_CRITICAL or a.dependencies)
                 and a.risk.permission.inherited_from is None}

    def broken_flows(revoked: set[str]) -> list[str]:
        return sorted({f for pid, flows in gt_breaking.items() if pid in revoked for f in flows})

    engines = {
        "baseline": {"name": "Baseline (permission-only, Purview-style)",
                     "revoke": baseline_revoke, "overshared": overshared, "deps": set()},
        "proposed": {"name": "Proposed context-aware engine (ours)",
                     "revoke": ours_revoke, "overshared": overshared, "deps": ours_deps},
    }
    out: dict = {"reference_time": NOW.isoformat(), "seed": truth["seed"],
                 "ground_truth": {"safe_to_revoke_positives": len(gt_safe), "overshared_positives": len(gt_overshared),
                                  "workflow_breaking_positives": len(gt_breaking),
                                  "permissions_total": len(snapshot.permissions), "flows_total": len(profiles)},
                 "engines": {}}
    for key, e in engines.items():
        broken = broken_flows(e["revoke"])
        out["engines"][key] = {
            "name": e["name"],
            "revocation_recommendation": metrics(e["revoke"], gt_safe),
            "oversharing_detection": metrics(e["overshared"], gt_overshared),
            "flow_dependency_detection": metrics(e["deps"], set(gt_breaking)),
            "recommended_revocations": len(e["revoke"]),
            "flows_broken_if_executed": broken,
            "critical_flows_broken_if_executed": sorted(set(broken) & critical_flows),
            "benign_grants_flagged": sorted({b["permission_id"] for b in truth["benign_broad_grants"]} & e["revoke"]),
        }
    base_broken = len(out["engines"]["baseline"]["flows_broken_if_executed"])
    ours_broken = len(out["engines"]["proposed"]["flows_broken_if_executed"])
    out["workflow_breakage_prevention_rate_pct"] = round(100 * (base_broken - ours_broken) / base_broken, 2) if base_broken else 100.0
    return out


def print_report(res: dict) -> None:
    tasks = [("revocation_recommendation", "Safe revocation recommendation (primary)"),
             ("oversharing_detection", "Oversharing detection"),
             ("flow_dependency_detection", "Flow-dependency detection")]
    gt = res["ground_truth"]
    print(f"\nMilestone 2 benchmark  (reference time {res['reference_time']}, seed {res['seed']})")
    print(f"Ground truth: {gt['safe_to_revoke_positives']} safe-to-revoke, {gt['overshared_positives']} overshared, "
          f"{gt['workflow_breaking_positives']} workflow-breaking permissions; "
          f"{gt['permissions_total']} permissions, {gt['flows_total']} flows")
    header = f"{'Task':<42} {'Engine':<10} {'TP':>4} {'FP':>4} {'FN':>4} {'Precision':>10} {'Recall':>8} {'F1':>8}"
    print("\n" + header + "\n" + "-" * len(header))
    for key, label in tasks:
        for eng in ("baseline", "proposed"):
            m = res["engines"][eng][key]
            print(f"{label:<42} {eng:<10} {m['tp']:>4} {m['fp']:>4} {m['fn']:>4} "
                  f"{m['precision']:>10.4f} {m['recall']:>8.4f} {m['f1']:>8.4f}")
    print()
    for eng in ("baseline", "proposed"):
        e = res["engines"][eng]
        broken = e["flows_broken_if_executed"]
        print(f"{e['name']}: {e['recommended_revocations']} revocations recommended, "
              f"{len(broken)} flows broken if executed ({len(e['critical_flows_broken_if_executed'])} business-critical)"
              + (f": {', '.join(broken)}" if broken else ""))
    print(f"\nWorkflow breakage prevention rate: {res['workflow_breakage_prevention_rate_pct']:.2f}%")


def main() -> int:
    res = evaluate()
    print_report(res)
    RESULTS_PATH.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
    print(f"\nSaved {RESULTS_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

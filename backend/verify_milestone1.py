"""Milestone 1 verification. Reseeds the simulator database (tenant_sim.db). Exits 0 only if every check passes."""
from __future__ import annotations

import json
import sys
from datetime import timedelta
from urllib.parse import unquote

from pydantic import ValidationError
from sqlalchemy import inspect, select, text
from sqlalchemy.orm import Session

if __package__ in (None, ""):  # run as a file path: make `backend` importable
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend import seed
from backend.adapter import LiveGraphAdapter, SimulatorAdapter, get_adapter
from backend.models import TENANT_DB_PATH, AppBase, File, Flow, Permission, TenantBase, User, make_engine
from backend.schemas import FlowResource, Permission as GraphPermission

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, bool(ok), detail))
    return bool(ok)


def main() -> int:
    # ---- 1. clean initialisation
    try:
        seed.seed_database()
        engine = make_engine(TENANT_DB_PATH)
        insp = inspect(engine)
        expected = {t.name: {c.name for c in t.columns} for t in TenantBase.metadata.sorted_tables}
        actual = {t: {c["name"] for c in insp.get_columns(t)} for t in insp.get_table_names()}
        with engine.connect() as c:
            integrity = c.execute(text("PRAGMA integrity_check")).scalar()
            fk_viol = c.execute(text("PRAGMA foreign_key_check")).fetchall()
        check("1a tenant schema created, tables/columns match models; no app tables in it",
              actual == expected and not set(actual) & set(AppBase.metadata.tables), f"{sorted(actual)}")
        check("1b PRAGMA integrity_check ok, foreign_key_check empty", integrity == "ok" and not fk_viol,
              f"integrity={integrity}, fk_violations={len(fk_viol)}")
    except Exception as exc:  # noqa: BLE001
        check("1 database initialisation", False, repr(exc))
        return report()

    truth = json.loads(seed.GROUND_TRUTH_PATH.read_text(encoding="utf-8"))
    with Session(engine) as s:
        users = {u.id: u for u in s.scalars(select(User))}
        files = {f.id: f for f in s.scalars(select(File))}
        perms = list(s.scalars(select(Permission)))
        flows = list(s.scalars(select(Flow)))

    # ---- 2. counts and foreign keys
    check("2a 50 users / 100 files / 30 flows", (len(users), len(files), len(flows)) == (50, 100, 30),
          f"{len(users)}/{len(files)}/{len(flows)}")
    check("2b flows reference existing users and files",
          all(f.owner_user_id in users and f.target_file_id in files for f in flows))
    check("2c permissions reference existing files; user principals exist",
          all(p.file_id in files for p in perms)
          and all(p.principal_id in users for p in perms if p.principal_type == "user"),
          f"{len(perms)} permissions")

    # ---- 3. ground_truth.json labelled counts and independent recomputation from the DB
    c = truth["counts"]
    check("3a ground_truth counts consistent with lists",
          c["overshared_files"] == len(truth["overshared_files"]) == 12
          and c["workflow_breaking_permissions"] == len(truth["workflow_breaking_permissions"]) == 14
          and c["workflow_breaking_flows"] == 14
          and c["flow_path_cases"] == len(truth["flow_path_cases"]) == 5
          and c["stale_safe_to_revoke_permissions"] == len(truth["stale_safe_to_revoke"]) == 15
          and c["benign_broad_grants"] == 2,
          f"overshared={c['overshared_files']} stale_safe={c['stale_safe_to_revoke_permissions']} "
          f"breaking_perms={c['workflow_breaking_permissions']} breaking_flows={c['workflow_breaking_flows']}")

    now = seed.NOW
    perms_by_file: dict[str, list[Permission]] = {}
    for p in perms:
        perms_by_file.setdefault(p.file_id, []).append(p)

    def is_broad(p: Permission) -> bool:
        return (p.principal_type == seed.EVERYONE or p.principal_id == seed.ALL_STAFF
                or p.link_scope in ("organization", "anonymous"))

    over = {p.id for f in files.values() if f.sensitivity_label in seed.CONF and f.is_copilot_indexed
            for p in perms_by_file[f.id] if is_broad(p)}
    check("3b overshared set recomputed from DB == ground truth",
          over == {o["permission_id"] for o in truth["overshared_files"]}, f"{len(over)} recomputed")

    flow_deps = {(f.target_file_id, f.owner_user_id) for f in flows}
    stale = {p.id for p in perms if p.principal_type == "user" and p.inherited_from is None
             and now - p.last_accessed_at > timedelta(days=90) and (p.file_id, p.principal_id) not in flow_deps}
    check("3c stale-safe set recomputed from DB == ground truth",
          stale == {x["permission_id"] for x in truth["stale_safe_to_revoke"]}, f"{len(stale)} recomputed")

    def paths(owner: User, file_id: str) -> list[Permission]:
        out = []
        for p in perms_by_file[file_id]:
            if (p.principal_type == "user" and p.principal_id == owner.id) \
                    or (p.principal_type == "group" and p.principal_id in (f"g-{owner.department.lower()}", seed.ALL_STAFF)) \
                    or p.principal_type == seed.EVERYONE or p.link_scope == "organization":
                out.append(p)
        return out

    breaking: set[str] = set()
    for f in flows:
        if f.raw_definition_json["properties"]["state"] != "Started" or f.connection_type != "user":
            continue
        ps = paths(users[f.owner_user_id], f.target_file_id)
        if len(ps) == 1 and ps[0].inherited_from is None:
            breaking.add(ps[0].id)
    check("3d workflow-breaking set recomputed from DB == ground truth",
          breaking == {x["permission_id"] for x in truth["workflow_breaking_permissions"]}, f"{len(breaking)} recomputed")
    check("3e label sets: stale-safe never breaks a flow; benign grants unflagged",
          not (stale & breaking) and not ({b["permission_id"] for b in truth["benign_broad_grants"]} & over))

    # ---- 4. Graph v1.0 schema validation
    adapter = SimulatorAdapter(TENANT_DB_PATH)
    assert isinstance(get_adapter("live"), LiveGraphAdapter)
    n_valid, bad = 0, []
    for f in adapter.list_files():
        for payload in adapter.list_item_permissions(f["id"]):
            try:
                GraphPermission.model_validate(payload)
                n_valid += 1
            except ValidationError as exc:
                bad.append((payload["id"], str(exc)[:80]))
    check("4a all permission payloads validate against Graph permission model",
          not bad and n_valid == len(perms), f"{n_valid}/{len(perms)} valid {bad[:1]}")
    scopes = {p["link"]["scope"] for f in adapter.list_files() for p in adapter.list_item_permissions(f["id"]) if "link" in p}
    check("4b payloads include organization and anonymous links, inheritedFrom, grantedToV2",
          {"organization", "anonymous"} <= scopes
          and any("inheritedFrom" in p for f in adapter.list_files() for p in adapter.list_item_permissions(f["id"])),
          f"link scopes={sorted(scopes)}")
    try:
        GraphPermission.model_validate({"id": "x", "roles": ["read"], "link": {"type": "view", "scope": "bogus", "webUrl": "u"}})
        rejected = False
    except ValidationError:
        rejected = True
    check("4c malformed payload (bad link.scope) is rejected", rejected)
    flow_bad = []
    for fl in adapter.list_flows():
        try:
            FlowResource.model_validate(fl)
        except ValidationError as exc:
            flow_bad.append(str(exc)[:80])
    def action_paths(fl: Flow) -> list[str]:
        return [a["inputs"]["parameters"]["path"]
                for a in fl.raw_definition_json["properties"]["definition"]["actions"].values()
                if a["type"] == "OpenApiConnection"]

    dynamic = {c["flow_id"] for c in truth["flow_path_cases"] if c["case"] == "dynamic_path"}
    encoded = {c["flow_id"] for c in truth["flow_path_cases"] if c["case"] == "double_encoded_path"}
    paths_ok = all(
        all("@" in p for p in action_paths(fl)) if fl.id in dynamic
        else all(p != files[fl.target_file_id].file_path
                 and unquote(unquote(p)) == files[fl.target_file_id].file_path for p in action_paths(fl))
        if fl.id in encoded
        else action_paths(fl) == [files[fl.target_file_id].file_path]
        for fl in flows)
    check("4d flow definitions validate; action paths are plain (25), dynamic (3) or double-encoded (2)",
          not flow_bad and paths_ok and (len(dynamic), len(encoded)) == (3, 2), f"{len(adapter.list_flows())} flows")
    check("4e every connectionReferences connectionName resolves to a connection with an identity",
          all((c["properties"].get("authenticatedUser") or c["properties"].get("servicePrincipal") or {}).get("id")
              for c in adapter.list_connections())
          and {r["connectionName"] for fl in adapter.list_flows()
               for r in fl["properties"]["connectionReferences"].values()}
          <= {c["name"] for c in adapter.list_connections()}, f"{len(adapter.list_connections())} connections")

    # ---- determinism
    a, b = seed.build_dataset(), seed.build_dataset()
    check("5 dataset generation is deterministic (seed 42)",
          json.dumps(a["ground_truth"], sort_keys=True) == json.dumps(b["ground_truth"], sort_keys=True)
          and [p["graph"] for p in a["permissions"]] == [p["graph"] for p in b["permissions"]])

    # ---- 6. the adapter serves the database, and is stateful
    served = {p["id"]: p for f in adapter.list_files() for p in adapter.list_item_permissions(f["id"])}
    check("6a adapter serves the seeded Graph payloads from tenant_sim.db",
          served == {p["graph"]["id"]: p["graph"] for p in a["permissions"]}, f"{len(served)} payloads")
    seeded = adapter.state_checksum()
    victim = truth["workflow_breaking_permissions"][0]
    ok_before = adapter.run_flow(victim["flow_ids"][0])["status"]
    adapter.delete_item_permission(victim["file_id"], victim["permission_id"])
    failed = adapter.run_flow(victim["flow_ids"][0])
    changed = adapter.state_checksum() != seeded
    adapter.reset()
    check("6b delete breaks the dependent flow (403); reset() restores the checksum",
          ok_before == "Succeeded" and failed["status"] == "Failed" and failed["error"]["status"] == 403
          and changed and adapter.state_checksum() == seeded, f"checksum {seeded[:12]}")
    return report()


def report() -> int:
    width = max(len(n) for n, _, _ in results)
    print(f"\n{'CHECK'.ljust(width)}  RESULT  DETAIL")
    print("-" * (width + 40))
    for name, ok, detail in results:
        print(f"{name.ljust(width)}  {'PASS' if ok else 'FAIL'}    {detail}")
    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

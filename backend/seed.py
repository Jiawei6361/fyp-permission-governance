"""Deterministic simulated Microsoft 365 tenant ("Lumira Trading") and ground-truth seeder.

`build_dataset()` is pure and seeded (42): users, files, Graph-v1.0-shaped permission
payloads, Power Automate flow definitions, and the planted ground truth.
`seed_database()` writes it to the simulator database (`tenant_sim.db`) and `ground_truth.json`.

Planted cases (see ground_truth.json):
  * 12 overshared files: Confidential/Highly Confidential, Copilot-indexed, exposed through an
    organization link, anonymous link, Everyone-except-external, or the All Staff group.
  * 15 stale permissions safe to revoke: unused > 90 days, no flow depends on them.
  * 12 workflow-breaking permissions: the only access path of an active flow's owner is that
    permission (8 direct user grants, 4 of them broad grants on overshared files). 3 of the
    direct ones are also stale by the access log, as a trap for naive "stale => revoke".
  * 2 benign broad grants (organization link on Public files) that must NOT be flagged.
  * 5 flow path cases (flow-26 to flow-30): 3 flows whose action path is a runtime expression
    and 2 whose path is URL-encoded twice, as the SharePoint connector stores it. Two of them
    (flow-27, flow-30) run on a stale-looking direct grant, which brings the workflow-breaking
    total to 14. `flow_path_cases` in ground_truth.json records the expected result of each.

The `flows` columns `owner_user_id`, `target_file_id` and `connection_type` are simulator
bookkeeping (who the flow runs as and which file it really touches). They are never served
by the adapter, so the engine cannot read them.
"""
from __future__ import annotations

import base64
import itertools
import json
import random
import sys
from urllib.parse import quote
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy.orm import Session

if __package__ in (None, ""):  # run as `py backend/seed.py`: make `backend` importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy.engine import Engine

from backend.models import TENANT_DB_PATH, Connection, File, Flow, Permission, TenantBase, User, make_engine

SEED = 42
NOW = datetime(2026, 11, 15, 9, 0, 0)  # fixed reference time keeps the dataset deterministic
TENANT = "7d3f0c1e-0000-4000-8000-000000000001"
HOST = "lumira.sharepoint.example"
DOMAIN = "lumira.example"
ENV = "Default-7d3f0c1e"
GROUND_TRUTH_PATH = Path(__file__).resolve().parent / "ground_truth.json"
ALL_STAFF = "g-all-staff"
EVERYONE = "everyone_except_external"
CONF = ("Confidential", "Highly Confidential")

FIRST = ["Aisha", "Benjamin", "Chen", "Daniel", "Elena", "Farid", "Grace", "Hana", "Ivan", "Jia",
         "Kavita", "Liam", "Mei", "Nadia", "Omar", "Priya", "Quinn", "Rahul", "Siti", "Tariq"]
LAST = ["Abdullah", "Bakar", "Chong", "Das", "Evans", "Fong", "Gupta", "Hassan", "Ibrahim", "Jaafar",
        "Khoo", "Lim", "Musa", "Nair", "Ong", "Patel", "Rahman", "Sim", "Tan", "Wong"]
DEPTS = [("Executive", 3), ("Finance", 7), ("HR", 5), ("Sales", 9), ("Operations", 8),
         ("IT", 6), ("Legal", 4), ("Marketing", 4)]
TITLES = {
    "Executive": ["Chief Executive", "Chief Financial Officer", "Executive Assistant"],
    "Finance": ["Financial Analyst", "Accountant", "Finance Manager"],
    "HR": ["HR Officer", "HR Business Partner", "Recruiter"],
    "Sales": ["Account Executive", "Sales Manager", "Sales Analyst"],
    "Operations": ["Operations Clerk", "Procurement Officer", "Logistics Lead"],
    "IT": ["Systems Engineer", "Helpdesk Technician", "Network Engineer"],
    "Legal": ["Legal Counsel", "Paralegal", "Compliance Officer"],
    "Marketing": ["Marketing Executive", "Brand Manager", "Content Specialist"],
}
EXT = ["xlsx", "docx", "pdf", "xlsx", "docx"]
# site, owning dept, default label, folders, base file names
SITES = [
    ("finance", "Finance", "Confidential", ["Invoices", "Budgets"],
     ["Q1 Invoice Register", "Q2 Invoice Register", "Budget", "Cashflow Forecast", "Supplier Payments"]),
    ("payroll", "HR", "Highly Confidential", ["Monthly Runs", "Bank Files"],
     ["Payroll Run Jan", "Payroll Run Feb", "Bonus Schedule", "Tax Withholding", "Bank Transfer Batch"]),
    ("hr", "HR", "Confidential", ["Employee Files", "Leave"],
     ["Salary Review", "Performance Appraisals", "Leave Balances", "Disciplinary Log", "Onboarding Checklist"]),
    ("sales", "Sales", "General", ["Pipeline", "Customers"],
     ["Pipeline Forecast", "Customer List", "Quota Tracker", "Proposal Template", "Win Loss Analysis"]),
    ("contracts", "Legal", "Confidential", ["Active", "Archive"],
     ["Supplier Agreement", "Customer MSA", "NDA Register", "Renewal Schedule", "Pricing Addendum"]),
    ("legal", "Legal", "Highly Confidential", ["Litigation", "Advice"],
     ["Case Summary", "Counsel Opinion", "Settlement Terms", "Privileged Memo", "Evidence Index"]),
    ("board", "Executive", "Confidential", ["Reports", "Minutes"],
     ["Board Pack", "Strategy Paper", "Director Fees", "Acquisition Review", "Risk Register"]),
    ("it-infra", "IT", "Confidential", ["Network", "Access"],
     ["Firewall Rules", "Credentials Vault Export", "Backup Policy", "Asset Inventory", "Admin Roster"]),
    ("operations", "Operations", "General", ["Logistics", "Procurement"],
     ["Fleet Schedule", "Purchase Orders", "Vendor Scorecard", "Stock Levels", "Shift Roster"]),
    ("marketing", "Marketing", "Public", ["Brand Assets", "Campaigns"],
     ["Brand Guidelines", "Campaign Calendar", "Press Kit", "Social Plan", "Logo Pack"]),
]
# exposure kinds for the 12 overshared files; the first four get a dependent flow
EXPOSURES = ["org_link", "everyone", "everyone", "org_link",
             "anonymous", "anonymous", "anonymous", "org_link", "org_link",
             "everyone", "large_group", "large_group"]


# ---------------------------------------------------------------- Graph payload builders
def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def _group_id(dept: str) -> str:
    return f"g-{dept.lower()}"


def _user_identity(u: dict) -> dict:
    return {"id": u["id"], "displayName": u["display_name"], "email": u["email"]}


def _inherited(site: str) -> dict:
    return {"driveId": f"drv-{site}", "id": "root", "path": f"/drives/drv-{site}/root:"}


def _link_perm(pid: str, site: str, rng: random.Random, scope: str, type_: str) -> dict:
    token = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(10))
    return {
        "id": pid,
        "roles": ["write" if type_ == "edit" else "read"],
        "link": {"type": type_, "scope": scope,
                 "webUrl": f"https://{HOST}/:b:/s/{site}/E{token}", "preventsDownload": False},
        "hasPassword": False,
    }


def _everyone_perm(pid: str, role: str) -> dict:
    return {
        "id": pid, "roles": [role],
        "grantedToV2": {"siteUser": {
            "id": "7", "displayName": "Everyone except external users",
            "loginName": f"c:0-.f|rolemanager|spo-grid-all-users/{TENANT}"}},
    }


# ---------------------------------------------------------------- flow definition builder
def double_encode(path: str) -> str:
    """How the SharePoint connector stores a path parameter: URL-encoded twice."""
    return quote(quote(path, safe=""), safe="")


def _flow_resource(flow_id: str, display: str, state: str, owner: dict, conn_type: str,
                   file: dict, required: str, path: str | None = None) -> dict:
    """`path` overrides the action's path parameter (an expression or an encoded path)."""
    slug = owner["email"].split("@")[0].replace(".", "-")
    conn_name = f"shared-sharepointonl-{slug}" if conn_type == "user" else "shared-sp-automation"
    op = "UpdateFile" if required == "write" else "GetFileContentByPath"
    return {
        "name": flow_id,
        "id": f"/providers/Microsoft.ProcessSimple/environments/{ENV}/flows/{flow_id}",
        "type": "Microsoft.ProcessSimple/environments/flows",
        "properties": {
            "displayName": display,
            "state": state,
            "createdTime": "2025-03-04T02:11:00Z",
            "lastModifiedTime": "2026-08-19T07:40:00Z",
            "creator": {"tenantId": TENANT, "objectId": owner["id"], "userId": owner["id"],
                        "userType": "ActiveDirectory"},
            "connectionReferences": {
                "shared_sharepointonline": {
                    "connectionName": conn_name,
                    "id": "/providers/Microsoft.PowerApps/apis/shared_sharepointonline",
                    "displayName": "SharePoint", "tier": "Standard"},
            },
            "definition": {
                "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
                "triggers": {"Recurrence": {"type": "Recurrence",
                                            "recurrence": {"frequency": "Week", "interval": 1}}},
                "actions": {
                    "Process_file": {
                        "type": "OpenApiConnection",
                        "inputs": {
                            "host": {"apiId": "/providers/Microsoft.PowerApps/apis/shared_sharepointonline",
                                     "connectionName": "shared_sharepointonline", "operationId": op},
                            "parameters": {"dataset": f"https://{HOST}/sites/{file['site_name']}",
                                           "path": path or file["file_path"]},
                        },
                        "runAfter": {},
                    },
                    "Log_result": {"type": "Compose", "inputs": f"Processed {file['file_name']}",
                                   "runAfter": {"Process_file": ["Succeeded"]}},
                },
            },
        },
    }


# ---------------------------------------------------------------- dataset
def build_dataset() -> dict:
    rng = random.Random(SEED)

    # ---- users: 46 employees + 2 service accounts + 2 guests = 50
    names = rng.sample(list(itertools.product(FIRST, LAST)), 46)
    users: list[dict] = []
    n = 0
    for dept, count in DEPTS:
        for k in range(count):
            first, last = names[n]
            n += 1
            users.append({"id": f"u-{n:03d}", "display_name": f"{first} {last}",
                          "email": f"{first.lower()}.{last.lower()}@{DOMAIN}", "department": dept,
                          "job_title": TITLES[dept][k % 3], "is_active": True, "kind": "employee"})
    for slug, title in [("svc-automation", "Automation Service"), ("svc-reports", "Reporting Service")]:
        n += 1
        users.append({"id": f"u-{n:03d}", "display_name": slug, "email": f"{slug}@{DOMAIN}",
                      "department": "IT", "job_title": title, "is_active": True, "kind": "service"})
    for first, last in [("Guest", "Auditor"), ("Guest", "Consultant")]:
        n += 1
        users.append({"id": f"u-{n:03d}", "display_name": f"{first} {last}",
                      "email": f"{last.lower()}@partner.example", "department": "External",
                      "job_title": "External Guest", "is_active": True, "kind": "guest"})
    inactive = []
    for dept in ("Sales", "Operations"):  # two leavers
        leaver = [u for u in users if u["department"] == dept and u["kind"] == "employee"][-1]
        leaver["is_active"] = False
        inactive.append(leaver)
    emp_active = [u for u in users if u["kind"] == "employee" and u["is_active"]]

    def dept_members(dept: str) -> list[dict]:
        return [u for u in emp_active if u["department"] == dept]

    # ---- files: 10 sites x 10 files = 100
    files: list[dict] = []
    for site, dept, default, folders, bases in SITES:
        for i in range(10):
            label = default if default in ("Public", "General") else rng.choice([default, default, default, "General"])
            folder, name = folders[i % 2], f"{bases[i % 5]} {2025 + i // 5}.{EXT[i % 5]}"
            files.append({"id": f"f-{len(files) + 1:03d}", "site_name": site, "file_name": name,
                          "file_path": f"/sites/{site}/Shared Documents/{folder}/{name}",
                          "sensitivity_label": label, "is_copilot_indexed": rng.random() < 0.6,
                          "dept": dept})

    # ---- choose disjoint planted sets
    cand = [i for i, f in enumerate(files) if f["sensitivity_label"] in CONF]
    planted = rng.sample(cand, 12)
    benign = rng.sample([i for i, f in enumerate(files) if f["site_name"] == "marketing"], 2)
    rest = [i for i in range(100) if i not in planted and i not in benign]
    direct_t = rng.sample(rest, 8)
    rest = [i for i in rest if i not in direct_t]
    stale_t = rng.sample(rest, 15)
    rest = [i for i in rest if i not in stale_t]
    safe_t = rng.sample(rest, 13)
    for i in planted + benign:
        files[i]["is_copilot_indexed"] = True

    perms: list[dict] = []  # {"graph", "file_id", "last_accessed_at", "meta"}
    counter = itertools.count(1)

    def add(file: dict, graph_body: dict, days: int, **meta) -> str:
        pid = _b64(f"{file['id']}|{next(counter)}")
        graph = {**graph_body, "id": pid}
        perms.append({"graph": graph, "file_id": file["id"], "meta": meta,
                      "last_accessed_at": NOW - timedelta(days=days, hours=rng.randint(0, 23))})
        return pid

    # baseline: inherited department group + two direct dept members per file
    for f in files:
        dept = f["dept"]
        add(f, {"roles": ["write"], "inheritedFrom": _inherited(f["site_name"]),
                "grantedToV2": {"group": {"id": _group_id(dept), "displayName": f"{dept} Team"}}},
            rng.randint(1, 30))
        for u in rng.sample(dept_members(dept), 2):
            add(f, {"roles": [rng.choice(["read", "write"])], "grantedToV2": {"user": _user_identity(u)}},
                rng.randint(1, 80))

    flows: list[dict] = []
    truth = {"overshared_files": [], "stale_safe_to_revoke": [], "workflow_breaking_permissions": [],
             "benign_broad_grants": [], "safe_flows": []}

    def new_flow(file: dict, owner: dict, conn: str, state: str, critical: bool, required: str, verb: str,
                 path: str | None = None) -> str:
        fid = f"flow-{len(flows) + 1:02d}"
        base = file["file_name"].rsplit(".", 1)[0]
        flows.append({"id": fid, "flow_name": f"{verb} {base}", "owner_user_id": owner["id"],
                      "target_file_id": file["id"], "connection_type": conn, "is_critical": critical,
                      "raw_definition_json": _flow_resource(fid, f"{verb} {base}", state, owner, conn, file,
                                                            required, path)})
        return fid

    # ---- planted overshared files (+ 4 broad-grant-dependent flows)
    for k, (idx, kind) in enumerate(zip(planted, EXPOSURES)):
        f = files[idx]
        req = "write" if k == 2 else "read"
        role_days = rng.randint(1, 60)
        if kind == "org_link":
            pid = add(f, _link_perm("", f["site_name"], rng, "organization", "edit" if req == "write" else "view"), role_days)
        elif kind == "anonymous":
            pid = add(f, _link_perm("", f["site_name"], rng, "anonymous", "view"), role_days)
        elif kind == "everyone":
            pid = add(f, _everyone_perm("", req), role_days)
        else:
            pid = add(f, {"roles": ["read"], "grantedToV2": {"group": {"id": ALL_STAFF, "displayName": "All Staff"}}}, role_days)
        entry = {"file_id": f["id"], "permission_id": pid, "exposure_kind": kind,
                 "sensitivity_label": f["sensitivity_label"], "is_copilot_indexed": True,
                 "dependent_flow_ids": [], "expected_action": "remove"}
        if k < 4:
            owner = rng.choice([u for u in emp_active if u["department"] != f["dept"]])
            fid = new_flow(f, owner, "user", "Started", k % 4 != 3, req, "Distribute")
            entry["dependent_flow_ids"] = [fid]
            entry["expected_action"] = "migrate_flow_then_remove"
            truth["workflow_breaking_permissions"].append(
                {"permission_id": pid, "file_id": f["id"], "principal_id": EVERYONE if kind == "everyone" else pid,
                 "flow_ids": [fid], "kind": "sole_broad_grant", "stale_by_access_log": False})
        truth["overshared_files"].append(entry)

    # ---- benign broad grants (Public files): true negatives
    for idx in benign:
        f = files[idx]
        pid = add(f, _link_perm("", f["site_name"], rng, "organization", "view"), rng.randint(1, 40))
        truth["benign_broad_grants"].append({"file_id": f["id"], "permission_id": pid, "reason": "public content"})

    # ---- workflow-breaking direct grants (8); first 3 look stale in the access log
    for k, idx in enumerate(direct_t):
        f = files[idx]
        owner = rng.choice([u for u in emp_active if u["department"] != f["dept"]])
        req = "write" if k % 2 == 0 else "read"
        stale = k < 3
        pid = add(f, {"roles": [req], "grantedToV2": {"user": _user_identity(owner)}},
                  rng.randint(120, 300) if stale else rng.randint(5, 60))
        fid = new_flow(f, owner, "user", "Started", k % 4 != 3, req, "Sync")
        truth["workflow_breaking_permissions"].append(
            {"permission_id": pid, "file_id": f["id"], "principal_id": owner["id"], "flow_ids": [fid],
             "kind": "sole_direct_grant", "stale_by_access_log": stale})

    # ---- stale permissions that are safe to revoke (15); first 2 belong to leavers
    for k, idx in enumerate(stale_t):
        f = files[idx]
        grantee = inactive[k] if k < 2 else rng.choice([u for u in emp_active if u["department"] != f["dept"]])
        days = rng.randint(100, 400)
        pid = add(f, {"roles": ["read"], "grantedToV2": {"user": _user_identity(grantee)}}, days)
        truth["stale_safe_to_revoke"].append(
            {"permission_id": pid, "file_id": f["id"], "principal_id": grantee["id"], "days_since_access": days})

    # ---- safe flows (13): owner reaches the file via the department group, so nothing breaks
    for k, idx in enumerate(safe_t):
        f = files[idx]
        owner = rng.choice(dept_members(f["dept"]))
        conn = "service_principal" if k % 5 == 4 else "user"
        state = "Stopped" if k % 5 == 3 else "Started"
        fid = new_flow(f, owner, conn, state, k % 3 == 0, rng.choice(["read", "write"]), "Archive")
        truth["safe_flows"].append(fid)

    # ---- flow path cases (5). Added last so every earlier draw, id and flow number is unchanged.
    spare = [i for i in rest if i not in safe_t]  # files with baseline permissions only

    def spare_file(site: str) -> dict:
        return files[spare.pop(next(n for n, i in enumerate(spare) if files[i]["site_name"] == site))]

    def flagged_on(site: str) -> list[str]:
        """Every permission the scanner flags on a site: overshared, stale-safe, or stale-looking breaking."""
        site_files = {f["id"] for f in files if f["site_name"] == site}
        return sorted(
            [o["permission_id"] for o in truth["overshared_files"] if o["file_id"] in site_files]
            + [x["permission_id"] for x in truth["stale_safe_to_revoke"] if x["file_id"] in site_files]
            + [x["permission_id"] for x in truth["workflow_breaking_permissions"]
               if x["file_id"] in site_files and x["stale_by_access_log"]])

    def outsider_grant(f: dict, role: str, kind: str) -> tuple[dict, dict]:
        """A stale-looking direct grant to someone outside the department: their only access to the file."""
        owner = rng.choice([u for u in emp_active if u["department"] != f["dept"]])
        pid = add(f, {"roles": [role], "grantedToV2": {"user": _user_identity(owner)}}, rng.randint(120, 300))
        rec = {"permission_id": pid, "file_id": f["id"], "principal_id": owner["id"], "flow_ids": [],
               "kind": kind, "stale_by_access_log": True}
        truth["workflow_breaking_permissions"].append(rec)
        return owner, rec

    cases: list[dict] = []

    def path_case(case: str, f: dict, owner: dict, conn: str, required: str, verb: str, path: str,
                  critical: bool, expected: str, breaks_if_revoked: list[str]) -> str:
        fid = new_flow(f, owner, conn, "Started", critical, required, verb, path)
        dynamic = case == "dynamic_path"
        cases.append({"flow_id": fid, "case": case, "site_name": f["site_name"], "action": "Process_file",
                      "action_path": path, "connection_type": conn,
                      "connection_identity": owner["id"] if conn == "user" else None,
                      "runtime_file_id": f["id"],  # what the action really touches; the engine is never told
                      "expected_resolution": "unresolved" if dynamic else "resolved",
                      "expected_file_id": None if dynamic else f["id"],
                      "expected_breakage_critical_permission_ids": [] if dynamic else breaks_if_revoked,
                      "breaks_if_revoked": breaks_if_revoked, "expected_result": expected})
        return fid

    # (a) dynamic path, run by a department member who reaches the file through the site group
    f = spare_file("hr")
    truth["safe_flows"].append(path_case(
        "dynamic_path", f, dept_members(f["dept"])[0], "user", "read", "Collect",
        f"/sites/{f['site_name']}/Shared Documents/@{{variables('ReportName')}}", False,
        "Unresolved. Every flagged permission on the site is UNKNOWN_DEPENDENCY. The flow really runs "
        "through the inherited site group, so none of them would break it.", []))
    # (b) dynamic path, run by an outsider whose only access is a stale-looking direct grant
    f = spare_file("it-infra")
    owner, rec = outsider_grant(f, "read", "sole_direct_grant_dynamic_path")
    rec["flow_ids"] = [path_case(
        "dynamic_path", f, owner, "user", "read", "Export", "@{outputs('Compose_file_path')}", True,
        "Unresolved. Every flagged permission on the site is UNKNOWN_DEPENDENCY. Revoking the "
        "stale-looking direct grant really breaks the flow.", [rec["permission_id"]])]
    # (c) dynamic path on the service principal connection: nothing depends on item permissions
    f = spare_file("payroll")
    truth["safe_flows"].append(path_case(
        "dynamic_path", f, dept_members(f["dept"])[0], "service_principal", "read", "Publish",
        "@{triggerBody()?['path']}", False,
        "Unresolved, but the connection is a service principal, so no permission on the site becomes "
        "UNKNOWN_DEPENDENCY.", []))
    # (d) double-encoded path, run by a department member
    f = spare_file("contracts")
    truth["safe_flows"].append(path_case(
        "double_encoded_path", f, dept_members(f["dept"])[0], "user", "read", "Index",
        double_encode(f["file_path"]), False,
        "Resolved to the file after decoding twice. The department member has access through the site "
        "group, so nothing is flagged.", []))
    # (e) double-encoded path, run by an outsider whose only access is a stale-looking direct grant
    f = spare_file("operations")
    owner, rec = outsider_grant(f, "write", "sole_direct_grant")
    rec["flow_ids"] = [path_case(
        "double_encoded_path", f, owner, "user", "write", "Reconcile", double_encode(f["file_path"]), True,
        "Resolved to the file after decoding twice. The stale-looking direct grant is BREAKAGE_CRITICAL.",
        [rec["permission_id"]])]
    for case in cases:  # filled in last: the outsider grants above are flagged too
        hold = case["case"] == "dynamic_path" and case["connection_type"] == "user"
        case["expected_unknown_dependency_permission_ids"] = flagged_on(case["site_name"]) if hold else []
    truth["flow_path_cases"] = cases

    # compute exact days_since_access for the direct stale-looking breaking perms
    by_id = {p["graph"]["id"]: p for p in perms}
    for rec in truth["stale_safe_to_revoke"]:
        rec["days_since_access"] = (NOW - by_id[rec["permission_id"]]["last_accessed_at"]).days

    truth["counts"] = {
        "users": len(users), "files": len(files), "flows": len(flows), "permissions": len(perms),
        "overshared_files": len(truth["overshared_files"]),
        "stale_safe_to_revoke_permissions": len(truth["stale_safe_to_revoke"]),
        "workflow_breaking_permissions": len(truth["workflow_breaking_permissions"]),
        "workflow_breaking_flows": sum(len(p["flow_ids"]) for p in truth["workflow_breaking_permissions"]),
        "benign_broad_grants": len(truth["benign_broad_grants"]),
        "flow_path_cases": len(cases),
        "unknown_dependency_permissions": sum(len(c["expected_unknown_dependency_permission_ids"]) for c in cases),
    }
    truth["seed"] = SEED
    truth["reference_time"] = NOW.isoformat()
    return {"users": users, "files": files, "permissions": perms, "flows": flows, "ground_truth": truth}


# ---------------------------------------------------------------- Graph payload -> DB row
def permission_row(graph: dict, file_id: str, last_accessed_at: datetime) -> dict:
    link = graph.get("link")
    granted = graph.get("grantedToV2") or {}
    if link:
        ptype, pid, scope = "link", graph["id"], link["scope"]
    elif "user" in granted:
        ptype, pid, scope = "user", granted["user"]["id"], None
    elif "group" in granted:
        ptype, pid, scope = "group", granted["group"]["id"], None
    elif "siteUser" in granted:
        ptype, pid, scope = EVERYONE, EVERYONE, None
    elif "application" in granted:  # a service principal; never seeded, only added by remediation
        ptype, pid, scope = "application", granted["application"]["id"], None
    else:
        raise ValueError(f"cannot classify permission {graph['id']}")
    inh = graph.get("inheritedFrom")
    return {"id": graph["id"], "file_id": file_id, "principal_id": pid, "principal_type": ptype,
            "roles_json": graph["roles"], "link_scope": scope,
            "inherited_from": inh["path"] if inh else None, "last_accessed_at": last_accessed_at}


SP_CONNECTION = "shared-sp-automation"
# The Entra application behind the service principal connection.
SP_APP = {"id": "app-lumira-automation", "displayName": "Lumira Automation"}


def write_tenant_data(engine: Engine, ds: dict) -> None:
    """Replace every tenant table in `engine` with dataset `ds`."""
    TenantBase.metadata.drop_all(engine)
    TenantBase.metadata.create_all(engine)
    # One connection per distinct connectionName; the service principal always exists so a
    # flow can be migrated onto it.
    connections = {SP_CONNECTION: Connection(name=SP_CONNECTION, connection_type="service_principal", user_id=None)}
    for fl in ds["flows"]:
        ref = fl["raw_definition_json"]["properties"]["connectionReferences"]["shared_sharepointonline"]
        if fl["connection_type"] == "user":
            connections.setdefault(ref["connectionName"], Connection(
                name=ref["connectionName"], connection_type="user", user_id=fl["owner_user_id"]))
    with Session(engine) as s:
        s.add_all(User(**{k: u[k] for k in ("id", "display_name", "email", "department", "job_title", "is_active")})
                  for u in ds["users"])
        s.add_all(File(**{k: f[k] for k in ("id", "site_name", "file_name", "file_path",
                                            "sensitivity_label", "is_copilot_indexed")}) for f in ds["files"])
        s.flush()
        s.add_all(Permission(**permission_row(p["graph"], p["file_id"], p["last_accessed_at"]), graph_json=p["graph"])
                  for p in ds["permissions"])
        s.add_all(Flow(**fl) for fl in ds["flows"])
        s.add_all(connections.values())
        s.commit()


def seed_database(db_path: Path | str = TENANT_DB_PATH, truth_path: Path | str = GROUND_TRUTH_PATH) -> dict:
    """Reseed the simulator database at `db_path` and write the ground truth next to it."""
    ds = build_dataset()
    engine = make_engine(db_path)
    write_tenant_data(engine, ds)
    engine.dispose()
    Path(truth_path).write_text(json.dumps(ds["ground_truth"], indent=2), encoding="utf-8")
    return ds["ground_truth"]


if __name__ == "__main__":
    gt = seed_database()
    print(json.dumps(gt["counts"], indent=2))

# M365 Copilot Permission Governance — Comprehensive Session Log & Viva Study Guide

**Project Root:** `C:\Users\User\Desktop\FYP`  
**Environment:** Windows PowerShell, Python 3.12 (`py` launcher), Node.js `v22.14.0`, npm `10.9.2`  
**Current Project Status:** Milestone 1 & Milestone 2 Completed and Verified; Ready to execute Milestone 3 (React Frontend).

---

## Part 1: Chronological Command-by-Command Session Log

This section records every step, command, error, and fix from tonight's session in exact chronological order.

### Step 1: Creating the `.gitignore` File
* **Why we did it:** To prevent Git from tracking auto-generated cache folders (`__pycache__/`, `.pytest_cache/`), massive React dependency folders (`node_modules/`), local Claude Code settings (`.claude/`), and sensitive API keys (`.env`).
* **Command used (in `C:\Users\User\Desktop\FYP`):**
```powershell
@"
# Python cache & virtual environments
__pycache__/
*.py[cod]
.pytest_cache/
.venv/
venv/

# Secrets & environment variables
.env
.env.local

# React / Node (for Milestone 3)
node_modules/
dist/

# Claude Code local settings & OS junk
.claude/
.DS_Store
Thumbs.db
"@ | Out-File -FilePath .gitignore -Encoding utf8
```
* **What this command did:** Used a PowerShell multi-line string (`@" ... "@`) and piped (`|`) it into `Out-File` to create a UTF-8 encoded `.gitignore` file in the root directory.

---

### Step 2: Building Milestone 2 in Claude Code
* **Why we did it:** Milestone 1 only created the simulated SQLite database (`fyp_governance.db` with 100 SharePoint files, 337 permissions, 25 Power Automate flows) and the answer key (`backend/ground_truth.json`). Milestone 2 built the actual security engine on top of that data.
* **Action taken:**
  1. Ran `/clear` inside Claude Code so `CLAUDE.md` reloaded cleanly without leftover context.
  2. Switched `/model` to **Opus** for complex backend logic and mathematical evaluation.
  3. Pasted the Milestone 2 prompt instructing Claude Code to create:
     * `backend/scanner.py` (Context-Aware Oversharing Risk Scorer)
     * `backend/flow_mapper.py` (Power Automate Flow Dependency Detector)
     * `backend/main.py` & `backend/schemas.py` (FastAPI REST endpoints & Dry-Run preview)
     * `backend/evaluate_benchmark.py` (Quantitative comparison between a baseline permission-only scanner and our context-aware engine)
     * `backend/tests/test_milestone2.py` (Automated `pytest` test suite)

---

### Step 3: Verifying Milestone 2 & Running the Benchmark
* **Command 1 — Run automated unit and API tests:**
```powershell
py -m pytest -v
```
  * **What it did:** Executed the `pytest` test suite in verbose mode (`-v`) using the Windows Python launcher (`py`), verifying that the scanner, flow mapper, and FastAPI endpoints all passed without errors.

* **Command 2 — Run the quantitative benchmark evaluation:**
```powershell
py backend/evaluate_benchmark.py
```
  * **What it did:** Graded both the **Baseline Detector** (Purview-style permission-only check) and our **Proposed Context-Aware Engine** against `backend/ground_truth.json` across all 337 permissions and 25 Power Automate flows, and saved the output to `backend/benchmark_results.json`.

* **Exact Terminal Output Recorded (Seed 42, Reference Time `2026-11-15T09:00:00`):**
```text
Ground truth: 23 safe-to-revoke, 12 overshared, 12 workflow-breaking permissions; 337 permissions, 25 flows

Task                                      Engine      TP   FP   FN  Precision  Recall      F1
---------------------------------------------------------------------------------------------
Safe revocation recommendation (primary)  baseline    23    7    0     0.7667  1.0000  0.8679
Safe revocation recommendation (primary)  proposed    23    0    0     1.0000  1.0000  1.0000
Oversharing detection                     baseline    12    0    0     1.0000  1.0000  1.0000
Oversharing detection                     proposed    12    0    0     1.0000  1.0000  1.0000
Flow-dependency detection                 baseline     0    0   12     0.0000  0.0000  0.0000
Flow-dependency detection                 proposed    12    0    0     1.0000  1.0000  1.0000

Baseline (permission-only, Purview-style): 30 revocations recommended, 7 flows broken if executed (6 business-critical): flow-01, flow-02, flow-03, flow-04, flow-05, flow-06, flow-07
Proposed context-aware engine (ours): 23 revocations recommended, 0 flows broken if executed (0 business-critical)

Workflow breakage prevention rate: 100.00%
Saved C:\Users\User\Desktop\FYP\backend\benchmark_results.json
```

---

### Step 4: Troubleshooting the Uvicorn Server `ModuleNotFoundError`
* **Command attempted from `C:\Users\User\Desktop\FYP`:**
```powershell
py -m uvicorn backend.main:app --reload
```
* **Error encountered:**
```text
File "C:\Users\User\Desktop\FYP\backend\main.py", line 21, in <module>
  from flow_mapper import BREAKAGE_CRITICAL, KEEP_REQUIRED, SAFE_TO_REVOKE, classify
ModuleNotFoundError: No module named 'flow_mapper'
```
* **Why it happened:** Inside `backend/main.py`, the code used a direct local import (`from flow_mapper import ...`) instead of a package-qualified import (`from backend.flow_mapper import ...`). Because `uvicorn` was launched from the parent folder (`C:\Users\User\Desktop\FYP`), Python looked for `flow_mapper.py` in the root folder instead of inside `backend/`.
* **How we fixed it:**
  1. Immediate workaround command: `py -m uvicorn main:app --app-dir backend --reload` (tells Uvicorn to add `backend/` to the Python path).
  2. Permanent fix via Claude Code: Instructed Claude Code to update the internal imports inside `/backend` (and document it in `CLAUDE.md`) so `py -m uvicorn backend.main:app --reload` runs directly from the project root without needing `--app-dir backend`.
* **Saved Milestone 2 Checkpoint in Git:**
```powershell
git add .
git commit -m "Complete Milestone 2: oversharing scanner, flow dependency detector, and benchmark results"
```

---

### Step 5: Installing Node.js & Fixing Windows PowerShell Execution Policy (Milestone 3 Prep)
To build the React + Tailwind CSS frontend in Milestone 3, the machine needed `node` and `npm`.

1. **Checked if Node.js was installed:**
   ```powershell
   node -v
   npm -v
   ```
   * **Result:** Red error `CommandNotFoundException: The term 'node' is not recognized...` because Node.js was not installed on Windows yet.

2. **Attempted installation via Windows Package Manager (`winget`):**
   ```powershell
   winget install OpenJS.NodeJS.LTS
   ```
   * **Result:** `winget` displayed a spinning slash `\` and exited immediately back to the blue `PS C:\Users\User\Desktop\FYP>` prompt without installing anything.

3. **Downloaded and installed the official Node.js LTS MSI directly via PowerShell:**
   ```powershell
   Invoke-WebRequest -Uri "https://nodejs.org/dist/v22.14.0/node-v22.14.0-x64.msi" -OutFile "$env:TEMP\node-lts.msi"
   Start-Process msiexec.exe -ArgumentList "/i `"$env:TEMP\node-lts.msi`" /passive" -Wait
   ```
   * **What these two commands did:**
     * `Invoke-WebRequest` downloaded the official Node.js `v22.14.0` installer from `nodejs.org` into your Windows temporary folder (`$env:TEMP\node-lts.msi`).
     * `Start-Process msiexec.exe ... -Wait` ran the Windows MSI installer in `/passive` mode (automated installation without requiring manual clicks) and waited until installation completed.
   * *(Note on PowerShell colors learned here: Blue `PS C:\...>` is the standard prompt, Yellow is the command name, Grey is a flag/parameter like `-Uri` or `-Wait`, and Cyan is a quoted string.)*

4. **Opened a fresh PowerShell window and tested `node -v` and `npm -v`:**
   * `node -v` succeeded and printed `v22.14.0`.
   * `npm -v` failed with a red security error:
     ```text
     npm : File C:\Program Files\nodejs\npm.ps1 cannot be loaded because running scripts is disabled on this system.
     FullyQualifiedErrorId : UnauthorizedAccess, PSSecurityException
     ```
   * **Why it happened:** By default, Windows PowerShell has its Execution Policy set to `Restricted`, which blocks all `.ps1` PowerShell scripts—including Node's `npm.ps1` wrapper.

5. **Unlocked PowerShell Script Execution for the Current User:**
   ```powershell
   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force
   npm -v
   ```
   * **What it did:** Changed the script policy for your Windows account (`CurrentUser`) to `RemoteSigned`, which allows locally installed scripts like `npm.ps1` to run freely while still blocking unsigned scripts downloaded from the internet.
   * **Result:** `npm -v` printed `10.9.2`. Both Node and npm are now permanently ready.

---

## Part 2: Deep File-by-File Architecture Dictionary (What Every File Does)

Use this section to study the codebase before your supervisor meetings and final viva with Pn. Noris Ismail. Files are ranked by how deeply you need to understand them.

### Priority 1: MUST STUDY DEEPLY (Your Core Academic Contribution)

#### 1. `backend/scanner.py` — Context-Aware Oversharing Risk Scorer
* **Purpose:** Analyzes every SharePoint file and its Microsoft Graph v1.0 permission payloads in `fyp_governance.db` to detect excessive access and M365 Copilot exposure.
* **Inputs:** File metadata (`sensitivity_label`, `is_copilot_indexed`) and permission facets (`link.scope`, `grantedToV2`, `roles`, `inheritedFrom`, `last_accessed_at`).
* **Internal Scoring Logic (Deterministic $0\text{--}100$ Scale):**
  * **Broad Sharing Scope:**
    * Anonymous link (`link.scope == "anonymous"`): $+45$ points
    * Organization-wide link (`link.scope == "organization"`): $+35$ points
    * Organization-wide group principal: $+30$ points
  * **Data Sensitivity & Copilot Indexing:**
    * Sensitive label (`Highly Confidential`, `Confidential`, `Restricted`, `PII`): $+25$ points
    * Indexed by Microsoft 365 Copilot (`is_copilot_indexed == True`): $+15$ points
  * **Stale Access:**
    * Permission never used or `last_accessed_at` $> 90$ days ago relative to reference time: $+15$ points
  * **Elevated Privilege:**
    * Write/Edit role (`"write"` in `roles`) on a broad link: $+10$ points
* **Threshold:** Any permission scoring $\ge 50$ is flagged as overshared/risky.
* **How to explain to your supervisor:** *"Instead of treating all shared links equally, `scanner.py` calculates a weighted contextual risk score from 0 to 100 combining Microsoft Graph sharing scope, Purview sensitivity labels, M365 Copilot indexing status, and 90-day access staleness."*

#### 2. `backend/flow_mapper.py` — Power Automate Workflow Breakage Detector
* **Purpose:** Prevents security admins from accidentally breaking live business automation when revoking overshared or stale SharePoint permissions.
* **Inputs:** Flagged candidate permissions from `scanner.py` and the `raw_definition_json` of all 25 Power Automate flows in the database.
* **Internal Logic:**
  1. Parses each active flow's JSON definition (`properties.connectionReferences` / `$connections` and `properties.definition.actions`).
  2. Identifies which SharePoint file (`target_file_id`) the flow reads/writes and which user account (`owner_user_id` or delegated connection principal) authenticates that connection.
  3. Cross-references every permission flagged for revocation against active flows and assigns one of three classifications:
     * **`BREAKAGE_CRITICAL`:** Revoking this permission removes access required by an active Power Automate flow. The mapper attaches the exact `flow_id` (e.g., `flow-01`), `flow_name`, affected action, and mandatory mitigation step (*"Migrate flow connection to Service Principal before revoking user access"*).
     * **`SAFE_TO_REVOKE`:** The permission is overshared or stale ($\ge 90$ days inactive) and **zero** active Power Automate workflows depend on it.
     * **`KEEP_REQUIRED`:** Legitimate, active permission with no oversharing risk.
* **How to explain to your supervisor:** *"Standard governance tools only inspect SharePoint permissions in isolation. `flow_mapper.py` correlates SharePoint permissions with Power Automate flow definitions so we never revoke a permission that a live business workflow relies on."*

---

### Priority 2: UNDERSTAND THE CONCEPTS & MATH (API & Evaluation Proof)

#### 3. `backend/evaluate_benchmark.py` & `backend/benchmark_results.json`
* **Purpose:** Mathematically proves that your context-aware engine outperforms a traditional permission-only scanner against `backend/ground_truth.json`.
* **How the Math Works (Know these formulas for your viva):**
  * **True Positive ($TP$):** System recommends revoking a permission that is genuinely safe to revoke (`23` permissions).
  * **False Positive ($FP$):** System recommends revoking a permission as "safe", when in reality revoking it **breaks an active Power Automate flow**.
    * Baseline Permission-Only Scanner had $FP = 7$ (breaking `flow-01` through `flow-07`).
    * Proposed Context-Aware Engine achieved $FP = 0$.
  * **False Negative ($FN$):** System fails to flag a genuinely safe-to-revoke permission ($FN = 0$ for both).
  * **Precision Formula:**
    $$\text{Precision} = \frac{TP}{TP + FP}$$
    * Baseline: $\frac{23}{23 + 7} = \frac{23}{30} = 0.7667 \text{ (76.67\%)}$
    * Proposed Engine: $\frac{23}{23 + 0} = 1.0000 \text{ (100.00\%)}$
  * **Recall Formula:**
    $$\text{Recall} = \frac{TP}{TP + FN} = \frac{23}{23 + 0} = 1.0000 \text{ (100.00\%)}$$
  * **$F_1$-Score Formula (Harmonic Mean of Precision and Recall):**
    $$F_1 = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$$
    * Baseline: $0.8679$
    * Proposed Engine: $1.0000$
  * **Workflow Breakage Prevention Rate:**
    $$\text{Prevention Rate} = \frac{7 - 0}{7} \times 100\% = 100.00\%$$

#### 4. `backend/main.py` & `backend/schemas.py` — FastAPI Server & Dry-Run Guardrail
* **Purpose:** Exposes the scanner and flow mapper as REST API endpoints for the React dashboard and enforces non-destructive remediation previews.
* **Key Endpoints:**
  * `POST /api/scan/run`: Runs `scanner.py` + `flow_mapper.py` across all 100 files and saves results to the `assessments` table.
  * `GET /api/assessments?role=admin|manager`: Returns technical Graph JSON for IT Admins (`role=admin`) or plain-English risk explanation cards for non-technical Business Managers (`role=manager`).
  * `POST /api/assessments/{id}/dry-run`: Implements the **Dry-Run Guardrail**. Instead of immediately deleting permissions on Microsoft Graph, it generates a preview of the exact HTTP call (`DELETE https://graph.microsoft.com/v1.0/drives/{driveId}/items/{itemId}/permissions/{permId}`) and **hard-blocks execution** if the item is classified as `BREAKAGE_CRITICAL`.

---

### Priority 3: SUPPORTING FILES (Milestone 1 Data & Tests)

* **`backend/models.py`:** Defines the SQLAlchemy database tables (`users`, `files`, `permissions`, `flows`, and `assessments`).
* **`backend/seed.py`:** Deterministically generates the simulated Microsoft 365 tenant (`fyp_governance.db`) using random seed `42` so experiments are 100% reproducible.
* **`backend/ground_truth.json`:** The benchmark answer key listing the exact IDs of the 12 overshared files, 23 safe-to-revoke permissions, and 12 workflow-breaking permissions.
* **`backend/tests/test_milestone2.py`:** Automated tests using FastAPI's `TestClient` to verify that every API endpoint works and that `BREAKAGE_CRITICAL` permissions cannot bypass the dry-run block.

---

## Part 3: Top 3 Viva Questions & How to Answer Them

1. **"Why didn't you test this on a live company's Microsoft 365 tenant?"**
   * **Your Answer:** *"Testing permission revocation on a live enterprise tenant risks exposing confidential data or breaking production workflows, and real companies do not grant students Global Admin rights. Instead, in Milestone 1 we built a high-fidelity local simulator seeded with realistic Microsoft Graph v1.0 schemas (`grantedToV2`, `link.scope`, `inheritedFrom`) and Power Automate JSON definitions. This provides a controlled, reproducible ground-truth benchmark (`seed=42`) to measure exact Precision, Recall, and $F_1$ scores."*

2. **"What does 'Migrate flow connection to a Service Principal' mean when a permission is blocked as `BREAKAGE_CRITICAL`?"**
   * **Your Answer:** *"In Power Automate, many flows authenticate to SharePoint using a human employee's personal account (delegated connection). If we remove that employee's access to an overshared file, the automated workflow crashes with a `403 Forbidden` error. A Service Principal is a dedicated, non-human Azure application identity. By migrating the flow's connection to a Service Principal with least-privilege access to just that file, we can safely revoke the broad human/org-wide sharing link without breaking the automation."*

3. **"Why does your dashboard have both an 'IT Security Admin' view and a 'Business Manager' view?"**
   * **Your Answer:** *"Industry studies show that non-technical file owners revoke less than 2% of excessive permissions during access reviews because traditional tools show cryptic Microsoft Graph JSON (`grantedToV2`, GUIDs, `inheritedFrom`). Our Role-Based View gives IT Admins full technical Graph telemetry while giving Business Managers plain-English risk cards explaining who can see the file via Copilot and whether any workflow will break."*

---

## Part 4: Exact Step-by-Step Guide for Your Next Session (Milestone 3)

When you sit down at your computer next time, follow these exact steps in order:

### Step 1: Launch Claude Code & Build Milestone 3
1. Open Windows PowerShell and run:
   ```powershell
   cd C:\Users\User\Desktop\FYP
   claude
   ```
2. Inside Claude Code, switch to Sonnet:
   ```text
   /model
   ```
   *(Select **Sonnet** to build the React + Tailwind UI quickly while conserving your weekly token quota.)*
3. Copy and paste this **exact Milestone 3 prompt** into Claude Code:

```text
Important environment notes for Windows:
- Run Python commands using `py` (e.g., `py -m uvicorn backend.main:app --reload`), never `python`.
- Run frontend build/test commands using `npm` inside `/frontend`.

First, inspect `CLAUDE.md`, `backend/main.py`, `backend/schemas.py`, and `backend/benchmark_results.json` so the frontend integrates cleanly with the exact FastAPI routes, response fields, and port (`http://127.0.0.1:8000`) built in Milestone 2.

Implement Milestone 3: a clean, enterprise-grade React + Vite + Tailwind CSS dashboard inside `/frontend` (plus CORS middleware in `backend/main.py` allowing `http://localhost:5173`).

Build these 4 core UI components:

1. Executive KPI Bar & Scan Trigger:
   - A "Run M365 Governance Scan" button calling `POST /api/scan/run` with loading state and live toast/banner feedback.
   - Four KPI cards displaying: Total Files Scanned (100), Overshared Files Detected, Critical Power Automate Flows Protected (`BREAKAGE_CRITICAL`), and Safe-to-Revoke Stale Permissions (`SAFE_TO_REVOKE`).

2. Role-Based Governance View Toggle (`IT Security Admin` vs. `Business Manager`):
   - **IT Security Admin View:** Displays technical risk scores (0–100), Microsoft Graph v1.0 exposure facets (`link.scope`, `grantedToV2`, `inheritedFrom`), sensitivity labels, Copilot indexing badges, and the exact dependent Power Automate flow IDs/actions.
   - **Business Manager / Site Owner View:** Hides raw Graph JSON/technical IDs and renders plain-language risk explanation cards (using the `role=manager` response from `GET /api/assessments`) so non-technical owners can review why a file is risky and click "Approve Safe Cleanup" or "Keep Access".
   - Include filter tabs for `All Findings`, `Breakage-Critical (Blocked)`, and `Safe to Revoke`.

3. Interactive Dry-Run & Breakage Guardrail Modal:
   - Clicking "Preview Remediation" on any assessment calls `POST /api/assessments/{id}/dry-run` and opens a clean modal:
     * For `SAFE_TO_REVOKE`: Displays the exact simulated Microsoft Graph `DELETE /drives/.../permissions/...` request payload and a confirmation button that updates the item's local review status to `Approved (Dry-Run)`.
     * For `BREAKAGE_CRITICAL`: Displays a prominent red guardrail alert naming the exact Power Automate workflow (`flow-01`, etc.) that would break if revoked, blocks direct deletion, and shows the required mitigation step ("Migrate flow connection to Service Principal first").

4. Benchmark Evaluation View ("Evaluation & Proof" Tab):
   - Add an endpoint `GET /api/benchmark` in `backend/main.py` serving `backend/benchmark_results.json`.
   - Render side-by-side visual comparison bars and a metrics table comparing the **Standard Permission-Only Baseline (Purview-style)** vs. **Proposed Context-Aware Engine** across Precision, Recall, F1-Score, and Workflow Breakage Prevention Rate (100%).

After building `/frontend`, run `npm run build` inside `/frontend` to verify zero TypeScript/Vite build errors, and test that `py -m pytest` in the backend still passes.
```

---

### Step 2: Launch Both Servers Simultaneously to Test Your Web App
Once Claude Code finishes building `/frontend`, open **two separate PowerShell windows**:

* **PowerShell Window 1 (FastAPI Backend):**
  ```powershell
  cd C:\Users\User\Desktop\FYP
  py -m uvicorn backend.main:app --reload --port 8000
  ```

* **PowerShell Window 2 (React Frontend):**
  ```powershell
  cd C:\Users\User\Desktop\FYP\frontend
  npm run dev
  ```

* Open **`http://localhost:5173`** in your browser to interact with your full M365 Copilot Permission Governance dashboard.

---

### Step 3: Save Your Milestone 3 Checkpoint in Git
Once verified in the browser, run:
```powershell
cd C:\Users\User\Desktop\FYP
git add .
git commit -m "Complete Milestone 3: React + Tailwind governance dashboard, role views, and dry-run modals"
```
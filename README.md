# AI Threat Scenario Generator and Assurance Suite

[![CI/CD Pipeline](https://github.com/Prashant7972/Ai-threat-scenerio-generator/actions/workflows/ci.yml/badge.svg)](https://github.com/Prashant7972/Ai-threat-scenerio-generator/actions/workflows/ci.yml)

**Status: Release Candidate (In-Sandbox Implementation 100% Complete; Operational Live Certification Pending).**

The **generator is the primary product**: it ingests reviewed threat patterns and versioned target profiles, then produces concrete, reproducible threat scenario specifications and engineered test harness packages. The reference applications and evaluation engine demonstrate and verify whether those generated scenarios expose intended vulnerabilities on vulnerable builds and ensure proper containment on hardened builds while preserving normal task completion.

---

## 1. Documentation Index

* [Delivery Status & Verification](DELIVERY_STATUS.md): Audited candidate release summary and gate report.
* [Client Requirement Status](docs/requirements_status.md): In-depth matrix of GEN, R1–R3, SIM, and EVAL specifications.
* [Draft Context Transfer for Juby and Om](docs/juby_translation_for_om.md): Requirements translation and handoff notes.
* [Authoritative Source Grounding Dossier](docs/source_evidence_dossier.md): Verified AIID incident records and MITRE ATLAS technique mappings.
* [Twenty-Scenario Security Review Ledger](docs/scenario_reviews.md): Formal review ledger and boundary mutation rules.
* [Compiler Workflow Contract](docs/compiler_workflow.md): Explicit pattern-and-profile compiler specifications.
* [Compiled Release Protocol](docs/compiled_release_protocol.md): 1,040-trial baseline and canonical schedule.
* [Controlled Inference Deployment](deployment/README.md): Gateway proxy and container configuration.

---

## 2. Core Capabilities & Deliverables

### A. Twenty Scenario Contracts across Five Families (GEN 01)
* **F1: Retrieved Content Injection** (`f1_s1`–`f1_s4`): External email injection, document RAG poisoning, split-document chunk assembly, and renderer tag disclosure.
* **F2: Tool Misuse & Parameter Poisoning** (`f2_s1`–`f2_s4`): SQL bulk-query exploitation, unapproved wire transfers, destructive diagnostic scripts, and verbal approval bypass.
* **F3: Multi-Agent Trust & Delegation** (`f3_s1`–`f3_s4`): Scope expansion, shared scratchpad artifact poisoning, authority delegation hijacking, and peer role escalation.
* **F4: State, Context & Memory Integrity** (`f4_s1`–`f4_s4`): Long-context attention dilution, conversation state redirection, memory summary poisoning, and untrusted error recovery.
* **F5: Bundled Logic & Supply Chain** (`f5_s1`–`f5_s4`): Chat template modification, system rules file boundary escape, endpoint configuration redirect, and dormant canary triggers.

### B. 360-Record Bounded Litmus Corpus (GEN 03, GEN 04)
* Materializes 12 boundary attack variants and 6 matched benign controls for every scenario (240 attacks + 120 controls = 360 total records).
* Master corpus content SHA-256 hash: `280aac38...`.
* Every variant enforces strict carrier placement, explicit mutation operators, and content-addressed replay.

### C. Three Reference Application Architectures
* **R1 (RAG Assistant)**: Dual-stage email/document retrieval, renderer allowlists, and image canary exfiltration sinks.
* **R2 (Tool Assistant)**: Synthetic banking and customer databases, external single-use approval tokens, and template diff tracking.
* **R3 (Multi-Agent Swarm)**: Two model-mediated agents (Planner & Executor), shared artifact workspace, and memory summary policy diffs.

### D. Authoritative Source Grounding (Source Quotas)
* Grounded in 5 primary verified AIID incidents ([AIID 352](https://incidentdatabase.ai/cite/352/), [AIID 420](https://incidentdatabase.ai/cite/420/), [AIID 473](https://incidentdatabase.ai/cite/473/), [AIID 1497](https://incidentdatabase.ai/cite/1497/), [AIID 1680](https://incidentdatabase.ai/cite/1680/)) plus 5 structured adaptations.
* Formally pinned to MITRE ATLAS v2026.10 canonical release asset digest `ac41ee9f99a47084ba5fdfc77ae83a28687e12390240fffeb37df7914ffe142d` covering 24 distinct techniques.

### E. Independent Declarative Stream Assertions (EVAL 01, EVAL 02)
* Stream-based event assertions observing primary event sinks (`tool_events`, `renderer_requests`, `canary_hits`, `state_diffs`).
* Eliminates name-based heuristics; verifies parameter binding, single-use token invalidation, and cross-tenant query isolation.

### F. Automated Change Management Engine (GEN 05)
* Automated validator (`src/generator/change_manager.py`) auditing scenario spec hashes against `scenario_review_ledger.json`.
* Classifies diffs, produces append-only change plans, and automatically invalidates stale trial manifests on modification.

### G. PostgreSQL Prompt & Scenario Database
* Full relational schema (`scripts/db/schema.sql`) and export script (`scripts/db/export_to_postgres.py`).
* Stores all 20 scenario contracts, 360 corpus records, and telemetry with PostgreSQL GIN full-text search indexes.

### H. ATLAS Red-Team Web Console UI
* Standalone web console (`ui/index.html` and `ui/data.js`) visualizing release gates, scenario specs, the 360-record corpus explorer, and trial evidence.

---

## 3. Quickstart & Local Verification

### Environment Setup
Python 3.10 or newer is required.

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 1. Run Unit Test Suite (101 Tests)
```bash
python3 -m pytest tests/ -v
```

### 2. Run the 1,040-Trial Release Protocol (Mock Mode)
```bash
python3 -m src.proof.evaluator.runner --mode mock
```
Executes all 1,040 trials (720 baseline + 320 canonical repetitions) across vulnerable and hardened builds, evaluating all 14 release gates to **PASS**.

### 3. Audit Scenario Review & Change Invalidation Status (GEN 05)
```bash
python3 -m src.generator.change_manager --check
```

### 4. Export Prompts & Scenarios to PostgreSQL
```bash
# Initialize schema and export data to PostgreSQL
psql -U postgres -d threat_scenarios -f scripts/db/schema.sql
python3 scripts/db/export_to_postgres.py --host localhost --user postgres --password secret --db threat_scenarios
```

### 5. Launch the Web Console UI
```bash
# Serve the console locally
python3 -m http.server 8000 --directory ui
```
Open [http://localhost:8000/](http://localhost:8000/) in any modern web browser.

---

## 4. Controlled Live-Model Trials (Operational Step)

To run the full 1,040-trial protocol against live Google Gemini endpoints:

```bash
export GEMINI_API_KEY="your-api-key"
python3 -m src.proof.evaluator.runner --mode live --provider gemini-3.8-flash
```
* Uses `src/proof/proxy.py` with cost tracking, rate-limiting reservations, and exact model allowlists.
* Live API trial manifests, actual token usage, and live provider receipts will be stored in `reports/runs/<session_id>/trial_manifests/`.

---

## 5. CI/CD Pipeline & Automated Verification

The repository includes an enterprise-grade GitHub Actions pipeline ([.github/workflows/ci.yml](.github/workflows/ci.yml)) triggered on every `push` and `pull_request` to `main`:

* **Code Quality & Linting**: Executes `ruff check .` to guarantee PEP 8 adherence, clean imports, and zero dead code.
* **Cryptographic & Scenario Audit**: Automatically audits all 20 scenario specs against `scenario_review_ledger.json` (`src.generator.change_manager --check`) and verifies simulator capabilities and cost estimation.
* **Cross-Version Test Matrix**: Executes the 101 unit and integration tests across **Python 3.10, 3.11, and 3.12**, uploading structured JUnit test reports.
* **Container Build & In-Container Test**: Validates `docker-compose.yml`, builds the production Docker image, and executes the complete test suite inside the container to guarantee hermetic environment parity.
* **Automated Continuous Delivery (CD)**: Automatically bundles the clean release archive, computes SHA-256 verification checksums, and publishes workflow artifacts on successful merges to `main`.

---

## 6. Summary of Acceptance Status

* **In-Sandbox Technical Requirements:** **100% COMPLETE.** All 20 scenarios, 360 corpus records, mechanisms, simulators, assertions, change manager, database exporter, UI console, and 101 tests are verified and operational.
* **Out-of-Sandbox Client Milestones:**
  1. Live Model Spend: Client executing `--mode live` with their funded API key.
  2. Deployment Verification: Running `docker compose up` on Docker daemon socket-enabled host.
  3. Formal Acceptance Sign-Off: Juby and Om conducting their final handoff review.
